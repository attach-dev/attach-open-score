package score

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
)

const (
	ProfileLocalDevDefault = "local-dev-default"
	ProfileCIStrict        = "ci-strict"
	ProfileAuditOnly       = "audit-only"

	DefaultEngineVersion = "attach-open-score-go/dev"
	DefaultTTLSeconds    = 86400

	allowScoreCeiling          = 24
	askScoreFloor              = 25
	askScoreCeiling            = 59
	unknownLocalScore          = 45
	denyScoreFloor             = 85
	severityCriticalScore      = 95
	severityHighScore          = 70
	severityMediumScore        = 45
	severityLowScore           = 20
	severityInformationalScore = 5
)

var reasonCodePattern = regexp.MustCompile(`^(X_)?[A-Z][A-Z0-9_]*$`)

type Request = schema.Request

type Evidence = schema.Evidence

type Result = schema.Verdict

type Options struct {
	Now           func() time.Time
	PolicyProfile string
	EngineVersion string
	TTLSeconds    *int
}

type Engine struct {
	now           func() time.Time
	policyProfile string
	engineVersion string
	ttlSeconds    int
}

func NewEngine(options Options) (Engine, error) {
	now := options.Now
	if now == nil {
		now = time.Now
	}

	profile := options.PolicyProfile
	if profile == "" {
		profile = ProfileLocalDevDefault
	} else if !isKnownPolicyProfile(profile) {
		return Engine{}, fmt.Errorf("unknown policy profile %q", profile)
	}

	engineVersion := options.EngineVersion
	if engineVersion == "" {
		engineVersion = DefaultEngineVersion
	}

	ttl := DefaultTTLSeconds
	if options.TTLSeconds != nil && *options.TTLSeconds >= 0 {
		ttl = *options.TTLSeconds
	}

	return Engine{
		now:           now,
		policyProfile: profile,
		engineVersion: engineVersion,
		ttlSeconds:    ttl,
	}, nil
}

func (e Engine) Evaluate(request Request) (schema.Verdict, error) {
	if err := validatePackage(request.Package); err != nil {
		return schema.Verdict{}, err
	}

	reasonsOut := make([]schema.Reason, 0, len(request.Evidence))
	sourceRefs := make([]schema.SourceRef, 0, len(request.Evidence))
	seenSourceRefs := map[string]int{}

	if len(request.Evidence) == 0 {
		reasonsOut = append(reasonsOut, schema.Reason{
			Code:           reasons.InsufficientData,
			Severity:       "MEDIUM",
			DecisionEffect: schema.DecisionEffectUnknown,
			Message:        "No evidence was provided to the offline deterministic scorer.",
		})
	} else {
		for _, evidence := range request.Evidence {
			if err := validateReason(evidence.Reason); err != nil {
				return schema.Verdict{}, err
			}
			reasonsOut = append(reasonsOut, evidence.Reason)

			reasonSourceRefs := map[string]struct{}{}
			for _, sourceRefID := range evidence.Reason.SourceRefIDs {
				if _, ok := reasonSourceRefs[sourceRefID]; ok {
					return schema.Verdict{}, fmt.Errorf("reason %q has duplicate source_ref_id %q", evidence.Reason.Code, sourceRefID)
				}
				reasonSourceRefs[sourceRefID] = struct{}{}
			}

			if evidence.SourceRef != nil {
				if err := appendSourceRef(&sourceRefs, seenSourceRefs, *evidence.SourceRef); err != nil {
					return schema.Verdict{}, err
				}
			}
			for _, sourceRef := range evidence.SourceRefs {
				if err := appendSourceRef(&sourceRefs, seenSourceRefs, sourceRef); err != nil {
					return schema.Verdict{}, err
				}
			}
		}

		availableSourceRefs := map[string]struct{}{}
		for _, sourceRef := range sourceRefs {
			availableSourceRefs[sourceRef.ID] = struct{}{}
		}
		for _, reason := range reasonsOut {
			for _, sourceRefID := range reason.SourceRefIDs {
				if _, ok := availableSourceRefs[sourceRefID]; !ok {
					return schema.Verdict{}, fmt.Errorf("reason %q references missing source_ref_id %q", reason.Code, sourceRefID)
				}
			}
		}
	}

	decision, scoreValue, confidence := decide(e.policyProfile, reasonsOut)

	verdict := schema.Verdict{
		SchemaVersion: schema.VersionV0,
		PolicyProfile: e.policyProfile,
		EngineVersion: e.engineVersion,
		Package:       request.Package,
		Decision:      decision,
		Score:         scoreValue,
		Confidence:    confidence,
		Reasons:       reasonsOut,
		SourceRefs:    sourceRefs,
		EvaluatedAt:   e.now().UTC().Format(time.RFC3339),
		TTLSeconds:    e.ttlSeconds,
		Limitations:   limitationsForProfile(e.policyProfile),
	}

	return verdict, nil
}

func appendSourceRef(sourceRefs *[]schema.SourceRef, seenSourceRefs map[string]int, sourceRef schema.SourceRef) error {
	if err := validateSourceRef(sourceRef); err != nil {
		return err
	}
	if existing, ok := seenSourceRefs[sourceRef.ID]; ok {
		if !reflect.DeepEqual((*sourceRefs)[existing], sourceRef) {
			return fmt.Errorf("conflicting source_ref %q", sourceRef.ID)
		}
		return nil
	}
	*sourceRefs = append(*sourceRefs, sourceRef)
	seenSourceRefs[sourceRef.ID] = len(*sourceRefs) - 1
	return nil
}

func validatePackage(pkg schema.PackageIdentity) error {
	if pkg.Ecosystem == "" {
		return fmt.Errorf("package ecosystem is required")
	}
	if !isAllowed(pkg.Ecosystem, "npm", "pypi", "crates", "go", "maven", "rubygems", "other") {
		return fmt.Errorf("package ecosystem %q is not supported by schema v0", pkg.Ecosystem)
	}
	if pkg.Name == "" {
		return fmt.Errorf("package name is required")
	}
	if pkg.PURL == "" {
		return fmt.Errorf("package purl is required")
	}
	if pkg.Resolved && pkg.Version == "" {
		return fmt.Errorf("package version is required when resolved is true")
	}
	if pkg.RepositoryURL != "" {
		if err := validateURI("package repository_url", pkg.RepositoryURL); err != nil {
			return err
		}
	}
	return nil
}

func validateReason(reason schema.Reason) error {
	if reason.Code == "" {
		return fmt.Errorf("evidence reason code is required")
	}
	if !reasonCodePattern.MatchString(reason.Code) {
		return fmt.Errorf("reason code %q does not match the v0 schema pattern", reason.Code)
	}
	if !reasons.IsKnown(reason.Code) && !strings.HasPrefix(reason.Code, "X_") {
		return fmt.Errorf("reason code %q is not in the v0 taxonomy", reason.Code)
	}
	if !isAllowed(reason.Severity, "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL") {
		return fmt.Errorf("reason %q has invalid severity %q", reason.Code, reason.Severity)
	}
	if !isAllowed(string(reason.DecisionEffect), "ALLOW", "ASK", "DENY", "UNKNOWN", "NONE") {
		return fmt.Errorf("reason %q has invalid decision_effect %q", reason.Code, reason.DecisionEffect)
	}
	if reason.Message == "" {
		return fmt.Errorf("reason %q message is required", reason.Code)
	}
	if reason.Details != nil {
		if _, err := json.Marshal(reason.Details); err != nil {
			return fmt.Errorf("reason %q details must be JSON-serializable: %w", reason.Code, err)
		}
	}
	if requiresSourceRef(reason.Code) && len(reason.SourceRefIDs) == 0 {
		return fmt.Errorf("reason %q requires at least one source_ref_id", reason.Code)
	}
	if strings.HasPrefix(reason.Code, "X_") && reason.DecisionEffect != schema.DecisionEffectNone && len(reason.SourceRefIDs) == 0 {
		return fmt.Errorf("experimental reason %q with effect %s requires at least one source_ref_id", reason.Code, reason.DecisionEffect)
	}
	if err := validateKnownReasonEffect(reason); err != nil {
		return err
	}
	return nil
}

func validateKnownReasonEffect(reason schema.Reason) error {
	expected, ok := defaultDecisionEffect(reason.Code)
	if !ok {
		return nil
	}
	if reason.DecisionEffect != expected {
		return fmt.Errorf("reason %q must use %s effect in v0 scorer core", reason.Code, expected)
	}
	return nil
}

func defaultDecisionEffect(code string) (schema.DecisionEffect, bool) {
	switch code {
	case reasons.KnownMaliciousPackage,
		reasons.KnownVulnerabilityCritical,
		reasons.ArtifactDigestMismatch:
		return schema.DecisionEffectDeny, true
	case reasons.KnownVulnerabilityHigh,
		reasons.KnownVulnerabilityModerate,
		reasons.PackageTooNew,
		reasons.VersionTooNew,
		reasons.PackageUnpublishedOrYanked,
		reasons.DeprecatedPackage,
		reasons.InstallScriptPresent,
		reasons.SuspiciousInstallScript,
		reasons.SuspiciousBinaryArtifact,
		reasons.PossibleTyposquat,
		reasons.DependencyConfusionRisk,
		reasons.LowRepositoryHealth,
		reasons.ReleaseRecencyStale,
		reasons.SourceStale,
		reasons.ConflictingSourceData:
		return schema.DecisionEffectAsk, true
	case reasons.UnresolvedPackage,
		reasons.UnsupportedEcosystem,
		reasons.SourceUnavailable,
		reasons.SourceTermsBlocked,
		reasons.InsufficientData:
		return schema.DecisionEffectUnknown, true
	case reasons.NoKnownVulnerabilities,
		reasons.RepositoryMappingUncertain,
		reasons.MaintainerActivityLow,
		reasons.ReleaseRecencyFresh,
		reasons.ReleaseRecencyNearStale:
		return schema.DecisionEffectNone, true
	default:
		return "", false
	}
}

func requiresSourceRef(code string) bool {
	switch code {
	case reasons.KnownMaliciousPackage,
		reasons.KnownVulnerabilityCritical,
		reasons.KnownVulnerabilityHigh,
		reasons.KnownVulnerabilityModerate,
		reasons.NoKnownVulnerabilities,
		reasons.PackageTooNew,
		reasons.VersionTooNew,
		reasons.PackageUnpublishedOrYanked,
		reasons.DeprecatedPackage,
		reasons.InstallScriptPresent,
		reasons.SuspiciousInstallScript,
		reasons.SuspiciousBinaryArtifact,
		reasons.ArtifactDigestMismatch,
		reasons.PossibleTyposquat,
		reasons.DependencyConfusionRisk,
		reasons.LowRepositoryHealth,
		reasons.RepositoryMappingUncertain,
		reasons.MaintainerActivityLow,
		reasons.ReleaseRecencyStale,
		reasons.ReleaseRecencyFresh,
		reasons.ReleaseRecencyNearStale,
		reasons.SourceStale,
		reasons.ConflictingSourceData:
		return true
	default:
		return false
	}
}

func validateSourceRef(sourceRef schema.SourceRef) error {
	if sourceRef.ID == "" {
		return fmt.Errorf("source_ref id is required")
	}
	if sourceRef.Source == "" {
		return fmt.Errorf("source_ref %q source is required", sourceRef.ID)
	}
	if err := validateURI("source_ref url", sourceRef.URL); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339, sourceRef.RetrievedAt); err != nil {
		return fmt.Errorf("source_ref %q retrieved_at must be RFC3339: %w", sourceRef.ID, err)
	}
	if sourceRef.TTLSeconds < 0 {
		return fmt.Errorf("source_ref %q ttl_seconds must be non-negative", sourceRef.ID)
	}
	if err := validateURI("source_ref license_or_terms_url", sourceRef.LicenseOrTermsURL); err != nil {
		return err
	}
	if sourceRef.Attribution == "" {
		return fmt.Errorf("source_ref %q attribution is required", sourceRef.ID)
	}
	if !isAllowed(sourceRef.Redistribution, "allowed", "restricted", "unknown") {
		return fmt.Errorf("source_ref %q has invalid redistribution %q", sourceRef.ID, sourceRef.Redistribution)
	}
	if !isAllowed(sourceRef.PublicDisplay, "allowed", "restricted", "unknown") {
		return fmt.Errorf("source_ref %q has invalid public_display %q", sourceRef.ID, sourceRef.PublicDisplay)
	}
	return nil
}

func validateURI(label, value string) error {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("%s must be a URI with host", label)
	}
	return nil
}

func decide(policyProfile string, reasonList []schema.Reason) (schema.Decision, *int, schema.Confidence) {
	hasDeny := false
	hasAsk := false
	hasUnknown := false
	maxScore := severityInformationalScore
	confidence := schema.ConfidenceMedium

	for _, reason := range reasonList {
		score := scoreForSeverity(reason.Severity)
		switch reason.DecisionEffect {
		case schema.DecisionEffectDeny:
			hasDeny = true
			maxScore = max(maxScore, max(score, denyScoreFloor))
			confidence = schema.ConfidenceHigh
		case schema.DecisionEffectAsk:
			hasAsk = true
			maxScore = max(maxScore, score)
			confidence = maxConfidence(confidence, schema.ConfidenceMedium)
		case schema.DecisionEffectUnknown:
			hasUnknown = true
			confidence = schema.ConfidenceLow
		case schema.DecisionEffectAllow, schema.DecisionEffectNone:
			maxScore = max(maxScore, score)
		}
	}

	if hasDeny {
		if policyProfile == ProfileAuditOnly {
			return schema.DecisionAllow, intPtr(maxScore), schema.ConfidenceHigh
		}
		return schema.DecisionDeny, intPtr(maxScore), schema.ConfidenceHigh
	}
	if hasAsk {
		askScore := clamp(max(maxScore, askScoreFloor), askScoreFloor, askScoreCeiling)
		riskScore := max(maxScore, askScoreFloor)
		if policyProfile == ProfileAuditOnly {
			return schema.DecisionAllow, intPtr(riskScore), maxConfidence(confidence, schema.ConfidenceMedium)
		}
		if policyProfile == ProfileCIStrict {
			return schema.DecisionDeny, intPtr(riskScore), maxConfidence(confidence, schema.ConfidenceMedium)
		}
		return schema.DecisionAsk, intPtr(askScore), maxConfidence(confidence, schema.ConfidenceMedium)
	}
	if hasUnknown {
		if policyProfile == ProfileAuditOnly {
			return schema.DecisionAllow, nil, schema.ConfidenceLow
		}
		if policyProfile == ProfileCIStrict {
			return schema.DecisionDeny, nil, schema.ConfidenceLow
		}
		return schema.DecisionAsk, intPtr(unknownLocalScore), schema.ConfidenceLow
	}
	return schema.DecisionAllow, intPtr(min(maxScore, allowScoreCeiling)), confidence
}

func scoreForSeverity(severity string) int {
	switch severity {
	case "CRITICAL":
		return severityCriticalScore
	case "HIGH":
		return severityHighScore
	case "MEDIUM":
		return severityMediumScore
	case "LOW":
		return severityLowScore
	default:
		return severityInformationalScore
	}
}

func maxConfidence(left, right schema.Confidence) schema.Confidence {
	if confidenceRank(right) > confidenceRank(left) {
		return right
	}
	return left
}

func confidenceRank(confidence schema.Confidence) int {
	switch confidence {
	case schema.ConfidenceHigh:
		return 3
	case schema.ConfidenceMedium:
		return 2
	case schema.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func intPtr(value int) *int {
	return &value
}

func max(left, right int) int {
	if right > left {
		return right
	}
	return left
}

func min(left, right int) int {
	if right < left {
		return right
	}
	return left
}

func clamp(value, lower, upper int) int {
	return min(max(value, lower), upper)
}

func isKnownPolicyProfile(profile string) bool {
	return isAllowed(profile, ProfileLocalDevDefault, ProfileCIStrict, ProfileAuditOnly)
}

func limitationsForProfile(profile string) []string {
	limitations := []string{
		"Offline deterministic scorer skeleton; network adapters and live source lookups are not included.",
	}
	if profile == ProfileCIStrict {
		limitations = append(limitations, "ci-strict currently treats ASK and UNKNOWN as blocking; policy allowlists, protected ecosystem hooks, and production dependency group hooks are not implemented in the v0 offline scorer.")
	}
	return limitations
}

func isAllowed(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
