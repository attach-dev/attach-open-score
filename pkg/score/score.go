package score

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
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
)

type Request struct {
	Package  schema.PackageIdentity
	Evidence []Evidence
	Mode     string
}

type Evidence struct {
	Reason    schema.Reason
	SourceRef *schema.SourceRef
}

type Result = schema.Verdict

type Options struct {
	Now           func() time.Time
	PolicyProfile string
	EngineVersion string
	TTLSeconds    int
}

type Engine struct {
	now           func() time.Time
	policyProfile string
	engineVersion string
	ttlSeconds    int
}

func NewEngine(options Options) Engine {
	now := options.Now
	if now == nil {
		now = time.Now
	}

	profile := options.PolicyProfile
	if profile == "" {
		profile = ProfileLocalDevDefault
	}

	engineVersion := options.EngineVersion
	if engineVersion == "" {
		engineVersion = DefaultEngineVersion
	}

	ttl := options.TTLSeconds
	if ttl <= 0 {
		ttl = DefaultTTLSeconds
	}

	return Engine{
		now:           now,
		policyProfile: profile,
		engineVersion: engineVersion,
		ttlSeconds:    ttl,
	}
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
				if err := validateSourceRef(*evidence.SourceRef); err != nil {
					return schema.Verdict{}, err
				}
				if existing, ok := seenSourceRefs[evidence.SourceRef.ID]; ok {
					if !reflect.DeepEqual(sourceRefs[existing], *evidence.SourceRef) {
						return schema.Verdict{}, fmt.Errorf("conflicting source_ref %q", evidence.SourceRef.ID)
					}
					continue
				}
				sourceRefs = append(sourceRefs, *evidence.SourceRef)
				seenSourceRefs[evidence.SourceRef.ID] = len(sourceRefs) - 1
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
		Limitations: []string{
			"Offline deterministic scorer skeleton; network adapters and live source lookups are not included.",
		},
	}

	return verdict, nil
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
	if reason.DecisionEffect == schema.DecisionEffectDeny && !isAllowed(reason.Code, reasons.KnownMaliciousPackage, reasons.KnownVulnerabilityCritical, reasons.ArtifactDigestMismatch) {
		return fmt.Errorf("reason %q cannot use DENY effect in v0 scorer core", reason.Code)
	}
	return nil
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
	if sourceRef.TTLSeconds <= 0 {
		return fmt.Errorf("source_ref %q ttl_seconds must be positive", sourceRef.ID)
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
	if err != nil || parsed.Scheme == "" {
		return fmt.Errorf("%s must be a URI", label)
	}
	return nil
}

func decide(policyProfile string, reasonList []schema.Reason) (schema.Decision, *int, schema.Confidence) {
	hasDeny := false
	hasAsk := false
	hasUnknown := false
	maxScore := 5
	confidence := schema.ConfidenceMedium

	for _, reason := range reasonList {
		score := scoreForSeverity(reason.Severity)
		switch reason.DecisionEffect {
		case schema.DecisionEffectDeny:
			hasDeny = true
			maxScore = max(maxScore, max(score, 85))
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
		return schema.DecisionDeny, intPtr(maxScore), confidence
	}
	if hasAsk {
		return schema.DecisionAsk, intPtr(max(maxScore, 25)), maxConfidence(confidence, schema.ConfidenceMedium)
	}
	if hasUnknown {
		if policyProfile == ProfileLocalDevDefault && hasProviderUncertainty(reasonList) {
			return schema.DecisionAsk, intPtr(45), schema.ConfidenceLow
		}
		return schema.DecisionUnknown, nil, schema.ConfidenceLow
	}
	return schema.DecisionAllow, intPtr(min(maxScore, 24)), confidence
}

func hasProviderUncertainty(reasonList []schema.Reason) bool {
	for _, reason := range reasonList {
		switch reason.Code {
		case reasons.SourceUnavailable, reasons.SourceTermsBlocked, reasons.SourceStale, reasons.ConflictingSourceData:
			return true
		}
	}
	return false
}

func scoreForSeverity(severity string) int {
	switch severity {
	case "CRITICAL":
		return 95
	case "HIGH":
		return 70
	case "MEDIUM":
		return 45
	case "LOW":
		return 20
	default:
		return 5
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

func isAllowed(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
