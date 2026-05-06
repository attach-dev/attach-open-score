package fixtures

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
)

type Report struct {
	Path     string
	Decision schema.Decision
	Reasons  []string
}

func ValidateRepository(root string) ([]Report, error) {
	pattern := filepath.Join(root, "fixtures", "v0", "*.json")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no fixtures matched %s", pattern)
	}
	sort.Strings(paths)

	reports := make([]Report, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		report, err := ValidateBytes(path, data)
		if err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}
	return reports, nil
}

func ValidateBytes(path string, data []byte) (Report, error) {
	var verdict schema.Verdict
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&verdict); err != nil {
		return Report{}, fmt.Errorf("%s: invalid JSON verdict: %w", path, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Report{}, fmt.Errorf("%s: invalid JSON verdict: trailing data after first JSON document", path)
	}
	if err := validateRequiredKeys(data); err != nil {
		return Report{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := validateVerdict(verdict); err != nil {
		return Report{}, fmt.Errorf("%s: %w", path, err)
	}

	reasons := make([]string, 0, len(verdict.Reasons))
	for _, reason := range verdict.Reasons {
		reasons = append(reasons, reason.Code)
	}
	return Report{Path: path, Decision: verdict.Decision, Reasons: reasons}, nil
}

func validateRequiredKeys(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, key := range []string{"schema_version", "package", "decision", "score", "confidence", "reasons", "source_refs", "evaluated_at", "ttl_seconds", "limitations"} {
		if _, ok := raw[key]; !ok {
			return fmt.Errorf("missing required field %q", key)
		}
	}
	if msg, ok := raw["policy_profile"]; ok && isEmptyJSONString(msg) {
		return errors.New("policy_profile must be non-empty when present")
	}
	if msg, ok := raw["engine_version"]; ok && isEmptyJSONString(msg) {
		return errors.New("engine_version must be non-empty when present")
	}

	var pkg map[string]json.RawMessage
	if err := json.Unmarshal(raw["package"], &pkg); err != nil {
		return fmt.Errorf("package must be an object: %w", err)
	}
	for _, key := range []string{"ecosystem", "name", "purl", "resolved"} {
		if _, ok := pkg[key]; !ok {
			return fmt.Errorf("package missing required field %q", key)
		}
	}

	var refs []map[string]json.RawMessage
	if err := json.Unmarshal(raw["source_refs"], &refs); err != nil {
		return fmt.Errorf("source_refs must be an array: %w", err)
	}
	for i, ref := range refs {
		for _, key := range []string{"id", "source", "url", "retrieved_at", "ttl_seconds", "license_or_terms_url", "attribution", "attribution_required", "redistribution", "public_display"} {
			if _, ok := ref[key]; !ok {
				return fmt.Errorf("source_refs[%d] missing required field %q", i, key)
			}
		}
	}
	return nil
}

func isEmptyJSONString(data json.RawMessage) bool {
	var s string
	return json.Unmarshal(data, &s) == nil && s == ""
}

func validateVerdict(v schema.Verdict) error {
	if v.SchemaVersion != schema.VersionV0 {
		return fmt.Errorf("schema_version must be %q", schema.VersionV0)
	}
	if !validEcosystem(v.Package.Ecosystem) {
		return fmt.Errorf("package.ecosystem is invalid: %q", v.Package.Ecosystem)
	}
	if v.Package.Name == "" || v.Package.PURL == "" {
		return errors.New("package must include name and purl")
	}
	if v.Package.RepositoryURL != "" && !validURI(v.Package.RepositoryURL) {
		return fmt.Errorf("package.repository_url must be a URI: %q", v.Package.RepositoryURL)
	}
	if v.Package.Resolved && v.Package.Version == "" {
		return errors.New("package.version is required when package.resolved is true")
	}
	if !validDecision(v.Decision) {
		return fmt.Errorf("decision must be one of ALLOW, ASK, DENY, UNKNOWN; got %q", v.Decision)
	}
	if v.Score != nil && (*v.Score < 0 || *v.Score > 100) {
		return fmt.Errorf("score must be null or 0-100; got %d", *v.Score)
	}
	if !validConfidence(v.Confidence) {
		return fmt.Errorf("confidence must be LOW, MEDIUM, or HIGH; got %q", v.Confidence)
	}
	if len(v.Reasons) == 0 {
		return errors.New("reasons must contain at least one reason")
	}
	if _, err := time.Parse(time.RFC3339, v.EvaluatedAt); err != nil {
		return fmt.Errorf("evaluated_at must be RFC3339 date-time: %w", err)
	}
	if v.TTLSeconds < 0 {
		return errors.New("ttl_seconds must be non-negative")
	}
	for _, limitation := range v.Limitations {
		if limitation == "" {
			return errors.New("limitations entries must be non-empty")
		}
	}

	sourceIDs := map[string]struct{}{}
	for _, ref := range v.SourceRefs {
		if ref.ID == "" {
			return errors.New("source_refs entries must include id")
		}
		if _, exists := sourceIDs[ref.ID]; exists {
			return fmt.Errorf("source_ref id %q is duplicated", ref.ID)
		}
		if ref.Source == "" || ref.URL == "" || ref.RetrievedAt == "" || ref.LicenseOrTermsURL == "" || ref.Attribution == "" {
			return fmt.Errorf("source_ref %q is missing required provenance fields", ref.ID)
		}
		if !validURI(ref.URL) {
			return fmt.Errorf("source_ref %q url must be a URI: %q", ref.ID, ref.URL)
		}
		if !validURI(ref.LicenseOrTermsURL) {
			return fmt.Errorf("source_ref %q license_or_terms_url must be a URI: %q", ref.ID, ref.LicenseOrTermsURL)
		}
		if !validRedistribution(ref.Redistribution) {
			return fmt.Errorf("source_ref %q redistribution is invalid: %q", ref.ID, ref.Redistribution)
		}
		if !validPublicDisplay(ref.PublicDisplay) {
			return fmt.Errorf("source_ref %q public_display is invalid: %q", ref.ID, ref.PublicDisplay)
		}
		if _, err := time.Parse(time.RFC3339, ref.RetrievedAt); err != nil {
			return fmt.Errorf("source_ref %q retrieved_at must be RFC3339 date-time: %w", ref.ID, err)
		}
		if ref.TTLSeconds < 0 {
			return fmt.Errorf("source_ref %q ttl_seconds must be non-negative", ref.ID)
		}
		sourceIDs[ref.ID] = struct{}{}
	}

	for _, reason := range v.Reasons {
		if reason.Code == "" || reason.Severity == "" || reason.Message == "" {
			return errors.New("reasons must include code, severity, and message")
		}
		if !validSeverity(reason.Severity) {
			return fmt.Errorf("reason %q severity is invalid: %q", reason.Code, reason.Severity)
		}
		if !reasons.IsKnown(reason.Code) && !strings.HasPrefix(reason.Code, "X_") {
			return fmt.Errorf("reason %q is not in the v0 reason-code taxonomy", reason.Code)
		}
		if !validDecisionEffect(reason.DecisionEffect) {
			return fmt.Errorf("reason %q decision_effect is invalid: %q", reason.Code, reason.DecisionEffect)
		}
		seenReasonRefs := map[string]struct{}{}
		for _, id := range reason.SourceRefIDs {
			if _, duplicate := seenReasonRefs[id]; duplicate {
				return fmt.Errorf("reason %q source_ref_ids contains duplicate %q", reason.Code, id)
			}
			seenReasonRefs[id] = struct{}{}
			if _, ok := sourceIDs[id]; !ok {
				return fmt.Errorf("reason %q source_ref_ids references missing source_ref %q", reason.Code, id)
			}
		}
	}
	return nil
}

func validEcosystem(ecosystem string) bool {
	switch ecosystem {
	case "npm", "pypi", "crates", "go", "maven", "rubygems", "other":
		return true
	default:
		return false
	}
}

func validSeverity(severity string) bool {
	switch severity {
	case "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return true
	default:
		return false
	}
}

func validRedistribution(value string) bool {
	switch value {
	case "allowed", "restricted", "unknown":
		return true
	default:
		return false
	}
}

func validPublicDisplay(value string) bool {
	return validRedistribution(value)
}

func validURI(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.Scheme != "" && parsed.Host != ""
}

func validDecision(d schema.Decision) bool {
	switch d {
	case schema.DecisionAllow, schema.DecisionAsk, schema.DecisionDeny, schema.DecisionUnknown:
		return true
	default:
		return false
	}
}

func validConfidence(c schema.Confidence) bool {
	switch c {
	case schema.ConfidenceLow, schema.ConfidenceMedium, schema.ConfidenceHigh:
		return true
	default:
		return false
	}
}

func validDecisionEffect(d schema.DecisionEffect) bool {
	switch d {
	case schema.DecisionEffectAllow, schema.DecisionEffectAsk, schema.DecisionEffectDeny, schema.DecisionEffectUnknown, schema.DecisionEffectNone:
		return true
	default:
		return false
	}
}
