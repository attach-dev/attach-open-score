package compose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/score"
)

// Bundle is a fixture-friendly, offline container for evidence already emitted
// by source adapters. It preserves adapter family grouping while composing into
// the scorer's normal request contract.
type Bundle struct {
	Package      schema.PackageIdentity `json:"package"`
	EvidenceSets []EvidenceSet          `json:"evidence_sets"`
}

// Evaluator is satisfied by score.Engine.
type Evaluator interface {
	Evaluate(schema.Request) (schema.Verdict, error)
}

// DecodeBundleJSON decodes a strict offline evidence bundle. The bundle format
// intentionally carries schema.Evidence values rather than source-specific raw
// API responses, so decoding never performs network calls.
func DecodeBundleJSON(data []byte) (Bundle, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return Bundle{}, errors.New("evidence bundle JSON is empty")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, fmt.Errorf("invalid evidence bundle JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Bundle{}, errors.New("invalid evidence bundle JSON: trailing data after bundle object")
	}
	if err := requireBundleJSONFields(data); err != nil {
		return Bundle{}, err
	}
	if err := validateBundleShape(bundle); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

// RequestFromBundle converts grouped offline evidence into the scorer's normal
// request contract without changing reason codes, severities, or effects.
func RequestFromBundle(bundle Bundle) (schema.Request, error) {
	if err := validateBundleShape(bundle); err != nil {
		return schema.Request{}, err
	}
	request, err := Request(bundle.Package, bundle.EvidenceSets...)
	if err != nil {
		return schema.Request{}, err
	}
	engine, err := score.NewEngine(score.Options{})
	if err != nil {
		return schema.Request{}, err
	}
	if _, err := engine.Evaluate(request); err != nil {
		return schema.Request{}, fmt.Errorf("evidence bundle is not a valid score request: %w", err)
	}
	return request, nil
}

// RequestFromBundleJSON decodes and composes an offline evidence bundle into a
// schema.Request suitable for score.Engine.
func RequestFromBundleJSON(data []byte) (schema.Request, error) {
	bundle, err := DecodeBundleJSON(data)
	if err != nil {
		return schema.Request{}, err
	}
	return RequestFromBundle(bundle)
}

// EvaluateBundleJSON scores a decoded offline evidence bundle through the
// deterministic evaluator supplied by the caller.
func EvaluateBundleJSON(data []byte, evaluator Evaluator) (schema.Verdict, error) {
	if evaluator == nil {
		return schema.Verdict{}, errors.New("evidence bundle evaluator is required")
	}
	request, err := RequestFromBundleJSON(data)
	if err != nil {
		return schema.Verdict{}, err
	}
	return evaluator.Evaluate(request)
}

func requireBundleJSONFields(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("invalid evidence bundle JSON: %w", err)
	}
	pkgRaw, ok := raw["package"]
	if !ok {
		return errors.New("evidence bundle package is required")
	}
	if err := requireJSONObjectFields(pkgRaw, "package", "ecosystem", "name", "purl", "resolved"); err != nil {
		return err
	}
	if err := requireJSONObjectFieldTypes(pkgRaw, "package", map[string]string{
		"ecosystem":      "string",
		"name":           "string",
		"version":        "string",
		"purl":           "string",
		"requested_spec": "string",
		"repository_url": "string",
		"resolved":       "bool",
	}); err != nil {
		return err
	}
	evidenceSetsRaw, ok := raw["evidence_sets"]
	if !ok {
		return errors.New("evidence bundle evidence_sets is required")
	}
	var evidenceSets []map[string]json.RawMessage
	if err := json.Unmarshal(evidenceSetsRaw, &evidenceSets); err != nil {
		return fmt.Errorf("invalid evidence bundle evidence_sets: %w", err)
	}
	for i, set := range evidenceSets {
		prefix := fmt.Sprintf("evidence_sets[%d]", i)
		if _, ok := set["source"]; !ok {
			return fmt.Errorf("evidence bundle %s.source is required", prefix)
		}
		evidenceRaw, ok := set["evidence"]
		if !ok {
			return fmt.Errorf("evidence bundle %s.evidence is required", prefix)
		}
		var evidenceItems []map[string]json.RawMessage
		if err := json.Unmarshal(evidenceRaw, &evidenceItems); err != nil {
			return fmt.Errorf("invalid evidence bundle %s.evidence: %w", prefix, err)
		}
		for j, item := range evidenceItems {
			itemPrefix := fmt.Sprintf("%s.evidence[%d]", prefix, j)
			reasonRaw, ok := item["reason"]
			if !ok {
				return fmt.Errorf("evidence bundle %s.reason is required", itemPrefix)
			}
			if err := requireJSONObjectFields(reasonRaw, itemPrefix+".reason", "code", "severity", "decision_effect", "message"); err != nil {
				return err
			}
			if err := requireJSONObjectFieldTypes(reasonRaw, itemPrefix+".reason", map[string]string{
				"code":            "string",
				"severity":        "string",
				"decision_effect": "string",
				"message":         "string",
			}); err != nil {
				return err
			}
			if sourceRefRaw, ok := item["source_ref"]; ok {
				if err := requireSourceRefJSONFields(sourceRefRaw, itemPrefix+".source_ref"); err != nil {
					return err
				}
			}
			if sourceRefsRaw, ok := item["source_refs"]; ok {
				var sourceRefs []json.RawMessage
				if err := json.Unmarshal(sourceRefsRaw, &sourceRefs); err != nil {
					return fmt.Errorf("invalid evidence bundle %s.source_refs: %w", itemPrefix, err)
				}
				for k, sourceRefRaw := range sourceRefs {
					if err := requireSourceRefJSONFields(sourceRefRaw, fmt.Sprintf("%s.source_refs[%d]", itemPrefix, k)); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func requireSourceRefJSONFields(raw json.RawMessage, path string) error {
	if err := requireJSONObjectFields(raw, path, "id", "source", "source_id", "url", "retrieved_at", "ttl_seconds", "license_or_terms_url", "attribution", "attribution_required", "redistribution", "public_display"); err != nil {
		return err
	}
	return requireJSONObjectFieldTypes(raw, path, map[string]string{
		"id":                   "string",
		"source":               "string",
		"source_id":            "string",
		"url":                  "string",
		"retrieved_at":         "string",
		"ttl_seconds":          "number",
		"license_or_terms_url": "string",
		"attribution":          "string",
		"attribution_required": "bool",
		"redistribution":       "string",
		"public_display":       "string",
	})
}

func requireJSONObjectFields(raw json.RawMessage, path string, fields ...string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return fmt.Errorf("invalid evidence bundle %s: %w", path, err)
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return fmt.Errorf("evidence bundle %s.%s is required", path, field)
		}
	}
	return nil
}

func requireJSONObjectFieldTypes(raw json.RawMessage, path string, fieldTypes map[string]string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return fmt.Errorf("invalid evidence bundle %s: %w", path, err)
	}
	for field, kind := range fieldTypes {
		rawValue, ok := object[field]
		if !ok {
			continue
		}
		if err := requireJSONKind(rawValue, kind); err != nil {
			return fmt.Errorf("evidence bundle %s.%s must be %s", path, field, kind)
		}
	}
	return nil
}

func requireJSONKind(raw json.RawMessage, kind string) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	switch kind {
	case "string":
		_, ok := value.(string)
		if !ok {
			return errors.New("not string")
		}
	case "bool":
		_, ok := value.(bool)
		if !ok {
			return errors.New("not bool")
		}
	case "number":
		_, ok := value.(float64)
		if !ok {
			return errors.New("not number")
		}
	default:
		return fmt.Errorf("unsupported JSON kind %q", kind)
	}
	return nil
}

func validateBundleShape(bundle Bundle) error {
	for _, value := range []struct {
		path  string
		value string
	}{
		{path: "package.ecosystem", value: bundle.Package.Ecosystem},
		{path: "package.name", value: bundle.Package.Name},
		{path: "package.purl", value: bundle.Package.PURL},
		{path: "package.requested_spec", value: bundle.Package.RequestedSpec},
		{path: "package.repository_url", value: bundle.Package.RepositoryURL},
	} {
		if err := rejectProprietaryString(value.path, value.value); err != nil {
			return err
		}
	}
	if strings.TrimSpace(bundle.Package.Ecosystem) == "" || strings.TrimSpace(bundle.Package.Name) == "" || strings.TrimSpace(bundle.Package.PURL) == "" {
		return errors.New("evidence bundle package identity is incomplete")
	}
	if len(bundle.EvidenceSets) == 0 {
		return errors.New("evidence bundle requires at least one evidence_set")
	}
	for i, set := range bundle.EvidenceSets {
		if strings.TrimSpace(set.Name) == "" {
			return fmt.Errorf("evidence bundle evidence_sets[%d].source is required", i)
		}
		if !allowedBundleSource(set.Name) {
			return fmt.Errorf("evidence bundle evidence_sets[%d].source is not an allowed public/open source", i)
		}
		if set.Evidence == nil {
			return fmt.Errorf("evidence bundle evidence_sets[%d].evidence is required", i)
		}
		for j, evidence := range set.Evidence {
			if err := validateBundleEvidence(set.Name, evidence); err != nil {
				return fmt.Errorf("evidence bundle evidence_sets[%d].evidence[%d]: %w", i, j, err)
			}
		}
	}
	return nil
}

func validateBundleEvidence(setName string, evidence schema.Evidence) error {
	if strings.TrimSpace(evidence.Reason.Code) == "" || strings.TrimSpace(evidence.Reason.Severity) == "" ||
		strings.TrimSpace(string(evidence.Reason.DecisionEffect)) == "" || strings.TrimSpace(evidence.Reason.Message) == "" {
		return errors.New("reason is incomplete")
	}
	for _, value := range []struct {
		path  string
		value string
	}{
		{path: "reason.code", value: evidence.Reason.Code},
		{path: "reason.severity", value: evidence.Reason.Severity},
		{path: "reason.decision_effect", value: string(evidence.Reason.DecisionEffect)},
		{path: "reason.message", value: evidence.Reason.Message},
	} {
		if err := rejectProprietaryString(value.path, value.value); err != nil {
			return err
		}
	}
	if err := rejectRawOrProprietaryDetails(evidence.Reason.Details, "reason.details"); err != nil {
		return err
	}
	sourceRefs := append([]schema.SourceRef(nil), evidence.SourceRefs...)
	if evidence.SourceRef != nil {
		sourceRefs = append(sourceRefs, *evidence.SourceRef)
	}
	if len(evidence.Reason.SourceRefIDs) > 0 && len(sourceRefs) == 0 {
		return errors.New("source-backed reason requires source_refs")
	}
	for _, sourceRef := range sourceRefs {
		if err := validateBundleSourceRef(setName, sourceRef); err != nil {
			return err
		}
	}
	return nil
}

func validateBundleSourceRef(setName string, sourceRef schema.SourceRef) error {
	for _, value := range []struct {
		path  string
		value string
	}{
		{path: "source_ref.id", value: sourceRef.ID},
		{path: "source_ref.source", value: sourceRef.Source},
		{path: "source_ref.source_id", value: sourceRef.SourceID},
		{path: "source_ref.url", value: sourceRef.URL},
		{path: "source_ref.license_or_terms_url", value: sourceRef.LicenseOrTermsURL},
		{path: "source_ref.attribution", value: sourceRef.Attribution},
		{path: "source_ref.redistribution", value: sourceRef.Redistribution},
		{path: "source_ref.public_display", value: sourceRef.PublicDisplay},
	} {
		if err := rejectProprietaryString(value.path, value.value); err != nil {
			return err
		}
	}
	if strings.TrimSpace(sourceRef.ID) == "" {
		return errors.New("source_ref id is required")
	}
	if strings.TrimSpace(sourceRef.Source) == "" || strings.TrimSpace(sourceRef.SourceID) == "" || strings.TrimSpace(sourceRef.URL) == "" ||
		strings.TrimSpace(sourceRef.RetrievedAt) == "" || strings.TrimSpace(sourceRef.LicenseOrTermsURL) == "" ||
		strings.TrimSpace(sourceRef.Attribution) == "" || strings.TrimSpace(sourceRef.Redistribution) == "" ||
		strings.TrimSpace(sourceRef.PublicDisplay) == "" || sourceRef.TTLSeconds < 0 {
		return errors.New("source_ref is incomplete")
	}
	if _, err := time.Parse(time.RFC3339, sourceRef.RetrievedAt); err != nil {
		return fmt.Errorf("source_ref %q retrieved_at must be RFC3339: %w", sourceRef.ID, err)
	}
	if !allowedBundleSource(sourceRef.Source) {
		return fmt.Errorf("source_ref %q source %q is not an allowed public/open source", sourceRef.ID, sourceRef.Source)
	}
	if canonicalBundleSource(sourceRef.Source) != canonicalBundleSource(setName) {
		return fmt.Errorf("source_ref %q source %q does not match evidence_set source %q", sourceRef.ID, sourceRef.Source, setName)
	}
	return nil
}

func allowedBundleSource(source string) bool {
	return canonicalBundleSource(source) != ""
}

func canonicalBundleSource(source string) string {
	switch strings.TrimSpace(strings.ToLower(source)) {
	case "osv.dev", "osv":
		return "osv.dev"
	case "github-advisory-database", "ghsa", "github_advisory_database":
		return "github-advisory-database"
	case "deps.dev":
		return "deps.dev"
	case "openssf-scorecard", "scorecard":
		return "openssf-scorecard"
	case "npm-registry", "npm_public_facts":
		return "npm-registry"
	case "pypi", "pypi-registry", "pypi_public_facts":
		return "pypi"
	case "crates.io", "crates.io-index", "crates_public_facts":
		return "crates.io"
	case "go-module-services", "go_module_public_facts":
		return "go-module-services"
	default:
		return ""
	}
}

func rejectProprietaryString(path, value string) error {
	lower := strings.ToLower(value)
	normalized := strings.Join(strings.Fields(strings.NewReplacer("_", " ", "-", " ").Replace(lower)), " ")
	for _, blocked := range []string{"socket", "snyk", "aikido", "sonatype", "endor", "raw upstream", "raw payload", "raw dump", "private registry", "private package"} {
		if strings.Contains(lower, blocked) || strings.Contains(normalized, blocked) {
			return fmt.Errorf("%s contains blocked proprietary/raw/private source marker %q", path, blocked)
		}
	}
	return nil
}

func rejectRawOrProprietaryDetails(value any, path string) error {
	switch typed := value.(type) {
	case nil:
		return nil
	case map[string]any:
		for key, nested := range typed {
			lowerKey := strings.ToLower(key)
			for _, blocked := range []string{"raw", "payload", "dump", "socket", "snyk", "aikido", "sonatype", "endor"} {
				if strings.Contains(lowerKey, blocked) {
					return fmt.Errorf("%s.%s is not allowed in offline evidence bundle details", path, key)
				}
			}
			if err := rejectRawOrProprietaryDetails(nested, path+"."+key); err != nil {
				return err
			}
		}
	case []any:
		for i, nested := range typed {
			if err := rejectRawOrProprietaryDetails(nested, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case string:
		return rejectProprietaryString(path, typed)
	}
	return nil
}
