package ghsa

import (
	"strings"
	"testing"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/score"
	"github.com/attach-dev/attach-open-score/pkg/sources"
)

var fixedNow = time.Date(2026, 5, 10, 9, 30, 0, 0, time.UTC)

func TestAdapterEvidenceFromJSONNormalizesAdvisoryMatch(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})
	evidence, err := adapter.EvidenceFromJSON(Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, []byte(`{
		"schema_version": "1.4.0",
		"id": "GHSA-abcd-1234-wxyz",
		"aliases": ["CVE-2026-0001"],
		"summary": "Synthetic GHSA fixture advisory.",
		"published": "2026-05-01T00:00:00Z",
		"modified": "2026-05-02T00:00:00Z",
		"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
		"affected": [{
			"package": {"ecosystem": "npm", "name": "left-pad"},
			"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.3.1"}]}]
		}],
		"references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-abcd-1234-wxyz"}]
	}`))
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	if len(evidence) != 1 {
		t.Fatalf("evidence length = %d, want 1", len(evidence))
	}

	got := evidence[0]
	if got.Reason.Code != reasons.KnownVulnerabilityCritical {
		t.Fatalf("reason code = %s, want %s", got.Reason.Code, reasons.KnownVulnerabilityCritical)
	}
	if got.Reason.Severity != "CRITICAL" || got.Reason.DecisionEffect != schema.DecisionEffectDeny {
		t.Fatalf("reason severity/effect = %s/%s, want CRITICAL/DENY", got.Reason.Severity, got.Reason.DecisionEffect)
	}
	if got.SourceRef == nil {
		t.Fatalf("source_ref is nil")
	}
	if got.SourceRef.ID != "ghsa-ghsa-abcd-1234-wxyz" {
		t.Fatalf("source_ref id = %q, want ghsa-ghsa-abcd-1234-wxyz", got.SourceRef.ID)
	}
	if got.SourceRef.Source != SourceName || got.SourceRef.SourceID != "GHSA-ABCD-1234-WXYZ" {
		t.Fatalf("source ref source/source_id = %q/%q", got.SourceRef.Source, got.SourceRef.SourceID)
	}
	if got.SourceRef.URL != "https://github.com/advisories/GHSA-abcd-1234-wxyz" {
		t.Fatalf("source ref url = %q", got.SourceRef.URL)
	}
	if len(got.Reason.SourceRefIDs) != 3 || got.Reason.SourceRefIDs[0] != got.SourceRef.ID {
		t.Fatalf("source_ref_ids = %#v, want primary plus upstream refs", got.Reason.SourceRefIDs)
	}
	if len(got.SourceRefs) != 2 {
		t.Fatalf("upstream source_refs length = %d, want 2", len(got.SourceRefs))
	}
	if got.SourceRefs[0].SourceID != "CVE-2026-0001" {
		t.Fatalf("alias source_ref source_id = %q", got.SourceRefs[0].SourceID)
	}
	if got.SourceRefs[1].URL != "https://github.com/advisories/GHSA-abcd-1234-wxyz" {
		t.Fatalf("reference source_ref url = %q", got.SourceRefs[1].URL)
	}
	if got.Reason.Details["advisory_id"] != "GHSA-ABCD-1234-WXYZ" {
		t.Fatalf("details advisory_id = %#v", got.Reason.Details["advisory_id"])
	}
	if got.Reason.Details["ecosystem_key"] != "npm" || got.Reason.Details["package_name"] != "left-pad" || got.Reason.Details["version"] != "1.3.0" {
		t.Fatalf("coordinate details = %#v", got.Reason.Details)
	}

	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestAdapterEvidenceReturnsNoKnownForUnaffectedAndNoMatch(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})
	evidence, err := adapter.EvidenceFromJSON(Coordinate{Ecosystem: "pypi", Name: "Django", Version: "4.2.0"}, []byte(`[
		{
			"id": "GHSA-unaf-0001-0002",
			"database_specific": {"severity": "HIGH"},
			"affected": [{
				"package": {"ecosystem": "PyPI", "name": "django"},
				"versions": ["4.1.0"]
			}]
		},
		{
			"id": "GHSA-mism-0001-0002",
			"database_specific": {"severity": "CRITICAL"},
			"affected": [{
				"package": {"ecosystem": "npm", "name": "left-pad"},
				"versions": ["4.2.0"]
			}]
		}
	]`))
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	assertNoKnownVulnerabilities(t, evidence)
	if evidence[0].SourceRef == nil || !strings.HasPrefix(evidence[0].SourceRef.ID, "ghsa-json-") {
		t.Fatalf("source_ref = %#v, want local JSON source ref", evidence[0].SourceRef)
	}
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "pypi", Name: "Django", Version: "4.2.0"}, evidence)
}

func TestAdapterEvidenceMissingSeverityDefaultsModerate(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})
	evidence, err := adapter.EvidenceFromJSON(Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, []byte(`{
		"id": "GHSA-minm-0001-0002",
		"affected": [{
			"package": {"ecosystem": "npm", "name": "left-pad"},
			"versions": ["1.3.0"]
		}]
	}`))
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	if len(evidence) != 1 {
		t.Fatalf("evidence length = %d, want 1", len(evidence))
	}
	got := evidence[0]
	if got.Reason.Code != reasons.KnownVulnerabilityModerate || got.Reason.Severity != "MEDIUM" || got.Reason.DecisionEffect != schema.DecisionEffectAsk {
		t.Fatalf("reason = %#v, want moderate known vulnerability", got.Reason)
	}
	if got.Reason.Details["explicit_severity"] != false || got.Reason.Details["severity_default"] != "moderate" {
		t.Fatalf("severity details = %#v", got.Reason.Details)
	}
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestAdapterEvidenceReportsSourceUnavailableForMinimalMalformedRecord(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})
	evidence, err := adapter.EvidenceFromJSON(Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, []byte(`{
		"id": "GHSA-minimal-0001-0002"
	}`))
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	assertSourceUnavailable(t, evidence, "malformed_record")
	if evidence[0].Reason.Details["unusable_reason"] != "missing_affected_entries" {
		t.Fatalf("unusable_reason = %#v", evidence[0].Reason.Details["unusable_reason"])
	}
	if evidence[0].SourceRef == nil || evidence[0].SourceRef.ID != "ghsa-ghsa-minimal-0001-0002" {
		t.Fatalf("source_ref = %#v, want advisory source ref for malformed record", evidence[0].SourceRef)
	}
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestAdapterEvidenceFromJSONReportsParseFailure(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})
	evidence, err := adapter.EvidenceFromJSON(Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, []byte(`{"id":`))
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	assertSourceUnavailable(t, evidence, "parse_failure")
	if _, ok := evidence[0].Reason.Details["parse_error"].(string); !ok {
		t.Fatalf("parse_error detail missing from %#v", evidence[0].Reason.Details)
	}
	if evidence[0].SourceRef == nil || !strings.HasPrefix(evidence[0].SourceRef.ID, "ghsa-json-") {
		t.Fatalf("source_ref = %#v, want local JSON source ref", evidence[0].SourceRef)
	}
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestAdapterEvidenceDeduplicatesDuplicateSourceRefs(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})
	evidence, err := adapter.EvidenceFromJSON(Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, []byte(`{
		"ghsa_id": "GHSA-dupe-0001-0002",
		"cve_id": "CVE-2026-0002",
		"identifiers": [
			{"type": "GHSA", "value": "GHSA-dupe-0001-0002"},
			{"type": "CVE", "value": "CVE-2026-0002"}
		],
		"severity": "high",
		"vulnerabilities": [{
			"package": {"ecosystem": "npm", "name": "left-pad"},
			"vulnerable_version_range": ">= 1.0.0, < 2.0.0"
		}],
		"references": [
			"https://github.com/advisories/GHSA-dupe-0001-0002",
			"https://github.com/advisories/GHSA-dupe-0001-0002",
			"not a valid url"
		]
	}`))
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	if len(evidence) != 1 {
		t.Fatalf("evidence length = %d, want 1", len(evidence))
	}
	got := evidence[0]
	if got.Reason.Code != reasons.KnownVulnerabilityHigh {
		t.Fatalf("reason code = %s, want %s", got.Reason.Code, reasons.KnownVulnerabilityHigh)
	}
	if len(got.SourceRefs) != 2 {
		t.Fatalf("source_refs length = %d, want deduped CVE alias plus advisory reference", len(got.SourceRefs))
	}
	if len(got.Reason.SourceRefIDs) != 3 {
		t.Fatalf("source_ref_ids = %#v, want primary plus two deduped upstream refs", got.Reason.SourceRefIDs)
	}
	seen := map[string]struct{}{}
	for _, id := range got.Reason.SourceRefIDs {
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate source_ref_id %q in %#v", id, got.Reason.SourceRefIDs)
		}
		seen[id] = struct{}{}
	}
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestAdapterEvidenceSourceRefAttributionFields(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})
	evidence, err := adapter.Evidence(Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, nil)
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	if len(evidence) != 1 || evidence[0].SourceRef == nil {
		t.Fatalf("evidence = %#v, want one item with source_ref", evidence)
	}

	sourceRef := evidence[0].SourceRef
	if sourceRef.Source != SourceName {
		t.Fatalf("source = %q, want %q", sourceRef.Source, SourceName)
	}
	if sourceRef.RetrievedAt != fixedNow.Format(time.RFC3339) {
		t.Fatalf("retrieved_at = %q, want fixed time", sourceRef.RetrievedAt)
	}
	if sourceRef.TTLSeconds != DefaultTTLSeconds {
		t.Fatalf("ttl_seconds = %d, want %d", sourceRef.TTLSeconds, DefaultTTLSeconds)
	}
	if sourceRef.LicenseOrTermsURL != licenseOrTermsURL {
		t.Fatalf("license_or_terms_url = %q, want %q", sourceRef.LicenseOrTermsURL, licenseOrTermsURL)
	}
	if !strings.Contains(sourceRef.Attribution, "GitHub Advisory Database") || !strings.Contains(sourceRef.Attribution, "CC-BY-4.0") {
		t.Fatalf("attribution = %q", sourceRef.Attribution)
	}
	if !sourceRef.AttributionRequired {
		t.Fatalf("attribution_required = false, want true")
	}
	if sourceRef.Redistribution != sources.RedistributionUnknown {
		t.Fatalf("redistribution = %q, want %q", sourceRef.Redistribution, sources.RedistributionUnknown)
	}
	if sourceRef.PublicDisplay != sources.PublicDisplayAllowed {
		t.Fatalf("public_display = %q, want %q", sourceRef.PublicDisplay, sources.PublicDisplayAllowed)
	}
}

func assertNoKnownVulnerabilities(t *testing.T, evidence []schema.Evidence) {
	t.Helper()
	if len(evidence) != 1 {
		t.Fatalf("evidence length = %d, want 1", len(evidence))
	}
	got := evidence[0]
	if got.Reason.Code != reasons.NoKnownVulnerabilities {
		t.Fatalf("reason code = %s, want %s", got.Reason.Code, reasons.NoKnownVulnerabilities)
	}
	if got.Reason.Severity != "INFO" || got.Reason.DecisionEffect != schema.DecisionEffectNone {
		t.Fatalf("reason severity/effect = %s/%s, want INFO/NONE", got.Reason.Severity, got.Reason.DecisionEffect)
	}
	if got.SourceRef == nil {
		t.Fatalf("source_ref is nil")
	}
	if len(got.Reason.SourceRefIDs) != 1 || got.Reason.SourceRefIDs[0] != got.SourceRef.ID {
		t.Fatalf("source_ref_ids = %#v, want %q", got.Reason.SourceRefIDs, got.SourceRef.ID)
	}
}

func assertSourceUnavailable(t *testing.T, evidence []schema.Evidence, failureKind string) {
	t.Helper()
	if len(evidence) != 1 {
		t.Fatalf("evidence length = %d, want 1", len(evidence))
	}
	got := evidence[0]
	if got.Reason.Code != reasons.SourceUnavailable {
		t.Fatalf("reason code = %s, want %s", got.Reason.Code, reasons.SourceUnavailable)
	}
	if got.Reason.Severity != "MEDIUM" || got.Reason.DecisionEffect != schema.DecisionEffectUnknown {
		t.Fatalf("reason severity/effect = %s/%s, want MEDIUM/UNKNOWN", got.Reason.Severity, got.Reason.DecisionEffect)
	}
	if got.Reason.Details["failure_kind"] != failureKind {
		t.Fatalf("failure_kind = %#v, want %q", got.Reason.Details["failure_kind"], failureKind)
	}
	if got.SourceRef == nil {
		t.Fatalf("source_ref is nil")
	}
	if len(got.Reason.SourceRefIDs) != 1 || got.Reason.SourceRefIDs[0] != got.SourceRef.ID {
		t.Fatalf("source_ref_ids = %#v, want %q", got.Reason.SourceRefIDs, got.SourceRef.ID)
	}
}

func assertEvidenceAccepted(t *testing.T, coordinate Coordinate, evidence []schema.Evidence) {
	t.Helper()

	engine, err := score.NewEngine(score.Options{Now: fixedClock})
	if err != nil {
		t.Fatalf("NewEngine returned error: %v", err)
	}
	_, err = engine.Evaluate(schema.Request{
		Package: schema.PackageIdentity{
			Ecosystem: coordinate.Ecosystem,
			Name:      coordinate.Name,
			Version:   coordinate.Version,
			PURL:      "pkg:" + coordinate.Ecosystem + "/" + coordinate.Name + "@" + coordinate.Version,
			Resolved:  true,
		},
		Evidence: evidence,
	})
	if err != nil {
		t.Fatalf("scorer rejected evidence: %v", err)
	}
}

func mustNewAdapter(t *testing.T, options Options) Adapter {
	t.Helper()
	adapter, err := NewAdapter(options)
	if err != nil {
		t.Fatalf("NewAdapter returned error: %v", err)
	}
	return adapter
}

func fixedClock() time.Time {
	return fixedNow
}
