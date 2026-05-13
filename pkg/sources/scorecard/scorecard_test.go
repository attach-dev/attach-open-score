package scorecard

import (
	"strings"
	"testing"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/score"
	"github.com/attach-dev/attach-open-score/pkg/sources"
)

var fixedNow = time.Date(2026, 5, 13, 9, 0, 0, 0, time.UTC)

func TestEvidenceFromJSONHealthyReportStaysEvidenceOnly(t *testing.T) {
	adapter := mustAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"date": "2026-05-12T10:00:00Z",
		"repo": {"name": "github.com/attach-dev/healthy", "commit": "abc123"},
		"scorecard": {"version": "v5.0.0", "commit": "scorecardcommit"},
		"score": 8.7,
		"checks": [
			{"name": "Maintained", "score": 10, "reason": "30 commits observed", "documentation": {"url": "https://github.com/ossf/scorecard/blob/main/docs/checks.md#maintained", "short": "Maintained check"}},
			{"name": "Branch-Protection", "score": 8, "reason": "branch protection observed"},
			{"name": "Dangerous-Workflow", "score": 10, "reason": "no dangerous workflow patterns found"},
			{"name": "Pinned-Dependencies", "score": 7, "reason": "most dependencies pinned"}
		]
	}`))
	if err != nil {
		t.Fatalf("EvidenceFromJSON error: %v", err)
	}
	if len(evidence) != 1 {
		t.Fatalf("evidence length = %d, want 1", len(evidence))
	}

	got := evidence[0]
	if got.Reason.Code != reasons.RepositoryMappingUncertain {
		t.Fatalf("reason code = %s, want %s", got.Reason.Code, reasons.RepositoryMappingUncertain)
	}
	if got.Reason.DecisionEffect != schema.DecisionEffectUnknown {
		t.Fatalf("decision_effect = %s, want UNKNOWN", got.Reason.DecisionEffect)
	}
	if got.Reason.Details["health_status"] != "observed_no_low_selected_checks" {
		t.Fatalf("health_status = %#v", got.Reason.Details["health_status"])
	}
	if got.Reason.Details["repository_url"] != "https://github.com/attach-dev/healthy" {
		t.Fatalf("repository_url = %#v", got.Reason.Details["repository_url"])
	}
	if got.SourceRef == nil {
		t.Fatalf("source_ref is nil")
	}
	sourceRef := got.SourceRef
	if sourceRef.Source != SourceName {
		t.Fatalf("source = %q, want %q", sourceRef.Source, SourceName)
	}
	if sourceRef.RetrievedAt != "2026-05-12T10:00:00Z" {
		t.Fatalf("retrieved_at = %q, want scorecard date", sourceRef.RetrievedAt)
	}
	if sourceRef.TTLSeconds != DefaultTTLSeconds {
		t.Fatalf("ttl_seconds = %d, want %d", sourceRef.TTLSeconds, DefaultTTLSeconds)
	}
	if sourceRef.LicenseOrTermsURL != licenseOrTermsURL {
		t.Fatalf("license_or_terms_url = %q, want %q", sourceRef.LicenseOrTermsURL, licenseOrTermsURL)
	}
	for _, want := range []string{"OpenSSF Scorecard", "local/synthetic", "bulk redistribution"} {
		if !strings.Contains(sourceRef.Attribution, want) {
			t.Fatalf("attribution = %q, want mention of %q", sourceRef.Attribution, want)
		}
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
	if len(got.Reason.SourceRefIDs) < 2 {
		t.Fatalf("source_ref_ids = %#v, want report and check refs", got.Reason.SourceRefIDs)
	}
	assertNoDuplicateSourceRefs(t, evidence)
	assertEvidenceScoresAsAsk(t, evidence)
}

func TestEvidenceLowScoreAndRiskyChecksAskOnly(t *testing.T) {
	adapter := mustAdapter(t)
	evidence, err := adapter.Evidence(Report{
		Date:      "2026-05-12T10:00:00Z",
		Repo:      Repository{Name: "https://github.com/attach-dev/risky.git"},
		Scorecard: ScorecardInfo{Version: "v5.0.0"},
		Score:     floatPtr(4.1),
		Checks: []Check{
			{Name: "Dangerous-Workflow", Score: floatPtr(0), Reason: "dangerous workflow pattern detected", Details: Details{".github/workflows/release.yml uses pull_request_target"}},
			{Name: "Token-Permissions", Score: floatPtr(2), Reason: "top-level token permissions are broad"},
			{Name: "Maintained", Score: floatPtr(-1), Reason: "not enough public activity to evaluate"},
			{Name: "License", Score: floatPtr(10), Reason: "license found"},
		},
	})
	if err != nil {
		t.Fatalf("Evidence error: %v", err)
	}
	got := evidence[0]
	if got.Reason.Code != reasons.LowRepositoryHealth {
		t.Fatalf("reason code = %s, want %s", got.Reason.Code, reasons.LowRepositoryHealth)
	}
	if got.Reason.DecisionEffect != schema.DecisionEffectAsk {
		t.Fatalf("decision_effect = %s, want ASK", got.Reason.DecisionEffect)
	}
	if got.Reason.Details["health_status"] != "low" {
		t.Fatalf("health_status = %#v", got.Reason.Details["health_status"])
	}
	lowChecks, ok := got.Reason.Details["low_checks"].([]map[string]any)
	if !ok || len(lowChecks) != 2 {
		t.Fatalf("low_checks = %#v, want two risky checks", got.Reason.Details["low_checks"])
	}
	unknownChecks, ok := got.Reason.Details["unknown_checks"].([]map[string]any)
	if !ok || len(unknownChecks) != 1 || unknownChecks[0]["name"] != "Maintained" {
		t.Fatalf("unknown_checks = %#v, want Maintained", got.Reason.Details["unknown_checks"])
	}
	if got.SourceRef == nil || got.SourceRef.URL != "https://github.com/attach-dev/risky" {
		t.Fatalf("source_ref = %#v, want normalized repository URL", got.SourceRef)
	}
	assertEvidenceScoresAsAsk(t, evidence)
}

func TestEvidenceFromJSONMalformedAndMinimalReportsAreSourceUnavailable(t *testing.T) {
	adapter := mustAdapter(t)

	malformed, err := adapter.EvidenceFromJSON([]byte(`{"repo":`))
	if err != nil {
		t.Fatalf("EvidenceFromJSON malformed error: %v", err)
	}
	assertSourceUnavailable(t, malformed, "parse_failure")
	if _, ok := malformed[0].Reason.Details["parse_error"].(string); !ok {
		t.Fatalf("parse_error detail missing from %#v", malformed[0].Reason.Details)
	}
	if malformed[0].SourceRef == nil || !strings.HasPrefix(malformed[0].SourceRef.ID, "openssf-scorecard-local-json-") {
		t.Fatalf("malformed source_ref = %#v, want local JSON ref", malformed[0].SourceRef)
	}

	minimal, err := adapter.EvidenceFromJSON([]byte(`{"repo":{"name":"github.com/attach-dev/minimal"}}`))
	if err != nil {
		t.Fatalf("EvidenceFromJSON minimal error: %v", err)
	}
	assertSourceUnavailable(t, minimal, "missing_required_data")
	missing, ok := minimal[0].Reason.Details["missing_fields"].([]string)
	if !ok || len(missing) != 1 || missing[0] != "score_or_checks" {
		t.Fatalf("missing_fields = %#v, want score_or_checks", minimal[0].Reason.Details["missing_fields"])
	}
	assertEvidenceScoresAsAsk(t, minimal)
}

func TestEvidenceFromJSONMissingRepositoryIdentityIsUnknownQuality(t *testing.T) {
	adapter := mustAdapter(t)
	for _, tc := range []struct {
		name string
		json string
	}{
		{
			name: "missing repo field",
			json: `{
				"date": "2026-05-12T10:00:00Z",
				"score": 2.1,
				"checks": [{"name": "Dangerous-Workflow", "score": 0, "reason": "dangerous workflow pattern detected"}]
			}`,
		},
		{
			name: "repository URL with userinfo",
			json: `{
				"date": "2026-05-12T10:00:00Z",
				"repo": "https://token@github.com/attach-dev/private.git",
				"score": 2.1,
				"checks": [{"name": "Dangerous-Workflow", "score": 0, "reason": "dangerous workflow pattern detected"}]
			}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evidence, err := adapter.EvidenceFromJSON([]byte(tc.json))
			if err != nil {
				t.Fatalf("EvidenceFromJSON error: %v", err)
			}
			assertSourceUnavailable(t, evidence, "missing_repository_identity")
			if _, ok := evidence[0].Reason.Details["repository_url"]; ok {
				t.Fatalf("repository_url detail = %#v, want absent", evidence[0].Reason.Details["repository_url"])
			}
			if strings.Contains(evidence[0].Reason.Message, "token@") {
				t.Fatalf("message leaked credential-bearing repository: %q", evidence[0].Reason.Message)
			}
			for _, ref := range allSourceRefs(evidence[0]) {
				if strings.Contains(ref.ID+ref.SourceID+ref.URL+ref.Attribution, "token@") {
					t.Fatalf("source_ref leaked credential-bearing repository: %#v", ref)
				}
			}
			assertEvidenceScoresAsAsk(t, evidence)
		})
	}
}

func TestEvidenceDeduplicatesDuplicateCheckSourceRefs(t *testing.T) {
	adapter := mustAdapter(t)
	evidence, err := adapter.Evidence(Report{
		Date:  "2026-05-12T10:00:00Z",
		Repo:  Repository{Name: "github.com/attach-dev/duplicate-checks"},
		Score: floatPtr(3.5),
		Checks: []Check{
			{Name: "Dangerous-Workflow", Score: floatPtr(0), Reason: "first finding"},
			{Name: "Dangerous_Workflow", Score: floatPtr(0), Reason: "duplicate finding shape"},
		},
	})
	if err != nil {
		t.Fatalf("Evidence error: %v", err)
	}
	got := evidence[0]
	if got.Reason.Code != reasons.LowRepositoryHealth {
		t.Fatalf("reason code = %s, want %s", got.Reason.Code, reasons.LowRepositoryHealth)
	}
	if len(got.Reason.SourceRefIDs) != 2 {
		t.Fatalf("source_ref_ids = %#v, want report plus one deduped check ref", got.Reason.SourceRefIDs)
	}
	refs := allSourceRefs(got)
	if len(refs) != 2 {
		t.Fatalf("source_refs = %#v, want report plus one deduped check ref", refs)
	}
	assertNoDuplicateSourceRefs(t, evidence)
	assertEvidenceScoresAsAsk(t, evidence)
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

func assertNoDuplicateSourceRefs(t *testing.T, evidence []schema.Evidence) {
	t.Helper()
	for _, item := range evidence {
		seenIDs := map[string]struct{}{}
		for _, id := range item.Reason.SourceRefIDs {
			if _, ok := seenIDs[id]; ok {
				t.Fatalf("duplicate source_ref_id %q in %#v", id, item.Reason.SourceRefIDs)
			}
			seenIDs[id] = struct{}{}
		}

		seenRefs := map[string]struct{}{}
		for _, sourceRef := range allSourceRefs(item) {
			if _, ok := seenRefs[sourceRef.ID]; ok {
				t.Fatalf("duplicate source_ref %q in %#v", sourceRef.ID, allSourceRefs(item))
			}
			seenRefs[sourceRef.ID] = struct{}{}
		}
	}
}

func assertEvidenceScoresAsAsk(t *testing.T, evidence []schema.Evidence) {
	t.Helper()
	engine, err := score.NewEngine(score.Options{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	verdict, err := engine.Evaluate(schema.Request{
		Package: schema.PackageIdentity{
			Ecosystem:     "npm",
			Name:          "synthetic-scorecard-consumer",
			Version:       "1.0.0",
			PURL:          "pkg:npm/synthetic-scorecard-consumer@1.0.0",
			Resolved:      true,
			RepositoryURL: "https://github.com/attach-dev/healthy",
		},
		Evidence: evidence,
	})
	if err != nil {
		t.Fatalf("scorer rejected evidence: %v", err)
	}
	if verdict.Decision != schema.DecisionAsk {
		t.Fatalf("decision = %s, want ASK", verdict.Decision)
	}
}

func allSourceRefs(evidence schema.Evidence) []schema.SourceRef {
	refs := []schema.SourceRef{}
	if evidence.SourceRef != nil {
		refs = append(refs, *evidence.SourceRef)
	}
	refs = append(refs, evidence.SourceRefs...)
	return refs
}

func mustAdapter(t *testing.T) Adapter {
	t.Helper()
	adapter, err := NewAdapter(Options{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("NewAdapter error: %v", err)
	}
	return adapter
}

func floatPtr(value float64) *float64 {
	return &value
}
