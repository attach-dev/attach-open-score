package compose

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attach-dev/attach-open-score/internal/fixtures"
	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/score"
	"github.com/attach-dev/attach-open-score/pkg/sources/depsdev"
	"github.com/attach-dev/attach-open-score/pkg/sources/ghsa"
	"github.com/attach-dev/attach-open-score/pkg/sources/osv"
	"github.com/attach-dev/attach-open-score/pkg/sources/scorecard"
)

var fixedNow = time.Date(2026, 5, 13, 14, 0, 0, 0, time.UTC)

func TestRequestComposesOfflineAdapterEvidenceIntoDeterministicDeny(t *testing.T) {
	request := mustComposedHighRiskRequest(t)

	verdict := mustEvaluate(t, request)
	if verdict.Decision != schema.DecisionDeny {
		t.Fatalf("decision = %s, want DENY", verdict.Decision)
	}
	if verdict.Score == nil || *verdict.Score < 85 {
		t.Fatalf("score = %v, want critical risk score >= 85", verdict.Score)
	}
	if verdict.Confidence != schema.ConfidenceHigh {
		t.Fatalf("confidence = %s, want HIGH", verdict.Confidence)
	}

	assertReasonCodes(t, verdict.Reasons, []string{
		reasons.NoKnownVulnerabilities,
		reasons.KnownVulnerabilityCritical,
		reasons.RepositoryMappingUncertain,
		reasons.RepositoryMappingUncertain,
	})
	assertSourceFamilies(t, verdict.SourceRefs, []string{
		osv.SourceName,
		ghsa.SourceName,
		depsdev.SourceName,
		scorecard.SourceName,
	})
	assertSourceRefsUniqueAndComplete(t, verdict)
	assertSchemaValid(t, "generated-composed-verdict.json", verdict)
}

func TestHealthyRepositoryMetadataOnlyStaysAskQuality(t *testing.T) {
	request, err := Request(testPackage(),
		EvidenceSet{Name: depsdev.SourceName, Evidence: mustDepsDevEvidence(t)},
		EvidenceSet{Name: scorecard.SourceName, Evidence: mustHealthyScorecardEvidence(t)},
	)
	if err != nil {
		t.Fatalf("Request returned error: %v", err)
	}

	verdict := mustEvaluate(t, request)
	if verdict.Decision != schema.DecisionAsk {
		t.Fatalf("decision = %s, want ASK for deps.dev/Scorecard-only metadata", verdict.Decision)
	}
	if verdict.Confidence != schema.ConfidenceLow {
		t.Fatalf("confidence = %s, want LOW for UNKNOWN-quality metadata", verdict.Confidence)
	}
	for _, reason := range verdict.Reasons {
		if reason.DecisionEffect != schema.DecisionEffectUnknown {
			t.Fatalf("reason %s effect = %s, want UNKNOWN-quality evidence only", reason.Code, reason.DecisionEffect)
		}
	}
	assertSourceRefsUniqueAndComplete(t, verdict)
	assertSchemaValid(t, "generated-healthy-metadata-verdict.json", verdict)
}

func TestEvidenceDeduplicatesRefsAndRejectsConflicts(t *testing.T) {
	sourceRef := syntheticSourceRef("shared-source")
	evidence := schema.Evidence{
		Reason: schema.Reason{
			Code:           reasons.RepositoryMappingUncertain,
			Severity:       "MEDIUM",
			DecisionEffect: schema.DecisionEffectUnknown,
			Message:        "Synthetic duplicated provenance.",
			SourceRefIDs:   []string{sourceRef.ID, sourceRef.ID},
		},
		SourceRef:  &sourceRef,
		SourceRefs: []schema.SourceRef{sourceRef},
	}

	composed, err := Evidence(EvidenceSet{Name: "duplicates", Evidence: []schema.Evidence{evidence}})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	if got := composed[0].Reason.SourceRefIDs; len(got) != 1 || got[0] != sourceRef.ID {
		t.Fatalf("source_ref_ids = %#v, want one deduped id", got)
	}
	if len(composed[0].SourceRefs) != 0 {
		t.Fatalf("source_refs = %#v, want duplicate tail source_ref removed", composed[0].SourceRefs)
	}

	conflicting := evidence
	conflictingRef := sourceRef
	conflictingRef.URL = "https://example.invalid/attach-open-score/other-source"
	conflicting.SourceRef = &conflictingRef

	_, err = Evidence(
		EvidenceSet{Name: "first", Evidence: []schema.Evidence{evidence}},
		EvidenceSet{Name: "second", Evidence: []schema.Evidence{conflicting}},
	)
	if err == nil {
		t.Fatalf("Evidence returned nil error for conflicting source_ref")
	}
	if !strings.Contains(err.Error(), "conflicting source_ref") {
		t.Fatalf("error = %v, want conflicting source_ref", err)
	}
}

func TestComposedFixtureMatchesOfflineAdapterProof(t *testing.T) {
	verdict := mustEvaluate(t, mustComposedHighRiskRequest(t))
	fixturePath := filepath.Join("..", "..", "..", "fixtures", "v0", "deny-composed-source-evidence.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if _, err := fixtures.ValidateBytes(fixturePath, data); err != nil {
		t.Fatalf("fixture validation failed: %v", err)
	}

	var fixture schema.Verdict
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if fixture.Decision != verdict.Decision || !reflect.DeepEqual(fixture.Score, verdict.Score) || fixture.Confidence != verdict.Confidence {
		t.Fatalf("fixture decision/score/confidence = %s/%v/%s, want %s/%v/%s", fixture.Decision, fixture.Score, fixture.Confidence, verdict.Decision, verdict.Score, verdict.Confidence)
	}
	if !reflect.DeepEqual(reasonCodes(fixture.Reasons), reasonCodes(verdict.Reasons)) {
		t.Fatalf("fixture reason codes = %#v, want %#v", reasonCodes(fixture.Reasons), reasonCodes(verdict.Reasons))
	}
	if !reflect.DeepEqual(sourceFamilies(fixture.SourceRefs), sourceFamilies(verdict.SourceRefs)) {
		t.Fatalf("fixture source families = %#v, want %#v", sourceFamilies(fixture.SourceRefs), sourceFamilies(verdict.SourceRefs))
	}
}

func mustComposedHighRiskRequest(t *testing.T) schema.Request {
	t.Helper()
	request, err := Request(testPackage(),
		EvidenceSet{Name: osv.SourceName, Evidence: mustOSVNoKnownEvidence(t)},
		EvidenceSet{Name: ghsa.SourceName, Evidence: mustGHSAEvidence(t)},
		EvidenceSet{Name: depsdev.SourceName, Evidence: mustDepsDevEvidence(t)},
		EvidenceSet{Name: scorecard.SourceName, Evidence: mustHealthyScorecardEvidence(t)},
	)
	if err != nil {
		t.Fatalf("Request returned error: %v", err)
	}
	return request
}

func mustOSVNoKnownEvidence(t *testing.T) []schema.Evidence {
	t.Helper()
	client, err := osv.NewClient(osv.Options{
		BaseURL:    "https://example.invalid/attach-open-score/osv",
		HTTPClient: staticHTTPClient(`{"vulns":[]}`),
		Now:        fixedClock,
	})
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	evidence, err := client.Evidence(context.Background(), osv.Coordinate{Ecosystem: "npm", Name: "synthetic-compose", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("OSV Evidence returned error: %v", err)
	}
	return evidence
}

func mustGHSAEvidence(t *testing.T) []schema.Evidence {
	t.Helper()
	adapter, err := ghsa.NewAdapter(ghsa.Options{Now: fixedClock})
	if err != nil {
		t.Fatalf("NewAdapter returned error: %v", err)
	}
	evidence, err := adapter.Evidence(ghsa.Coordinate{Ecosystem: "npm", Name: "synthetic-compose", Version: "1.0.0"}, []ghsa.Advisory{{
		ID:      "GHSA-comp-crit-0001",
		Summary: "Synthetic GHSA composition fixture advisory.",
		Severity: ghsa.SeverityValues{Entries: []ghsa.Severity{{
			Type:  "CVSS_V3",
			Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		}}},
		Affected: []ghsa.Affected{{
			Package:  ghsa.Package{Ecosystem: "npm", Name: "synthetic-compose"},
			Versions: []string{"1.0.0"},
		}},
		References: ghsa.References{{Type: "ADVISORY", URL: "https://github.com/advisories/GHSA-comp-crit-0001"}},
	}})
	if err != nil {
		t.Fatalf("GHSA Evidence returned error: %v", err)
	}
	return evidence
}

func mustDepsDevEvidence(t *testing.T) []schema.Evidence {
	t.Helper()
	adapter, err := depsdev.NewAdapter(depsdev.Options{Now: fixedClock})
	if err != nil {
		t.Fatalf("NewAdapter returned error: %v", err)
	}
	evidence, err := adapter.Evidence(depsdev.Metadata{
		Version: depsdev.Version{
			VersionKey:  depsdev.VersionKey{System: "NPM", Name: "synthetic-compose", Version: "1.0.0"},
			PublishedAt: "2026-05-01T00:00:00Z",
			Licenses:    depsdev.Licenses{"Apache-2.0"},
			Links: []depsdev.Link{
				{Label: "SOURCE_REPO", URL: "https://example.invalid/attach-open-score/synthetic-compose"},
				{Label: "SOURCE_REPO", URL: "https://example.invalid/attach-open-score/synthetic-compose"},
			},
			Dependencies: []depsdev.Dependency{{
				PackageKey:  depsdev.PackageKey{System: "NPM", Name: "left-pad"},
				Requirement: "^1.3.0",
				Relation:    "DIRECT",
			}},
		},
	})
	if err != nil {
		t.Fatalf("deps.dev Evidence returned error: %v", err)
	}
	return evidence
}

func mustHealthyScorecardEvidence(t *testing.T) []schema.Evidence {
	t.Helper()
	adapter, err := scorecard.NewAdapter(scorecard.Options{Now: fixedClock})
	if err != nil {
		t.Fatalf("NewAdapter returned error: %v", err)
	}
	evidence, err := adapter.Evidence(scorecard.Report{
		Date:      "2026-05-12T10:00:00Z",
		Repo:      scorecard.Repository{Name: "https://example.invalid/attach-open-score/synthetic-compose"},
		Scorecard: scorecard.ScorecardInfo{Version: "v5.0.0", Commit: "synthetic-scorecard-commit"},
		Score:     floatPtr(8.9),
		Checks: []scorecard.Check{
			{Name: "Maintained", Score: floatPtr(10), Reason: "synthetic local report shows recent maintenance"},
			{Name: "Dangerous-Workflow", Score: floatPtr(10), Reason: "synthetic local report shows no dangerous workflow patterns"},
			{Name: "Token-Permissions", Score: floatPtr(8), Reason: "synthetic local report shows scoped token permissions"},
		},
	})
	if err != nil {
		t.Fatalf("Scorecard Evidence returned error: %v", err)
	}
	return evidence
}

func mustEvaluate(t *testing.T, request schema.Request) schema.Verdict {
	t.Helper()
	engine, err := score.NewEngine(score.Options{Now: fixedClock})
	if err != nil {
		t.Fatalf("NewEngine returned error: %v", err)
	}
	verdict, err := engine.Evaluate(request)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	return verdict
}

func testPackage() schema.PackageIdentity {
	return schema.PackageIdentity{
		Ecosystem:     "npm",
		Name:          "synthetic-compose",
		Version:       "1.0.0",
		PURL:          "pkg:npm/synthetic-compose@1.0.0",
		Resolved:      true,
		RepositoryURL: "https://example.invalid/attach-open-score/synthetic-compose",
	}
}

func assertReasonCodes(t *testing.T, got []schema.Reason, want []string) {
	t.Helper()
	if !reflect.DeepEqual(reasonCodes(got), want) {
		t.Fatalf("reason codes = %#v, want %#v", reasonCodes(got), want)
	}
}

func assertSourceFamilies(t *testing.T, refs []schema.SourceRef, want []string) {
	t.Helper()
	got := sourceFamilies(refs)
	for _, family := range want {
		if !slices.Contains(got, family) {
			t.Fatalf("source families = %#v, want family %q", got, family)
		}
	}
}

func assertSourceRefsUniqueAndComplete(t *testing.T, verdict schema.Verdict) {
	t.Helper()
	refs := map[string]struct{}{}
	for _, sourceRef := range verdict.SourceRefs {
		if _, ok := refs[sourceRef.ID]; ok {
			t.Fatalf("duplicate source_ref id %q", sourceRef.ID)
		}
		refs[sourceRef.ID] = struct{}{}
	}
	for _, reason := range verdict.Reasons {
		seen := map[string]struct{}{}
		for _, id := range reason.SourceRefIDs {
			if _, ok := seen[id]; ok {
				t.Fatalf("reason %s contains duplicate source_ref_id %q", reason.Code, id)
			}
			seen[id] = struct{}{}
			if _, ok := refs[id]; !ok {
				t.Fatalf("reason %s references missing source_ref_id %q", reason.Code, id)
			}
		}
	}
}

func assertSchemaValid(t *testing.T, name string, verdict schema.Verdict) {
	t.Helper()
	data, err := json.Marshal(verdict)
	if err != nil {
		t.Fatalf("marshal verdict: %v", err)
	}
	if _, err := fixtures.ValidateBytes(name, data); err != nil {
		t.Fatalf("generated verdict failed fixture validation: %v\n%s", err, string(data))
	}
}

func reasonCodes(reasons []schema.Reason) []string {
	codes := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		codes = append(codes, reason.Code)
	}
	return codes
}

func sourceFamilies(refs []schema.SourceRef) []string {
	families := []string{}
	seen := map[string]struct{}{}
	for _, ref := range refs {
		if _, ok := seen[ref.Source]; ok {
			continue
		}
		seen[ref.Source] = struct{}{}
		families = append(families, ref.Source)
	}
	return families
}

func syntheticSourceRef(id string) schema.SourceRef {
	return schema.SourceRef{
		ID:                  id,
		Source:              "synthetic-fixture",
		SourceID:            id,
		URL:                 "https://example.invalid/attach-open-score/" + id,
		RetrievedAt:         fixedNow.Format(time.RFC3339),
		TTLSeconds:          86400,
		LicenseOrTermsURL:   "https://example.invalid/terms",
		Attribution:         "Synthetic fixture data for Attach Open Score tests.",
		AttributionRequired: false,
		Redistribution:      "allowed",
		PublicDisplay:       "allowed",
	}
}

type staticHTTPClient string

func (c staticHTTPClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(c))),
	}, nil
}

func fixedClock() time.Time {
	return fixedNow
}

func floatPtr(value float64) *float64 {
	return &value
}
