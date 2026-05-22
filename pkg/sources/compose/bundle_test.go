package compose

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/score"
	"github.com/attach-dev/attach-open-score/pkg/sources/depsdev"
	"github.com/attach-dev/attach-open-score/pkg/sources/osv"
	"github.com/attach-dev/attach-open-score/pkg/sources/scorecard"
)

func TestBundleJSONScoresThroughEngineWithMixedSourceFamilies(t *testing.T) {
	data := mustReadBundleFixture(t, "mixed-evidence-bundle.json")

	request, err := RequestFromBundleJSON(data)
	if err != nil {
		t.Fatalf("RequestFromBundleJSON returned error: %v", err)
	}
	if request.Package.Name != "synthetic-bundle" || len(request.Evidence) != 3 {
		t.Fatalf("request package/evidence = %s/%d, want synthetic-bundle/3", request.Package.Name, len(request.Evidence))
	}
	if got := request.Evidence[0].Reason.SourceRefIDs; !reflect.DeepEqual(got, []string{"osv-query-synthetic-bundle"}) {
		t.Fatalf("source_ref_ids = %#v, want duplicate IDs deduped", got)
	}
	if len(request.Evidence[0].SourceRefs) != 0 {
		t.Fatalf("source_refs = %#v, want duplicate source_ref tail removed", request.Evidence[0].SourceRefs)
	}

	engine, err := score.NewEngine(score.Options{Now: fixedClock})
	if err != nil {
		t.Fatalf("NewEngine returned error: %v", err)
	}
	verdict, err := EvaluateBundleJSON(data, engine)
	if err != nil {
		t.Fatalf("EvaluateBundleJSON returned error: %v", err)
	}
	if verdict.Decision != schema.DecisionDeny {
		t.Fatalf("decision = %s, want DENY", verdict.Decision)
	}
	if verdict.Score == nil || *verdict.Score < 85 {
		t.Fatalf("score = %v, want deny score >= 85", verdict.Score)
	}
	assertReasonCodes(t, verdict.Reasons, []string{
		"X_SYNTHETIC_ALLOW",
		reasons.KnownVulnerabilityCritical,
		reasons.LowRepositoryHealth,
	})
	assertSourceFamilies(t, verdict.SourceRefs, []string{
		osv.SourceName,
		scorecard.SourceName,
	})
	assertSourceRefsUniqueAndComplete(t, verdict)
}

func TestBundleJSONRejectsConflictingSourceRefs(t *testing.T) {
	shared := bundleSourceRef("shared-ref", depsdev.SourceName)
	conflicting := shared
	conflicting.URL = "https://example.invalid/attach-open-score/conflicting-source"

	_, err := RequestFromBundleJSON(mustBundleJSON(t, Bundle{
		Package: testBundlePackage(),
		EvidenceSets: []EvidenceSet{{Name: depsdev.SourceName, Evidence: []schema.Evidence{
			bundleEvidence(reasons.SourceStale, "MEDIUM", schema.DecisionEffectAsk, shared),
			bundleEvidence(reasons.SourceStale, "MEDIUM", schema.DecisionEffectAsk, conflicting),
		}}},
	}))
	if err == nil {
		t.Fatalf("RequestFromBundleJSON returned nil error for conflicting source_ref")
	}
	if !strings.Contains(err.Error(), "conflicting source_ref") {
		t.Fatalf("error = %v, want conflicting source_ref", err)
	}
}

func TestBundleJSONRejectsMissingSourceRefIDs(t *testing.T) {
	tests := []struct {
		name     string
		evidence schema.Evidence
		want     string
	}{
		{
			name: "missing referenced id",
			evidence: func() schema.Evidence {
				sourceRef := bundleSourceRef("available-ref", osv.SourceName)
				evidence := bundleEvidence(reasons.KnownVulnerabilityHigh, "HIGH", schema.DecisionEffectAsk, sourceRef)
				evidence.Reason.SourceRefIDs = []string{"missing-ref"}
				return evidence
			}(),
			want: "references missing source_ref_id",
		},
		{
			name: "source ref without id",
			evidence: func() schema.Evidence {
				sourceRef := bundleSourceRef("available-ref", osv.SourceName)
				sourceRef.ID = ""
				evidence := bundleEvidence(reasons.KnownVulnerabilityHigh, "HIGH", schema.DecisionEffectAsk, sourceRef)
				evidence.Reason.SourceRefIDs = []string{""}
				return evidence
			}(),
			want: "source_ref id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RequestFromBundleJSON(mustBundleJSON(t, Bundle{
				Package:      testBundlePackage(),
				EvidenceSets: []EvidenceSet{{Name: osv.SourceName, Evidence: []schema.Evidence{tt.evidence}}},
			}))
			if err == nil {
				t.Fatalf("RequestFromBundleJSON returned nil error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestBundleJSONRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "empty", data: "", want: "empty"},
		{name: "unknown field", data: `{"package":{},"evidence_sets":[],"mode":"local"}`, want: "unknown field"},
		{name: "trailing data", data: `{"package":{},"evidence_sets":[]} {}`, want: "trailing data"},
		{name: "missing evidence sets", data: `{"package":{"ecosystem":"npm","name":"pkg","purl":"pkg:npm/pkg","resolved":true}}`, want: "evidence_sets is required"},
		{name: "missing package resolved", data: `{"package":{"ecosystem":"npm","name":"pkg","purl":"pkg:npm/pkg"},"evidence_sets":[]}`, want: "package.resolved is required"},
		{name: "null package resolved", data: `{"package":{"ecosystem":"npm","name":"pkg","purl":"pkg:npm/pkg","resolved":null},"evidence_sets":[]}`, want: "package.resolved must be bool"},
		{name: "null optional package scalar", data: `{"package":{"ecosystem":"npm","name":"pkg","version":null,"purl":"pkg:npm/pkg","resolved":true},"evidence_sets":[]}`, want: "package.version must be string"},
		{name: "missing set evidence", data: `{"package":{"ecosystem":"npm","name":"pkg","purl":"pkg:npm/pkg","resolved":true},"evidence_sets":[{"source":"osv.dev"}]}`, want: "evidence is required"},
		{name: "missing source ref ttl", data: `{"package":{"ecosystem":"npm","name":"pkg","purl":"pkg:npm/pkg","resolved":true},"evidence_sets":[{"source":"osv.dev","evidence":[{"reason":{"code":"KNOWN_VULNERABILITY_HIGH","severity":"HIGH","decision_effect":"ASK","message":"m","source_ref_ids":["s1"]},"source_ref":{"id":"s1","source":"osv.dev","source_id":"OSV-2026-1","url":"https://example.invalid/osv","retrieved_at":"2026-05-18T00:00:00Z","license_or_terms_url":"https://example.invalid/terms","attribution":"OSV","attribution_required":true,"redistribution":"metadata_only","public_display":"summary"}}]}]}`, want: "source_ref.ttl_seconds is required"},
		{name: "null source ref ttl", data: `{"package":{"ecosystem":"npm","name":"pkg","purl":"pkg:npm/pkg","resolved":true},"evidence_sets":[{"source":"osv.dev","evidence":[{"reason":{"code":"KNOWN_VULNERABILITY_HIGH","severity":"HIGH","decision_effect":"ASK","message":"m","source_ref_ids":["s1"]},"source_ref":{"id":"s1","source":"osv.dev","source_id":"OSV-2026-1","url":"https://example.invalid/osv","retrieved_at":"2026-05-18T00:00:00Z","ttl_seconds":null,"license_or_terms_url":"https://example.invalid/terms","attribution":"OSV","attribution_required":true,"redistribution":"metadata_only","public_display":"summary"}}]}]}`, want: "source_ref.ttl_seconds must be number"},
		{name: "null attribution required", data: `{"package":{"ecosystem":"npm","name":"pkg","purl":"pkg:npm/pkg","resolved":true},"evidence_sets":[{"source":"osv.dev","evidence":[{"reason":{"code":"KNOWN_VULNERABILITY_HIGH","severity":"HIGH","decision_effect":"ASK","message":"m","source_ref_ids":["s1"]},"source_ref":{"id":"s1","source":"osv.dev","source_id":"OSV-2026-1","url":"https://example.invalid/osv","retrieved_at":"2026-05-18T00:00:00Z","ttl_seconds":86400,"license_or_terms_url":"https://example.invalid/terms","attribution":"OSV","attribution_required":null,"redistribution":"metadata_only","public_display":"summary"}}]}]}`, want: "source_ref.attribution_required must be bool"},
		{name: "source ref mismatches set source", data: `{"package":{"ecosystem":"npm","name":"pkg","purl":"pkg:npm/pkg","resolved":true},"evidence_sets":[{"source":"osv.dev","evidence":[{"reason":{"code":"KNOWN_VULNERABILITY_HIGH","severity":"HIGH","decision_effect":"ASK","message":"m","source_ref_ids":["s1"]},"source_ref":{"id":"s1","source":"deps.dev","source_id":"pkg:npm/pkg@1.0.0","url":"https://example.invalid/deps","retrieved_at":"2026-05-18T00:00:00Z","ttl_seconds":86400,"license_or_terms_url":"https://example.invalid/terms","attribution":"deps.dev","attribution_required":true,"redistribution":"metadata_only","public_display":"summary"}}]}]}`, want: "does not match evidence_set source"},
		{name: "proprietary source", data: `{"package":{"ecosystem":"npm","name":"pkg","purl":"pkg:npm/pkg","resolved":true},"evidence_sets":[{"source":"socket_score_export","evidence":[]}]}`, want: "not an allowed public/open source"},
		{name: "raw reason code", data: `{"package":{"ecosystem":"npm","name":"pkg","purl":"pkg:npm/pkg","resolved":true},"evidence_sets":[{"source":"osv.dev","evidence":[{"reason":{"code":"X_RAW__UPSTREAM","severity":"LOW","decision_effect":"NONE","message":"m"}}]}]}`, want: "raw upstream"},
		{name: "raw reason message", data: `{"package":{"ecosystem":"npm","name":"pkg","purl":"pkg:npm/pkg","resolved":true},"evidence_sets":[{"source":"osv.dev","evidence":[{"reason":{"code":"X_SYNTHETIC","severity":"LOW","decision_effect":"NONE","message":"raw-upstream payload included"}}]}]}`, want: "raw upstream"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := RequestFromBundleJSON([]byte(tt.data))
			if err == nil {
				t.Fatalf("RequestFromBundleJSON returned nil error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func mustReadBundleFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read bundle fixture: %v", err)
	}
	return data
}

func mustBundleJSON(t *testing.T, bundle Bundle) []byte {
	t.Helper()
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return data
}

func testBundlePackage() schema.PackageIdentity {
	return schema.PackageIdentity{
		Ecosystem:     "npm",
		Name:          "synthetic-bundle",
		Version:       "1.0.0",
		PURL:          "pkg:npm/synthetic-bundle@1.0.0",
		Resolved:      true,
		RepositoryURL: "https://example.invalid/attach-open-score/synthetic-bundle",
	}
}

func bundleEvidence(code, severity string, effect schema.DecisionEffect, sourceRef schema.SourceRef) schema.Evidence {
	return schema.Evidence{
		Reason: schema.Reason{
			Code:           code,
			Severity:       severity,
			DecisionEffect: effect,
			Message:        "Synthetic offline bundle evidence.",
			SourceRefIDs:   []string{sourceRef.ID},
		},
		SourceRef: &sourceRef,
	}
}

func bundleSourceRef(id, source string) schema.SourceRef {
	sourceRef := syntheticSourceRef(id)
	sourceRef.Source = source
	sourceRef.SourceID = source + ":" + id
	return sourceRef
}
