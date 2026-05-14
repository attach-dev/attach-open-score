package registry

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/score"
	"github.com/attach-dev/attach-open-score/pkg/sources"
)

func TestCratesAdapterEvidenceFromSparseIndexRecordNormalizesResolutionMetadata(t *testing.T) {
	adapter := mustCratesAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"name": "serde",
		"vers": "1.0.197",
		"deps": [
			{
				"name": "serde_derive",
				"req": "^1.0.197",
				"features": ["alloc"],
				"optional": true,
				"default_features": false,
				"target": "cfg(not(target_arch = \"wasm32\"))",
				"kind": "normal",
				"registry": null,
				"package": "serde_derive"
			}
		],
		"cksum": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"features": {"derive": ["serde_derive"], "std": ["alloc"]},
		"features2": {"rc": ["alloc"]},
		"yanked": false,
		"rust_version": "1.70",
		"pubtime": "2026-05-01T00:00:00Z"
	}`), Coordinate{Ecosystem: "crates", Name: "serde", Version: "1.0.197"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	if len(evidence) != 1 {
		t.Fatalf("evidence length = %d, want 1", len(evidence))
	}

	got := evidence[0]
	if got.Reason.Code != reasons.RepositoryMappingUncertain {
		t.Fatalf("reason code = %s, want %s", got.Reason.Code, reasons.RepositoryMappingUncertain)
	}
	if got.Reason.Severity != "MEDIUM" || got.Reason.DecisionEffect != schema.DecisionEffectUnknown {
		t.Fatalf("reason severity/effect = %s/%s, want MEDIUM/UNKNOWN", got.Reason.Severity, got.Reason.DecisionEffect)
	}
	if got.SourceRef == nil {
		t.Fatalf("source_ref is nil")
	}
	if got.SourceRef.Source != cratesSourceName || got.SourceRef.SourceID != "index.crates.io/serde@1.0.197" {
		t.Fatalf("source ref source/source_id = %q/%q", got.SourceRef.Source, got.SourceRef.SourceID)
	}
	if got.SourceRef.URL != "https://index.crates.io/se/rd/serde" {
		t.Fatalf("source ref url = %q", got.SourceRef.URL)
	}
	if got.SourceRef.RetrievedAt != fixedNow.Format(time.RFC3339) {
		t.Fatalf("retrieved_at = %q, want fixed clock", got.SourceRef.RetrievedAt)
	}
	if got.SourceRef.TTLSeconds != DefaultTTLSeconds {
		t.Fatalf("ttl_seconds = %d, want %d", got.SourceRef.TTLSeconds, DefaultTTLSeconds)
	}
	if got.SourceRef.LicenseOrTermsURL != cratesTermsURL {
		t.Fatalf("terms url = %q, want %q", got.SourceRef.LicenseOrTermsURL, cratesTermsURL)
	}
	if !strings.Contains(got.SourceRef.Attribution, "crates.io package index") || !strings.Contains(got.SourceRef.Attribution, "index.crates.io") {
		t.Fatalf("attribution = %q, want crates.io index attribution", got.SourceRef.Attribution)
	}
	if !got.SourceRef.AttributionRequired {
		t.Fatalf("attribution_required = false, want true")
	}
	if got.SourceRef.Redistribution != sources.RedistributionUnknown || got.SourceRef.PublicDisplay != sources.PublicDisplayAllowed {
		t.Fatalf("redistribution/public_display = %q/%q, want unknown/allowed", got.SourceRef.Redistribution, got.SourceRef.PublicDisplay)
	}

	details := got.Reason.Details
	if details["source"] != cratesSourceName || details["ecosystem"] != "crates" || details["package_name"] != "serde" || details["version"] != "1.0.197" {
		t.Fatalf("coordinate details = %#v", details)
	}
	if details["purl"] != "pkg:cargo/serde@1.0.197" {
		t.Fatalf("purl = %#v", details["purl"])
	}
	if details["selected_version_source"] != "requested_version" || details["checksum"] != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("selection/checksum details = %#v", details)
	}
	if details["yanked"] != false || details["rust_version"] != "1.70" || details["pubtime"] != "2026-05-01T00:00:00Z" {
		t.Fatalf("yanked/rust/pubtime details = %#v", details)
	}
	if details["request_posture"] != cratesRequestPosture || details["terms_url"] != cratesTermsURL {
		t.Fatalf("posture details = %#v", details)
	}

	dependencies, ok := details["dependencies"].([]map[string]any)
	if !ok || len(dependencies) != 1 {
		t.Fatalf("dependencies = %#v, want one normalized dependency", details["dependencies"])
	}
	dependency := dependencies[0]
	if dependency["name"] != "serde_derive" || dependency["req"] != "^1.0.197" || dependency["kind"] != "normal" || dependency["package"] != "serde_derive" {
		t.Fatalf("dependency identity = %#v", dependency)
	}
	if dependency["optional"] != true || dependency["default_features"] != false || dependency["target"] != "cfg(not(target_arch = \"wasm32\"))" {
		t.Fatalf("dependency flags = %#v", dependency)
	}
	dependencyFeatures, ok := dependency["features"].([]string)
	if !ok || len(dependencyFeatures) != 1 || dependencyFeatures[0] != "alloc" {
		t.Fatalf("dependency features = %#v, want alloc", dependency["features"])
	}

	features, ok := details["features"].(map[string][]string)
	if !ok || len(features["derive"]) != 1 || features["derive"][0] != "serde_derive" || features["rc"][0] != "alloc" {
		t.Fatalf("features = %#v, want merged features/features2", details["features"])
	}

	assertNoDuplicateCratesSourceRefs(t, evidence)
	if len(got.Reason.SourceRefIDs) != 5 {
		t.Fatalf("source_ref_ids = %#v, want version/package/dependencies/features/checksum refs", got.Reason.SourceRefIDs)
	}
	if len(got.SourceRefs) != 4 {
		t.Fatalf("source_refs length = %d, want four secondary refs", len(got.SourceRefs))
	}
	assertCratesEvidenceScoresAs(t, "serde", "1.0.197", evidence, schema.DecisionAsk)
}

func TestCratesAdapterEvidenceSelectsRequestedVersionFromSparseIndexLines(t *testing.T) {
	adapter := mustCratesAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`
{"name":"line-demo","vers":"0.1.0","deps":[],"cksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","features":{},"yanked":false}
{"name":"line-demo","vers":"0.2.0","deps":[],"cksum":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","features":{"default":[]},"yanked":false,"rust_version":"1.72"}
`), Coordinate{Ecosystem: "crates", Name: "line-demo", Version: "0.2.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	got := evidence[0]
	if got.SourceRef == nil || got.SourceRef.SourceID != "index.crates.io/line-demo@0.2.0" {
		t.Fatalf("source_ref = %#v, want selected 0.2.0 ref", got.SourceRef)
	}
	if got.Reason.Details["version"] != "0.2.0" || got.Reason.Details["selected_version_source"] != "requested_version" {
		t.Fatalf("selected version details = %#v", got.Reason.Details)
	}
	if got.Reason.Details["checksum"] != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("checksum = %#v, want selected version checksum", got.Reason.Details["checksum"])
	}
	assertNoDuplicateCratesSourceRefs(t, evidence)
	assertCratesEvidenceScoresAs(t, "line-demo", "0.2.0", evidence, schema.DecisionAsk)
}

func TestCratesAdapterEvidenceEmitsYankedVersionASK(t *testing.T) {
	adapter := mustCratesAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"name": "yanked-demo",
		"vers": "0.9.0",
		"deps": [],
		"cksum": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"features": {},
		"yanked": true
	}`), Coordinate{Ecosystem: "crates", Name: "yanked-demo", Version: "0.9.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	if len(evidence) != 2 {
		t.Fatalf("evidence length = %d, want metadata plus yanked evidence", len(evidence))
	}
	if evidence[0].Reason.Code != reasons.RepositoryMappingUncertain {
		t.Fatalf("metadata reason code = %s", evidence[0].Reason.Code)
	}

	yanked := evidence[1]
	if yanked.Reason.Code != reasons.PackageUnpublishedOrYanked {
		t.Fatalf("yanked reason code = %s, want %s", yanked.Reason.Code, reasons.PackageUnpublishedOrYanked)
	}
	if yanked.Reason.Severity != "MEDIUM" || yanked.Reason.DecisionEffect != schema.DecisionEffectAsk {
		t.Fatalf("yanked severity/effect = %s/%s, want MEDIUM/ASK", yanked.Reason.Severity, yanked.Reason.DecisionEffect)
	}
	if yanked.Reason.Details["yanked"] != true || yanked.Reason.Details["package_name"] != "yanked-demo" || yanked.Reason.Details["version"] != "0.9.0" {
		t.Fatalf("yanked details = %#v", yanked.Reason.Details)
	}
	if len(yanked.Reason.SourceRefIDs) != 1 || yanked.SourceRef == nil || yanked.Reason.SourceRefIDs[0] != yanked.SourceRef.ID {
		t.Fatalf("yanked source refs = %#v / %#v", yanked.Reason.SourceRefIDs, yanked.SourceRef)
	}
	assertNoDuplicateCratesSourceRefs(t, evidence)
	assertCratesEvidenceScoresAs(t, "yanked-demo", "0.9.0", evidence, schema.DecisionAsk)
}

func TestCratesAdapterEvidenceReportsSourceUnavailableForMalformedInput(t *testing.T) {
	adapter := mustCratesAdapter(t)
	tests := map[string][]byte{
		"syntax":        []byte(`{"name":`),
		"trailing data": []byte(`{"name":"bad","vers":"1.0.0"} {"name":"extra","vers":"1.0.1"}`),
		"array":         []byte(`[{"name":"bad","vers":"1.0.0"}]`),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			evidence, err := adapter.EvidenceFromJSON(data, Coordinate{Ecosystem: "crates", Name: "bad", Version: "1.0.0"})
			if err != nil {
				t.Fatalf("EvidenceFromJSON returned error: %v", err)
			}

			assertCratesSourceUnavailable(t, evidence, "parse_failure")
			if evidence[0].SourceRef == nil || !strings.HasPrefix(evidence[0].SourceRef.ID, "crates-io-index-json-") {
				t.Fatalf("source_ref = %#v, want local JSON source ref", evidence[0].SourceRef)
			}
			if _, ok := evidence[0].Reason.Details["parse_error"].(string); !ok {
				t.Fatalf("parse_error detail missing from %#v", evidence[0].Reason.Details)
			}
			assertCratesEvidenceScoresAs(t, "bad", "1.0.0", evidence, schema.DecisionAsk)
		})
	}
}

func TestCratesAdapterEvidenceReportsSourceUnavailableForMissingRequiredData(t *testing.T) {
	adapter := mustCratesAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"name": "missing-version",
		"deps": [],
		"cksum": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		"features": {}
	}`), Coordinate{Ecosystem: "crates", Name: "missing-version"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	assertCratesSourceUnavailable(t, evidence, "missing_required_data")
	missing, ok := evidence[0].Reason.Details["missing_fields"].([]string)
	if !ok || len(missing) != 1 || missing[0] != "version" {
		t.Fatalf("missing_fields = %#v, want version", evidence[0].Reason.Details["missing_fields"])
	}
}

func TestCratesAdapterEvidenceDoesNotModelOwnerDownloadReadmeOrProfileMetadata(t *testing.T) {
	adapter := mustCratesAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"name": "blocked-fields-demo",
		"vers": "1.0.0",
		"deps": [],
		"cksum": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		"features": {},
		"yanked": false,
		"owners": ["fixture-owner"],
		"owner": "fixture-owner",
		"downloads": 123456,
		"download_count": 123456,
		"readme": "fixture-readme",
		"profile": {"github": "fixture-profile"}
	}`), Coordinate{Ecosystem: "crates", Name: "blocked-fields-demo", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	for _, blockedKey := range []string{"owners", "owner", "downloads", "download_count", "readme", "profile"} {
		if _, ok := evidence[0].Reason.Details[blockedKey]; ok {
			t.Fatalf("details included blocked field %q: %#v", blockedKey, evidence[0].Reason.Details)
		}
	}
	rendered := fmt.Sprintf("%#v", evidence)
	for _, blocked := range []string{"fixture-owner", "fixture-readme", "fixture-profile"} {
		if strings.Contains(rendered, blocked) {
			t.Fatalf("evidence included blocked field material %q: %s", blocked, rendered)
		}
	}
	assertNoDuplicateCratesSourceRefs(t, evidence)
	assertCratesEvidenceScoresAs(t, "blocked-fields-demo", "1.0.0", evidence, schema.DecisionAsk)
}

func TestCratesAdapterEvidenceDeduplicatesSourceRefsAndSourceRefIDs(t *testing.T) {
	adapter := mustCratesAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"name": "dedupe-demo",
		"vers": "1.0.0",
		"deps": [{"name": "serde", "req": "^1", "features": [], "optional": false, "default_features": true, "kind": "normal"}],
		"cksum": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"features": {"default": ["std"]},
		"features2": {"serde": ["dep:serde"]},
		"yanked": false
	}`), Coordinate{Ecosystem: "crates", Name: "dedupe-demo", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	assertNoDuplicateCratesSourceRefs(t, evidence)
	if len(evidence[0].Reason.SourceRefIDs) != 5 {
		t.Fatalf("source_ref_ids = %#v, want version/package/dependencies/features/checksum refs after dedupe", evidence[0].Reason.SourceRefIDs)
	}
	if len(evidence[0].SourceRefs) != 4 {
		t.Fatalf("source_refs length = %d, want four secondary refs", len(evidence[0].SourceRefs))
	}
}

func assertCratesSourceUnavailable(t *testing.T, evidence []schema.Evidence, failureKind string) {
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
	if got.Reason.Details["source"] != cratesSourceName || got.Reason.Details["failure_kind"] != failureKind {
		t.Fatalf("source unavailable details = %#v", got.Reason.Details)
	}
	if got.SourceRef == nil {
		t.Fatalf("source_ref is nil")
	}
	if len(got.Reason.SourceRefIDs) != 1 || got.Reason.SourceRefIDs[0] != got.SourceRef.ID {
		t.Fatalf("source_ref_ids = %#v, want %q", got.Reason.SourceRefIDs, got.SourceRef.ID)
	}
}

func assertNoDuplicateCratesSourceRefs(t *testing.T, evidence []schema.Evidence) {
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
		if item.SourceRef != nil {
			seenRefs[item.SourceRef.ID] = struct{}{}
		}
		for _, sourceRef := range item.SourceRefs {
			if _, ok := seenRefs[sourceRef.ID]; ok {
				t.Fatalf("duplicate source_ref %q in %#v", sourceRef.ID, item.SourceRefs)
			}
			seenRefs[sourceRef.ID] = struct{}{}
			if sourceRef.Source != cratesSourceName {
				t.Fatalf("source_ref source = %q, want %q", sourceRef.Source, cratesSourceName)
			}
		}
	}
}

func assertCratesEvidenceScoresAs(t *testing.T, name, version string, evidence []schema.Evidence, wantDecision schema.Decision) {
	t.Helper()
	engine, err := score.NewEngine(score.Options{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("NewEngine returned error: %v", err)
	}
	verdict, err := engine.Evaluate(schema.Request{
		Package: schema.PackageIdentity{
			Ecosystem: "crates",
			Name:      name,
			Version:   version,
			PURL:      "pkg:cargo/" + name + "@" + version,
			Resolved:  true,
		},
		Evidence: evidence,
	})
	if err != nil {
		t.Fatalf("scorer rejected evidence: %v", err)
	}
	if verdict.Decision != wantDecision {
		t.Fatalf("scorer decision = %s, want %s", verdict.Decision, wantDecision)
	}
}

func mustCratesAdapter(t *testing.T) CratesAdapter {
	t.Helper()
	adapter, err := NewCratesAdapter(CratesOptions{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("NewCratesAdapter returned error: %v", err)
	}
	return adapter
}
