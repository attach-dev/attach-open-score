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

func TestNPMAdapterEvidenceFromPackumentNormalizesPackageVersionMetadata(t *testing.T) {
	adapter := mustNPMAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"name": "@synthetic/example",
		"dist-tags": {"latest": "1.2.0", "beta": "1.3.0-beta.1"},
		"time": {
			"created": "2026-04-01T00:00:00.000Z",
			"modified": "2026-05-10T00:00:00.000Z",
			"1.2.0": "2026-05-01T00:00:00.000Z"
		},
		"license": "Apache-2.0",
		"repository": {"type": "git", "url": "git+https://github.com/attach-dev/synthetic-npm.git"},
		"versions": {
			"1.2.0": {
				"name": "@synthetic/example",
				"version": "1.2.0",
				"license": "Apache-2.0",
				"repository": {"type": "git", "url": "git+https://github.com/attach-dev/synthetic-npm.git"}
			}
		}
	}`), Coordinate{Ecosystem: "npm", Name: "@synthetic/example", Version: "1.2.0"})
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
	if got.SourceRef.Source != npmSourceName || got.SourceRef.SourceID != "registry.npmjs.org/@synthetic/example@1.2.0" {
		t.Fatalf("source ref source/source_id = %q/%q", got.SourceRef.Source, got.SourceRef.SourceID)
	}
	if got.SourceRef.URL != "https://registry.npmjs.org/%40synthetic%2Fexample/1.2.0" {
		t.Fatalf("source ref url = %q", got.SourceRef.URL)
	}
	if got.SourceRef.RetrievedAt != fixedNow.Format(time.RFC3339) {
		t.Fatalf("retrieved_at = %q, want fixed clock", got.SourceRef.RetrievedAt)
	}
	if got.SourceRef.TTLSeconds != DefaultTTLSeconds {
		t.Fatalf("ttl_seconds = %d, want %d", got.SourceRef.TTLSeconds, DefaultTTLSeconds)
	}
	if got.SourceRef.LicenseOrTermsURL != npmTermsURL {
		t.Fatalf("terms url = %q, want %q", got.SourceRef.LicenseOrTermsURL, npmTermsURL)
	}
	if !strings.Contains(got.SourceRef.Attribution, "npm public registry") || !strings.Contains(got.SourceRef.Attribution, "registry.npmjs.org") {
		t.Fatalf("attribution = %q, want npm registry attribution", got.SourceRef.Attribution)
	}
	if !got.SourceRef.AttributionRequired {
		t.Fatalf("attribution_required = false, want true")
	}
	if got.SourceRef.Redistribution != sources.RedistributionUnknown || got.SourceRef.PublicDisplay != sources.PublicDisplayAllowed {
		t.Fatalf("redistribution/public_display = %q/%q, want unknown/allowed", got.SourceRef.Redistribution, got.SourceRef.PublicDisplay)
	}
	if len(got.Reason.SourceRefIDs) < 2 || got.Reason.SourceRefIDs[0] != got.SourceRef.ID {
		t.Fatalf("source_ref_ids = %#v, want primary version ref plus package refs", got.Reason.SourceRefIDs)
	}
	if len(got.SourceRefs) == 0 || got.SourceRefs[0].SourceID != "registry.npmjs.org/@synthetic/example" {
		t.Fatalf("source_refs = %#v, want package source ref", got.SourceRefs)
	}

	details := got.Reason.Details
	if details["source"] != npmSourceName || details["ecosystem"] != "npm" || details["package_name"] != "@synthetic/example" || details["version"] != "1.2.0" {
		t.Fatalf("coordinate details = %#v", details)
	}
	if details["purl"] != "pkg:npm/%40synthetic/example@1.2.0" {
		t.Fatalf("purl = %#v", details["purl"])
	}
	if details["latest_dist_tag"] != "1.2.0" || details["selected_version_source"] != "requested_version" {
		t.Fatalf("dist-tag details = %#v", details)
	}
	if details["package_created_at"] != "2026-04-01T00:00:00.000Z" || details["package_modified_at"] != "2026-05-10T00:00:00.000Z" || details["version_published_at"] != "2026-05-01T00:00:00.000Z" {
		t.Fatalf("time details = %#v", details)
	}
	if details["license"] != "Apache-2.0" || details["license_metadata_status"] != "reported_by_npm_registry" {
		t.Fatalf("license details = %#v", details)
	}
	if details["repository_url"] != "https://github.com/attach-dev/synthetic-npm" || details["repository_mapping_status"] != "reported_by_npm_registry" {
		t.Fatalf("repository details = %#v", details)
	}
	if details["deprecated"] != false {
		t.Fatalf("deprecated marker = %#v, want false", details["deprecated"])
	}
	if details["request_posture"] != npmRequestPosture || details["terms_url"] != npmTermsURL {
		t.Fatalf("posture details = %#v", details)
	}

	assertNoDuplicateNPMSourceRefs(t, evidence)
	assertNPMEvidenceScoresAs(t, "@synthetic/example", "1.2.0", evidence, schema.DecisionAsk)
}

func TestNPMAdapterEvidenceUsesLatestDistTagWhenVersionOmitted(t *testing.T) {
	adapter := mustNPMAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"name": "latest-only",
		"dist-tags": {"latest": "2.0.0", "next": "2.1.0-beta.1"},
		"versions": {
			"2.0.0": {"name": "latest-only", "version": "2.0.0", "license": "MIT"}
		}
	}`), Coordinate{Ecosystem: "npm", Name: "latest-only"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	got := evidence[0]
	if got.Reason.DecisionEffect != schema.DecisionEffectUnknown {
		t.Fatalf("decision_effect = %s, want UNKNOWN", got.Reason.DecisionEffect)
	}
	if got.SourceRef == nil || got.SourceRef.SourceID != "registry.npmjs.org/latest-only@2.0.0" {
		t.Fatalf("source_ref = %#v, want selected latest version ref", got.SourceRef)
	}
	if got.Reason.Details["version"] != "2.0.0" || got.Reason.Details["selected_version_source"] != "dist-tags.latest" {
		t.Fatalf("selected version details = %#v", got.Reason.Details)
	}
	distTags, ok := got.Reason.Details["dist_tags"].(map[string]string)
	if !ok || distTags["latest"] != "2.0.0" || distTags["next"] != "2.1.0-beta.1" {
		t.Fatalf("dist_tags = %#v, want latest and next", got.Reason.Details["dist_tags"])
	}
	if got.Reason.Details["dist_tags_status"] != "reported_by_npm_registry_mutable" {
		t.Fatalf("dist_tags_status = %#v, want mutable status", got.Reason.Details["dist_tags_status"])
	}
	assertNoDuplicateNPMSourceRefs(t, evidence)
	assertNPMEvidenceScoresAs(t, "latest-only", "2.0.0", evidence, schema.DecisionAsk)
}

func TestNPMAdapterEvidenceEmitsDeprecatedPackageASK(t *testing.T) {
	adapter := mustNPMAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"name": "deprecated-demo",
		"dist-tags": {"latest": "1.0.0"},
		"versions": {
			"1.0.0": {
				"name": "deprecated-demo",
				"version": "1.0.0",
				"deprecated": "Use deprecated-demo-safe instead."
			}
		}
	}`), Coordinate{Ecosystem: "npm", Name: "deprecated-demo", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	if len(evidence) != 2 {
		t.Fatalf("evidence length = %d, want metadata plus deprecated evidence", len(evidence))
	}
	if evidence[0].Reason.Code != reasons.RepositoryMappingUncertain {
		t.Fatalf("metadata reason code = %s", evidence[0].Reason.Code)
	}
	deprecated := evidence[1]
	if deprecated.Reason.Code != reasons.DeprecatedPackage {
		t.Fatalf("deprecated reason code = %s, want %s", deprecated.Reason.Code, reasons.DeprecatedPackage)
	}
	if deprecated.Reason.Severity != "MEDIUM" || deprecated.Reason.DecisionEffect != schema.DecisionEffectAsk {
		t.Fatalf("deprecated severity/effect = %s/%s, want MEDIUM/ASK", deprecated.Reason.Severity, deprecated.Reason.DecisionEffect)
	}
	if deprecated.Reason.Details["deprecated"] != true || deprecated.Reason.Details["deprecation_message"] != "Use deprecated-demo-safe instead." {
		t.Fatalf("deprecated details = %#v", deprecated.Reason.Details)
	}
	if len(deprecated.Reason.SourceRefIDs) != 1 || deprecated.SourceRef == nil || deprecated.Reason.SourceRefIDs[0] != deprecated.SourceRef.ID {
		t.Fatalf("deprecated source refs = %#v / %#v", deprecated.Reason.SourceRefIDs, deprecated.SourceRef)
	}
	assertNoDuplicateNPMSourceRefs(t, evidence)
	assertNPMEvidenceScoresAs(t, "deprecated-demo", "1.0.0", evidence, schema.DecisionAsk)
}

func TestNPMAdapterEvidenceFromVersionJSONMissingOptionalFields(t *testing.T) {
	adapter := mustNPMAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"name": "no-optionals",
		"version": "0.1.0"
	}`), Coordinate{Ecosystem: "npm"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	got := evidence[0]
	if got.Reason.Code != reasons.RepositoryMappingUncertain || got.Reason.DecisionEffect != schema.DecisionEffectUnknown {
		t.Fatalf("reason = %#v, want non-authoritative metadata evidence", got.Reason)
	}
	if got.Reason.Details["license_metadata_status"] != "not_reported" || got.Reason.Details["repository_mapping_status"] != "not_reported" {
		t.Fatalf("optional field details = %#v", got.Reason.Details)
	}
	if got.Reason.Details["dist_tags_status"] != "not_reported" {
		t.Fatalf("dist tag details = %#v", got.Reason.Details)
	}
	assertNoDuplicateNPMSourceRefs(t, evidence)
	assertNPMEvidenceScoresAs(t, "no-optionals", "0.1.0", evidence, schema.DecisionAsk)
}

func TestNPMAdapterEvidenceReportsSourceUnavailableForMalformedInput(t *testing.T) {
	adapter := mustNPMAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{"name":`), Coordinate{Ecosystem: "npm", Name: "broken", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	assertNPMSourceUnavailable(t, evidence, "parse_failure")
	if evidence[0].SourceRef == nil || !strings.HasPrefix(evidence[0].SourceRef.ID, "npm-registry-json-") {
		t.Fatalf("source_ref = %#v, want local JSON source ref", evidence[0].SourceRef)
	}
	if _, ok := evidence[0].Reason.Details["parse_error"].(string); !ok {
		t.Fatalf("parse_error detail missing from %#v", evidence[0].Reason.Details)
	}
	assertNPMEvidenceScoresAs(t, "broken", "1.0.0", evidence, schema.DecisionAsk)
}

func TestNPMAdapterEvidenceReportsSourceUnavailableForMissingRequiredData(t *testing.T) {
	adapter := mustNPMAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"dist-tags": {"latest": "1.0.0"},
		"versions": {}
	}`), Coordinate{Ecosystem: "npm"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	assertNPMSourceUnavailable(t, evidence, "missing_required_data")
	missing, ok := evidence[0].Reason.Details["missing_fields"].([]string)
	if !ok || len(missing) != 2 || missing[0] != "name" || missing[1] != "version" {
		t.Fatalf("missing_fields = %#v, want name and version", evidence[0].Reason.Details["missing_fields"])
	}
}

func TestNPMAdapterEvidenceReportsSourceUnavailableForConflictingRequiredData(t *testing.T) {
	adapter := mustNPMAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"name": "left-name",
		"dist-tags": {"latest": "1.0.0"},
		"versions": {
			"1.0.0": {"name": "right-name", "version": "1.0.0"}
		}
	}`), Coordinate{Ecosystem: "npm", Name: "left-name", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	assertNPMSourceUnavailable(t, evidence, "conflicting_required_data")
	conflicts, ok := evidence[0].Reason.Details["conflicting_fields"].([]string)
	if !ok || len(conflicts) != 1 || conflicts[0] != "versions[1.0.0].name" {
		t.Fatalf("conflicting_fields = %#v, want version name conflict", evidence[0].Reason.Details["conflicting_fields"])
	}
}

func TestNPMAdapterEvidenceDeduplicatesSourceRefsAndSourceRefIDs(t *testing.T) {
	adapter := mustNPMAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"name": "dedupe-demo",
		"dist-tags": {"latest": "1.0.0"},
		"license": "MIT",
		"repository": "git+https://github.com/attach-dev/dedupe-demo.git",
		"versions": {
			"1.0.0": {
				"name": "dedupe-demo",
				"version": "1.0.0",
				"license": "MIT",
				"repository": {"type": "git", "url": "git+https://github.com/attach-dev/dedupe-demo.git"}
			}
		}
	}`), Coordinate{Ecosystem: "npm", Name: "dedupe-demo", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	assertNoDuplicateNPMSourceRefs(t, evidence)
	if len(evidence[0].Reason.SourceRefIDs) != 5 {
		t.Fatalf("source_ref_ids = %#v, want version/package/dist-tags/license/repository refs", evidence[0].Reason.SourceRefIDs)
	}
	if len(evidence[0].SourceRefs) != 4 {
		t.Fatalf("source_refs length = %d, want four secondary refs", len(evidence[0].SourceRefs))
	}
}

func TestNPMAdapterEvidenceDoesNotLeakSensitiveRepositoryURLs(t *testing.T) {
	adapter := mustNPMAdapter(t)
	repositoryURL := "git+https://" + "user" + ":" + "redacted" + "@" + "github.com/attach-dev/sensitive-url-demo.git" + "?auth=" + "redacted" + "#fragment"
	evidence, err := adapter.EvidenceFromJSON([]byte(fmt.Sprintf(`{
		"name": "sensitive-url-demo",
		"version": "1.0.0",
		"repository": {
			"type": "git",
			"url": %q
		}
	}`, repositoryURL)), Coordinate{Ecosystem: "npm", Name: "sensitive-url-demo", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	got := evidence[0]
	if got.Reason.Code != reasons.RepositoryMappingUncertain || got.Reason.DecisionEffect != schema.DecisionEffectUnknown {
		t.Fatalf("reason = %#v, want non-authoritative metadata evidence", got.Reason)
	}
	if got.Reason.Details["repository_mapping_status"] != "invalid_or_sensitive" {
		t.Fatalf("repository status = %#v, want invalid_or_sensitive", got.Reason.Details["repository_mapping_status"])
	}
	rendered := fmt.Sprintf("%#v", evidence)
	for _, sensitive := range []string{"redacted", "?auth=", "@github.com", "#fragment"} {
		if strings.Contains(rendered, sensitive) {
			t.Fatalf("evidence leaked sensitive repository URL material %q: %s", sensitive, rendered)
		}
	}
	assertNoDuplicateNPMSourceRefs(t, evidence)
	assertNPMEvidenceScoresAs(t, "sensitive-url-demo", "1.0.0", evidence, schema.DecisionAsk)
}

func assertNPMSourceUnavailable(t *testing.T, evidence []schema.Evidence, failureKind string) {
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
	if got.Reason.Details["source"] != npmSourceName || got.Reason.Details["failure_kind"] != failureKind {
		t.Fatalf("source unavailable details = %#v", got.Reason.Details)
	}
	if got.SourceRef == nil {
		t.Fatalf("source_ref is nil")
	}
	if len(got.Reason.SourceRefIDs) != 1 || got.Reason.SourceRefIDs[0] != got.SourceRef.ID {
		t.Fatalf("source_ref_ids = %#v, want %q", got.Reason.SourceRefIDs, got.SourceRef.ID)
	}
}

func assertNoDuplicateNPMSourceRefs(t *testing.T, evidence []schema.Evidence) {
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
			if sourceRef.Source != npmSourceName {
				t.Fatalf("source_ref source = %q, want %q", sourceRef.Source, npmSourceName)
			}
		}
	}
}

func assertNPMEvidenceScoresAs(t *testing.T, name, version string, evidence []schema.Evidence, wantDecision schema.Decision) {
	t.Helper()
	engine, err := score.NewEngine(score.Options{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("NewEngine returned error: %v", err)
	}
	verdict, err := engine.Evaluate(schema.Request{
		Package: schema.PackageIdentity{
			Ecosystem: "npm",
			Name:      name,
			Version:   version,
			PURL:      "pkg:npm/" + name + "@" + version,
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

func mustNPMAdapter(t *testing.T) NPMAdapter {
	t.Helper()
	adapter, err := NewNPMAdapter(NPMOptions{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("NewNPMAdapter returned error: %v", err)
	}
	return adapter
}
