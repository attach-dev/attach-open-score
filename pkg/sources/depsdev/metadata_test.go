package depsdev

import (
	"strings"
	"testing"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/score"
	"github.com/attach-dev/attach-open-score/pkg/sources"
)

var fixedNow = time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)

func TestAdapterEvidenceFromJSONNormalizesPackageVersionMetadata(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"package": {
			"packageKey": {"system": "NPM", "name": "left-pad"},
			"description": "Synthetic deps.dev package metadata.",
			"versions": [
				{"versionKey": {"system": "NPM", "name": "left-pad", "version": "1.2.0"}},
				{"versionKey": {"system": "NPM", "name": "left-pad", "version": "1.3.0"}, "isDefault": true}
			]
		},
		"version": {
			"versionKey": {"system": "NPM", "name": "left-pad", "version": "1.3.0"},
			"publishedAt": "2026-05-01T00:00:00Z",
			"isDefault": true
		}
	}`))
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
	if got.SourceRef.Source != SourceName || got.SourceRef.SourceID != "NPM:left-pad@1.3.0" {
		t.Fatalf("source ref source/source_id = %q/%q", got.SourceRef.Source, got.SourceRef.SourceID)
	}
	if got.SourceRef.URL != "https://api.deps.dev/v3/systems/NPM/packages/left-pad/versions/1.3.0" {
		t.Fatalf("source ref url = %q", got.SourceRef.URL)
	}
	if len(got.Reason.SourceRefIDs) != 2 || got.Reason.SourceRefIDs[0] != got.SourceRef.ID {
		t.Fatalf("source_ref_ids = %#v, want version and package refs", got.Reason.SourceRefIDs)
	}
	if len(got.SourceRefs) != 1 || got.SourceRefs[0].SourceID != "NPM:left-pad" {
		t.Fatalf("source_refs = %#v, want package ref", got.SourceRefs)
	}
	if got.Reason.Details["ecosystem"] != "npm" || got.Reason.Details["depsdev_system"] != "NPM" || got.Reason.Details["package_name"] != "left-pad" || got.Reason.Details["version"] != "1.3.0" {
		t.Fatalf("coordinate details = %#v", got.Reason.Details)
	}
	if got.Reason.Details["purl"] != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("purl = %#v", got.Reason.Details["purl"])
	}
	if got.Reason.Details["published_at"] != "2026-05-01T00:00:00Z" || got.Reason.Details["is_default"] != true {
		t.Fatalf("version details = %#v", got.Reason.Details)
	}
	versions, ok := got.Reason.Details["package_versions"].([]map[string]any)
	if !ok || len(versions) != 2 {
		t.Fatalf("package_versions = %#v, want two normalized versions", got.Reason.Details["package_versions"])
	}

	assertEvidenceScoresAs(t, "npm", "left-pad", "1.3.0", evidence, schema.DecisionAsk)
}

func TestAdapterEvidenceEscapesScopedAndSlashContainingCoordinates(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})

	npmEvidence, err := adapter.Evidence(Metadata{
		Version: Version{VersionKey: VersionKey{System: "NPM", Name: "@scope/pkg", Version: "1.0.0-beta.1"}},
	})
	if err != nil {
		t.Fatalf("npm Evidence returned error: %v", err)
	}
	if got := npmEvidence[0].SourceRef.URL; got != "https://api.deps.dev/v3/systems/NPM/packages/%40scope%2Fpkg/versions/1.0.0-beta.1" {
		t.Fatalf("scoped npm source ref URL = %q", got)
	}
	if got := npmEvidence[0].Reason.Details["purl"]; got != "pkg:npm/%40scope/pkg@1.0.0-beta.1" {
		t.Fatalf("scoped npm purl = %#v", got)
	}
	assertEvidenceScoresAs(t, "npm", "@scope/pkg", "1.0.0-beta.1", npmEvidence, schema.DecisionAsk)

	goEvidence, err := adapter.Evidence(Metadata{
		Version: Version{VersionKey: VersionKey{System: "GO", Name: "google.golang.org/grpc", Version: "v1.60.0"}},
	})
	if err != nil {
		t.Fatalf("go Evidence returned error: %v", err)
	}
	if got := goEvidence[0].SourceRef.URL; got != "https://api.deps.dev/v3/systems/GO/packages/google.golang.org%2Fgrpc/versions/v1.60.0" {
		t.Fatalf("go source ref URL = %q", got)
	}
	if got := goEvidence[0].Reason.Details["purl"]; got != "pkg:golang/google.golang.org/grpc@v1.60.0" {
		t.Fatalf("go purl = %#v", got)
	}
	assertEvidenceScoresAs(t, "go", "google.golang.org/grpc", "v1.60.0", goEvidence, schema.DecisionAsk)
}

func TestAdapterEvidenceIncludesDependenciesLicensesAndRepositoryLinks(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})
	evidence, err := adapter.Evidence(Metadata{
		Version: Version{
			VersionKey:  VersionKey{System: "PYPI", Name: "demo-pkg", Version: "2.0.0"},
			PublishedAt: "2026-04-30T00:00:00Z",
			Licenses:    Licenses{"MIT", "Apache-2.0", "MIT"},
			Links: []Link{
				{Label: "SOURCE_REPO", URL: "https://github.com/example/demo-pkg"},
				{Label: "SOURCE_REPO", URL: "https://github.com/example/demo-pkg"},
			},
			Dependencies: []Dependency{
				{PackageKey: PackageKey{System: "PYPI", Name: "requests"}, Requirement: ">=2.0.0", Relation: "DIRECT"},
			},
		},
		DependencyGraph: DependencyGraph{
			Nodes: []DependencyNode{
				{VersionKey: VersionKey{System: "PYPI", Name: "demo-pkg", Version: "2.0.0"}, Relation: "SELF"},
				{VersionKey: VersionKey{System: "PYPI", Name: "urllib3", Version: "2.2.0"}, Relation: "INDIRECT"},
			},
			Edges: []DependencyEdge{{FromNode: 0, ToNode: 1, Requirement: ">=2.0.0"}},
		},
	})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	got := evidence[0]
	if got.Reason.Code != reasons.RepositoryMappingUncertain || got.Reason.DecisionEffect != schema.DecisionEffectUnknown {
		t.Fatalf("reason = %#v, want non-authoritative metadata evidence", got.Reason)
	}

	licenses, ok := got.Reason.Details["licenses"].([]string)
	if !ok || len(licenses) != 2 || licenses[0] != "MIT" || licenses[1] != "Apache-2.0" {
		t.Fatalf("licenses = %#v, want deduped license list", got.Reason.Details["licenses"])
	}
	dependencies, ok := got.Reason.Details["dependencies"].([]map[string]string)
	if !ok || len(dependencies) != 2 {
		t.Fatalf("dependencies = %#v, want direct and graph dependencies", got.Reason.Details["dependencies"])
	}
	if got.Reason.Details["dependency_count"] != 2 || got.Reason.Details["dependency_metadata_status"] != "reported_by_deps_dev" {
		t.Fatalf("dependency status details = %#v", got.Reason.Details)
	}
	repositoryLinks, ok := got.Reason.Details["repository_links"].([]map[string]string)
	if !ok || len(repositoryLinks) != 1 || repositoryLinks[0]["url"] != "https://github.com/example/demo-pkg" {
		t.Fatalf("repository_links = %#v, want one deduped repo link", got.Reason.Details["repository_links"])
	}
	if got.Reason.Details["repository_mapping_status"] != "reported_by_deps_dev" {
		t.Fatalf("repository_mapping_status = %#v", got.Reason.Details["repository_mapping_status"])
	}
	if len(got.Reason.SourceRefIDs) != 4 {
		t.Fatalf("source_ref_ids = %#v, want version/package/dependencies/repo refs", got.Reason.SourceRefIDs)
	}
	assertNoDuplicateSourceRefs(t, evidence)
	assertEvidenceScoresAs(t, "pypi", "demo-pkg", "2.0.0", evidence, schema.DecisionAsk)
}

func TestAdapterEvidenceMissingAndAmbiguousOptionalFieldsAreNonAuthoritative(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})

	t.Run("missing optional fields", func(t *testing.T) {
		evidence, err := adapter.Evidence(Metadata{
			Version: Version{VersionKey: VersionKey{System: "NPM", Name: "left-pad", Version: "1.3.0"}},
		})
		if err != nil {
			t.Fatalf("Evidence returned error: %v", err)
		}
		got := evidence[0]
		if got.Reason.Code != reasons.RepositoryMappingUncertain || got.Reason.Severity != "MEDIUM" || got.Reason.DecisionEffect != schema.DecisionEffectUnknown {
			t.Fatalf("reason = %#v, want non-authoritative metadata evidence", got.Reason)
		}
		if got.Reason.Details["repository_mapping_status"] != "not_reported" || got.Reason.Details["license_metadata_status"] != "not_reported" || got.Reason.Details["dependency_metadata_status"] != "not_reported" {
			t.Fatalf("optional metadata status details = %#v", got.Reason.Details)
		}
		assertEvidenceScoresAs(t, "npm", "left-pad", "1.3.0", evidence, schema.DecisionAsk)
	})

	t.Run("ambiguous repository links", func(t *testing.T) {
		evidence, err := adapter.Evidence(Metadata{
			Version: Version{
				VersionKey: VersionKey{System: "NPM", Name: "left-pad", Version: "1.3.0"},
				Links: []Link{
					{Label: "SOURCE_REPO", URL: "https://github.com/example/left-pad"},
					{Label: "SOURCE_REPO", URL: "https://gitlab.com/example/left-pad"},
				},
			},
		})
		if err != nil {
			t.Fatalf("Evidence returned error: %v", err)
		}
		got := evidence[0]
		if got.Reason.Code != reasons.RepositoryMappingUncertain || got.Reason.DecisionEffect != schema.DecisionEffectUnknown {
			t.Fatalf("reason = %#v, want non-authoritative evidence for ambiguous optional data", got.Reason)
		}
		if got.Reason.Details["repository_mapping_status"] != "ambiguous" {
			t.Fatalf("repository_mapping_status = %#v, want ambiguous", got.Reason.Details["repository_mapping_status"])
		}
		assertEvidenceScoresAs(t, "npm", "left-pad", "1.3.0", evidence, schema.DecisionAsk)
	})
}

func TestAdapterEvidenceReportsSourceUnavailableForMissingRequiredLocalData(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})
	evidence, err := adapter.Evidence(Metadata{
		Package: Package{PackageKey: PackageKey{System: "NPM", Name: "left-pad"}},
	})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}

	assertSourceUnavailable(t, evidence, "missing_required_data")
	missing, ok := evidence[0].Reason.Details["missing_fields"].([]string)
	if !ok || len(missing) != 1 || missing[0] != "version" {
		t.Fatalf("missing_fields = %#v, want version", evidence[0].Reason.Details["missing_fields"])
	}
	assertEvidenceScoresAs(t, "npm", "left-pad", "1.3.0", evidence, schema.DecisionAsk)
}

func TestAdapterEvidenceReportsSourceUnavailableForConflictingRequiredLocalData(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})
	evidence, err := adapter.Evidence(Metadata{
		Package: Package{PackageKey: PackageKey{System: "NPM", Name: "left-pad"}},
		Version: Version{VersionKey: VersionKey{System: "NPM", Name: "right-pad", Version: "1.3.0"}},
	})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}

	assertSourceUnavailable(t, evidence, "conflicting_required_data")
	conflicts, ok := evidence[0].Reason.Details["conflicting_fields"].([]string)
	if !ok || len(conflicts) != 1 || conflicts[0] != "version.versionKey.name" {
		t.Fatalf("conflicting_fields = %#v, want version.versionKey.name", evidence[0].Reason.Details["conflicting_fields"])
	}
	assertEvidenceScoresAs(t, "npm", "left-pad", "1.3.0", evidence, schema.DecisionAsk)
}

func TestAdapterEvidenceDeduplicatesSourceRefsAndSourceRefIDs(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})
	evidence, err := adapter.Evidence(Metadata{
		Package: Package{
			PackageKey: PackageKey{System: "NPM", Name: "left-pad"},
			Links: []Link{
				{Label: "SOURCE_REPO", URL: "https://github.com/example/left-pad"},
				{Label: "SOURCE_REPO", URL: "https://github.com/example/left-pad"},
			},
		},
		Version: Version{
			VersionKey: VersionKey{System: "NPM", Name: "left-pad", Version: "1.3.0"},
			Links: []Link{
				{Type: "repository", URL: "https://github.com/example/left-pad"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}

	got := evidence[0]
	if len(got.SourceRefs) != 2 {
		t.Fatalf("source_refs length = %d, want package ref plus one repository ref", len(got.SourceRefs))
	}
	if len(got.Reason.SourceRefIDs) != 3 {
		t.Fatalf("source_ref_ids = %#v, want deduped version/package/repository ids", got.Reason.SourceRefIDs)
	}
	assertNoDuplicateSourceRefs(t, evidence)
	assertEvidenceScoresAs(t, "npm", "left-pad", "1.3.0", evidence, schema.DecisionAsk)
}

func TestAdapterEvidenceFromJSONReportsParseFailure(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})
	evidence, err := adapter.EvidenceFromJSON([]byte(`{"versionKey":`))
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	assertSourceUnavailable(t, evidence, "parse_failure")
	if _, ok := evidence[0].Reason.Details["parse_error"].(string); !ok {
		t.Fatalf("parse_error detail missing from %#v", evidence[0].Reason.Details)
	}
	if evidence[0].SourceRef == nil || !strings.HasPrefix(evidence[0].SourceRef.ID, "depsdev-json-") {
		t.Fatalf("source_ref = %#v, want local JSON source ref", evidence[0].SourceRef)
	}
	assertEvidenceScoresAs(t, "npm", "left-pad", "1.3.0", evidence, schema.DecisionAsk)
}

func TestAdapterEvidenceSourceRefAttributionFields(t *testing.T) {
	adapter := mustNewAdapter(t, Options{Now: fixedClock})
	evidence, err := adapter.Evidence(Metadata{
		Version: Version{VersionKey: VersionKey{System: "NPM", Name: "left-pad", Version: "1.3.0"}},
	})
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
	for _, want := range []string{"deps.dev", "Open Source Insights", "Google", "CC-BY-4.0"} {
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
	seenIDs := map[string]struct{}{}
	for _, item := range evidence {
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
		}
	}
}

func assertEvidenceScoresAs(t *testing.T, ecosystem, name, version string, evidence []schema.Evidence, wantDecision schema.Decision) {
	t.Helper()

	engine, err := score.NewEngine(score.Options{Now: fixedClock})
	if err != nil {
		t.Fatalf("NewEngine returned error: %v", err)
	}
	verdict, err := engine.Evaluate(schema.Request{
		Package: schema.PackageIdentity{
			Ecosystem: ecosystem,
			Name:      name,
			Version:   version,
			PURL:      "pkg:" + ecosystem + "/" + name + "@" + version,
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
