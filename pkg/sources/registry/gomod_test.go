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

func TestGoModuleAdapterEvidenceFromJSONNormalizesVersionListAndGoModRequirements(t *testing.T) {
	adapter := mustGoModuleAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"module_path": "github.com/attach-dev/synthetic-go",
		"version": "v1.2.3",
		"time": "2026-05-01T00:00:00Z",
		"version_list": "v1.2.2\nv1.2.3\n",
		"go_mod": "module github.com/attach-dev/synthetic-go\n\ngo 1.22\n\nrequire (\n\tgithub.com/attach-dev/synthetic-dep v0.1.0\n\tgolang.org/x/mod v0.17.0 // indirect\n)\n"
	}`), Coordinate{Ecosystem: "go", Name: "github.com/attach-dev/synthetic-go", Version: "v1.2.3"})
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
	if got.SourceRef.Source != goModuleSourceName || got.SourceRef.SourceID != "proxy.golang.org/github.com/attach-dev/synthetic-go@v1.2.3" {
		t.Fatalf("source ref source/source_id = %q/%q", got.SourceRef.Source, got.SourceRef.SourceID)
	}
	if got.SourceRef.URL != "https://proxy.golang.org/github.com/attach-dev/synthetic-go/@v/v1.2.3.info" {
		t.Fatalf("source ref url = %q", got.SourceRef.URL)
	}
	if got.SourceRef.RetrievedAt != fixedNow.Format(time.RFC3339) {
		t.Fatalf("retrieved_at = %q, want fixed clock", got.SourceRef.RetrievedAt)
	}
	if got.SourceRef.TTLSeconds != DefaultTTLSeconds {
		t.Fatalf("ttl_seconds = %d, want %d", got.SourceRef.TTLSeconds, DefaultTTLSeconds)
	}
	if got.SourceRef.LicenseOrTermsURL != goModuleTermsURL {
		t.Fatalf("terms url = %q, want %q", got.SourceRef.LicenseOrTermsURL, goModuleTermsURL)
	}
	if !strings.Contains(got.SourceRef.Attribution, "Go module services") || !strings.Contains(got.SourceRef.Attribution, "proxy.golang.org") {
		t.Fatalf("attribution = %q, want Go module services attribution", got.SourceRef.Attribution)
	}
	if !got.SourceRef.AttributionRequired {
		t.Fatalf("attribution_required = false, want true")
	}
	if got.SourceRef.Redistribution != sources.RedistributionUnknown || got.SourceRef.PublicDisplay != sources.PublicDisplayAllowed {
		t.Fatalf("redistribution/public_display = %q/%q, want unknown/allowed", got.SourceRef.Redistribution, got.SourceRef.PublicDisplay)
	}
	if len(got.Reason.SourceRefIDs) != 4 || got.Reason.SourceRefIDs[0] != got.SourceRef.ID {
		t.Fatalf("source_ref_ids = %#v, want version/list/go.mod refs without duplicates", got.Reason.SourceRefIDs)
	}

	details := got.Reason.Details
	if details["source"] != goModuleSourceName || details["ecosystem"] != "go" || details["module_path"] != "github.com/attach-dev/synthetic-go" || details["version"] != "v1.2.3" {
		t.Fatalf("coordinate details = %#v", details)
	}
	if details["purl"] != "pkg:golang/github.com/attach-dev/synthetic-go@v1.2.3" {
		t.Fatalf("purl = %#v", details["purl"])
	}
	if details["version_time"] != "2026-05-01T00:00:00Z" || details["selected_version_source"] != "requested_version" {
		t.Fatalf("version details = %#v", details)
	}
	versions, ok := details["versions"].([]string)
	if !ok || len(versions) != 2 || versions[0] != "v1.2.2" || versions[1] != "v1.2.3" {
		t.Fatalf("versions = %#v, want normalized version list", details["versions"])
	}
	if details["requirements_count"] != 2 || details["requirements_status"] != "reported_by_go_mod_redacted" || details["go_mod_status"] != "reported_by_go_module_services" {
		t.Fatalf("go.mod status details = %#v", details)
	}
	if _, ok := details["requirements"]; ok {
		t.Fatalf("requirements should redact exact module paths: %#v", details["requirements"])
	}
	if details["request_posture"] != goModuleRequestPosture || details["terms_url"] != goModuleTermsURL {
		t.Fatalf("posture details = %#v", details)
	}

	assertNoDuplicateGoModuleSourceRefs(t, evidence)
	assertGoModuleEvidenceScoresAs(t, "github.com/attach-dev/synthetic-go", "v1.2.3", evidence, schema.DecisionAsk)
}

func TestGoModuleAdapterEvidenceUsesInfoJSONAndArrayVersionList(t *testing.T) {
	adapter := mustGoModuleAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"Path": "google.golang.org/grpc",
		"Version": "v1.60.0",
		"Time": "2026-04-30T00:00:00Z",
		"versions": ["v1.59.0", "v1.60.0", "v1.60.0"]
	}`), Coordinate{Ecosystem: "go"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	got := evidence[0]
	if got.SourceRef == nil || got.SourceRef.SourceID != "proxy.golang.org/google.golang.org/grpc@v1.60.0" {
		t.Fatalf("source_ref = %#v, want selected version ref", got.SourceRef)
	}
	if got.Reason.Details["module_path"] != "google.golang.org/grpc" || got.Reason.Details["version"] != "v1.60.0" {
		t.Fatalf("details = %#v", got.Reason.Details)
	}
	versions, ok := got.Reason.Details["versions"].([]string)
	if !ok || len(versions) != 2 || versions[0] != "v1.59.0" || versions[1] != "v1.60.0" {
		t.Fatalf("versions = %#v, want deduped array version list", got.Reason.Details["versions"])
	}
	assertNoDuplicateGoModuleSourceRefs(t, evidence)
	assertGoModuleEvidenceScoresAs(t, "google.golang.org/grpc", "v1.60.0", evidence, schema.DecisionAsk)
}

func TestGoModuleAdapterEvidenceEmitsASKForDeprecationAndRetraction(t *testing.T) {
	adapter := mustGoModuleAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"module_path": "example.com/synthetic/retracted",
		"version": "v1.1.0",
		"time": "2026-05-02T00:00:00Z",
		"go_mod": "// Deprecated: use example.com/synthetic/replacement instead.\nmodule example.com/synthetic/retracted\n\ngo 1.22\n\nretract v1.1.0 // bad release\n"
	}`), Coordinate{Ecosystem: "go", Name: "example.com/synthetic/retracted", Version: "v1.1.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	if len(evidence) != 3 {
		t.Fatalf("evidence length = %d, want metadata plus deprecation and retraction evidence", len(evidence))
	}

	deprecated := evidence[1]
	if deprecated.Reason.Code != reasons.DeprecatedPackage || deprecated.Reason.DecisionEffect != schema.DecisionEffectAsk {
		t.Fatalf("deprecated reason = %#v", deprecated.Reason)
	}
	if deprecated.Reason.Details["deprecation_message"] != "use example.com/synthetic/replacement instead." {
		t.Fatalf("deprecated details = %#v", deprecated.Reason.Details)
	}

	retracted := evidence[2]
	if retracted.Reason.Code != reasons.PackageUnpublishedOrYanked || retracted.Reason.DecisionEffect != schema.DecisionEffectAsk {
		t.Fatalf("retraction reason = %#v", retracted.Reason)
	}
	if retracted.Reason.Details["retracted"] != true || retracted.Reason.Details["retraction_rationale"] != "bad release" {
		t.Fatalf("retraction details = %#v", retracted.Reason.Details)
	}
	if retracted.SourceRef == nil || len(retracted.Reason.SourceRefIDs) != 1 || retracted.Reason.SourceRefIDs[0] != retracted.SourceRef.ID {
		t.Fatalf("retraction source refs = %#v / %#v", retracted.Reason.SourceRefIDs, retracted.SourceRef)
	}
	assertNoDuplicateGoModuleSourceRefs(t, evidence)
	assertGoModuleEvidenceScoresAs(t, "example.com/synthetic/retracted", "v1.1.0", evidence, schema.DecisionAsk)
}

func TestGoModuleAdapterEvidenceRedactsSensitiveDeprecationAndRetractionText(t *testing.T) {
	adapter := mustGoModuleAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"module_path": "example.com/synthetic/sensitive-comment",
		"version": "v1.1.0",
		"go_mod": "// Deprecated: use github.com/acme/internal-api or git.company.internal/team/secret-module instead\nmodule example.com/synthetic/sensitive-comment\n\ngo 1.22\nretract v1.1.0 // see https://git.company.internal/team/secret-module?auth=redacted\n"
	}`), Coordinate{Ecosystem: "go", Name: "example.com/synthetic/sensitive-comment", Version: "v1.1.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	if len(evidence) != 3 {
		t.Fatalf("evidence length = %d, want metadata plus deprecation and retraction", len(evidence))
	}
	if evidence[1].Reason.Details["deprecation_message"] != "redacted publisher-provided module comment" {
		t.Fatalf("deprecation details = %#v", evidence[1].Reason.Details)
	}
	if evidence[2].Reason.Details["retraction_rationale"] != "redacted publisher-provided module comment" {
		t.Fatalf("retraction details = %#v", evidence[2].Reason.Details)
	}
	rendered := fmt.Sprintf("%#v", evidence)
	for _, sensitive := range []string{"git.company.internal", "secret-module", "internal-api", "?auth="} {
		if strings.Contains(rendered, sensitive) {
			t.Fatalf("evidence leaked sensitive publisher text material %q: %s", sensitive, rendered)
		}
	}
}

func TestGoModuleAdapterEvidenceReportsSourceUnavailableForMalformedJSON(t *testing.T) {
	adapter := mustGoModuleAdapter(t)
	tests := map[string]string{
		"malformed":     `{"module_path":`,
		"trailing data": `{"module_path":"example.com/synthetic/broken","version":"v1.0.0"} {}`,
		"array":         `[{"module_path":"example.com/synthetic/broken"}]`,
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			evidence, err := adapter.EvidenceFromJSON([]byte(payload), Coordinate{Ecosystem: "go", Name: "example.com/synthetic/broken", Version: "v1.0.0"})
			if err != nil {
				t.Fatalf("EvidenceFromJSON returned error: %v", err)
			}
			assertGoModuleSourceUnavailable(t, evidence, "parse_failure")
			if evidence[0].SourceRef == nil || !strings.HasPrefix(evidence[0].SourceRef.ID, "go-module-services-json-") {
				t.Fatalf("source_ref = %#v, want local JSON source ref", evidence[0].SourceRef)
			}
			if _, ok := evidence[0].Reason.Details["parse_error"].(string); !ok {
				t.Fatalf("parse_error detail missing from %#v", evidence[0].Reason.Details)
			}
		})
	}
}

func TestGoModuleAdapterEvidenceReportsSourceUnavailableForConflictingVersionMetadata(t *testing.T) {
	adapter := mustGoModuleAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"module_path": "github.com/attach-dev/synthetic-go",
		"Version": "v2.0.0",
		"version": "v2.0.0",
		"time": "2026-05-03T00:00:00Z"
	}`), Coordinate{Ecosystem: "go", Name: "github.com/attach-dev/synthetic-go", Version: "v1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	assertGoModuleSourceUnavailable(t, evidence, "conflicting_required_data")
	conflicts, ok := evidence[0].Reason.Details["conflicting_fields"].([]string)
	if !ok || len(conflicts) != 2 || conflicts[0] != "metadata.Version" || conflicts[1] != "metadata.version" {
		t.Fatalf("conflicting_fields = %#v", evidence[0].Reason.Details["conflicting_fields"])
	}
}

func TestGoModuleAdapterEvidenceReportsSourceUnavailableForUnrepresentedRequestedVersion(t *testing.T) {
	adapter := mustGoModuleAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"module_path": "github.com/attach-dev/synthetic-go",
		"time": "2026-05-03T00:00:00Z"
	}`), Coordinate{Ecosystem: "go", Name: "github.com/attach-dev/synthetic-go", Version: "v1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	assertGoModuleSourceUnavailable(t, evidence, "conflicting_required_data")
	conflicts, ok := evidence[0].Reason.Details["conflicting_fields"].([]string)
	if !ok || len(conflicts) != 1 || conflicts[0] != "coordinate.version" {
		t.Fatalf("conflicting_fields = %#v", evidence[0].Reason.Details["conflicting_fields"])
	}
	rendered := fmt.Sprintf("%#v", evidence)
	if strings.Contains(rendered, "/@v/v1.0.0.info") {
		t.Fatalf("evidence emitted represented-version source ref for unrepresented coordinate: %s", rendered)
	}
}

func TestGoModuleAdapterEvidenceRejectsPrivateLookingModulePathsWithoutLeakingThem(t *testing.T) {
	adapter := mustGoModuleAdapter(t)
	for _, modulePath := range []string{"git.company.internal/team/secret-module", "internal.example.com/module"} {
		t.Run(modulePath, func(t *testing.T) {
			evidence, err := adapter.EvidenceFromJSON([]byte(fmt.Sprintf(`{
				"module_path": %q,
				"version": "v0.0.1",
				"time": "2026-05-03T00:00:00Z"
			}`, modulePath)), Coordinate{Ecosystem: "go", Name: modulePath, Version: "v0.0.1"})
			if err != nil {
				t.Fatalf("EvidenceFromJSON returned error: %v", err)
			}
			assertGoModuleSourceUnavailable(t, evidence, "private_module_path")
			if evidence[0].SourceRef == nil {
				t.Fatalf("source_ref is nil")
			}
			if strings.Contains(evidence[0].SourceRef.SourceID, "company") || strings.Contains(evidence[0].SourceRef.URL, "company") || strings.Contains(evidence[0].SourceRef.SourceID, "internal.example") || strings.Contains(evidence[0].SourceRef.URL, "internal.example") {
				t.Fatalf("source_ref leaked private module path: %#v", evidence[0].SourceRef)
			}
			rendered := fmt.Sprintf("%#v", evidence)
			for _, sensitive := range []string{"git.company.internal", "secret-module", "team/secret", "private-api", "internal.example.com"} {
				if strings.Contains(rendered, sensitive) {
					t.Fatalf("evidence leaked private module path material %q: %s", sensitive, rendered)
				}
			}
		})
	}
}

func TestGoModuleAdapterEvidenceDoesNotLeakSensitiveSourceURLs(t *testing.T) {
	adapter := mustGoModuleAdapter(t)
	sourceURL := "https://" + "user" + ":" + "redacted" + "@" + "proxy.golang.org/github.com/attach-dev/sensitive-go/@v/v1.0.0.info" + "?auth=" + "redacted" + "#fragment"
	evidence, err := adapter.EvidenceFromJSON([]byte(fmt.Sprintf(`{
		"module_path": "github.com/attach-dev/sensitive-go",
		"version": "v1.0.0",
		"time": "2026-05-04T00:00:00Z",
		"source_url": %q
	}`, sourceURL)), Coordinate{Ecosystem: "go", Name: "github.com/attach-dev/sensitive-go", Version: "v1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	got := evidence[0]
	if got.SourceRef == nil || got.SourceRef.URL != "https://proxy.golang.org/github.com/attach-dev/sensitive-go/@v/v1.0.0.info" {
		t.Fatalf("source ref url = %#v, want sanitized fallback", got.SourceRef)
	}
	if got.Reason.Details["source_url_status"] != "fallback_sanitized" {
		t.Fatalf("source_url_status = %#v, want fallback_sanitized", got.Reason.Details["source_url_status"])
	}
	rendered := fmt.Sprintf("%#v", evidence)
	for _, sensitive := range []string{"redacted", "?auth=", "@proxy.golang.org", "#fragment"} {
		if strings.Contains(rendered, sensitive) {
			t.Fatalf("evidence leaked sensitive source URL material %q: %s", sensitive, rendered)
		}
	}
	assertNoDuplicateGoModuleSourceRefs(t, evidence)
	assertGoModuleEvidenceScoresAs(t, "github.com/attach-dev/sensitive-go", "v1.0.0", evidence, schema.DecisionAsk)
}

func TestGoModuleAdapterEvidenceDoesNotLeakPrivateRequirementsOrMismatchedSourceURLPath(t *testing.T) {
	adapter := mustGoModuleAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"module_path": "github.com/attach-dev/public-go",
		"version": "v1.0.0",
		"source_url": "https://proxy.golang.org/git.company.internal/team/secret-module/@v/v0.0.1.info",
		"go_mod": "module github.com/attach-dev/public-go\n\ngo 1.22\nrequire (\n\tgit.company.internal/team/secret-module v0.0.1\n\tgithub.com/acme/private-api v0.0.2\n\tgithub.com/attach-dev/public-dep v0.2.0\n)\n"
	}`), Coordinate{Ecosystem: "go", Name: "github.com/attach-dev/public-go", Version: "v1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	got := evidence[0]
	if got.SourceRef == nil || got.SourceRef.URL != "https://proxy.golang.org/github.com/attach-dev/public-go/@v/v1.0.0.info" {
		t.Fatalf("source ref url = %#v, want canonical fallback", got.SourceRef)
	}
	if got.Reason.Details["source_url_status"] != "fallback_sanitized" {
		t.Fatalf("source_url_status = %#v, want fallback_sanitized", got.Reason.Details["source_url_status"])
	}
	if got.Reason.Details["requirements_count"] != 1 || got.Reason.Details["requirements_status"] != "reported_by_go_mod_redacted" {
		t.Fatalf("requirements status = %#v, want redacted public requirement count", got.Reason.Details)
	}
	if _, ok := got.Reason.Details["requirements"]; ok {
		t.Fatalf("requirements should not expose exact module paths: %#v", got.Reason.Details["requirements"])
	}
	rendered := fmt.Sprintf("%#v", evidence)
	for _, sensitive := range []string{"git.company.internal", "secret-module", "team/secret", "private-api"} {
		if strings.Contains(rendered, sensitive) {
			t.Fatalf("evidence leaked private requirement/source URL material %q: %s", sensitive, rendered)
		}
	}
}

func TestGoModuleAdapterEvidenceDetectsRetractionRangesAndEscapesUppercaseProxyPaths(t *testing.T) {
	adapter := mustGoModuleAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"module_path": "github.com/Azure/SyntheticGo",
		"version": "v1.0.0-rc.2",
		"go_mod": "module github.com/Azure/SyntheticGo\n\ngo 1.22\nretract [v1.0.0-rc.1, v1.0.0] // bad range\n"
	}`), Coordinate{Ecosystem: "go", Name: "github.com/Azure/SyntheticGo", Version: "v1.0.0-rc.2"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	if len(evidence) != 2 {
		t.Fatalf("evidence length = %d, want metadata plus range retraction", len(evidence))
	}
	if evidence[0].SourceRef == nil || evidence[0].SourceRef.URL != "https://proxy.golang.org/github.com/!azure/!synthetic!go/@v/v1.0.0-rc.2.info" {
		t.Fatalf("source ref url = %#v, want Go proxy uppercase escaping", evidence[0].SourceRef)
	}
	retracted := evidence[1]
	if retracted.Reason.Code != reasons.PackageUnpublishedOrYanked || retracted.Reason.DecisionEffect != schema.DecisionEffectAsk {
		t.Fatalf("retraction reason = %#v", retracted.Reason)
	}
	if retracted.Reason.Details["retraction_rationale"] != "bad range" {
		t.Fatalf("retraction details = %#v", retracted.Reason.Details)
	}
}

func TestGoModuleAdapterEvidenceDeduplicatesSourceRefsAndSourceRefIDs(t *testing.T) {
	adapter := mustGoModuleAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"module_path": "example.com/synthetic/dedupe",
		"version": "v1.0.0",
		"time": "2026-05-05T00:00:00Z",
		"versions": ["v1.0.0", "v1.0.0"],
		"version_list": "v1.0.0\nv1.0.0\n",
		"go_mod": "module example.com/synthetic/dedupe\n\ngo 1.22\nrequire example.com/synthetic/dep v0.1.0\n"
	}`), Coordinate{Ecosystem: "go", Name: "example.com/synthetic/dedupe", Version: "v1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	assertNoDuplicateGoModuleSourceRefs(t, evidence)
	if len(evidence[0].Reason.SourceRefIDs) != 4 {
		t.Fatalf("source_ref_ids = %#v, want version/module/list/go.mod refs", evidence[0].Reason.SourceRefIDs)
	}
	if len(evidence[0].SourceRefs) != 3 {
		t.Fatalf("source_refs length = %d, want three secondary refs", len(evidence[0].SourceRefs))
	}
	versions, ok := evidence[0].Reason.Details["versions"].([]string)
	if !ok || len(versions) != 1 || versions[0] != "v1.0.0" {
		t.Fatalf("versions = %#v, want deduped version detail", evidence[0].Reason.Details["versions"])
	}
}

func assertGoModuleSourceUnavailable(t *testing.T, evidence []schema.Evidence, failureKind string) {
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
	if got.Reason.Details["source"] != goModuleSourceName || got.Reason.Details["failure_kind"] != failureKind {
		t.Fatalf("source unavailable details = %#v", got.Reason.Details)
	}
	if got.SourceRef == nil {
		t.Fatalf("source_ref is nil")
	}
	if len(got.Reason.SourceRefIDs) != 1 || got.Reason.SourceRefIDs[0] != got.SourceRef.ID {
		t.Fatalf("source_ref_ids = %#v, want %q", got.Reason.SourceRefIDs, got.SourceRef.ID)
	}
}

func assertNoDuplicateGoModuleSourceRefs(t *testing.T, evidence []schema.Evidence) {
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
			if item.SourceRef.Source != goModuleSourceName {
				t.Fatalf("primary source_ref source = %q, want %q", item.SourceRef.Source, goModuleSourceName)
			}
		}
		for _, sourceRef := range item.SourceRefs {
			if _, ok := seenRefs[sourceRef.ID]; ok {
				t.Fatalf("duplicate source_ref %q in %#v", sourceRef.ID, item.SourceRefs)
			}
			seenRefs[sourceRef.ID] = struct{}{}
			if sourceRef.Source != goModuleSourceName {
				t.Fatalf("source_ref source = %q, want %q", sourceRef.Source, goModuleSourceName)
			}
		}
	}
}

func assertGoModuleEvidenceScoresAs(t *testing.T, name, version string, evidence []schema.Evidence, wantDecision schema.Decision) {
	t.Helper()
	engine, err := score.NewEngine(score.Options{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("NewEngine returned error: %v", err)
	}
	verdict, err := engine.Evaluate(schema.Request{
		Package: schema.PackageIdentity{
			Ecosystem: "go",
			Name:      name,
			Version:   version,
			PURL:      "pkg:golang/" + name + "@" + version,
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

func mustGoModuleAdapter(t *testing.T) GoModuleAdapter {
	t.Helper()
	adapter, err := NewGoModuleAdapter(GoModuleOptions{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("NewGoModuleAdapter returned error: %v", err)
	}
	return adapter
}
