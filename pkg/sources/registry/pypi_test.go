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

func TestPyPIAdapterEvidenceFromPackageJSONNormalizesReleaseFiles(t *testing.T) {
	adapter := mustPyPIAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"info": {
			"name": "synthetic-pypi",
			"version": "1.2.0",
			"license": "Apache-2.0",
			"requires_python": ">=3.9",
			"project_urls": {
				"Homepage": "https://example.invalid/synthetic-pypi",
				"Source": "https://github.com/attach-dev/synthetic-pypi"
			}
		},
		"last_serial": 1234567,
		"releases": {
			"1.2.0": [
				{
					"filename": "synthetic_pypi-1.2.0-py3-none-any.whl",
					"packagetype": "bdist_wheel",
					"python_version": "py3",
					"requires_python": ">=3.9",
					"upload_time_iso_8601": "2026-05-01T00:00:00.000Z",
					"url": "https://files.pythonhosted.org/packages/synthetic/synthetic_pypi-1.2.0-py3-none-any.whl",
					"digests": {
						"sha256": "1111111111111111111111111111111111111111111111111111111111111111",
						"blake2b_256": "2222222222222222222222222222222222222222222222222222222222222222"
					},
					"yanked": false
				}
			]
		}
	}`), Coordinate{Ecosystem: "pypi", Name: "synthetic-pypi", Version: "1.2.0"})
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
	if got.SourceRef.Source != pypiSourceName || got.SourceRef.SourceID != "pypi.org/pypi/synthetic-pypi/1.2.0" {
		t.Fatalf("source ref source/source_id = %q/%q", got.SourceRef.Source, got.SourceRef.SourceID)
	}
	if got.SourceRef.URL != "https://pypi.org/pypi/synthetic-pypi/1.2.0/json" {
		t.Fatalf("source ref url = %q", got.SourceRef.URL)
	}
	if got.SourceRef.RetrievedAt != fixedNow.Format(time.RFC3339) {
		t.Fatalf("retrieved_at = %q, want fixed clock", got.SourceRef.RetrievedAt)
	}
	if got.SourceRef.TTLSeconds != DefaultTTLSeconds {
		t.Fatalf("ttl_seconds = %d, want %d", got.SourceRef.TTLSeconds, DefaultTTLSeconds)
	}
	if got.SourceRef.LicenseOrTermsURL != pypiTermsURL {
		t.Fatalf("terms url = %q, want %q", got.SourceRef.LicenseOrTermsURL, pypiTermsURL)
	}
	if !strings.Contains(got.SourceRef.Attribution, "PyPI") || !strings.Contains(got.SourceRef.Attribution, "pypi.org") {
		t.Fatalf("attribution = %q, want PyPI attribution", got.SourceRef.Attribution)
	}
	if !got.SourceRef.AttributionRequired {
		t.Fatalf("attribution_required = false, want true")
	}
	if got.SourceRef.Redistribution != sources.RedistributionUnknown || got.SourceRef.PublicDisplay != sources.PublicDisplayAllowed {
		t.Fatalf("redistribution/public_display = %q/%q, want unknown/allowed", got.SourceRef.Redistribution, got.SourceRef.PublicDisplay)
	}

	details := got.Reason.Details
	if details["source"] != pypiSourceName || details["ecosystem"] != "pypi" || details["package_name"] != "synthetic-pypi" || details["version"] != "1.2.0" {
		t.Fatalf("coordinate details = %#v", details)
	}
	if details["purl"] != "pkg:pypi/synthetic-pypi@1.2.0" {
		t.Fatalf("purl = %#v", details["purl"])
	}
	if details["selected_version_source"] != "requested_version" || details["metadata_format"] != "pypi_json" {
		t.Fatalf("format/version details = %#v", details)
	}
	if details["last_serial"] != float64(1234567) || details["serial_ttl_posture"] != "short_ttl_serial_or_etag_aware_refresh_recommended" {
		t.Fatalf("serial details = %#v", details)
	}
	if details["requires_python"] != ">=3.9" || details["requires_python_status"] != "reported_by_pypi" {
		t.Fatalf("requires_python details = %#v", details)
	}
	if details["license"] != "Apache-2.0" || details["license_metadata_status"] != "reported_by_pypi" {
		t.Fatalf("license details = %#v", details)
	}
	if details["repository_url"] != "https://github.com/attach-dev/synthetic-pypi" || details["repository_mapping_status"] != "reported_by_pypi_project_urls" {
		t.Fatalf("repository details = %#v", details)
	}
	if details["release_file_count"] != 1 || details["yanked_file_count"] != 0 {
		t.Fatalf("file count details = %#v", details)
	}
	files, ok := details["release_files"].([]map[string]any)
	if !ok || len(files) != 1 {
		t.Fatalf("release_files = %#v, want one file detail", details["release_files"])
	}
	if files[0]["filename"] != "synthetic_pypi-1.2.0-py3-none-any.whl" || files[0]["packagetype"] != "bdist_wheel" {
		t.Fatalf("file identity details = %#v", files[0])
	}
	if files[0]["sha256"] != "1111111111111111111111111111111111111111111111111111111111111111" || files[0]["blake2b_256"] != "2222222222222222222222222222222222222222222222222222222222222222" {
		t.Fatalf("digest details = %#v", files[0])
	}
	if files[0]["requires_python"] != ">=3.9" || files[0]["yanked"] != false {
		t.Fatalf("file metadata details = %#v", files[0])
	}
	projectURLs, ok := details["project_urls"].(map[string]string)
	if !ok || projectURLs["Homepage"] != "https://example.invalid/synthetic-pypi" || projectURLs["Source"] != "https://github.com/attach-dev/synthetic-pypi" {
		t.Fatalf("project_urls = %#v", details["project_urls"])
	}
	if details["request_posture"] != pypiRequestPosture || details["terms_url"] != pypiTermsURL {
		t.Fatalf("posture details = %#v", details)
	}

	assertNoDuplicatePyPISourceRefs(t, evidence)
	assertPyPIEvidenceScoresAs(t, "synthetic-pypi", "1.2.0", evidence, schema.DecisionAsk)
}

func TestPyPIAdapterEvidenceFromIndexJSONNormalizesActiveAndYankedFiles(t *testing.T) {
	adapter := mustPyPIAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"meta": {"api-version": "1.3"},
		"name": "index-demo",
		"versions": ["1.0.0", "1.1.0"],
		"files": [
			{
				"filename": "index_demo-1.1.0-py3-none-any.whl",
				"url": "https://files.pythonhosted.org/packages/synthetic/index_demo-1.1.0-py3-none-any.whl",
				"hashes": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
				"requires-python": ">=3.10",
				"upload-time": "2026-05-02T00:00:00Z",
				"yanked": false
			},
			{
				"filename": "index_demo-1.1.0.tar.gz",
				"url": "https://files.pythonhosted.org/packages/synthetic/index_demo-1.1.0.tar.gz",
				"hashes": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
				"requires-python": ">=3.10",
				"yanked": "bad metadata"
			}
		],
		"_last-serial": 7654321,
		"etag": "synthetic-etag"
	}`), Coordinate{Ecosystem: "pypi", Name: "index-demo", Version: "1.1.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	if len(evidence) != 2 {
		t.Fatalf("evidence length = %d, want metadata plus yanked evidence", len(evidence))
	}

	metadata := evidence[0]
	if metadata.Reason.Code != reasons.RepositoryMappingUncertain || metadata.Reason.DecisionEffect != schema.DecisionEffectUnknown {
		t.Fatalf("metadata reason = %#v, want non-authoritative metadata", metadata.Reason)
	}
	if metadata.Reason.Details["metadata_format"] != "pypi_index_json" || metadata.Reason.Details["index_api_version"] != "1.3" {
		t.Fatalf("index details = %#v", metadata.Reason.Details)
	}
	if metadata.Reason.Details["last_serial"] != float64(7654321) || metadata.Reason.Details["etag_present"] != true {
		t.Fatalf("serial/etag details = %#v", metadata.Reason.Details)
	}
	if metadata.Reason.Details["release_file_count"] != 2 || metadata.Reason.Details["yanked_file_count"] != 1 {
		t.Fatalf("file count details = %#v", metadata.Reason.Details)
	}
	files := metadata.Reason.Details["release_files"].([]map[string]any)
	if files[0]["filename"] != "index_demo-1.1.0-py3-none-any.whl" || files[1]["filename"] != "index_demo-1.1.0.tar.gz" {
		t.Fatalf("release_files order/details = %#v", files)
	}

	yanked := evidence[1]
	if yanked.Reason.Code != reasons.PackageUnpublishedOrYanked {
		t.Fatalf("yanked reason code = %s, want %s", yanked.Reason.Code, reasons.PackageUnpublishedOrYanked)
	}
	if yanked.Reason.Severity != "HIGH" || yanked.Reason.DecisionEffect != schema.DecisionEffectAsk {
		t.Fatalf("yanked severity/effect = %s/%s, want HIGH/ASK", yanked.Reason.Severity, yanked.Reason.DecisionEffect)
	}
	if yanked.Reason.Details["yanked_file_count"] != 1 || yanked.Reason.Details["yanked_reason"] != "bad metadata" {
		t.Fatalf("yanked details = %#v", yanked.Reason.Details)
	}
	assertNoDuplicatePyPISourceRefs(t, evidence)
	assertPyPIEvidenceScoresAs(t, "index-demo", "1.1.0", evidence, schema.DecisionAsk)
}

func TestPyPIAdapterIndexFileSelectionRequiresExactVersionBoundary(t *testing.T) {
	adapter := mustPyPIAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"meta": {"api-version": "1.3"},
		"name": "boundary-demo",
		"versions": ["1.0", "1.0.1"],
		"files": [
			{
				"filename": "boundary_demo-1.0-py3-none-any.whl",
				"hashes": {"sha256": "1111111111111111111111111111111111111111111111111111111111111111"},
				"yanked": false
			},
			{
				"filename": "boundary_demo_1.0-1.0.1-py3-none-any.whl",
				"hashes": {"sha256": "2222222222222222222222222222222222222222222222222222222222222222"},
				"requires-python": ">=3.12",
				"yanked": "wrong version"
			}
		]
	}`), Coordinate{Ecosystem: "pypi", Name: "boundary-demo", Version: "1.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	if len(evidence) != 1 {
		t.Fatalf("evidence length = %d, want only metadata for exact 1.0", len(evidence))
	}
	files := evidence[0].Reason.Details["release_files"].([]map[string]any)
	if len(files) != 1 || files[0]["filename"] != "boundary_demo-1.0-py3-none-any.whl" {
		t.Fatalf("release files = %#v, want only exact 1.0 file", files)
	}
	if evidence[0].Reason.Details["yanked_file_count"] != 0 {
		t.Fatalf("yanked count = %#v, want 0 for exact 1.0", evidence[0].Reason.Details["yanked_file_count"])
	}
}

func TestPyPIAdapterHomepageDoesNotBecomeRepositoryMapping(t *testing.T) {
	adapter := mustPyPIAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"info": {
			"name": "homepage-only",
			"version": "1.0.0",
			"home_page": "https://example.invalid/homepage-only",
			"project_urls": {"Homepage": "https://example.invalid/project-url-homepage"}
		},
		"releases": {
			"1.0.0": [{"filename": "homepage_only-1.0.0.tar.gz", "digests": {"sha256": "3333333333333333333333333333333333333333333333333333333333333333"}}]
		}
	}`), Coordinate{Ecosystem: "pypi", Name: "homepage-only", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	if evidence[0].Reason.Details["repository_url"] != nil {
		t.Fatalf("repository_url = %#v, want homepage to stay project URL only", evidence[0].Reason.Details["repository_url"])
	}
	if evidence[0].Reason.Details["repository_mapping_status"] != "not_reported" {
		t.Fatalf("repository status = %#v, want not_reported", evidence[0].Reason.Details["repository_mapping_status"])
	}
}

func TestPyPIAdapterRedactsSensitiveProjectURLLabels(t *testing.T) {
	adapter := mustPyPIAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"info": {
			"name": "sensitive-labels",
			"version": "1.0.0",
			"project_urls": {
				"maintainer@example.invalid token": "https://github.com/attach-dev/sensitive-labels",
				"Secret Dashboard": "https://example.invalid/dashboard"
			}
		},
		"releases": {
			"1.0.0": [{"filename": "sensitive_labels-1.0.0.tar.gz", "digests": {"sha256": "5555555555555555555555555555555555555555555555555555555555555555"}}]
		}
	}`), Coordinate{Ecosystem: "pypi", Name: "sensitive-labels", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	projectURLs, ok := evidence[0].Reason.Details["project_urls"].(map[string]string)
	if !ok || projectURLs["redacted-project-url-label"] == "" {
		t.Fatalf("project_urls = %#v, want redacted label", evidence[0].Reason.Details["project_urls"])
	}
	rendered := fmt.Sprintf("%#v", evidence)
	for _, sensitive := range []string{"maintainer@example.invalid", "Secret Dashboard"} {
		if strings.Contains(rendered, sensitive) {
			t.Fatalf("evidence leaked sensitive project_url label material %q: %s", sensitive, rendered)
		}
	}
}

func TestPyPIAdapterYankedReasonRedactsSensitivePublisherText(t *testing.T) {
	adapter := mustPyPIAdapter(t)
	sensitiveReason := "contact " + "person" + "@" + "example.invalid or see https://example.invalid/path?token=redacted#fragment"
	evidence, err := adapter.EvidenceFromJSON([]byte(fmt.Sprintf(`{
		"meta": {"api-version": "1.3"},
		"name": "sensitive-yank",
		"versions": ["1.0.0"],
		"files": [{
			"filename": "sensitive_yank-1.0.0-py3-none-any.whl",
			"hashes": {"sha256": "4444444444444444444444444444444444444444444444444444444444444444"},
			"yanked": %q
		}]
	}`, sensitiveReason)), Coordinate{Ecosystem: "pypi", Name: "sensitive-yank", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}
	if len(evidence) != 2 {
		t.Fatalf("evidence length = %d, want metadata plus yanked evidence", len(evidence))
	}
	if evidence[1].Reason.Details["yanked_reason"] != "redacted publisher-provided yanked reason" {
		t.Fatalf("yanked details = %#v", evidence[1].Reason.Details)
	}
	rendered := fmt.Sprintf("%#v", evidence)
	for _, sensitive := range []string{"person@example.invalid", "https://example.invalid", "?token=", "#fragment"} {
		if strings.Contains(rendered, sensitive) {
			t.Fatalf("evidence leaked sensitive yanked reason material %q: %s", sensitive, rendered)
		}
	}
}

func TestPyPIAdapterEvidenceReportsSourceUnavailableForMalformedInput(t *testing.T) {
	adapter := mustPyPIAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{"info":`), Coordinate{Ecosystem: "pypi", Name: "broken", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	assertPyPISourceUnavailable(t, evidence, "parse_failure")
	if evidence[0].SourceRef == nil || !strings.HasPrefix(evidence[0].SourceRef.ID, "pypi-registry-json-") {
		t.Fatalf("source_ref = %#v, want local JSON source ref", evidence[0].SourceRef)
	}
	if _, ok := evidence[0].Reason.Details["parse_error"].(string); !ok {
		t.Fatalf("parse_error detail missing from %#v", evidence[0].Reason.Details)
	}
	assertPyPIEvidenceScoresAs(t, "broken", "1.0.0", evidence, schema.DecisionAsk)
}

func TestPyPIAdapterEvidenceReportsSourceUnavailableForMissingRequiredData(t *testing.T) {
	adapter := mustPyPIAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"info": {"name": "missing-version"},
		"releases": {}
	}`), Coordinate{Ecosystem: "pypi"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	assertPyPISourceUnavailable(t, evidence, "missing_required_data")
	missing, ok := evidence[0].Reason.Details["missing_fields"].([]string)
	if !ok || len(missing) != 1 || missing[0] != "version" {
		t.Fatalf("missing_fields = %#v, want version", evidence[0].Reason.Details["missing_fields"])
	}
}

func TestPyPIAdapterEvidenceDoesNotExposePersonalContactFields(t *testing.T) {
	adapter := mustPyPIAdapter(t)
	contactKey := "author" + "_" + "email"
	contactValue := "person" + "@" + "example.invalid"
	input := fmt.Sprintf(`{
		"info": {
			"name": "contact-demo",
			"version": "1.0.0",
			%q: %q,
			"project_urls": {"Source": "https://github.com/attach-dev/contact-demo"}
		},
		"releases": {
			"1.0.0": [{"filename": "contact_demo-1.0.0.tar.gz", "digests": {"sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}]
		}
	}`, contactKey, contactValue)

	evidence, err := adapter.EvidenceFromJSON([]byte(input), Coordinate{Ecosystem: "pypi", Name: "contact-demo", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	rendered := fmt.Sprintf("%#v", evidence)
	if strings.Contains(rendered, contactKey) || strings.Contains(rendered, contactValue) {
		t.Fatalf("evidence leaked personal contact metadata: %s", rendered)
	}
	assertNoDuplicatePyPISourceRefs(t, evidence)
}

func TestPyPIAdapterEvidenceDoesNotLeakSensitiveURLs(t *testing.T) {
	adapter := mustPyPIAdapter(t)
	projectURL := "https://" + "user" + ":" + "redacted" + "@" + "github.com/attach-dev/sensitive-pypi.git" + "?auth=" + "redacted" + "#fragment"
	fileURL := "https://" + "user" + ":" + "redacted" + "@" + "files.pythonhosted.org/packages/synthetic/sensitive_pypi-1.0.0.tar.gz" + "?token=" + "redacted"
	evidence, err := adapter.EvidenceFromJSON([]byte(fmt.Sprintf(`{
		"info": {
			"name": "sensitive-pypi",
			"version": "1.0.0",
			"project_urls": {"Source": %q}
		},
		"releases": {
			"1.0.0": [{
				"filename": "sensitive_pypi-1.0.0.tar.gz",
				"url": %q,
				"digests": {"sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}
			}]
		}
	}`, projectURL, fileURL)), Coordinate{Ecosystem: "pypi", Name: "sensitive-pypi", Version: "1.0.0"})
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
	for _, sensitive := range []string{"redacted", "?auth=", "?token=", "@github.com", "@files.pythonhosted.org", "#fragment"} {
		if strings.Contains(rendered, sensitive) {
			t.Fatalf("evidence leaked sensitive URL material %q: %s", sensitive, rendered)
		}
	}
	assertNoDuplicatePyPISourceRefs(t, evidence)
	assertPyPIEvidenceScoresAs(t, "sensitive-pypi", "1.0.0", evidence, schema.DecisionAsk)
}

func TestPyPIAdapterEvidenceDeduplicatesSourceRefsAndSourceRefIDs(t *testing.T) {
	adapter := mustPyPIAdapter(t)
	evidence, err := adapter.EvidenceFromJSON([]byte(`{
		"info": {
			"name": "dedupe-pypi",
			"version": "1.0.0",
			"license": "MIT",
			"requires_python": ">=3.8",
			"project_urls": {
				"Source": "git+https://github.com/attach-dev/dedupe-pypi.git",
				"Repository": "git+https://github.com/attach-dev/dedupe-pypi.git"
			}
		},
		"releases": {
			"1.0.0": [
				{
					"filename": "dedupe_pypi-1.0.0-py3-none-any.whl",
					"url": "https://files.pythonhosted.org/packages/synthetic/dedupe_pypi-1.0.0-py3-none-any.whl",
					"requires_python": ">=3.8",
					"digests": {"sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
				},
				{
					"filename": "dedupe_pypi-1.0.0-py3-none-any.whl",
					"url": "https://files.pythonhosted.org/packages/synthetic/dedupe_pypi-1.0.0-py3-none-any.whl",
					"requires_python": ">=3.8",
					"digests": {"sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}
				}
			]
		}
	}`), Coordinate{Ecosystem: "pypi", Name: "dedupe-pypi", Version: "1.0.0"})
	if err != nil {
		t.Fatalf("EvidenceFromJSON returned error: %v", err)
	}

	assertNoDuplicatePyPISourceRefs(t, evidence)
	if len(evidence[0].Reason.SourceRefIDs) != 5 {
		t.Fatalf("source_ref_ids = %#v, want version/package/license/requires-python/repository refs", evidence[0].Reason.SourceRefIDs)
	}
	if len(evidence[0].SourceRefs) != 4 {
		t.Fatalf("source_refs length = %d, want four secondary refs", len(evidence[0].SourceRefs))
	}
	files := evidence[0].Reason.Details["release_files"].([]map[string]any)
	if len(files) != 1 {
		t.Fatalf("release_files length = %d, want deduped single file", len(files))
	}
}

func assertPyPISourceUnavailable(t *testing.T, evidence []schema.Evidence, failureKind string) {
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
	if got.Reason.Details["source"] != pypiSourceName || got.Reason.Details["failure_kind"] != failureKind {
		t.Fatalf("source unavailable details = %#v", got.Reason.Details)
	}
	if got.SourceRef == nil {
		t.Fatalf("source_ref is nil")
	}
	if len(got.Reason.SourceRefIDs) != 1 || got.Reason.SourceRefIDs[0] != got.SourceRef.ID {
		t.Fatalf("source_ref_ids = %#v, want %q", got.Reason.SourceRefIDs, got.SourceRef.ID)
	}
}

func assertNoDuplicatePyPISourceRefs(t *testing.T, evidence []schema.Evidence) {
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
			if item.SourceRef.Source != pypiSourceName {
				t.Fatalf("primary source_ref source = %q, want %q", item.SourceRef.Source, pypiSourceName)
			}
		}
		for _, sourceRef := range item.SourceRefs {
			if _, ok := seenRefs[sourceRef.ID]; ok {
				t.Fatalf("duplicate source_ref %q in %#v", sourceRef.ID, item.SourceRefs)
			}
			seenRefs[sourceRef.ID] = struct{}{}
			if sourceRef.Source != pypiSourceName {
				t.Fatalf("source_ref source = %q, want %q", sourceRef.Source, pypiSourceName)
			}
		}
	}
}

func assertPyPIEvidenceScoresAs(t *testing.T, name, version string, evidence []schema.Evidence, wantDecision schema.Decision) {
	t.Helper()
	engine, err := score.NewEngine(score.Options{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("NewEngine returned error: %v", err)
	}
	verdict, err := engine.Evaluate(schema.Request{
		Package: schema.PackageIdentity{
			Ecosystem: "pypi",
			Name:      name,
			Version:   version,
			PURL:      "pkg:pypi/" + name + "@" + version,
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

func mustPyPIAdapter(t *testing.T) PyPIAdapter {
	t.Helper()
	adapter, err := NewPyPIAdapter(PyPIOptions{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("NewPyPIAdapter returned error: %v", err)
	}
	return adapter
}
