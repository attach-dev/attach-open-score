package osv

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/score"
	"github.com/attach-dev/attach-open-score/pkg/sources"
)

var fixedNow = time.Date(2026, 5, 9, 10, 0, 0, 0, time.UTC)

func TestClientEvidenceNormalizesVulnerabilities(t *testing.T) {
	var sawRequest bool
	httpClient := clientFunc(func(r *http.Request) (*http.Response, error) {
		sawRequest = true
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/query" {
			t.Errorf("path = %s, want /v1/query", r.URL.Path)
		}

		var request queryRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if request.Package.Ecosystem != "npm" || request.Package.Name != "left-pad" || request.Version != "1.3.0" {
			t.Errorf("request = %#v, want npm left-pad@1.3.0", request)
		}

		return jsonResponse(http.StatusOK, `{
			"vulns": [{
				"id": "GHSA-abcd-1234-wxyz",
				"aliases": ["CVE-2026-0001"],
				"published": "2026-05-01T00:00:00Z",
				"modified": "2026-05-02T00:00:00Z",
				"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
				"affected": [{
					"package": {"ecosystem": "npm", "name": "left-pad"},
					"versions": ["1.3.0"]
				}],
				"references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-abcd-1234-wxyz"}]
			}]
		}`), nil
	})

	client := mustNewClient(t, Options{BaseURL: "https://osv.test", HTTPClient: httpClient, Now: fixedClock})
	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	if !sawRequest {
		t.Fatalf("server did not receive OSV query")
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
	if got.SourceRef.ID != "osv-ghsa-abcd-1234-wxyz" {
		t.Fatalf("source_ref id = %q, want osv-ghsa-abcd-1234-wxyz", got.SourceRef.ID)
	}
	if got.SourceRef.Source != SourceName || got.SourceRef.SourceID != "GHSA-abcd-1234-wxyz" {
		t.Fatalf("source ref source/source_id = %q/%q", got.SourceRef.Source, got.SourceRef.SourceID)
	}
	if got.SourceRef.URL != "https://osv.dev/vulnerability/GHSA-abcd-1234-wxyz" {
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
	if got.Reason.Details["advisory_id"] != "GHSA-abcd-1234-wxyz" {
		t.Fatalf("details advisory_id = %#v", got.Reason.Details["advisory_id"])
	}
	if got.Reason.Details["osv_ecosystem"] != "npm" || got.Reason.Details["package_name"] != "left-pad" || got.Reason.Details["version"] != "1.3.0" {
		t.Fatalf("coordinate details = %#v", got.Reason.Details)
	}

	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestClientEvidenceNoVulnerabilities(t *testing.T) {
	httpClient := clientFunc(func(r *http.Request) (*http.Response, error) {
		var request queryRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if request.Package.Ecosystem != "PyPI" {
			t.Errorf("OSV ecosystem = %q, want PyPI", request.Package.Ecosystem)
		}
		return jsonResponse(http.StatusOK, `{"vulns":[]}`), nil
	})

	client := mustNewClient(t, Options{BaseURL: "https://osv.test", HTTPClient: httpClient, Now: fixedClock})
	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "pypi", Name: "django", Version: "4.2.0"})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
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
	if !strings.HasPrefix(got.SourceRef.ID, "osv-query-") {
		t.Fatalf("source_ref id = %q, want osv-query-*", got.SourceRef.ID)
	}
	if got.SourceRef.SourceID != "PyPI:django@4.2.0" {
		t.Fatalf("source_id = %q, want PyPI:django@4.2.0", got.SourceRef.SourceID)
	}

	assertEvidenceAccepted(t, Coordinate{Ecosystem: "pypi", Name: "django", Version: "4.2.0"}, evidence)
}

func TestClientEvidenceFollowsPaginationBeforeNoVulnerabilities(t *testing.T) {
	var requests []queryRequest
	httpClient := clientFunc(func(r *http.Request) (*http.Response, error) {
		var request queryRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		requests = append(requests, request)
		if len(requests) == 1 {
			return jsonResponse(http.StatusOK, `{"vulns":[],"next_page_token":"page-2"}`), nil
		}
		return jsonResponse(http.StatusOK, `{"vulns":[{
			"id":"GHSA-page-0001-0002",
			"severity":[{"type":"CVSS_V3","score":"7.1"}],
			"affected":[{
				"package":{"ecosystem":"npm","name":"left-pad"},
				"versions":["1.3.0"]
			}]
		}]}`), nil
	})

	client := mustNewClient(t, Options{BaseURL: "https://osv.test", HTTPClient: httpClient, Now: fixedClock})
	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	if len(requests) != 2 || requests[1].PageToken != "page-2" {
		t.Fatalf("pagination requests = %#v", requests)
	}
	if len(evidence) != 1 || evidence[0].Reason.Code != reasons.KnownVulnerabilityHigh {
		t.Fatalf("evidence = %#v, want paginated high vulnerability", evidence)
	}
}

func TestClientEvidenceIgnoresMismatchedAffectedPackage(t *testing.T) {
	client := mustNewClient(t, Options{
		BaseURL: "https://osv.test",
		HTTPClient: clientFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"vulns":[{
				"id": "GHSA-mism-0001-0002",
				"severity": [{"type": "CVSS_V3", "score": "9.8"}],
				"affected": [{
					"package": {"ecosystem": "npm", "name": "right-pad"},
					"versions": ["1.3.0"]
				}]
			}]}`), nil
		}),
		Now: fixedClock,
	})

	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	assertNoKnownVulnerabilities(t, evidence)
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestClientEvidenceMatchesExactAffectedVersion(t *testing.T) {
	client := mustNewClient(t, Options{
		BaseURL: "https://osv.test",
		HTTPClient: clientFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"vulns":[{
				"id": "GHSA-exct-0001-0002",
				"severity": [{"type": "CVSS_V3", "score": "7.5"}],
				"affected": [{
					"package": {"ecosystem": "npm", "name": "left-pad"},
					"versions": ["1.2.0", "1.3.0"]
				}]
			}]}`), nil
		}),
		Now: fixedClock,
	})

	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	if len(evidence) != 1 || evidence[0].Reason.Code != reasons.KnownVulnerabilityHigh {
		t.Fatalf("evidence = %#v, want high vulnerability evidence", evidence)
	}
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestClientEvidenceOnlyUsesSeverityFromMatchedAffectedEntry(t *testing.T) {
	client := mustNewClient(t, Options{
		BaseURL: "https://osv.test",
		HTTPClient: clientFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"vulns":[{
				"id": "GHSA-msev-0001-0002",
				"affected": [
					{
						"package": {"ecosystem": "npm", "name": "other-pad"},
						"versions": ["1.3.0"],
						"ecosystem_specific": {"severity": "CRITICAL"}
					},
					{
						"package": {"ecosystem": "npm", "name": "left-pad"},
						"versions": ["1.3.0"],
						"severity": [{"type": "CVSS_V3", "score": "5.0"}]
					}
				]
			}]}`), nil
		}),
		Now: fixedClock,
	})

	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	if len(evidence) != 1 || evidence[0].Reason.Code != reasons.KnownVulnerabilityModerate {
		t.Fatalf("evidence = %#v, want matched moderate vulnerability evidence", evidence)
	}
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestClientEvidenceIgnoresExactUnaffectedVersion(t *testing.T) {
	client := mustNewClient(t, Options{
		BaseURL: "https://osv.test",
		HTTPClient: clientFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"vulns":[{
				"id": "GHSA-unaf-0001-0002",
				"severity": [{"type": "CVSS_V3", "score": "9.8"}],
				"affected": [{
					"package": {"ecosystem": "npm", "name": "left-pad"},
					"versions": ["1.2.0"]
				}]
			}]}`), nil
		}),
		Now: fixedClock,
	})

	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	assertNoKnownVulnerabilities(t, evidence)
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestClientEvidenceTreatsReturnedRangeMatchAsVulnerable(t *testing.T) {
	client := mustNewClient(t, Options{
		BaseURL: "https://osv.test",
		HTTPClient: clientFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"vulns":[{
				"id": "GHSA-rang-0001-0002",
				"severity": [{"type": "CVSS_V3", "score": "9.8"}],
				"affected": [{
					"package": {"ecosystem": "npm", "name": "left-pad"},
					"versions": ["1.2.0"],
					"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}]}]
				}]
			}]}`), nil
		}),
		Now: fixedClock,
	})

	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	if len(evidence) != 1 || evidence[0].Reason.Code != reasons.KnownVulnerabilityCritical {
		t.Fatalf("evidence = %#v, want critical vulnerability evidence", evidence)
	}
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestClientEvidenceClassifiesMinimalMissingSeverityRecord(t *testing.T) {
	client := mustNewClient(t, Options{
		BaseURL: "https://osv.test",
		HTTPClient: clientFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"vulns":[{
				"id": "GHSA-minm-0001-0002",
				"affected": [{
					"package": {"ecosystem": "npm", "name": "left-pad"},
					"versions": ["1.3.0"]
				}]
			}]}`), nil
		}),
		Now: fixedClock,
	})

	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	if len(evidence) != 1 {
		t.Fatalf("evidence length = %d, want 1", len(evidence))
	}
	got := evidence[0]
	if got.Reason.Code != reasons.KnownVulnerabilityModerate || got.Reason.Severity != "MEDIUM" || got.Reason.DecisionEffect != schema.DecisionEffectAsk {
		t.Fatalf("reason = %#v, want moderate known vulnerability", got.Reason)
	}
	if got.SourceRef == nil || got.Reason.SourceRefIDs[0] != got.SourceRef.ID {
		t.Fatalf("source refs = %#v / %#v, want primary source_ref linked", got.Reason.SourceRefIDs, got.SourceRef)
	}
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestClientEvidenceReturnsSourceUnavailableForMissingAffectedVersionData(t *testing.T) {
	client := mustNewClient(t, Options{
		BaseURL: "https://osv.test",
		HTTPClient: clientFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"vulns":[{
				"id": "GHSA-rang-0001-0002",
				"affected": [{
					"package": {"ecosystem": "npm", "name": "left-pad"}
				}]
			}]}`), nil
		}),
		Now: fixedClock,
	})

	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	assertSourceUnavailable(t, evidence, "malformed_response")
	if evidence[0].Reason.Details["unusable_reason"] != "unsupported_affected_version_data" {
		t.Fatalf("unusable_reason = %#v", evidence[0].Reason.Details["unusable_reason"])
	}
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestClientEvidenceDeduplicatesDuplicateUpstreamSourceRefs(t *testing.T) {
	client := mustNewClient(t, Options{
		BaseURL: "https://osv.test",
		HTTPClient: clientFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"vulns":[{
				"id": "GHSA-dupe-0001-0002",
				"aliases": ["CVE-2026-0002", "CVE-2026-0002"],
				"severity": [{"type": "CVSS_V3", "score": "7.5"}],
				"affected": [{
					"package": {"ecosystem": "npm", "name": "left-pad"},
					"versions": ["1.3.0"]
				}],
				"references": [
					{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-dupe-0001-0002"},
					{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-dupe-0001-0002"},
					{"type": "WEB", "url": "not a valid url"}
				]
			}]}`), nil
		}),
		Now: fixedClock,
	})

	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}
	if len(evidence) != 1 {
		t.Fatalf("evidence length = %d, want 1", len(evidence))
	}
	got := evidence[0]
	if len(got.SourceRefs) != 2 {
		t.Fatalf("source_refs length = %d, want deduped alias plus reference", len(got.SourceRefs))
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

func TestClientEvidenceReturnsSourceUnavailableForNon2xx(t *testing.T) {
	client := mustNewClient(t, Options{
		BaseURL: "https://osv.test",
		HTTPClient: clientFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusServiceUnavailable, "temporarily unavailable"), nil
		}),
		Now: fixedClock,
	})
	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}

	assertSourceUnavailable(t, evidence, "http_status")
	if evidence[0].Reason.Details["status_code"] != http.StatusServiceUnavailable {
		t.Fatalf("status_code = %#v, want %d", evidence[0].Reason.Details["status_code"], http.StatusServiceUnavailable)
	}
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestClientEvidenceReturnsSourceUnavailableForMalformedResponse(t *testing.T) {
	client := mustNewClient(t, Options{
		BaseURL: "https://osv.test",
		HTTPClient: clientFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"vulns":"not-an-array"}`), nil
		}),
		Now: fixedClock,
	})
	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}

	assertSourceUnavailable(t, evidence, "malformed_response")
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestClientEvidenceReturnsSourceUnavailableForClientError(t *testing.T) {
	client := mustNewClient(t, Options{
		HTTPClient: clientFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("deadline exceeded")
		}),
		Now: fixedClock,
	})

	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}

	assertSourceUnavailable(t, evidence, "request_failed")
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestClientEvidenceReturnsSourceUnavailableForOversizedResponse(t *testing.T) {
	client := mustNewClient(t, Options{
		BaseURL: "https://osv.test",
		HTTPClient: clientFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"vulns":[]}`), nil
		}),
		Now:              fixedClock,
		MaxResponseBytes: 8,
	})
	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
	if err != nil {
		t.Fatalf("Evidence returned error: %v", err)
	}

	assertSourceUnavailable(t, evidence, "response_too_large")
	if evidence[0].Reason.Details["max_response_bytes"] != int64(8) {
		t.Fatalf("max_response_bytes = %#v, want int64(8)", evidence[0].Reason.Details["max_response_bytes"])
	}
	assertEvidenceAccepted(t, Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, evidence)
}

func TestClientEvidenceSourceRefAttributionFields(t *testing.T) {
	client := mustNewClient(t, Options{
		BaseURL: "https://osv.test",
		HTTPClient: clientFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(http.StatusOK, `{"vulns":[]}`), nil
		}),
		Now: fixedClock,
	})
	evidence, err := client.Evidence(context.Background(), Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})
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
	if sourceRef.Attribution != "Source: OSV.dev query response" {
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

func mustNewClient(t *testing.T, options Options) Client {
	t.Helper()
	client, err := NewClient(options)
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	return client
}

func fixedClock() time.Time {
	return fixedNow
}

type clientFunc func(*http.Request) (*http.Response, error)

func (f clientFunc) Do(request *http.Request) (*http.Response, error) {
	return f(request)
}

func jsonResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
