package fixtures

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRepositoryFixtures(t *testing.T) {
	root := filepath.Join("..", "..")
	reports, err := ValidateRepository(root)
	if err != nil {
		t.Fatalf("ValidateRepository returned error: %v", err)
	}
	if len(reports) < 4 {
		t.Fatalf("expected at least 4 fixture reports, got %d", len(reports))
	}
	for _, report := range reports {
		if report.Path == "" {
			t.Fatalf("fixture report missing path: %#v", report)
		}
		if report.Decision == "" {
			t.Fatalf("fixture report missing decision for %s", report.Path)
		}
		if len(report.Reasons) == 0 {
			t.Fatalf("fixture report missing reasons for %s", report.Path)
		}
	}
}

func TestValidateBytesRejectsUnknownDecision(t *testing.T) {
	fixture := []byte(`{
		"schema_version":"attach-open-score/v0",
		"package":{"ecosystem":"npm","name":"synthetic","purl":"pkg:npm/synthetic@1.0.0","resolved":true,"version":"1.0.0"},
		"decision":"MAYBE",
		"score":10,
		"confidence":"HIGH",
		"reasons":[{"code":"NO_KNOWN_VULNERABILITIES","severity":"INFO","decision_effect":"ALLOW","message":"synthetic"}],
		"source_refs":[],
		"evaluated_at":"2026-05-05T00:00:00Z",
		"ttl_seconds":86400,
		"limitations":[]
	}`)

	_, err := ValidateBytes("bad-decision.json", fixture)
	if err == nil {
		t.Fatal("expected invalid decision error")
	}
	if !strings.Contains(err.Error(), "decision") {
		t.Fatalf("expected decision error, got %v", err)
	}
}

func TestValidateBytesRequiresSourceRefsForSourceBackedReasons(t *testing.T) {
	fixture := []byte(`{
		"schema_version":"attach-open-score/v0",
		"package":{"ecosystem":"npm","name":"synthetic","purl":"pkg:npm/synthetic@1.0.0","resolved":true,"version":"1.0.0"},
		"decision":"DENY",
		"score":95,
		"confidence":"HIGH",
		"reasons":[{"code":"KNOWN_MALICIOUS_PACKAGE","severity":"CRITICAL","decision_effect":"DENY","message":"synthetic","source_ref_ids":["missing"]}],
		"source_refs":[],
		"evaluated_at":"2026-05-05T00:00:00Z",
		"ttl_seconds":86400,
		"limitations":[]
	}`)

	_, err := ValidateBytes("missing-source-ref.json", fixture)
	if err == nil {
		t.Fatal("expected missing source_ref error")
	}
	if !strings.Contains(err.Error(), "source_ref_ids") {
		t.Fatalf("expected source_ref_ids error, got %v", err)
	}
}

func TestValidateBytesRequiresTopLevelScoreField(t *testing.T) {
	fixture := []byte(`{
		"schema_version":"attach-open-score/v0",
		"package":{"ecosystem":"npm","name":"synthetic","purl":"pkg:npm/synthetic@1.0.0","resolved":true,"version":"1.0.0"},
		"decision":"ALLOW",
		"confidence":"HIGH",
		"reasons":[{"code":"NO_KNOWN_VULNERABILITIES","severity":"INFO","decision_effect":"NONE","message":"synthetic"}],
		"source_refs":[],
		"evaluated_at":"2026-05-05T00:00:00Z",
		"ttl_seconds":86400,
		"limitations":[]
	}`)

	_, err := ValidateBytes("missing-score.json", fixture)
	if err == nil {
		t.Fatal("expected missing score error")
	}
	if !strings.Contains(err.Error(), "score") {
		t.Fatalf("expected score error, got %v", err)
	}
}

func TestValidateBytesRejectsInvalidSourceRefPosture(t *testing.T) {
	fixture := []byte(`{
		"schema_version":"attach-open-score/v0",
		"package":{"ecosystem":"npm","name":"synthetic","purl":"pkg:npm/synthetic@1.0.0","resolved":true,"version":"1.0.0"},
		"decision":"ASK",
		"score":50,
		"confidence":"MEDIUM",
		"reasons":[{"code":"SOURCE_STALE","severity":"MEDIUM","decision_effect":"ASK","message":"synthetic","source_ref_ids":["src"]}],
		"source_refs":[{"id":"src","source":"synthetic","url":"https://example.invalid/source","retrieved_at":"2026-05-05T00:00:00Z","ttl_seconds":86400,"license_or_terms_url":"https://example.invalid/terms","attribution":"synthetic","attribution_required":false,"redistribution":"maybe","public_display":"allowed"}],
		"evaluated_at":"2026-05-05T00:00:00Z",
		"ttl_seconds":86400,
		"limitations":[]
	}`)

	_, err := ValidateBytes("bad-source-posture.json", fixture)
	if err == nil {
		t.Fatal("expected redistribution error")
	}
	if !strings.Contains(err.Error(), "redistribution") {
		t.Fatalf("expected redistribution error, got %v", err)
	}
}

func TestValidateBytesRejectsTrailingData(t *testing.T) {
	fixture := []byte(`{
		"schema_version":"attach-open-score/v0",
		"package":{"ecosystem":"npm","name":"synthetic","purl":"pkg:npm/synthetic@1.0.0","resolved":true,"version":"1.0.0"},
		"decision":"UNKNOWN",
		"score":null,
		"confidence":"LOW",
		"reasons":[{"code":"INSUFFICIENT_DATA","severity":"MEDIUM","decision_effect":"UNKNOWN","message":"synthetic"}],
		"source_refs":[],
		"evaluated_at":"2026-05-05T00:00:00Z",
		"ttl_seconds":3600,
		"limitations":[]
	} {"extra":true}`)

	_, err := ValidateBytes("trailing.json", fixture)
	if err == nil {
		t.Fatal("expected trailing data error")
	}
	if !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("expected trailing data error, got %v", err)
	}
}

func TestValidateBytesRequiresSourceRefAttributionRequiredField(t *testing.T) {
	fixture := []byte(`{
		"schema_version":"attach-open-score/v0",
		"package":{"ecosystem":"npm","name":"synthetic","purl":"pkg:npm/synthetic@1.0.0","resolved":true,"version":"1.0.0"},
		"decision":"ASK",
		"score":50,
		"confidence":"MEDIUM",
		"reasons":[{"code":"SOURCE_STALE","severity":"MEDIUM","decision_effect":"ASK","message":"synthetic","source_ref_ids":["src"]}],
		"source_refs":[{"id":"src","source":"synthetic","url":"https://example.invalid/source","retrieved_at":"2026-05-05T00:00:00Z","ttl_seconds":86400,"license_or_terms_url":"https://example.invalid/terms","attribution":"synthetic","redistribution":"allowed","public_display":"allowed"}],
		"evaluated_at":"2026-05-05T00:00:00Z",
		"ttl_seconds":86400,
		"limitations":[]
	}`)

	_, err := ValidateBytes("missing-attribution-required.json", fixture)
	if err == nil {
		t.Fatal("expected attribution_required error")
	}
	if !strings.Contains(err.Error(), "attribution_required") {
		t.Fatalf("expected attribution_required error, got %v", err)
	}
}
