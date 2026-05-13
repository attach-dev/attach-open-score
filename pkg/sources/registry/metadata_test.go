package registry

import (
	"strings"
	"testing"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/score"
)

var fixedNow = time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)

func TestNormalizeRepositoryURLForms(t *testing.T) {
	tests := map[string]string{
		"git+https://github.com/Owner/Repo.git":   "https://github.com/Owner/Repo",
		"git@github.com:Owner/Repo.git":           "https://github.com/Owner/Repo",
		"github:Owner/Repo":                       "https://github.com/Owner/Repo",
		"http://github.com/Owner/Repo/":           "https://github.com/Owner/Repo",
		"git+ssh://git@github.com/Owner/Repo.git": "https://github.com/Owner/Repo",
		"git://github.com/Owner/Repo.git":         "https://github.com/Owner/Repo",
	}
	for raw, want := range tests {
		got, err := NormalizeRepositoryURL(raw)
		if err != nil {
			t.Fatalf("NormalizeRepositoryURL(%q) error: %v", raw, err)
		}
		if got != want {
			t.Fatalf("NormalizeRepositoryURL(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestEvidenceCoversRegistryFixtureShapes(t *testing.T) {
	adapter := mustAdapter(t)
	tests := []struct {
		name       string
		coordinate Coordinate
		record     Metadata
		wantURL    string
		wantSource string
	}{
		{
			name:       "npm repository object",
			coordinate: Coordinate{Ecosystem: "npm", Name: "@synthetic/example", Version: "1.0.0"},
			record:     Metadata{Source: "npm", Repository: Repository{Type: "git", URL: "git+https://github.com/attach-dev/example-js.git"}, SourceID: "npm:@synthetic/example@1.0.0"},
			wantURL:    "https://github.com/attach-dev/example-js",
			wantSource: "npm",
		},
		{
			name:       "pypi project urls",
			coordinate: Coordinate{Ecosystem: "pypi", Name: "example-py", Version: "2.0.0"},
			record:     Metadata{Source: "pypi", Links: map[string]string{"Repository": "https://github.com/attach-dev/example-py"}, SourceID: "pypi:example-py:2.0.0"},
			wantURL:    "https://github.com/attach-dev/example-py",
			wantSource: "pypi",
		},
		{
			name:       "go module origin",
			coordinate: Coordinate{Ecosystem: "go", Name: "github.com/attach-dev/example-go", Version: "v1.2.3"},
			record:     Metadata{Source: "go", RepositoryURL: "https://github.com/attach-dev/example-go.git", SourceID: "go:github.com/attach-dev/example-go@v1.2.3"},
			wantURL:    "https://github.com/attach-dev/example-go",
			wantSource: "go",
		},
		{
			name:       "crates repository",
			coordinate: Coordinate{Ecosystem: "crates", Name: "example-rs", Version: "0.1.0"},
			record:     Metadata{Source: "crates.io", RepositoryURL: "https://github.com/attach-dev/example-rs", SourceID: "crate:example-rs:0.1.0"},
			wantURL:    "https://github.com/attach-dev/example-rs",
			wantSource: "crates.io",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence, err := adapter.Evidence(tt.coordinate, []Metadata{tt.record})
			if err != nil {
				t.Fatalf("Evidence error: %v", err)
			}
			if len(evidence) != 1 {
				t.Fatalf("len(evidence) = %d, want 1", len(evidence))
			}
			reason := evidence[0].Reason
			if reason.DecisionEffect != schema.DecisionEffectUnknown {
				t.Fatalf("decision_effect = %s, want UNKNOWN", reason.DecisionEffect)
			}
			if reason.SourceRefIDs[0] != evidence[0].SourceRef.ID {
				t.Fatalf("reason source refs do not point at evidence source ref")
			}
			if got := reason.Details["repository_url"]; got != tt.wantURL {
				t.Fatalf("repository_url detail = %v, want %s", got, tt.wantURL)
			}
			if evidence[0].SourceRef.Source != tt.wantSource {
				t.Fatalf("source = %s, want %s", evidence[0].SourceRef.Source, tt.wantSource)
			}
		})
	}
}

func TestMissingAndAmbiguousRepositoryStayNonAuthoritative(t *testing.T) {
	adapter := mustAdapter(t)
	coordinate := Coordinate{Ecosystem: "npm", Name: "synthetic", Version: "1.0.0"}

	evidence, err := adapter.Evidence(coordinate, []Metadata{{Source: "npm", SourceID: "missing"}})
	if err != nil {
		t.Fatalf("Evidence error: %v", err)
	}
	assertUnknownNonAuthoritative(t, evidence)

	evidence, err = adapter.Evidence(coordinate, []Metadata{{Source: "npm", RepositoryURL: "https://github.com/attach-dev/one", SourceID: "one"}, {Source: "npm", RepositoryURL: "https://github.com/attach-dev/two", SourceID: "two"}})
	if err != nil {
		t.Fatalf("Evidence error: %v", err)
	}
	assertUnknownNonAuthoritative(t, evidence)
	if len(evidence[0].SourceRefs) != 2 {
		t.Fatalf("ambiguous mapping source_refs = %d, want 2", len(evidence[0].SourceRefs))
	}
	if len(evidence[0].Reason.SourceRefIDs) != 2 {
		t.Fatalf("ambiguous mapping reason source_ref_ids = %d, want 2", len(evidence[0].Reason.SourceRefIDs))
	}
}

func TestInvalidUntrustedRepositoryStaysNonAuthoritative(t *testing.T) {
	adapter := mustAdapter(t)
	for _, raw := range []string{"ftp://example.invalid/repo", "git+https://token@github.com/owner/repo.git"} {
		evidence, err := adapter.Evidence(Coordinate{Ecosystem: "pypi", Name: "synthetic", Version: "1.0.0"}, []Metadata{{Source: "pypi", RepositoryURL: raw, SourceID: "invalid"}})
		if err != nil {
			t.Fatalf("Evidence error: %v", err)
		}
		assertUnknownNonAuthoritative(t, evidence)
		if got := evidence[0].Reason.Message; strings.Contains(got, "token@") || strings.Contains(got, raw) {
			t.Fatalf("reason message leaked raw repository URL/userinfo: %q", got)
		}
	}
}

func TestSourceRefsArePreservedAndSanitized(t *testing.T) {
	adapter := mustAdapter(t)
	coordinate := Coordinate{Ecosystem: "npm", Name: "synthetic", Version: "1.0.0"}
	evidence, err := adapter.Evidence(coordinate, []Metadata{
		{Source: "npm", RepositoryURL: "https://github.com/attach-dev/synthetic", SourceID: "one", SourceURL: "https://registry.npmjs.org/synthetic?token=secret#fragment"},
		{Source: "pypi", RepositoryURL: "https://github.com/attach-dev/synthetic", SourceID: "two", SourceURL: "https://user:secret@example.invalid/source"},
	})
	if err != nil {
		t.Fatalf("Evidence error: %v", err)
	}
	assertUnknownNonAuthoritative(t, evidence)
	if len(evidence[0].SourceRefs) != 2 {
		t.Fatalf("source_refs = %d, want 2", len(evidence[0].SourceRefs))
	}
	if len(evidence[0].Reason.SourceRefIDs) != 2 {
		t.Fatalf("source_ref_ids = %d, want 2", len(evidence[0].Reason.SourceRefIDs))
	}
	if got := evidence[0].SourceRefs[0].URL; got != "https://registry.npmjs.org/synthetic" {
		t.Fatalf("sanitized source URL = %q, want query/fragment stripped", got)
	}
	if got := evidence[0].SourceRefs[1].URL; strings.Contains(got, "secret") || strings.Contains(got, "@") {
		t.Fatalf("source URL leaked userinfo: %q", got)
	}
}

func TestRegistryMappingEvidenceDoesNotProduceAllow(t *testing.T) {
	adapter := mustAdapter(t)
	evidence, err := adapter.Evidence(Coordinate{Ecosystem: "npm", Name: "synthetic", Version: "1.0.0"}, []Metadata{{Source: "npm", RepositoryURL: "https://github.com/attach-dev/synthetic", SourceID: "npm:synthetic@1.0.0"}})
	if err != nil {
		t.Fatalf("Evidence error: %v", err)
	}
	engine, err := score.NewEngine(score.Options{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("NewEngine error: %v", err)
	}
	verdict, err := engine.Evaluate(schema.Request{Package: schema.PackageIdentity{Ecosystem: "npm", Name: "synthetic", Version: "1.0.0", PURL: "pkg:npm/synthetic@1.0.0", Resolved: true}, Evidence: evidence})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if verdict.Decision != schema.DecisionAsk {
		t.Fatalf("decision = %s, want ASK for non-authoritative repository mapping", verdict.Decision)
	}
}

func mustAdapter(t *testing.T) Adapter {
	t.Helper()
	adapter, err := NewAdapter(Options{Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatalf("NewAdapter error: %v", err)
	}
	return adapter
}

func assertUnknownNonAuthoritative(t *testing.T, evidence []schema.Evidence) {
	t.Helper()
	if len(evidence) != 1 {
		t.Fatalf("len(evidence) = %d, want 1", len(evidence))
	}
	if evidence[0].Reason.DecisionEffect != schema.DecisionEffectUnknown {
		t.Fatalf("decision_effect = %s, want UNKNOWN", evidence[0].Reason.DecisionEffect)
	}
	if evidence[0].Reason.Severity != "MEDIUM" {
		t.Fatalf("severity = %s, want MEDIUM", evidence[0].Reason.Severity)
	}
	if evidence[0].SourceRef == nil && len(evidence[0].SourceRefs) == 0 {
		t.Fatalf("source_ref missing")
	}
}
