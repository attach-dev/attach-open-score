package fixtures

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
)

func TestLoadProviderConsumerManifestValidatesRepositoryManifest(t *testing.T) {
	root := filepath.Join("..", "..")
	manifestPath := filepath.Join(root, "fixtures", "manifests", "provider-consumer-v0.json")

	manifest, err := LoadProviderConsumerManifest(root, manifestPath)
	if err != nil {
		t.Fatalf("LoadProviderConsumerManifest returned error: %v", err)
	}
	if manifest.SchemaVersion != ProviderConsumerManifestVersion {
		t.Fatalf("schema_version = %q, want %q", manifest.SchemaVersion, ProviderConsumerManifestVersion)
	}
	if len(manifest.Entries) != 5 {
		t.Fatalf("entries = %d, want 5", len(manifest.Entries))
	}
	if manifest.Entries[0].ID != "npm" || manifest.Entries[0].ExpectedDecision != schema.DecisionAsk {
		t.Fatalf("first manifest entry = %#v, want npm ASK", manifest.Entries[0])
	}
}

func TestLoadProviderConsumerManifestRejectsMissingAndMalformedManifest(t *testing.T) {
	root := t.TempDir()

	tests := []struct {
		name string
		path string
		data *string
		want string
	}{
		{name: "missing", path: filepath.Join(root, "fixtures", "manifests", "missing.json"), want: "missing.json"},
		{name: "malformed", path: filepath.Join(root, "fixtures", "manifests", "bad.json"), data: ptrString(`{"schema_version":`), want: "invalid provider-consumer manifest JSON"},
		{name: "empty entries", path: filepath.Join(root, "fixtures", "manifests", "empty.json"), data: ptrString(`{"schema_version":"provider-consumer-fixture-manifest/v0","description":"empty","entries":[]}`), want: "entries must contain at least one entry"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.data != nil {
				writeManifestContent(t, tt.path, *tt.data)
			}

			_, err := LoadProviderConsumerManifest(root, tt.path)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestLoadProviderConsumerManifestRejectsFixturePathTraversal(t *testing.T) {
	root := t.TempDir()
	path := writeProviderConsumerManifest(t, root, ProviderConsumerManifest{
		SchemaVersion: ProviderConsumerManifestVersion,
		Description:   "synthetic traversal test",
		Entries: []ProviderConsumerManifestEntry{
			testProviderConsumerManifestEntry("../fixtures/v0/ask-provider-consumer-npm.json", schema.DecisionAsk),
		},
	})

	_, err := LoadProviderConsumerManifest(root, path)
	if err == nil {
		t.Fatal("expected traversal error")
	}
	if !strings.Contains(err.Error(), "must stay under fixtures/v0/") {
		t.Fatalf("error = %v, want fixture path rejection", err)
	}
}

func TestLoadProviderConsumerManifestRejectsFixturePathOutsideV0(t *testing.T) {
	root := t.TempDir()
	path := writeProviderConsumerManifest(t, root, ProviderConsumerManifest{
		SchemaVersion: ProviderConsumerManifestVersion,
		Description:   "synthetic fixture path scope test",
		Entries: []ProviderConsumerManifestEntry{
			testProviderConsumerManifestEntry("fixtures/manifests/provider-consumer-v0.json", schema.DecisionAsk),
		},
	})

	_, err := LoadProviderConsumerManifest(root, path)
	if err == nil {
		t.Fatal("expected fixture path scope error")
	}
	if !strings.Contains(err.Error(), "must stay under fixtures/v0/") {
		t.Fatalf("error = %v, want fixtures/v0 path rejection", err)
	}
}

func TestLoadProviderConsumerManifestRejectsUnknownExpectedDecision(t *testing.T) {
	root := filepath.Join("..", "..")
	path := writeProviderConsumerManifest(t, t.TempDir(), ProviderConsumerManifest{
		SchemaVersion: ProviderConsumerManifestVersion,
		Description:   "synthetic decision test",
		Entries: []ProviderConsumerManifestEntry{
			testProviderConsumerManifestEntry("fixtures/v0/ask-provider-consumer-npm.json", schema.Decision("MAYBE")),
		},
	})

	_, err := LoadProviderConsumerManifest(root, path)
	if err == nil {
		t.Fatal("expected unknown decision error")
	}
	if !strings.Contains(err.Error(), "expected_decision") {
		t.Fatalf("error = %v, want expected_decision rejection", err)
	}
}

func TestLoadProviderConsumerManifestValidatesReferencedFixture(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		data    *string
		want    string
	}{
		{name: "missing", fixture: "fixtures/v0/missing.json", want: "missing.json"},
		{name: "malformed", fixture: "fixtures/v0/bad.json", data: ptrString(`{"schema_version":"attach-open-score/v0","decision":"ASK"}`), want: "missing required field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if tt.data != nil {
				writeManifestContent(t, filepath.Join(root, filepath.FromSlash(tt.fixture)), *tt.data)
			}
			manifestPath := writeProviderConsumerManifest(t, root, ProviderConsumerManifest{
				SchemaVersion: ProviderConsumerManifestVersion,
				Description:   "synthetic referenced fixture validation test",
				Entries: []ProviderConsumerManifestEntry{
					testProviderConsumerManifestEntry(tt.fixture, schema.DecisionAsk),
				},
			})

			_, err := LoadProviderConsumerManifest(root, manifestPath)
			if err == nil {
				t.Fatal("expected referenced fixture validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestLoadProviderConsumerManifestRejectsManifestFixtureMismatch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ProviderConsumerManifestEntry)
		want   string
	}{
		{
			name: "package identity",
			mutate: func(entry *ProviderConsumerManifestEntry) {
				entry.Package = "other-synthetic-provider-consumer"
			},
			want: "package identity does not match referenced fixture",
		},
		{
			name: "decision",
			mutate: func(entry *ProviderConsumerManifestEntry) {
				entry.ExpectedDecision = schema.DecisionDeny
			},
			want: "expected_decision",
		},
		{
			name: "reason codes",
			mutate: func(entry *ProviderConsumerManifestEntry) {
				entry.ReasonCodes = []string{reasons.NoKnownVulnerabilities}
			},
			want: "reason_codes",
		},
		{
			name: "source refs",
			mutate: func(entry *ProviderConsumerManifestEntry) {
				entry.SourceRefIDs = append([]string{}, entry.SourceRefIDs...)
				entry.SourceRefIDs[0] = "synthetic-mismatched-source-ref"
			},
			want: "source_ref_ids",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			copyProviderConsumerFixture(t, root, "ask-provider-consumer-npm.json")
			entry := testProviderConsumerManifestEntry("fixtures/v0/ask-provider-consumer-npm.json", schema.DecisionAsk)
			tt.mutate(&entry)
			manifestPath := writeProviderConsumerManifest(t, root, ProviderConsumerManifest{
				SchemaVersion: ProviderConsumerManifestVersion,
				Description:   "synthetic manifest-to-fixture mismatch test",
				Entries:       []ProviderConsumerManifestEntry{entry},
			})

			_, err := LoadProviderConsumerManifest(root, manifestPath)
			if err == nil {
				t.Fatal("expected manifest-to-fixture mismatch error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func writeProviderConsumerManifest(t *testing.T, root string, manifest ProviderConsumerManifest) string {
	t.Helper()
	path := filepath.Join(root, "fixtures", "manifests", "manifest.json")
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	writeManifestContent(t, path, string(data))
	return path
}

func copyProviderConsumerFixture(t *testing.T, root, filename string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "v0", filename))
	if err != nil {
		t.Fatalf("read fixture copy source: %v", err)
	}
	writeManifestContent(t, filepath.Join(root, "fixtures", "v0", filename), string(data))
}

func writeManifestContent(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir manifest dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write manifest content: %v", err)
	}
}

func testProviderConsumerManifestEntry(fixture string, decision schema.Decision) ProviderConsumerManifestEntry {
	return ProviderConsumerManifestEntry{
		ID:                 "npm",
		Fixture:            fixture,
		Ecosystem:          "npm",
		Package:            "synthetic-npm-provider-consumer",
		Version:            "1.4.0",
		PURL:               "pkg:npm/synthetic-npm-provider-consumer@1.4.0",
		RequestedSpec:      "^1.4.0",
		ExpectedDecision:   decision,
		ExpectedConfidence: schema.ConfidenceLow,
		ReasonCodes:        []string{reasons.RepositoryMappingUncertain},
		SourceRefIDs: []string{
			"npm-registry-registry.npmjs.org-synthetic-npm-provider-consumer-1.4.0",
			"npm-registry-registry.npmjs.org-synthetic-npm-provider-consumer",
			"npm-registry-registry.npmjs.org-synthetic-npm-provider-consumer-dist-tags",
			"npm-registry-registry.npmjs.org-synthetic-npm-provider-consumer-1.4.0-license",
			"npm-registry-registry.npmjs.org-synthetic-npm-provider-consumer-1.4.0-repository",
		},
		ProvenancePosture: ProviderConsumerProvenancePosture,
	}
}

func ptrString(value string) *string {
	return &value
}
