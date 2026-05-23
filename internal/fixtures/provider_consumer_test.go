package fixtures

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/score"
)

var providerConsumerFixtureCases = []struct {
	name          string
	filename      string
	ecosystem     string
	packageName   string
	version       string
	purl          string
	requestedSpec string
}{
	{
		name:          "npm",
		filename:      "ask-provider-consumer-npm.json",
		ecosystem:     "npm",
		packageName:   "synthetic-npm-provider-consumer",
		version:       "1.4.0",
		purl:          "pkg:npm/synthetic-npm-provider-consumer@1.4.0",
		requestedSpec: "^1.4.0",
	},
	{
		name:          "pypi",
		filename:      "ask-provider-consumer-pypi.json",
		ecosystem:     "pypi",
		packageName:   "synthetic-pypi-provider-consumer",
		version:       "2.1.0",
		purl:          "pkg:pypi/synthetic-pypi-provider-consumer@2.1.0",
		requestedSpec: "==2.1.0",
	},
	{
		name:          "crates",
		filename:      "ask-provider-consumer-crates.json",
		ecosystem:     "crates",
		packageName:   "synthetic-cargo-provider-consumer",
		version:       "0.8.0",
		purl:          "pkg:cargo/synthetic-cargo-provider-consumer@0.8.0",
		requestedSpec: "^0.8",
	},
	{
		name:          "go module",
		filename:      "ask-provider-consumer-go-module.json",
		ecosystem:     "go",
		packageName:   "example.com/provider/consumer",
		version:       "v0.3.0",
		purl:          "pkg:golang/example.com/provider/consumer@v0.3.0",
		requestedSpec: "v0.3.0",
	},
	{
		name:          "yarn consumer npm coordinate",
		filename:      "ask-provider-consumer-yarn-npm-coordinate.json",
		ecosystem:     "npm",
		packageName:   "@attach-dev/yarn-provider-consumer",
		version:       "3.2.1",
		purl:          "pkg:npm/%40attach-dev/yarn-provider-consumer@3.2.1",
		requestedSpec: "npm:^3.2.0",
	},
}

func TestProviderConsumerFixturesCoverRequestedCoordinateFamilies(t *testing.T) {
	for _, tc := range providerConsumerFixtureCases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, data := readProviderConsumerFixture(t, tc.filename)

			if verdict.Package.Ecosystem != tc.ecosystem || verdict.Package.Name != tc.packageName || verdict.Package.Version != tc.version || verdict.Package.PURL != tc.purl {
				t.Fatalf("package identity = %#v, want ecosystem=%q name=%q version=%q purl=%q", verdict.Package, tc.ecosystem, tc.packageName, tc.version, tc.purl)
			}
			if verdict.Package.RequestedSpec != tc.requestedSpec || !verdict.Package.Resolved {
				t.Fatalf("package requested/resolved = %q/%t, want %q/true", verdict.Package.RequestedSpec, verdict.Package.Resolved, tc.requestedSpec)
			}
			if verdict.Decision != schema.DecisionAsk || verdict.Score == nil || *verdict.Score != 45 || verdict.Confidence != schema.ConfidenceLow {
				t.Fatalf("decision/score/confidence = %s/%v/%s, want ASK/45/LOW", verdict.Decision, verdict.Score, verdict.Confidence)
			}
			if len(verdict.Reasons) != 1 {
				t.Fatalf("expected one normalized registry-context reason, got %d", len(verdict.Reasons))
			}
			reason := verdict.Reasons[0]
			if reason.Code != reasons.RepositoryMappingUncertain || reason.DecisionEffect != schema.DecisionEffectUnknown {
				t.Fatalf("reason = %s/%s, want REPOSITORY_MAPPING_UNCERTAIN/UNKNOWN", reason.Code, reason.DecisionEffect)
			}
			if len(reason.SourceRefIDs) == 0 || len(verdict.SourceRefs) == 0 {
				t.Fatalf("fixture must preserve source refs: reason refs=%v source_refs=%d", reason.SourceRefIDs, len(verdict.SourceRefs))
			}
			assertProviderConsumerSourcePosture(t, verdict)
			assertNoBlockedProviderConsumerContent(t, string(data))
		})
	}
}

func TestProviderConsumerFixturesReplayThroughDeterministicScorer(t *testing.T) {
	for _, tc := range providerConsumerFixtureCases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, _ := readProviderConsumerFixture(t, tc.filename)
			evaluatedAt, err := time.Parse(time.RFC3339, verdict.EvaluatedAt)
			if err != nil {
				t.Fatalf("parse evaluated_at: %v", err)
			}
			ttlSeconds := verdict.TTLSeconds
			engine, err := score.NewEngine(score.Options{
				Now:           func() time.Time { return evaluatedAt },
				PolicyProfile: verdict.PolicyProfile,
				EngineVersion: verdict.EngineVersion,
				TTLSeconds:    &ttlSeconds,
			})
			if err != nil {
				t.Fatalf("NewEngine returned error: %v", err)
			}

			got, err := engine.Evaluate(score.Request{
				Package:  verdict.Package,
				Evidence: evidenceFromVerdict(t, verdict),
			})
			if err != nil {
				t.Fatalf("Evaluate returned error: %v", err)
			}

			if got.Decision != verdict.Decision || !reflect.DeepEqual(got.Score, verdict.Score) || got.Confidence != verdict.Confidence {
				t.Fatalf("scored decision/score/confidence = %s/%v/%s, want %s/%v/%s", got.Decision, got.Score, got.Confidence, verdict.Decision, verdict.Score, verdict.Confidence)
			}
			if got.PolicyProfile != verdict.PolicyProfile || got.EngineVersion != verdict.EngineVersion || got.EvaluatedAt != verdict.EvaluatedAt || got.TTLSeconds != verdict.TTLSeconds {
				t.Fatalf("scorer metadata = profile %q engine %q evaluated_at %q ttl %d, want profile %q engine %q evaluated_at %q ttl %d", got.PolicyProfile, got.EngineVersion, got.EvaluatedAt, got.TTLSeconds, verdict.PolicyProfile, verdict.EngineVersion, verdict.EvaluatedAt, verdict.TTLSeconds)
			}
			if !reflect.DeepEqual(got.Reasons, verdict.Reasons) {
				t.Fatalf("scored reasons differ\n got: %#v\nwant: %#v", got.Reasons, verdict.Reasons)
			}
			if !reflect.DeepEqual(got.SourceRefs, verdict.SourceRefs) {
				t.Fatalf("scored source_refs differ\n got: %#v\nwant: %#v", got.SourceRefs, verdict.SourceRefs)
			}
			assertProviderConsumerLimitations(t, verdict, got, tc.name)
		})
	}
}

type providerConsumerFixtureManifest struct {
	SchemaVersion string                          `json:"schema_version"`
	Description   string                          `json:"description"`
	Entries       []providerConsumerManifestEntry `json:"entries"`
}

type providerConsumerManifestEntry struct {
	ID                 string   `json:"id"`
	Fixture            string   `json:"fixture"`
	Ecosystem          string   `json:"ecosystem"`
	Package            string   `json:"package"`
	Version            string   `json:"version"`
	PURL               string   `json:"purl"`
	RequestedSpec      string   `json:"requested_spec"`
	ExpectedDecision   string   `json:"expected_decision"`
	ExpectedConfidence string   `json:"expected_confidence"`
	ReasonCodes        []string `json:"reason_codes"`
	SourceRefIDs       []string `json:"source_ref_ids"`
	ProvenancePosture  string   `json:"provenance_posture"`
}

func TestProviderConsumerFixtureManifestMatchesFixtures(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "fixtures", "manifests", "provider-consumer-v0.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	assertNoBlockedProviderConsumerContent(t, string(data))

	var manifest providerConsumerFixtureManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if manifest.SchemaVersion != "provider-consumer-fixture-manifest/v0" {
		t.Fatalf("schema_version = %q", manifest.SchemaVersion)
	}
	if len(manifest.Entries) != len(providerConsumerFixtureCases) {
		t.Fatalf("manifest entries = %d, want %d", len(manifest.Entries), len(providerConsumerFixtureCases))
	}

	seen := map[string]bool{}
	for _, entry := range manifest.Entries {
		if entry.ID == "" || entry.Fixture == "" || entry.ProvenancePosture != "offline-normalized-public-fixture" {
			t.Fatalf("manifest entry missing identity/provenance posture: %+v", entry)
		}
		if seen[entry.ID] {
			t.Fatalf("duplicate manifest id %q", entry.ID)
		}
		seen[entry.ID] = true
		if !strings.HasPrefix(entry.Fixture, "fixtures/v0/") || strings.Contains(entry.Fixture, "..") {
			t.Fatalf("manifest fixture path must stay under fixtures/v0: %q", entry.Fixture)
		}

		verdict, _ := readProviderConsumerFixture(t, strings.TrimPrefix(entry.Fixture, "fixtures/v0/"))
		if entry.Ecosystem != verdict.Package.Ecosystem || entry.Package != verdict.Package.Name || entry.Version != verdict.Package.Version || entry.PURL != verdict.Package.PURL || entry.RequestedSpec != verdict.Package.RequestedSpec {
			t.Fatalf("manifest package identity mismatch for %q", entry.ID)
		}
		if entry.ExpectedDecision != string(verdict.Decision) || entry.ExpectedConfidence != string(verdict.Confidence) {
			t.Fatalf("manifest expected verdict mismatch for %q", entry.ID)
		}
		if !reflect.DeepEqual(entry.ReasonCodes, reasonCodes(verdict)) || !reflect.DeepEqual(entry.SourceRefIDs, sourceRefIDs(verdict)) {
			t.Fatalf("manifest provenance mismatch for %q", entry.ID)
		}
	}
}

func reasonCodes(verdict schema.Verdict) []string {
	codes := make([]string, 0, len(verdict.Reasons))
	for _, reason := range verdict.Reasons {
		codes = append(codes, reason.Code)
	}
	return codes
}

func sourceRefIDs(verdict schema.Verdict) []string {
	ids := make([]string, 0, len(verdict.SourceRefs))
	for _, ref := range verdict.SourceRefs {
		ids = append(ids, ref.ID)
	}
	return ids
}

func readProviderConsumerFixture(t *testing.T, filename string) (schema.Verdict, []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "fixtures", "v0", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if _, err := ValidateBytes(path, data); err != nil {
		t.Fatalf("fixture failed validation: %v", err)
	}
	var verdict schema.Verdict
	if err := json.Unmarshal(data, &verdict); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return verdict, data
}

func evidenceFromVerdict(t *testing.T, verdict schema.Verdict) []schema.Evidence {
	t.Helper()
	refsByID := map[string]schema.SourceRef{}
	for _, ref := range verdict.SourceRefs {
		refsByID[ref.ID] = ref
	}

	evidence := make([]schema.Evidence, 0, len(verdict.Reasons))
	for _, reason := range verdict.Reasons {
		refs := make([]schema.SourceRef, 0, len(reason.SourceRefIDs))
		for _, id := range reason.SourceRefIDs {
			ref, ok := refsByID[id]
			if !ok {
				t.Fatalf("reason %q references missing source_ref %q", reason.Code, id)
			}
			refs = append(refs, ref)
		}
		item := schema.Evidence{Reason: reason}
		if len(refs) > 0 {
			item.SourceRef = &refs[0]
			item.SourceRefs = refs[1:]
		}
		evidence = append(evidence, item)
	}
	return evidence
}

func assertProviderConsumerSourcePosture(t *testing.T, verdict schema.Verdict) {
	t.Helper()
	for _, ref := range verdict.SourceRefs {
		if !ref.AttributionRequired {
			t.Fatalf("source_ref %q must preserve attribution_required=true", ref.ID)
		}
		if ref.LicenseOrTermsURL == "" || ref.Attribution == "" {
			t.Fatalf("source_ref %q missing terms or attribution", ref.ID)
		}
		if ref.Redistribution != "unknown" || ref.PublicDisplay != "allowed" {
			t.Fatalf("source_ref %q posture = %s/%s, want unknown/allowed", ref.ID, ref.Redistribution, ref.PublicDisplay)
		}
	}
	details := verdict.Reasons[0].Details
	for _, key := range []string{"request_posture", "terms_url", "redistribution", "public_display"} {
		if _, ok := details[key]; !ok {
			t.Fatalf("reason details missing %q", key)
		}
	}
}

func assertProviderConsumerLimitations(t *testing.T, verdict schema.Verdict, scored schema.Verdict, caseName string) {
	t.Helper()
	if len(verdict.Limitations) < 3 {
		t.Fatalf("provider-consumer fixture should preserve base plus source-specific limitations, got %#v", verdict.Limitations)
	}
	for _, limitation := range scored.Limitations {
		found := false
		for _, fixtureLimitation := range verdict.Limitations {
			if fixtureLimitation == limitation {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("fixture limitations %#v do not include scorer limitation %q", verdict.Limitations, limitation)
		}
	}
	joined := strings.ToLower(strings.Join(verdict.Limitations, "\n"))
	for _, want := range []string{"synthetic", "not a real package evaluation", "hosted cache"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("fixture limitations %#v missing %q", verdict.Limitations, want)
		}
	}
	perCase := map[string][]string{
		"npm":                          {"registry", "attribution", "redistribution"},
		"pypi":                         {"pypi", "personal contact", "raw upstream"},
		"crates":                       {"crates.io", "dependency-resolution", "standalone allow"},
		"go module":                    {"go module", "direct vcs", "standalone allow"},
		"yarn consumer npm coordinate": {"yarn", "npm package coordinates", "lockfile"},
	}
	for _, want := range perCase[caseName] {
		if !strings.Contains(joined, want) {
			t.Fatalf("fixture limitations for %q missing source-specific caveat %q: %#v", caseName, want, verdict.Limitations)
		}
	}
}

func assertNoBlockedProviderConsumerContent(t *testing.T, data string) {
	t.Helper()
	lower := strings.ToLower(data)
	for _, blocked := range []string{"socket score", "snyk score", "aikido score", "sonatype score", "endor score", "oauth", "password", "private package"} {
		if strings.Contains(lower, blocked) {
			t.Fatalf("provider-consumer fixture contains blocked marker %q", blocked)
		}
	}
	for _, rawField := range []string{`"dist-tags"`, `"_last-serial"`, `"info"`, `"releases"`, `"urls"`, `"deps"`, `"cksum"`, `"vers"`, `"go_mod"`} {
		if strings.Contains(lower, rawField) {
			t.Fatalf("provider-consumer fixture contains raw upstream field marker %s", rawField)
		}
	}
}
