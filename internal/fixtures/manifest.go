package fixtures

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
)

const (
	ProviderConsumerManifestVersion   = "provider-consumer-fixture-manifest/v0"
	ProviderConsumerProvenancePosture = "offline-normalized-public-fixture"
	providerConsumerFixturePathPrefix = "fixtures/v0/"
)

type ProviderConsumerManifest struct {
	SchemaVersion string                          `json:"schema_version"`
	Description   string                          `json:"description"`
	Entries       []ProviderConsumerManifestEntry `json:"entries"`
}

type ProviderConsumerManifestEntry struct {
	ID                 string            `json:"id"`
	Fixture            string            `json:"fixture"`
	Ecosystem          string            `json:"ecosystem"`
	Package            string            `json:"package"`
	Version            string            `json:"version"`
	PURL               string            `json:"purl"`
	RequestedSpec      string            `json:"requested_spec"`
	ExpectedDecision   schema.Decision   `json:"expected_decision"`
	ExpectedConfidence schema.Confidence `json:"expected_confidence"`
	ReasonCodes        []string          `json:"reason_codes"`
	SourceRefIDs       []string          `json:"source_ref_ids"`
	ProvenancePosture  string            `json:"provenance_posture"`
}

func LoadProviderConsumerManifest(root, manifestPath string) (ProviderConsumerManifest, error) {
	if root == "" {
		root = "."
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return ProviderConsumerManifest{}, fmt.Errorf("read provider-consumer manifest %s: %w", manifestPath, err)
	}

	manifest, err := decodeProviderConsumerManifest(data)
	if err != nil {
		return ProviderConsumerManifest{}, err
	}
	if err := validateProviderConsumerManifest(root, manifest); err != nil {
		return ProviderConsumerManifest{}, err
	}
	return manifest, nil
}

func decodeProviderConsumerManifest(data []byte) (ProviderConsumerManifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var manifest ProviderConsumerManifest
	if err := decoder.Decode(&manifest); err != nil {
		return ProviderConsumerManifest{}, fmt.Errorf("invalid provider-consumer manifest JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ProviderConsumerManifest{}, fmt.Errorf("invalid provider-consumer manifest JSON: trailing data after manifest object")
	}
	return manifest, nil
}

func validateProviderConsumerManifest(root string, manifest ProviderConsumerManifest) error {
	if manifest.SchemaVersion != ProviderConsumerManifestVersion {
		return fmt.Errorf("schema_version must be %q", ProviderConsumerManifestVersion)
	}
	if strings.TrimSpace(manifest.Description) == "" {
		return errors.New("description must be non-empty")
	}
	if len(manifest.Entries) == 0 {
		return errors.New("entries must contain at least one entry")
	}

	seenIDs := map[string]struct{}{}
	for i, entry := range manifest.Entries {
		label := fmt.Sprintf("entries[%d]", i)
		if entry.ID != "" {
			label = fmt.Sprintf("entries[%d] %q", i, entry.ID)
		}
		if err := validateProviderConsumerManifestEntry(root, label, entry); err != nil {
			return err
		}
		if _, exists := seenIDs[entry.ID]; exists {
			return fmt.Errorf("%s id is duplicated", label)
		}
		seenIDs[entry.ID] = struct{}{}
	}
	return nil
}

func validateProviderConsumerManifestEntry(root, label string, entry ProviderConsumerManifestEntry) error {
	if entry.ID == "" {
		return fmt.Errorf("%s id must be non-empty", label)
	}
	if entry.Ecosystem == "" || entry.Package == "" || entry.Version == "" || entry.PURL == "" || entry.RequestedSpec == "" {
		return fmt.Errorf("%s package identity fields must be non-empty", label)
	}
	fixturePath, err := cleanProviderConsumerFixturePath(entry.Fixture)
	if err != nil {
		return fmt.Errorf("%s fixture %w", label, err)
	}
	if fixturePath != entry.Fixture {
		return fmt.Errorf("%s fixture must be normalized under fixtures/v0/: %q", label, entry.Fixture)
	}
	if !validDecision(entry.ExpectedDecision) {
		return fmt.Errorf("%s expected_decision must be one of ALLOW, ASK, DENY, UNKNOWN; got %q", label, entry.ExpectedDecision)
	}
	if !validConfidence(entry.ExpectedConfidence) {
		return fmt.Errorf("%s expected_confidence must be LOW, MEDIUM, or HIGH; got %q", label, entry.ExpectedConfidence)
	}
	if err := validateReasonCodes(label, entry.ReasonCodes); err != nil {
		return err
	}
	if err := validateSourceRefIDs(label, entry.SourceRefIDs); err != nil {
		return err
	}
	if entry.ProvenancePosture != ProviderConsumerProvenancePosture {
		return fmt.Errorf("%s provenance_posture must be %q", label, ProviderConsumerProvenancePosture)
	}

	verdict, err := readManifestFixture(root, fixturePath)
	if err != nil {
		return fmt.Errorf("%s fixture %q: %w", label, fixturePath, err)
	}
	if err := validateManifestEntryMatchesVerdict(label, entry, verdict); err != nil {
		return err
	}
	return nil
}

func cleanProviderConsumerFixturePath(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", errors.New("must be non-empty")
	}
	if strings.Contains(value, "\\") || path.IsAbs(value) {
		return "", fmt.Errorf("must stay under fixtures/v0/: %q", value)
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return "", fmt.Errorf("must stay under fixtures/v0/: %q", value)
		}
	}
	clean := path.Clean(value)
	if !strings.HasPrefix(clean, providerConsumerFixturePathPrefix) {
		return "", fmt.Errorf("must stay under fixtures/v0/: %q", value)
	}
	return clean, nil
}

func validateReasonCodes(label string, codes []string) error {
	if len(codes) == 0 {
		return fmt.Errorf("%s reason_codes must contain at least one code", label)
	}
	seen := map[string]struct{}{}
	for _, code := range codes {
		if code == "" {
			return fmt.Errorf("%s reason_codes entries must be non-empty", label)
		}
		if !reasons.IsKnown(code) && !strings.HasPrefix(code, "X_") {
			return fmt.Errorf("%s reason_codes contains unknown reason code %q", label, code)
		}
		if _, exists := seen[code]; exists {
			return fmt.Errorf("%s reason_codes contains duplicate %q", label, code)
		}
		seen[code] = struct{}{}
	}
	return nil
}

func validateSourceRefIDs(label string, ids []string) error {
	if len(ids) == 0 {
		return fmt.Errorf("%s source_ref_ids must contain at least one id", label)
	}
	seen := map[string]struct{}{}
	for _, id := range ids {
		if id == "" {
			return fmt.Errorf("%s source_ref_ids entries must be non-empty", label)
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("%s source_ref_ids contains duplicate %q", label, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

func readManifestFixture(root, fixturePath string) (schema.Verdict, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(fixturePath)))
	if err != nil {
		return schema.Verdict{}, err
	}
	if _, err := ValidateBytes(fixturePath, data); err != nil {
		return schema.Verdict{}, err
	}

	var verdict schema.Verdict
	if err := json.Unmarshal(data, &verdict); err != nil {
		return schema.Verdict{}, fmt.Errorf("unmarshal validated verdict: %w", err)
	}
	return verdict, nil
}

func validateManifestEntryMatchesVerdict(label string, entry ProviderConsumerManifestEntry, verdict schema.Verdict) error {
	if entry.Ecosystem != verdict.Package.Ecosystem || entry.Package != verdict.Package.Name || entry.Version != verdict.Package.Version || entry.PURL != verdict.Package.PURL || entry.RequestedSpec != verdict.Package.RequestedSpec {
		return fmt.Errorf("%s package identity does not match referenced fixture", label)
	}
	if entry.ExpectedDecision != verdict.Decision {
		return fmt.Errorf("%s expected_decision %q does not match referenced fixture decision %q", label, entry.ExpectedDecision, verdict.Decision)
	}
	if entry.ExpectedConfidence != verdict.Confidence {
		return fmt.Errorf("%s expected_confidence %q does not match referenced fixture confidence %q", label, entry.ExpectedConfidence, verdict.Confidence)
	}
	if got := manifestReasonCodes(verdict); !reflect.DeepEqual(entry.ReasonCodes, got) {
		return fmt.Errorf("%s reason_codes %v do not match referenced fixture reason codes %v", label, entry.ReasonCodes, got)
	}
	if got := manifestSourceRefIDs(verdict); !reflect.DeepEqual(entry.SourceRefIDs, got) {
		return fmt.Errorf("%s source_ref_ids %v do not match referenced fixture source refs %v", label, entry.SourceRefIDs, got)
	}
	return nil
}

func manifestReasonCodes(verdict schema.Verdict) []string {
	codes := make([]string, 0, len(verdict.Reasons))
	for _, reason := range verdict.Reasons {
		codes = append(codes, reason.Code)
	}
	return codes
}

func manifestSourceRefIDs(verdict schema.Verdict) []string {
	ids := make([]string, 0, len(verdict.SourceRefs))
	for _, ref := range verdict.SourceRefs {
		ids = append(ids, ref.ID)
	}
	return ids
}
