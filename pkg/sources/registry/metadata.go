package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/sources"
)

const (
	DefaultTTLSeconds = 86400

	SourceName        = "registry-metadata"
	licenseOrTermsURL = "https://github.com/attach-dev/attach-open-score/blob/main/docs/SOURCES.md#public-registry-metadata"
)

var sourceRefIDReplacer = regexp.MustCompile(`[^a-z0-9._-]+`)

type Options struct {
	Now        func() time.Time
	TTLSeconds int
}

type Adapter struct {
	now        func() time.Time
	ttlSeconds int
}

type Coordinate struct {
	Ecosystem string
	Name      string
	Version   string
}

type Metadata struct {
	Ecosystem     string
	Name          string
	Version       string
	RepositoryURL string
	Repository    Repository
	Links         map[string]string
	Source        string
	SourceID      string
	SourceURL     string
	RetrievedAt   string
	TTLSeconds    int
}

type Repository struct {
	Type      string
	URL       string
	Directory string
}

type Result struct {
	Package       Coordinate
	RepositoryURL string
	Confidence    schema.Confidence
	Trusted       bool
	Reason        string
	SourceRef     schema.SourceRef
}

func NewAdapter(options Options) (Adapter, error) {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	ttlSeconds := options.TTLSeconds
	if ttlSeconds == 0 {
		ttlSeconds = DefaultTTLSeconds
	}
	if ttlSeconds < 0 {
		return Adapter{}, fmt.Errorf("registry metadata ttl_seconds must be non-negative")
	}
	return Adapter{now: now, ttlSeconds: ttlSeconds}, nil
}

func (a Adapter) Evidence(coordinate Coordinate, records []Metadata) ([]schema.Evidence, error) {
	if len(records) == 0 {
		ref := a.sourceRef(coordinate, Metadata{})
		return []schema.Evidence{a.unknownEvidence(ref, coordinate, "missing_metadata", "No registry metadata record was provided.", nil)}, nil
	}

	results := make([]Result, 0, len(records))
	for _, record := range records {
		result, err := a.Normalize(coordinate, record)
		if err != nil {
			ref := a.sourceRef(coordinate, record)
			return []schema.Evidence{a.unknownEvidence(ref, coordinate, "invalid_repository_url", err.Error(), map[string]any{"source": normalizedSource(record.Source)})}, nil
		}
		results = append(results, result)
	}

	unique := map[string]Result{}
	for _, result := range results {
		if result.RepositoryURL != "" {
			unique[result.RepositoryURL] = result
		}
	}
	if len(unique) == 0 {
		ref := results[0].SourceRef
		return []schema.Evidence{a.unknownEvidence(ref, coordinate, "missing_repository", "Registry metadata does not include a repository URL.", map[string]any{"confidence": schema.ConfidenceLow})}, nil
	}
	if len(unique) > 1 {
		urls := make([]string, 0, len(unique))
		refs := make([]schema.SourceRef, 0, len(results))
		for repositoryURL := range unique {
			urls = append(urls, repositoryURL)
		}
		for _, result := range results {
			refs = append(refs, result.SourceRef)
		}
		sort.Strings(urls)
		return []schema.Evidence{a.unknownEvidenceFromRefs(refs, "ambiguous_repository", "Registry metadata contains multiple repository URLs; mapping is non-authoritative.", map[string]any{"repository_urls": urls, "confidence": schema.ConfidenceLow})}, nil
	}

	var result Result
	for _, value := range unique {
		result = value
	}
	refs := make([]schema.SourceRef, 0, len(results))
	for _, result := range results {
		refs = append(refs, result.SourceRef)
	}
	evidence := schema.Evidence{
		Reason: schema.Reason{
			Code:           reasons.RepositoryMappingUncertain,
			Severity:       "MEDIUM",
			DecisionEffect: schema.DecisionEffectUnknown,
			Message:        "Registry metadata maps the package to a repository URL for future OpenSSF Scorecard evaluation; mapping is not an allow/deny signal.",
			SourceRefIDs:   sourceRefIDs(refs),
			Details: map[string]any{
				"repository_url": result.RepositoryURL,
				"confidence":     result.Confidence,
				"trusted":        result.Trusted,
				"reason":         result.Reason,
			},
		},
		SourceRefs: refs,
	}
	if len(refs) == 1 {
		evidence.SourceRef = &refs[0]
	}
	return []schema.Evidence{evidence}, nil
}

func (a Adapter) Normalize(coordinate Coordinate, record Metadata) (Result, error) {
	merged := Coordinate{
		Ecosystem: firstNonEmpty(record.Ecosystem, coordinate.Ecosystem),
		Name:      firstNonEmpty(record.Name, coordinate.Name),
		Version:   firstNonEmpty(record.Version, coordinate.Version),
	}
	repositoryCandidate := firstNonEmpty(record.RepositoryURL, record.Repository.URL, linkValue(record.Links, "repository"), linkValue(record.Links, "homepage"))
	ref := a.sourceRef(merged, record)
	if strings.TrimSpace(repositoryCandidate) == "" {
		return Result{Package: merged, Confidence: schema.ConfidenceLow, Trusted: false, Reason: "missing_repository", SourceRef: ref}, nil
	}
	repositoryURL, err := NormalizeRepositoryURL(repositoryCandidate)
	if err != nil {
		return Result{}, err
	}
	confidence, trusted, reason := confidenceForRepository(record, repositoryCandidate, repositoryURL)
	return Result{Package: merged, RepositoryURL: repositoryURL, Confidence: confidence, Trusted: trusted, Reason: reason, SourceRef: ref}, nil
}

func NormalizeRepositoryURL(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("repository URL is empty")
	}
	value = strings.TrimPrefix(value, "git+")
	value = strings.TrimSuffix(value, ".git")
	if strings.HasPrefix(value, "git://") {
		value = "https://" + strings.TrimPrefix(value, "git://")
	}
	if strings.HasPrefix(value, "ssh://git@") {
		sshValue := strings.TrimPrefix(value, "ssh://git@")
		parts := strings.SplitN(sshValue, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", fmt.Errorf("unsupported git ssh repository URL %q", raw)
		}
		value = "https://" + parts[0] + "/" + parts[1]
	}
	if strings.HasPrefix(value, "git@") {
		parts := strings.SplitN(strings.TrimPrefix(value, "git@"), ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", fmt.Errorf("unsupported git ssh repository URL %q", raw)
		}
		value = "https://" + parts[0] + "/" + parts[1]
	}
	if strings.HasPrefix(value, "github:") {
		value = "https://github.com/" + strings.TrimPrefix(value, "github:")
	}
	if strings.HasPrefix(value, "http://") {
		value = "https://" + strings.TrimPrefix(value, "http://")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("repository URL must include a scheme and host")
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("repository URL must normalize to https")
	}
	parsed.Host = strings.ToLower(parsed.Host)
	if parsed.User != nil {
		return "", fmt.Errorf("repository URL must not include userinfo")
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.Path = strings.TrimRight(parsed.EscapedPath(), "/")
	parsed.Path = strings.TrimSuffix(parsed.Path, ".git")
	if parsed.Path == "" || parsed.Path == "/" {
		return "", fmt.Errorf("repository URL must include an owner/repository path")
	}
	return parsed.String(), nil
}

func (a Adapter) unknownEvidence(ref schema.SourceRef, coordinate Coordinate, reason, message string, details map[string]any) schema.Evidence {
	return a.unknownEvidenceFromRefs([]schema.SourceRef{ref}, reason, message, details)
}

func (a Adapter) unknownEvidenceFromRefs(refs []schema.SourceRef, reason, message string, details map[string]any) schema.Evidence {
	if details == nil {
		details = map[string]any{}
	}
	details["reason"] = reason
	ids := sourceRefIDs(refs)
	evidence := schema.Evidence{
		Reason: schema.Reason{
			Code:           reasons.RepositoryMappingUncertain,
			Severity:       "MEDIUM",
			DecisionEffect: schema.DecisionEffectUnknown,
			Message:        message,
			SourceRefIDs:   ids,
			Details:        details,
		},
		SourceRefs: refs,
	}
	if len(refs) == 1 {
		evidence.SourceRef = &refs[0]
	}
	return evidence
}

func (a Adapter) sourceRef(coordinate Coordinate, record Metadata) schema.SourceRef {
	retrievedAt := a.now().UTC()
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(record.RetrievedAt)); err == nil {
		retrievedAt = parsed.UTC()
	}
	ttl := a.ttlSeconds
	if record.TTLSeconds > 0 {
		ttl = record.TTLSeconds
	}
	source := normalizedSource(record.Source)
	sourceID := firstNonEmpty(record.SourceID, stableSourceID(coordinate, record))
	fallbackURL := "https://example.invalid/attach-open-score/registry-metadata/" + sourceID
	sourceURL := sanitizeSourceURL(record.SourceURL, fallbackURL)
	return schema.SourceRef{
		ID:                  sourceRefID(source, sourceID),
		Source:              source,
		SourceID:            sourceID,
		URL:                 sourceURL,
		RetrievedAt:         retrievedAt.Format(time.RFC3339),
		TTLSeconds:          ttl,
		LicenseOrTermsURL:   licenseOrTermsURL,
		Attribution:         attributionForSource(source),
		AttributionRequired: true,
		Redistribution:      sources.RedistributionUnknown,
		PublicDisplay:       sources.PublicDisplayAllowed,
	}
}

func sourceRefIDs(refs []schema.SourceRef) []string {
	ids := make([]string, 0, len(refs))
	seen := map[string]struct{}{}
	for _, ref := range refs {
		if _, ok := seen[ref.ID]; ok {
			continue
		}
		seen[ref.ID] = struct{}{}
		ids = append(ids, ref.ID)
	}
	return ids
}

func sanitizeSourceURL(raw, fallback string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return fallback
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fallback
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func confidenceForRepository(record Metadata, raw, normalized string) (schema.Confidence, bool, string) {
	if normalized == "" {
		return schema.ConfidenceLow, false, "missing_repository"
	}
	if strings.Contains(raw, " ") {
		return schema.ConfidenceLow, false, "contains_whitespace"
	}
	if strings.EqualFold(record.Repository.Type, "git") || strings.Contains(normalized, "github.com/") || strings.Contains(normalized, "gitlab.com/") {
		return schema.ConfidenceMedium, false, "normalized_registry_repository"
	}
	return schema.ConfidenceLow, false, "weak_repository_hint"
}

func normalizedSource(source string) string {
	source = strings.ToLower(strings.TrimSpace(source))
	source = strings.ReplaceAll(source, "_", "-")
	if source == "" {
		return SourceName
	}
	return source
}

func attributionForSource(source string) string {
	switch source {
	case "npm", "pypi", "go", "crates", "crates.io":
		return "Synthetic registry metadata fixture for Attach Open Score tests; review registry-specific terms before using real metadata."
	default:
		return "Synthetic package metadata fixture for Attach Open Score tests; review source terms before using real metadata."
	}
}

func sourceRefID(source, sourceID string) string {
	value := strings.ToLower(source + "-" + sourceID)
	value = sourceRefIDReplacer.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	if value == "" {
		return "registry-metadata-unknown"
	}
	return value
}

func stableSourceID(coordinate Coordinate, record Metadata) string {
	parts := []string{coordinate.Ecosystem, coordinate.Name, coordinate.Version, record.RepositoryURL, record.Repository.URL, record.Source}
	keys := make([]string, 0, len(record.Links))
	for key := range record.Links {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, key+"="+record.Links[key])
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])[:16]
}

func linkValue(links map[string]string, key string) string {
	if links == nil {
		return ""
	}
	for candidate, value := range links {
		if strings.EqualFold(candidate, key) {
			return value
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
