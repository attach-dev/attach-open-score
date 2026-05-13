package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/sources"
)

const (
	npmSourceName     = "npm-registry"
	npmTermsURL       = "https://docs.npmjs.com/policies/terms/"
	npmRegistryBase   = "https://registry.npmjs.org"
	npmRequestPosture = "fixture_first_documented_registry_metadata_only_no_live_calls_no_website_crawling_no_audit_security_data"
)

type NPMOptions struct {
	Now        func() time.Time
	TTLSeconds int
}

type NPMAdapter struct {
	now        func() time.Time
	ttlSeconds int
}

type npmMetadata struct {
	Name       string                        `json:"name,omitempty"`
	Version    string                        `json:"version,omitempty"`
	DistTags   map[string]string             `json:"dist-tags,omitempty"`
	Versions   map[string]npmVersionMetadata `json:"versions,omitempty"`
	Time       map[string]string             `json:"time,omitempty"`
	License    npmLicense                    `json:"license,omitempty"`
	Repository npmRepository                 `json:"repository,omitempty"`
	Homepage   string                        `json:"homepage,omitempty"`
	Deprecated string                        `json:"deprecated,omitempty"`
}

type npmVersionMetadata struct {
	Name       string        `json:"name,omitempty"`
	Version    string        `json:"version,omitempty"`
	License    npmLicense    `json:"license,omitempty"`
	Repository npmRepository `json:"repository,omitempty"`
	Homepage   string        `json:"homepage,omitempty"`
	Deprecated string        `json:"deprecated,omitempty"`
}

type npmLicense struct {
	Value string
}

type npmRepository struct {
	Type      string
	URL       string
	Directory string
}

type npmNormalized struct {
	Name                  string
	Version               string
	PURL                  string
	SelectedVersionSource string
	IsPackument           bool
	DistTags              map[string]string
	LatestDistTag         string
	PackageCreatedAt      string
	PackageModifiedAt     string
	VersionPublishedAt    string
	License               string
	LicenseStatus         string
	LicenseReported       bool
	RepositoryURL         string
	RepositoryStatus      string
	RepositoryReported    bool
	Deprecated            bool
	DeprecationMessage    string
}

type npmValidation struct {
	ok          bool
	failureKind string
	missing     []string
	conflicts   []string
}

func NewNPMAdapter(options NPMOptions) (NPMAdapter, error) {
	now := options.Now
	if now == nil {
		now = time.Now
	}

	ttlSeconds := options.TTLSeconds
	if ttlSeconds == 0 {
		ttlSeconds = DefaultTTLSeconds
	}
	if ttlSeconds < 0 {
		return NPMAdapter{}, fmt.Errorf("npm registry ttl_seconds must be non-negative")
	}

	return NPMAdapter{
		now:        now,
		ttlSeconds: ttlSeconds,
	}, nil
}

func (a NPMAdapter) EvidenceFromJSON(data []byte, coordinate Coordinate) ([]schema.Evidence, error) {
	sourceRef := a.localJSONSourceRef(data)
	metadata, err := parseNPMMetadata(data)
	if err != nil {
		return []schema.Evidence{a.sourceUnavailableEvidence(sourceRef, nil, "parse_failure", map[string]any{
			"parse_error": err.Error(),
		})}, nil
	}

	return a.evidence(metadata, coordinate, sourceRef), nil
}

func parseNPMMetadata(data []byte) (npmMetadata, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return npmMetadata{}, errors.New("empty npm registry metadata JSON")
	}
	if data[0] == '[' {
		return npmMetadata{}, errors.New("npm registry metadata JSON must be an object")
	}

	var metadata npmMetadata
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&metadata); err != nil {
		return npmMetadata{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return npmMetadata{}, errors.New("npm registry metadata JSON contains trailing data")
	}
	return metadata, nil
}

func (l *npmLicense) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		l.Value = strings.TrimSpace(value)
		return nil
	}

	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}
	for _, key := range []string{"type", "spdx_id", "spdx", "id", "license", "name"} {
		if value, ok := object[key].(string); ok {
			if value = strings.TrimSpace(value); value != "" {
				l.Value = value
				return nil
			}
		}
	}
	return nil
}

func (r *npmRepository) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		r.URL = strings.TrimSpace(value)
		return nil
	}

	var object struct {
		Type      string `json:"type,omitempty"`
		URL       string `json:"url,omitempty"`
		Directory string `json:"directory,omitempty"`
	}
	if err := json.Unmarshal(data, &object); err != nil {
		return err
	}
	r.Type = strings.TrimSpace(object.Type)
	r.URL = strings.TrimSpace(object.URL)
	r.Directory = strings.TrimSpace(object.Directory)
	return nil
}

func (a NPMAdapter) evidence(metadata npmMetadata, coordinate Coordinate, fallbackSourceRef schema.SourceRef) []schema.Evidence {
	normalized, validation := normalizeNPMMetadata(metadata, coordinate)
	if !validation.ok {
		return []schema.Evidence{a.sourceUnavailableEvidence(fallbackSourceRef, nil, validation.failureKind, validation.details())}
	}

	sourceRefs := a.sourceRefs(normalized)
	details := a.metadataDetails(normalized, sourceRefs)

	evidence := []schema.Evidence{npmEvidenceWithSourceRefs(schema.Reason{
		Code:           reasons.RepositoryMappingUncertain,
		Severity:       "MEDIUM",
		DecisionEffect: schema.DecisionEffectUnknown,
		Message:        fmt.Sprintf("npm public registry metadata for %s@%s was normalized as non-authoritative package context only.", normalized.Name, normalized.Version),
		SourceRefIDs:   sourceRefIDs(sourceRefs),
		Details:        details,
	}, sourceRefs)}

	if normalized.Deprecated {
		versionRef := sourceRefs[0]
		evidence = append(evidence, npmEvidenceWithSourceRefs(schema.Reason{
			Code:           reasons.DeprecatedPackage,
			Severity:       "MEDIUM",
			DecisionEffect: schema.DecisionEffectAsk,
			Message:        fmt.Sprintf("npm public registry metadata marks %s@%s as deprecated.", normalized.Name, normalized.Version),
			SourceRefIDs:   []string{versionRef.ID},
			Details:        a.deprecatedDetails(normalized),
		}, []schema.SourceRef{versionRef}))
	}

	return evidence
}

func normalizeNPMMetadata(metadata npmMetadata, coordinate Coordinate) (npmNormalized, npmValidation) {
	isPackument := len(metadata.Versions) > 0 || len(metadata.DistTags) > 0 || len(metadata.Time) > 0
	selectedVersion, selectedVersionSource := selectNPMVersion(metadata, coordinate)
	selected, hasSelected := selectedNPMVersionMetadata(metadata, selectedVersion)

	conflicts := []string{}
	if coordinate.Ecosystem != "" && !strings.EqualFold(strings.TrimSpace(coordinate.Ecosystem), "npm") {
		conflicts = append(conflicts, "coordinate.ecosystem")
	}

	name := strings.TrimSpace(coordinate.Name)
	addNPMIdentityValue(&name, &conflicts, "packument.name", metadata.Name)
	if hasSelected {
		addNPMIdentityValue(&name, &conflicts, selectedVersionField(selectedVersion, "name"), selected.Name)
	}

	version := strings.TrimSpace(selectedVersion)
	if hasSelected {
		addNPMVersionValue(&version, &conflicts, selectedVersionField(selectedVersion, "version"), selected.Version)
	}

	if len(conflicts) > 0 {
		return npmNormalized{}, npmValidation{failureKind: "conflicting_required_data", conflicts: conflicts}
	}

	metadataHasName := strings.TrimSpace(metadata.Name) != ""
	metadataHasVersion := strings.TrimSpace(metadata.Version) != "" || hasSelected

	missing := []string{}
	if name == "" || !metadataHasName {
		missing = append(missing, "name")
	}
	if version == "" || !metadataHasVersion || (isPackument && !hasSelected) {
		missing = append(missing, "version")
	}
	if len(missing) > 0 {
		return npmNormalized{}, npmValidation{failureKind: "missing_required_data", missing: missing}
	}

	license, licenseStatus, licenseReported := npmLicenseDetails(selected, metadata)
	repositoryURL, repositoryStatus, repositoryReported := npmRepositoryDetails(selected, metadata)
	deprecationMessage := strings.TrimSpace(firstNonEmpty(selected.Deprecated, metadata.Deprecated))

	distTags := normalizeNPMDistTags(metadata.DistTags)
	normalized := npmNormalized{
		Name:                  name,
		Version:               version,
		PURL:                  npmPURL(name, version),
		SelectedVersionSource: selectedVersionSource,
		IsPackument:           isPackument,
		DistTags:              distTags,
		LatestDistTag:         strings.TrimSpace(distTags["latest"]),
		PackageCreatedAt:      strings.TrimSpace(metadata.Time["created"]),
		PackageModifiedAt:     strings.TrimSpace(metadata.Time["modified"]),
		VersionPublishedAt:    strings.TrimSpace(metadata.Time[version]),
		License:               license,
		LicenseStatus:         licenseStatus,
		LicenseReported:       licenseReported,
		RepositoryURL:         repositoryURL,
		RepositoryStatus:      repositoryStatus,
		RepositoryReported:    repositoryReported,
		Deprecated:            deprecationMessage != "",
		DeprecationMessage:    deprecationMessage,
	}
	return normalized, npmValidation{ok: true}
}

func selectNPMVersion(metadata npmMetadata, coordinate Coordinate) (string, string) {
	if version := strings.TrimSpace(coordinate.Version); version != "" {
		return version, "requested_version"
	}
	if version := strings.TrimSpace(metadata.Version); version != "" {
		return version, "version_metadata"
	}
	if latest := strings.TrimSpace(metadata.DistTags["latest"]); latest != "" {
		if _, ok := metadata.Versions[latest]; ok {
			return latest, "dist-tags.latest"
		}
	}
	if len(metadata.Versions) == 1 {
		for version := range metadata.Versions {
			return strings.TrimSpace(version), "single_version"
		}
	}
	return "", ""
}

func selectedNPMVersionMetadata(metadata npmMetadata, version string) (npmVersionMetadata, bool) {
	version = strings.TrimSpace(version)
	if version == "" {
		return npmVersionMetadata{}, false
	}
	if len(metadata.Versions) > 0 {
		selected, ok := metadata.Versions[version]
		return selected, ok
	}
	if metadata.Version != "" {
		return npmVersionMetadata{
			Name:       metadata.Name,
			Version:    metadata.Version,
			License:    metadata.License,
			Repository: metadata.Repository,
			Homepage:   metadata.Homepage,
			Deprecated: metadata.Deprecated,
		}, true
	}
	return npmVersionMetadata{}, false
}

func selectedVersionField(version, field string) string {
	if strings.TrimSpace(version) == "" {
		return "version." + field
	}
	return fmt.Sprintf("versions[%s].%s", version, field)
}

func addNPMIdentityValue(current *string, conflicts *[]string, field, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if *current == "" {
		*current = value
		return
	}
	if *current != value {
		*conflicts = append(*conflicts, field)
	}
}

func addNPMVersionValue(current *string, conflicts *[]string, field, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if *current == "" {
		*current = value
		return
	}
	if *current != value {
		*conflicts = append(*conflicts, field)
	}
}

func npmLicenseDetails(selected npmVersionMetadata, metadata npmMetadata) (string, string, bool) {
	license := strings.TrimSpace(firstNonEmpty(selected.License.Value, metadata.License.Value))
	if license == "" {
		return "", "not_reported", false
	}
	return license, "reported_by_npm_registry", true
}

func npmRepositoryDetails(selected npmVersionMetadata, metadata npmMetadata) (string, string, bool) {
	raw := firstNonEmpty(selected.Repository.URL, metadata.Repository.URL)
	if strings.TrimSpace(raw) == "" {
		return "", "not_reported", false
	}
	normalized, err := NormalizeRepositoryURL(raw)
	if err != nil {
		return "", "invalid_or_sensitive", true
	}
	return normalized, "reported_by_npm_registry", true
}

func normalizeNPMDistTags(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	normalized := map[string]string{}
	for key, value := range values {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		normalized[key] = value
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func (v npmValidation) details() map[string]any {
	details := map[string]any{
		"source":          npmSourceName,
		"request_posture": npmRequestPosture,
		"terms_url":       npmTermsURL,
	}
	if len(v.missing) > 0 {
		details["missing_fields"] = v.missing
	}
	if len(v.conflicts) > 0 {
		details["conflicting_fields"] = v.conflicts
	}
	return details
}

func (a NPMAdapter) metadataDetails(normalized npmNormalized, refs []schema.SourceRef) map[string]any {
	details := map[string]any{
		"source":                    npmSourceName,
		"ecosystem":                 "npm",
		"package_name":              normalized.Name,
		"version":                   normalized.Version,
		"purl":                      normalized.PURL,
		"selected_version_source":   normalized.SelectedVersionSource,
		"deprecated":                normalized.Deprecated,
		"license_metadata_status":   normalized.LicenseStatus,
		"repository_mapping_status": normalized.RepositoryStatus,
		"request_posture":           npmRequestPosture,
		"terms_url":                 npmTermsURL,
		"retrieved_at":              a.now().UTC().Format(time.RFC3339),
		"ttl_seconds":               a.ttlSeconds,
		"redistribution":            sources.RedistributionUnknown,
		"public_display":            sources.PublicDisplayAllowed,
	}
	if normalized.LatestDistTag != "" {
		details["latest_dist_tag"] = normalized.LatestDistTag
	}
	if len(normalized.DistTags) > 0 {
		details["dist_tags"] = normalized.DistTags
		details["dist_tags_status"] = "reported_by_npm_registry_mutable"
	} else {
		details["dist_tags_status"] = "not_reported"
	}
	if normalized.PackageCreatedAt != "" {
		details["package_created_at"] = normalized.PackageCreatedAt
	}
	if normalized.PackageModifiedAt != "" {
		details["package_modified_at"] = normalized.PackageModifiedAt
	}
	if normalized.VersionPublishedAt != "" {
		details["version_published_at"] = normalized.VersionPublishedAt
	}
	if normalized.License != "" {
		details["license"] = normalized.License
	}
	if normalized.RepositoryURL != "" {
		details["repository_url"] = normalized.RepositoryURL
	}
	if normalized.DeprecationMessage != "" {
		details["deprecation_message"] = normalized.DeprecationMessage
	}
	if len(refs) > 1 {
		details["source_refs"] = npmSourceRefDetails(refs)
	}
	return details
}

func (a NPMAdapter) deprecatedDetails(normalized npmNormalized) map[string]any {
	details := map[string]any{
		"source":          npmSourceName,
		"ecosystem":       "npm",
		"package_name":    normalized.Name,
		"version":         normalized.Version,
		"purl":            normalized.PURL,
		"deprecated":      true,
		"request_posture": npmRequestPosture,
		"terms_url":       npmTermsURL,
		"retrieved_at":    a.now().UTC().Format(time.RFC3339),
		"ttl_seconds":     a.ttlSeconds,
		"redistribution":  sources.RedistributionUnknown,
		"public_display":  sources.PublicDisplayAllowed,
	}
	if normalized.DeprecationMessage != "" {
		details["deprecation_message"] = normalized.DeprecationMessage
	}
	return details
}

func (a NPMAdapter) sourceRefs(normalized npmNormalized) []schema.SourceRef {
	refs := []schema.SourceRef{a.versionSourceRef(normalized)}
	if normalized.IsPackument {
		refs = append(refs, a.packageSourceRef(normalized))
	}
	if len(normalized.DistTags) > 0 {
		refs = append(refs, a.distTagsSourceRef(normalized))
	}
	if normalized.LicenseReported {
		refs = append(refs, a.licenseSourceRef(normalized))
	}
	if normalized.RepositoryReported {
		refs = append(refs, a.repositorySourceRef(normalized))
	}
	return dedupeNPMSourceRefs(refs)
}

func (a NPMAdapter) versionSourceRef(normalized npmNormalized) schema.SourceRef {
	sourceID := npmVersionSourceID(normalized.Name, normalized.Version)
	return a.sourceRef(sourceRefID(npmSourceName, sourceID), sourceID, npmVersionURL(normalized.Name, normalized.Version), "Source: npm public registry version metadata from registry.npmjs.org; preserve package name, version, registry URL, retrieval time, and attribution. Do not imply npm endorsement.")
}

func (a NPMAdapter) packageSourceRef(normalized npmNormalized) schema.SourceRef {
	sourceID := npmPackageSourceID(normalized.Name)
	return a.sourceRef(sourceRefID(npmSourceName, sourceID), sourceID, npmPackageURL(normalized.Name), "Source: npm public registry packument metadata from registry.npmjs.org; mutable package-level metadata such as dist-tags should be refreshed before relying on it. Do not imply npm endorsement.")
}

func (a NPMAdapter) distTagsSourceRef(normalized npmNormalized) schema.SourceRef {
	sourceID := npmPackageSourceID(normalized.Name) + "#dist-tags"
	return a.sourceRef(sourceRefID(npmSourceName, sourceID), sourceID, npmPackageURL(normalized.Name), "Source: npm public registry dist-tags metadata from registry.npmjs.org; dist-tags are mutable and should use a short TTL.")
}

func (a NPMAdapter) licenseSourceRef(normalized npmNormalized) schema.SourceRef {
	sourceID := npmVersionSourceID(normalized.Name, normalized.Version) + "#license"
	return a.sourceRef(sourceRefID(npmSourceName, sourceID), sourceID, npmVersionURL(normalized.Name, normalized.Version), "Source: npm public registry package metadata license field from registry.npmjs.org; license strings are publisher-provided metadata.")
}

func (a NPMAdapter) repositorySourceRef(normalized npmNormalized) schema.SourceRef {
	sourceID := npmVersionSourceID(normalized.Name, normalized.Version) + "#repository"
	return a.sourceRef(sourceRefID(npmSourceName, sourceID), sourceID, npmVersionURL(normalized.Name, normalized.Version), "Source: npm public registry package metadata repository field from registry.npmjs.org; repository mapping is non-authoritative.")
}

func (a NPMAdapter) localJSONSourceRef(data []byte) schema.SourceRef {
	sum := sha256.Sum256(bytes.TrimSpace(data))
	sourceID := "local-json:" + hex.EncodeToString(sum[:])[:16]
	return a.sourceRef("npm-registry-json-"+hex.EncodeToString(sum[:])[:16], sourceID, "https://example.invalid/attach-open-score/npm-registry/"+url.PathEscape(sourceID), "Source: local/synthetic npm public registry metadata JSON fixture for Attach Open Score tests; review npm registry terms before using real metadata.")
}

func (a NPMAdapter) sourceRef(id, sourceID, sourceURL, attribution string) schema.SourceRef {
	return schema.SourceRef{
		ID:                  id,
		Source:              npmSourceName,
		SourceID:            sourceID,
		URL:                 sourceURL,
		RetrievedAt:         a.now().UTC().Format(time.RFC3339),
		TTLSeconds:          a.ttlSeconds,
		LicenseOrTermsURL:   npmTermsURL,
		Attribution:         attribution,
		AttributionRequired: true,
		Redistribution:      sources.RedistributionUnknown,
		PublicDisplay:       sources.PublicDisplayAllowed,
	}
}

func (a NPMAdapter) sourceUnavailableEvidence(sourceRef schema.SourceRef, normalized *npmNormalized, failureKind string, extra map[string]any) schema.Evidence {
	details := map[string]any{
		"source":          npmSourceName,
		"failure_kind":    failureKind,
		"request_posture": npmRequestPosture,
		"terms_url":       npmTermsURL,
	}
	if normalized != nil {
		details["ecosystem"] = "npm"
		details["package_name"] = normalized.Name
		details["version"] = normalized.Version
	}
	for key, value := range extra {
		details[key] = value
	}

	return schema.Evidence{
		Reason: schema.Reason{
			Code:           reasons.SourceUnavailable,
			Severity:       "MEDIUM",
			DecisionEffect: schema.DecisionEffectUnknown,
			Message:        "npm public registry metadata was unavailable, malformed, or missing required package identity data.",
			SourceRefIDs:   []string{sourceRef.ID},
			Details:        details,
		},
		SourceRef: &sourceRef,
	}
}

func npmEvidenceWithSourceRefs(reason schema.Reason, refs []schema.SourceRef) schema.Evidence {
	evidence := schema.Evidence{
		Reason:     reason,
		SourceRefs: refs,
	}
	if len(refs) > 0 {
		evidence.SourceRef = &refs[0]
		evidence.SourceRefs = refs[1:]
	}
	return evidence
}

func dedupeNPMSourceRefs(refs []schema.SourceRef) []schema.SourceRef {
	out := make([]schema.SourceRef, 0, len(refs))
	seen := map[string]struct{}{}
	for _, ref := range refs {
		if ref.ID == "" {
			continue
		}
		if _, ok := seen[ref.ID]; ok {
			continue
		}
		seen[ref.ID] = struct{}{}
		out = append(out, ref)
	}
	return out
}

func npmSourceRefDetails(refs []schema.SourceRef) []map[string]string {
	details := make([]map[string]string, 0, len(refs))
	for _, ref := range refs {
		details = append(details, map[string]string{
			"id":        ref.ID,
			"source_id": ref.SourceID,
			"url":       ref.URL,
		})
	}
	return details
}

func npmPackageSourceID(name string) string {
	return "registry.npmjs.org/" + strings.TrimSpace(name)
}

func npmVersionSourceID(name, version string) string {
	return npmPackageSourceID(name) + "@" + strings.TrimSpace(version)
}

func npmPackageURL(name string) string {
	return npmRegistryBase + "/" + npmEscapeURIComponent(name)
}

func npmVersionURL(name, version string) string {
	return npmPackageURL(name) + "/" + npmEscapeURIComponent(version)
}

func npmPURL(name, version string) string {
	return "pkg:npm/" + npmPURLName(name) + "@" + npmEscapeURIComponent(version)
}

func npmPURLName(name string) string {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, "@") {
		namespace, packageName, ok := strings.Cut(name, "/")
		if ok && strings.TrimSpace(packageName) != "" {
			return npmEscapeURIComponent(namespace) + "/" + npmEscapeURIComponent(packageName)
		}
	}
	return npmEscapeURIComponent(name)
}

func npmEscapeURIComponent(value string) string {
	return strings.ReplaceAll(url.PathEscape(strings.TrimSpace(value)), "@", "%40")
}
