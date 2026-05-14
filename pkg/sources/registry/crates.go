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
	cratesSourceName       = "crates.io-index"
	cratesTermsURL         = "https://index.crates.io/"
	cratesIndexBase        = "https://index.crates.io"
	cratesIndexFormatURL   = "https://doc.rust-lang.org/cargo/reference/registry-index.html"
	cratesGitIndexURL      = "https://github.com/rust-lang/crates.io-index"
	cratesRequestPosture   = "fixture_first_crates_io_sparse_or_git_index_dependency_resolution_metadata_only_no_live_calls_no_api_crawling_no_db_dump"
	cratesAttributionBrief = "Source: crates.io package index metadata from index.crates.io or rust-lang/crates.io-index; preserve crate name, version, index URL, retrieval time, and attribution. Do not imply crates.io or Rust project endorsement."
)

type CratesOptions struct {
	Now        func() time.Time
	TTLSeconds int
}

type CratesAdapter struct {
	now        func() time.Time
	ttlSeconds int
}

type cratesIndexRecord struct {
	Name         string                  `json:"name,omitempty"`
	Version      string                  `json:"vers,omitempty"`
	Dependencies []cratesIndexDependency `json:"deps,omitempty"`
	Checksum     string                  `json:"cksum,omitempty"`
	Features     map[string][]string     `json:"features,omitempty"`
	Features2    map[string][]string     `json:"features2,omitempty"`
	Yanked       bool                    `json:"yanked,omitempty"`
	RustVersion  string                  `json:"rust_version,omitempty"`
	Pubtime      string                  `json:"pubtime,omitempty"`
	Schema       int                     `json:"v,omitempty"`
}

type cratesIndexDependency struct {
	Name            string   `json:"name,omitempty"`
	Req             string   `json:"req,omitempty"`
	Features        []string `json:"features,omitempty"`
	Optional        *bool    `json:"optional,omitempty"`
	DefaultFeatures *bool    `json:"default_features,omitempty"`
	Target          *string  `json:"target,omitempty"`
	Kind            *string  `json:"kind,omitempty"`
	Registry        *string  `json:"registry,omitempty"`
	Package         *string  `json:"package,omitempty"`
}

type cratesNormalized struct {
	Name                  string
	Version               string
	PURL                  string
	SelectedVersionSource string
	Dependencies          []map[string]any
	Features              map[string][]string
	FeaturesReported      bool
	Features2Reported     bool
	Checksum              string
	Yanked                bool
	RustVersion           string
	Pubtime               string
	Schema                int
}

type cratesValidation struct {
	ok          bool
	failureKind string
	missing     []string
	conflicts   []string
	extra       map[string]any
}

func NewCratesAdapter(options CratesOptions) (CratesAdapter, error) {
	now := options.Now
	if now == nil {
		now = time.Now
	}

	ttlSeconds := options.TTLSeconds
	if ttlSeconds == 0 {
		ttlSeconds = DefaultTTLSeconds
	}
	if ttlSeconds < 0 {
		return CratesAdapter{}, fmt.Errorf("crates.io index ttl_seconds must be non-negative")
	}

	return CratesAdapter{
		now:        now,
		ttlSeconds: ttlSeconds,
	}, nil
}

func (a CratesAdapter) EvidenceFromJSON(data []byte, coordinate Coordinate) ([]schema.Evidence, error) {
	sourceRef := a.localJSONSourceRef(data)
	records, err := parseCratesIndexRecords(data)
	if err != nil {
		return []schema.Evidence{a.sourceUnavailableEvidence(sourceRef, nil, "parse_failure", map[string]any{
			"parse_error": err.Error(),
		})}, nil
	}

	return a.evidence(records, coordinate, sourceRef), nil
}

func parseCratesIndexRecords(data []byte) ([]cratesIndexRecord, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("empty crates.io index metadata JSON")
	}
	if data[0] == '[' {
		return nil, errors.New("crates.io index metadata JSON must be an object or newline-delimited objects")
	}

	record, err := decodeCratesIndexRecord(data)
	if err == nil {
		return []cratesIndexRecord{record}, nil
	}
	if !bytes.Contains(data, []byte("\n")) {
		return nil, err
	}

	records := []cratesIndexRecord{}
	for index, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		record, lineErr := decodeCratesIndexRecord(line)
		if lineErr != nil {
			return nil, fmt.Errorf("crates.io index record %d: %w", index+1, lineErr)
		}
		records = append(records, record)
	}
	if len(records) == 0 {
		return nil, errors.New("empty crates.io index metadata JSON")
	}
	return records, nil
}

func decodeCratesIndexRecord(data []byte) (cratesIndexRecord, error) {
	var record cratesIndexRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&record); err != nil {
		return cratesIndexRecord{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return cratesIndexRecord{}, errors.New("crates.io index metadata JSON contains trailing data")
	}
	return record, nil
}

func (a CratesAdapter) evidence(records []cratesIndexRecord, coordinate Coordinate, fallbackSourceRef schema.SourceRef) []schema.Evidence {
	normalized, validation := normalizeCratesIndexRecords(records, coordinate)
	if !validation.ok {
		return []schema.Evidence{a.sourceUnavailableEvidence(fallbackSourceRef, nil, validation.failureKind, validation.details())}
	}

	sourceRefs := a.sourceRefs(normalized)
	details := a.metadataDetails(normalized, sourceRefs)
	evidence := []schema.Evidence{cratesEvidenceWithSourceRefs(schema.Reason{
		Code:           reasons.RepositoryMappingUncertain,
		Severity:       "MEDIUM",
		DecisionEffect: schema.DecisionEffectUnknown,
		Message:        fmt.Sprintf("crates.io package index metadata for %s@%s was normalized as non-authoritative dependency-resolution context only.", normalized.Name, normalized.Version),
		SourceRefIDs:   sourceRefIDs(sourceRefs),
		Details:        details,
	}, sourceRefs)}

	if normalized.Yanked {
		versionRef := sourceRefs[0]
		evidence = append(evidence, cratesEvidenceWithSourceRefs(schema.Reason{
			Code:           reasons.PackageUnpublishedOrYanked,
			Severity:       "MEDIUM",
			DecisionEffect: schema.DecisionEffectAsk,
			Message:        fmt.Sprintf("crates.io package index marks %s@%s as yanked.", normalized.Name, normalized.Version),
			SourceRefIDs:   []string{versionRef.ID},
			Details:        a.yankedDetails(normalized),
		}, []schema.SourceRef{versionRef}))
	}

	return evidence
}

func normalizeCratesIndexRecords(records []cratesIndexRecord, coordinate Coordinate) (cratesNormalized, cratesValidation) {
	record, selectedVersionSource, validation := selectCratesIndexRecord(records, coordinate)
	if !validation.ok {
		return cratesNormalized{}, validation
	}

	conflicts := []string{}
	if ecosystem := strings.TrimSpace(coordinate.Ecosystem); ecosystem != "" && normalizeCratesEcosystem(ecosystem) != "crates" {
		conflicts = append(conflicts, "coordinate.ecosystem")
	}

	name := strings.TrimSpace(coordinate.Name)
	recordName := strings.TrimSpace(record.Name)
	addCratesIdentityValue(&name, &conflicts, "record.name", recordName)

	version := strings.TrimSpace(coordinate.Version)
	recordVersion := strings.TrimSpace(record.Version)
	addCratesIdentityValue(&version, &conflicts, "record.vers", recordVersion)

	if len(conflicts) > 0 {
		return cratesNormalized{}, cratesValidation{failureKind: "conflicting_required_data", conflicts: conflicts}
	}

	missing := []string{}
	if name == "" || recordName == "" {
		missing = append(missing, "name")
	}
	if version == "" || recordVersion == "" {
		missing = append(missing, "version")
	}
	if len(missing) > 0 {
		return cratesNormalized{}, cratesValidation{failureKind: "missing_required_data", missing: missing}
	}

	features := mergeCratesFeatures(record.Features, record.Features2)
	normalized := cratesNormalized{
		Name:                  name,
		Version:               version,
		PURL:                  cratesPURL(name, version),
		SelectedVersionSource: selectedVersionSource,
		Dependencies:          normalizeCratesDependencies(record.Dependencies),
		Features:              features,
		FeaturesReported:      len(record.Features) > 0,
		Features2Reported:     len(record.Features2) > 0,
		Checksum:              strings.TrimSpace(record.Checksum),
		Yanked:                record.Yanked,
		RustVersion:           strings.TrimSpace(record.RustVersion),
		Pubtime:               strings.TrimSpace(record.Pubtime),
		Schema:                record.Schema,
	}
	return normalized, cratesValidation{ok: true}
}

func selectCratesIndexRecord(records []cratesIndexRecord, coordinate Coordinate) (cratesIndexRecord, string, cratesValidation) {
	if len(records) == 0 {
		return cratesIndexRecord{}, "", cratesValidation{failureKind: "missing_required_data", missing: []string{"name", "version"}}
	}
	if version := strings.TrimSpace(coordinate.Version); version != "" {
		for _, record := range records {
			if strings.TrimSpace(record.Version) == version {
				return record, "requested_version", cratesValidation{ok: true}
			}
		}
		return cratesIndexRecord{}, "", cratesValidation{
			failureKind: "missing_required_data",
			missing:     []string{"selected_version"},
			extra: map[string]any{
				"requested_version": version,
			},
		}
	}
	if len(records) == 1 {
		return records[0], "single_record", cratesValidation{ok: true}
	}
	return cratesIndexRecord{}, "", cratesValidation{failureKind: "missing_required_data", missing: []string{"version"}}
}

func addCratesIdentityValue(current *string, conflicts *[]string, field, value string) {
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

func normalizeCratesEcosystem(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "cargo", "crates", "crates.io", "rust":
		return "crates"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func normalizeCratesDependencies(dependencies []cratesIndexDependency) []map[string]any {
	if len(dependencies) == 0 {
		return nil
	}

	normalized := make([]map[string]any, 0, len(dependencies))
	for _, dependency := range dependencies {
		optional := false
		if dependency.Optional != nil {
			optional = *dependency.Optional
		}
		defaultFeatures := true
		if dependency.DefaultFeatures != nil {
			defaultFeatures = *dependency.DefaultFeatures
		}
		kind := strings.TrimSpace(cratesStringPointerValue(dependency.Kind))
		if kind == "" {
			kind = "normal"
		}

		item := map[string]any{
			"name":             strings.TrimSpace(dependency.Name),
			"req":              strings.TrimSpace(dependency.Req),
			"features":         normalizeCratesStringList(dependency.Features),
			"optional":         optional,
			"default_features": defaultFeatures,
			"kind":             kind,
		}
		if target := strings.TrimSpace(cratesStringPointerValue(dependency.Target)); target != "" {
			item["target"] = target
		}
		if registry := strings.TrimSpace(cratesStringPointerValue(dependency.Registry)); registry != "" {
			item["registry"] = registry
		}
		if packageName := strings.TrimSpace(cratesStringPointerValue(dependency.Package)); packageName != "" {
			item["package"] = packageName
		}
		normalized = append(normalized, item)
	}
	return normalized
}

func mergeCratesFeatures(features, features2 map[string][]string) map[string][]string {
	if len(features) == 0 && len(features2) == 0 {
		return nil
	}
	merged := map[string][]string{}
	for key, values := range features {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		merged[key] = normalizeCratesStringList(values)
	}
	for key, values := range features2 {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		merged[key] = appendCratesUniqueStrings(merged[key], values)
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

func appendCratesUniqueStrings(current []string, values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(current)+len(values))
	for _, value := range current {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizeCratesStringList(values []string) []string {
	return appendCratesUniqueStrings(nil, values)
}

func cratesStringPointerValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (v cratesValidation) details() map[string]any {
	details := map[string]any{
		"source":           cratesSourceName,
		"request_posture":  cratesRequestPosture,
		"terms_url":        cratesTermsURL,
		"index_format_url": cratesIndexFormatURL,
	}
	if len(v.missing) > 0 {
		details["missing_fields"] = v.missing
	}
	if len(v.conflicts) > 0 {
		details["conflicting_fields"] = v.conflicts
	}
	for key, value := range v.extra {
		details[key] = value
	}
	return details
}

func (a CratesAdapter) metadataDetails(normalized cratesNormalized, refs []schema.SourceRef) map[string]any {
	details := map[string]any{
		"source":                    cratesSourceName,
		"ecosystem":                 "crates",
		"package_name":              normalized.Name,
		"version":                   normalized.Version,
		"purl":                      normalized.PURL,
		"selected_version_source":   normalized.SelectedVersionSource,
		"yanked":                    normalized.Yanked,
		"request_posture":           cratesRequestPosture,
		"terms_url":                 cratesTermsURL,
		"index_format_url":          cratesIndexFormatURL,
		"git_index_url":             cratesGitIndexURL,
		"retrieved_at":              a.now().UTC().Format(time.RFC3339),
		"ttl_seconds":               a.ttlSeconds,
		"redistribution":            sources.RedistributionUnknown,
		"public_display":            sources.PublicDisplayAllowed,
		"repository_mapping_status": "not_reported_by_crates_io_index",
	}
	if len(normalized.Dependencies) > 0 {
		details["dependencies"] = normalized.Dependencies
		details["dependencies_status"] = "reported_by_crates_io_index"
	} else {
		details["dependencies_status"] = "not_reported_or_empty"
	}
	if len(normalized.Features) > 0 {
		details["features"] = normalized.Features
		details["features_status"] = "reported_by_crates_io_index"
	} else {
		details["features_status"] = "not_reported_or_empty"
	}
	if normalized.Checksum != "" {
		details["checksum"] = normalized.Checksum
		details["checksum_status"] = "reported_by_crates_io_index"
	} else {
		details["checksum_status"] = "not_reported"
	}
	if normalized.RustVersion != "" {
		details["rust_version"] = normalized.RustVersion
	}
	if normalized.Pubtime != "" {
		details["pubtime"] = normalized.Pubtime
	}
	if normalized.Schema > 0 {
		details["index_schema_version"] = normalized.Schema
	}
	if len(refs) > 1 {
		details["source_refs"] = cratesSourceRefDetails(refs)
	}
	return details
}

func (a CratesAdapter) yankedDetails(normalized cratesNormalized) map[string]any {
	return map[string]any{
		"source":           cratesSourceName,
		"ecosystem":        "crates",
		"package_name":     normalized.Name,
		"version":          normalized.Version,
		"purl":             normalized.PURL,
		"yanked":           true,
		"request_posture":  cratesRequestPosture,
		"terms_url":        cratesTermsURL,
		"index_format_url": cratesIndexFormatURL,
		"retrieved_at":     a.now().UTC().Format(time.RFC3339),
		"ttl_seconds":      a.ttlSeconds,
		"redistribution":   sources.RedistributionUnknown,
		"public_display":   sources.PublicDisplayAllowed,
	}
}

func (a CratesAdapter) sourceRefs(normalized cratesNormalized) []schema.SourceRef {
	refs := []schema.SourceRef{
		a.versionSourceRef(normalized),
		a.packageSourceRef(normalized),
	}
	if len(normalized.Dependencies) > 0 {
		refs = append(refs, a.dependenciesSourceRef(normalized))
	}
	if normalized.FeaturesReported {
		refs = append(refs, a.featuresSourceRef(normalized))
	}
	if normalized.Features2Reported {
		refs = append(refs, a.featuresSourceRef(normalized))
	}
	if normalized.Checksum != "" {
		refs = append(refs, a.checksumSourceRef(normalized))
	}
	return dedupeCratesSourceRefs(refs)
}

func (a CratesAdapter) versionSourceRef(normalized cratesNormalized) schema.SourceRef {
	sourceID := cratesVersionSourceID(normalized.Name, normalized.Version)
	return a.sourceRef(sourceRefID(cratesSourceName, sourceID), sourceID, cratesPackageIndexURL(normalized.Name), cratesAttributionBrief)
}

func (a CratesAdapter) packageSourceRef(normalized cratesNormalized) schema.SourceRef {
	sourceID := cratesPackageSourceID(normalized.Name)
	return a.sourceRef(sourceRefID(cratesSourceName, sourceID), sourceID, cratesPackageIndexURL(normalized.Name), "Source: crates.io package index crate metadata file from index.crates.io or rust-lang/crates.io-index; package-level index metadata is not an allow/deny signal.")
}

func (a CratesAdapter) dependenciesSourceRef(normalized cratesNormalized) schema.SourceRef {
	sourceID := cratesVersionSourceID(normalized.Name, normalized.Version) + "#dependencies"
	return a.sourceRef(sourceRefID(cratesSourceName, sourceID), sourceID, cratesPackageIndexURL(normalized.Name), "Source: crates.io package index dependency metadata used by Cargo resolution; dependency facts are publisher/index metadata and non-authoritative for risk allow decisions.")
}

func (a CratesAdapter) featuresSourceRef(normalized cratesNormalized) schema.SourceRef {
	sourceID := cratesVersionSourceID(normalized.Name, normalized.Version) + "#features"
	return a.sourceRef(sourceRefID(cratesSourceName, sourceID), sourceID, cratesPackageIndexURL(normalized.Name), "Source: crates.io package index feature metadata used by Cargo resolution; features and features2 are normalized as dependency-resolution context.")
}

func (a CratesAdapter) checksumSourceRef(normalized cratesNormalized) schema.SourceRef {
	sourceID := cratesVersionSourceID(normalized.Name, normalized.Version) + "#checksum"
	return a.sourceRef(sourceRefID(cratesSourceName, sourceID), sourceID, cratesPackageIndexURL(normalized.Name), "Source: crates.io package index cksum field for the crate archive SHA256 checksum; this records index metadata only and does not fetch or inspect crate contents.")
}

func (a CratesAdapter) localJSONSourceRef(data []byte) schema.SourceRef {
	sum := sha256.Sum256(bytes.TrimSpace(data))
	sourceID := "local-json:" + hex.EncodeToString(sum[:])[:16]
	return a.sourceRef("crates-io-index-json-"+hex.EncodeToString(sum[:])[:16], sourceID, "https://example.invalid/attach-open-score/crates-io-index/"+url.PathEscape(sourceID), "Source: local/synthetic crates.io package index JSON fixture for Attach Open Score tests; review crates.io index terms before using real metadata.")
}

func (a CratesAdapter) sourceRef(id, sourceID, sourceURL, attribution string) schema.SourceRef {
	return schema.SourceRef{
		ID:                  id,
		Source:              cratesSourceName,
		SourceID:            sourceID,
		URL:                 sourceURL,
		RetrievedAt:         a.now().UTC().Format(time.RFC3339),
		TTLSeconds:          a.ttlSeconds,
		LicenseOrTermsURL:   cratesTermsURL,
		Attribution:         attribution,
		AttributionRequired: true,
		Redistribution:      sources.RedistributionUnknown,
		PublicDisplay:       sources.PublicDisplayAllowed,
	}
}

func (a CratesAdapter) sourceUnavailableEvidence(sourceRef schema.SourceRef, normalized *cratesNormalized, failureKind string, extra map[string]any) schema.Evidence {
	details := map[string]any{
		"source":           cratesSourceName,
		"failure_kind":     failureKind,
		"request_posture":  cratesRequestPosture,
		"terms_url":        cratesTermsURL,
		"index_format_url": cratesIndexFormatURL,
	}
	if normalized != nil {
		details["ecosystem"] = "crates"
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
			Message:        "crates.io package index metadata was unavailable, malformed, or missing required crate identity data.",
			SourceRefIDs:   []string{sourceRef.ID},
			Details:        details,
		},
		SourceRef: &sourceRef,
	}
}

func cratesEvidenceWithSourceRefs(reason schema.Reason, refs []schema.SourceRef) schema.Evidence {
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

func dedupeCratesSourceRefs(refs []schema.SourceRef) []schema.SourceRef {
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

func cratesSourceRefDetails(refs []schema.SourceRef) []map[string]string {
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

func cratesPackageSourceID(name string) string {
	return "index.crates.io/" + strings.TrimSpace(name)
}

func cratesVersionSourceID(name, version string) string {
	return cratesPackageSourceID(name) + "@" + strings.TrimSpace(version)
}

func cratesPackageIndexURL(name string) string {
	segments := cratesIndexPathSegments(name)
	escaped := make([]string, 0, len(segments))
	for _, segment := range segments {
		escaped = append(escaped, url.PathEscape(segment))
	}
	return cratesIndexBase + "/" + strings.Join(escaped, "/")
}

func cratesIndexPathSegments(name string) []string {
	name = strings.ToLower(strings.TrimSpace(name))
	switch {
	case len(name) == 0:
		return []string{"."}
	case len(name) == 1:
		return []string{"1", name}
	case len(name) == 2:
		return []string{"2", name}
	case len(name) == 3:
		return []string{"3", name[:1], name}
	default:
		return []string{name[:2], name[2:4], name}
	}
}

func cratesPURL(name, version string) string {
	return "pkg:cargo/" + cratesEscapeURIComponent(name) + "@" + cratesEscapeURIComponent(version)
}

func cratesEscapeURIComponent(value string) string {
	return strings.ReplaceAll(url.PathEscape(strings.TrimSpace(value)), "@", "%40")
}
