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
	goModuleSourceName     = "go-module-services"
	goModuleTermsURL       = "https://proxy.golang.org/"
	goModuleProxyBase      = "https://proxy.golang.org"
	goModuleRequestPosture = "fixture_first_documented_go_module_services_metadata_only_no_live_calls_no_direct_vcs_no_private_lookup_no_zip_or_source_archive_redistribution"
)

type GoModuleOptions struct {
	Now        func() time.Time
	TTLSeconds int
}

type GoModuleAdapter struct {
	now        func() time.Time
	ttlSeconds int
}

type goModuleMetadata struct {
	ModulePath          string              `json:"module_path,omitempty"`
	Module              string              `json:"module,omitempty"`
	Path                string              `json:"Path,omitempty"`
	PathLower           string              `json:"path,omitempty"`
	Version             string              `json:"version,omitempty"`
	InfoVersion         string              `json:"Version,omitempty"`
	Time                string              `json:"time,omitempty"`
	InfoTime            string              `json:"Time,omitempty"`
	Timestamp           string              `json:"timestamp,omitempty"`
	Versions            goModuleVersionList `json:"versions,omitempty"`
	VersionList         goModuleVersionList `json:"version_list,omitempty"`
	GoMod               string              `json:"go_mod,omitempty"`
	Mod                 string              `json:"mod,omitempty"`
	SourceURL           string              `json:"source_url,omitempty"`
	RetrievedAt         string              `json:"retrieved_at,omitempty"`
	TTLSeconds          int                 `json:"ttl_seconds,omitempty"`
	Deprecated          string              `json:"deprecated,omitempty"`
	DeprecationMessage  string              `json:"deprecation_message,omitempty"`
	Retracted           bool                `json:"retracted,omitempty"`
	RetractionRationale string              `json:"retraction_rationale,omitempty"`
}

type goModuleVersionList []string

type goModuleRequirement struct {
	ModulePath string
	Version    string
	Indirect   bool
}

type goModuleRetraction struct {
	Version   string
	Rationale string
}

type parsedGoMod struct {
	ModulePath         string
	GoVersion          string
	Requirements       []goModuleRequirement
	DeprecationMessage string
	Retractions        []goModuleRetraction
}

type goModuleNormalized struct {
	ModulePath            string
	Version               string
	PURL                  string
	SelectedVersionSource string
	VersionTime           string
	Versions              []string
	GoModReported         bool
	GoModModulePath       string
	GoVersion             string
	Requirements          []goModuleRequirement
	DeprecationMessage    string
	Retracted             bool
	RetractionRationale   string
	SourceURL             string
	SourceURLStatus       string
	RetrievedAt           string
	TTLSeconds            int
}

type goModuleValidation struct {
	ok          bool
	failureKind string
	missing     []string
	conflicts   []string
}

func NewGoModuleAdapter(options GoModuleOptions) (GoModuleAdapter, error) {
	now := options.Now
	if now == nil {
		now = time.Now
	}

	ttlSeconds := options.TTLSeconds
	if ttlSeconds == 0 {
		ttlSeconds = DefaultTTLSeconds
	}
	if ttlSeconds < 0 {
		return GoModuleAdapter{}, fmt.Errorf("go module metadata ttl_seconds must be non-negative")
	}

	return GoModuleAdapter{
		now:        now,
		ttlSeconds: ttlSeconds,
	}, nil
}

func (a GoModuleAdapter) EvidenceFromJSON(data []byte, coordinate Coordinate) ([]schema.Evidence, error) {
	sourceRef := a.localJSONSourceRef(data)
	metadata, err := parseGoModuleMetadata(data)
	if err != nil {
		return []schema.Evidence{a.sourceUnavailableEvidence(sourceRef, nil, "parse_failure", map[string]any{
			"parse_error": err.Error(),
		})}, nil
	}

	return a.evidence(metadata, coordinate, sourceRef), nil
}

func parseGoModuleMetadata(data []byte) (goModuleMetadata, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return goModuleMetadata{}, errors.New("go module services metadata JSON is empty")
	}
	if data[0] == '[' {
		return goModuleMetadata{}, errors.New("go module services metadata JSON must be an object")
	}

	var metadata goModuleMetadata
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&metadata); err != nil {
		return goModuleMetadata{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return goModuleMetadata{}, errors.New("go module services metadata JSON contains trailing data")
	}
	return metadata, nil
}

func (l *goModuleVersionList) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		*l = splitGoModuleVersionList(value)
		return nil
	}

	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	*l = normalizeGoModuleStringList(values)
	return nil
}

func (a GoModuleAdapter) evidence(metadata goModuleMetadata, coordinate Coordinate, fallbackSourceRef schema.SourceRef) []schema.Evidence {
	normalized, validation := normalizeGoModuleMetadata(metadata, coordinate, a.now, a.ttlSeconds)
	if !validation.ok {
		return []schema.Evidence{a.sourceUnavailableEvidence(fallbackSourceRef, nil, validation.failureKind, validation.details())}
	}

	sourceRefs := a.sourceRefs(normalized)
	details := a.metadataDetails(normalized, sourceRefs)

	evidence := []schema.Evidence{goModuleEvidenceWithSourceRefs(schema.Reason{
		Code:           reasons.RepositoryMappingUncertain,
		Severity:       "MEDIUM",
		DecisionEffect: schema.DecisionEffectUnknown,
		Message:        fmt.Sprintf("Go module services metadata for %s@%s was normalized as non-authoritative package context only.", normalized.ModulePath, normalized.Version),
		SourceRefIDs:   sourceRefIDs(sourceRefs),
		Details:        details,
	}, sourceRefs)}

	if normalized.DeprecationMessage != "" {
		goModRef := a.goModSourceRef(normalized)
		evidence = append(evidence, goModuleEvidenceWithSourceRefs(schema.Reason{
			Code:           reasons.DeprecatedPackage,
			Severity:       "MEDIUM",
			DecisionEffect: schema.DecisionEffectAsk,
			Message:        fmt.Sprintf("Go module metadata marks %s as deprecated.", normalized.ModulePath),
			SourceRefIDs:   []string{goModRef.ID},
			Details:        a.deprecatedDetails(normalized),
		}, []schema.SourceRef{goModRef}))
	}

	if normalized.Retracted {
		goModRef := a.goModSourceRef(normalized)
		evidence = append(evidence, goModuleEvidenceWithSourceRefs(schema.Reason{
			Code:           reasons.PackageUnpublishedOrYanked,
			Severity:       "MEDIUM",
			DecisionEffect: schema.DecisionEffectAsk,
			Message:        fmt.Sprintf("Go module metadata marks %s@%s as retracted.", normalized.ModulePath, normalized.Version),
			SourceRefIDs:   []string{goModRef.ID},
			Details:        a.retractionDetails(normalized),
		}, []schema.SourceRef{goModRef}))
	}

	return evidence
}

func normalizeGoModuleMetadata(metadata goModuleMetadata, coordinate Coordinate, now func() time.Time, defaultTTLSeconds int) (goModuleNormalized, goModuleValidation) {
	parsedMod := parseGoMod(firstNonEmpty(metadata.GoMod, metadata.Mod))

	conflicts := []string{}
	ecosystem := strings.ToLower(strings.TrimSpace(coordinate.Ecosystem))
	if ecosystem != "" && ecosystem != "go" && ecosystem != "golang" {
		conflicts = append(conflicts, "coordinate.ecosystem")
	}

	modulePath := strings.TrimSpace(coordinate.Name)
	addGoModuleIdentityValue(&modulePath, &conflicts, "metadata.module_path", metadataModulePath(metadata))
	addGoModuleIdentityValue(&modulePath, &conflicts, "go_mod.module", parsedMod.ModulePath)
	if modulePath != "" && !isPublicGoModulePathAllowed(modulePath) {
		return goModuleNormalized{}, goModuleValidation{failureKind: "private_module_path"}
	}

	versions := mergeGoModuleVersions(metadata.VersionList, metadata.Versions)
	version, selectedVersionSource := selectGoModuleVersion(metadata, coordinate, versions)
	addGoModuleVersionConflict(version, &conflicts, "metadata.Version", metadata.InfoVersion)
	addGoModuleVersionConflict(version, &conflicts, "metadata.version", metadata.Version)
	if strings.TrimSpace(coordinate.Version) != "" && strings.TrimSpace(metadata.InfoVersion) == "" && strings.TrimSpace(metadata.Version) == "" && !goModuleVersionRepresented(version, metadata, versions) {
		conflicts = append(conflicts, "coordinate.version")
	}

	missing := []string{}
	if modulePath == "" {
		missing = append(missing, "module_path")
	}
	if version == "" {
		missing = append(missing, "version")
	}
	if len(missing) > 0 {
		return goModuleNormalized{}, goModuleValidation{failureKind: "missing_required_data", missing: missing}
	}
	if len(conflicts) > 0 {
		return goModuleNormalized{}, goModuleValidation{failureKind: "conflicting_required_data", conflicts: conflicts}
	}

	retrievedAt := now().UTC().Format(time.RFC3339)
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(metadata.RetrievedAt)); err == nil {
		retrievedAt = parsed.UTC().Format(time.RFC3339)
	}
	ttl := defaultTTLSeconds
	if metadata.TTLSeconds > 0 {
		ttl = metadata.TTLSeconds
	}

	fallbackSourceURL := goModuleVersionURL(modulePath, version)
	sourceURL, sourceURLStatus := sanitizeGoModuleFixtureSourceURL(metadata.SourceURL, fallbackSourceURL)
	deprecationMessage := sanitizeGoModulePublisherText(firstNonEmpty(metadata.DeprecationMessage, metadata.Deprecated, parsedMod.DeprecationMessage))
	retracted, retractionRationale := goModuleRetractionDetails(version, metadata, parsedMod)
	retractionRationale = sanitizeGoModulePublisherText(retractionRationale)

	normalized := goModuleNormalized{
		ModulePath:            modulePath,
		Version:               version,
		PURL:                  goModulePURL(modulePath, version),
		SelectedVersionSource: selectedVersionSource,
		VersionTime:           firstNonEmpty(metadata.InfoTime, metadata.Time, metadata.Timestamp),
		Versions:              versions,
		GoModReported:         strings.TrimSpace(firstNonEmpty(metadata.GoMod, metadata.Mod)) != "",
		GoModModulePath:       parsedMod.ModulePath,
		GoVersion:             parsedMod.GoVersion,
		Requirements:          sanitizeGoModuleRequirements(parsedMod.Requirements),
		DeprecationMessage:    deprecationMessage,
		Retracted:             retracted,
		RetractionRationale:   retractionRationale,
		SourceURL:             sourceURL,
		SourceURLStatus:       sourceURLStatus,
		RetrievedAt:           retrievedAt,
		TTLSeconds:            ttl,
	}
	return normalized, goModuleValidation{ok: true}
}

func metadataModulePath(metadata goModuleMetadata) string {
	return firstNonEmpty(metadata.ModulePath, metadata.Module, metadata.Path, metadata.PathLower)
}

func selectGoModuleVersion(metadata goModuleMetadata, coordinate Coordinate, versions []string) (string, string) {
	if version := strings.TrimSpace(coordinate.Version); version != "" {
		return version, "requested_version"
	}
	if version := firstNonEmpty(metadata.InfoVersion, metadata.Version); version != "" {
		return version, "version_metadata"
	}
	if len(versions) == 1 {
		return versions[0], "single_listed_version"
	}
	return "", ""
}

func goModuleVersionRepresented(version string, metadata goModuleMetadata, versions []string) bool {
	version = strings.TrimSpace(version)
	if version == "" {
		return false
	}
	if strings.TrimSpace(metadata.InfoVersion) == version || strings.TrimSpace(metadata.Version) == version {
		return true
	}
	for _, listed := range versions {
		if strings.TrimSpace(listed) == version {
			return true
		}
	}
	return false
}

func addGoModuleVersionConflict(selected string, conflicts *[]string, field, value string) {
	selected = strings.TrimSpace(selected)
	value = strings.TrimSpace(value)
	if selected == "" || value == "" {
		return
	}
	if selected != value {
		*conflicts = append(*conflicts, field)
	}
}

func addGoModuleIdentityValue(current *string, conflicts *[]string, field, value string) {
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

func (v goModuleValidation) details() map[string]any {
	details := map[string]any{
		"source":          goModuleSourceName,
		"request_posture": goModuleRequestPosture,
		"terms_url":       goModuleTermsURL,
	}
	if len(v.missing) > 0 {
		details["missing_fields"] = v.missing
	}
	if len(v.conflicts) > 0 {
		details["conflicting_fields"] = v.conflicts
	}
	return details
}

func parseGoMod(data string) parsedGoMod {
	parsed := parsedGoMod{}
	lines := strings.Split(data, "\n")
	inRequireBlock := false
	inRetractBlock := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if message := goModuleDeprecatedComment(line); message != "" && parsed.DeprecationMessage == "" {
			parsed.DeprecationMessage = message
		}
		if strings.HasPrefix(line, "//") {
			continue
		}

		if inRequireBlock {
			if strings.HasPrefix(line, ")") {
				inRequireBlock = false
				continue
			}
			if req, ok := parseGoModRequirementLine(line); ok {
				parsed.Requirements = append(parsed.Requirements, req)
			}
			continue
		}
		if inRetractBlock {
			if strings.HasPrefix(line, ")") {
				inRetractBlock = false
				continue
			}
			if retraction, ok := parseGoModRetractionLine(line); ok {
				parsed.Retractions = append(parsed.Retractions, retraction)
			}
			continue
		}

		lineWithoutComment, _ := splitGoModuleLineComment(line)
		fields := strings.Fields(lineWithoutComment)
		if len(fields) >= 2 && fields[0] == "module" && parsed.ModulePath == "" {
			parsed.ModulePath = fields[1]
			continue
		}
		if len(fields) >= 2 && fields[0] == "go" && parsed.GoVersion == "" {
			parsed.GoVersion = fields[1]
			continue
		}
		if strings.HasPrefix(lineWithoutComment, "require (") {
			inRequireBlock = true
			continue
		}
		if strings.HasPrefix(lineWithoutComment, "retract (") {
			inRetractBlock = true
			continue
		}
		if strings.HasPrefix(lineWithoutComment, "require ") {
			if req, ok := parseGoModRequirementLine(strings.TrimSpace(strings.TrimPrefix(line, "require "))); ok {
				parsed.Requirements = append(parsed.Requirements, req)
			}
			continue
		}
		if strings.HasPrefix(lineWithoutComment, "retract ") {
			if retraction, ok := parseGoModRetractionLine(strings.TrimSpace(strings.TrimPrefix(line, "retract "))); ok {
				parsed.Retractions = append(parsed.Retractions, retraction)
			}
			continue
		}
	}
	parsed.Requirements = dedupeGoModuleRequirements(parsed.Requirements)
	return parsed
}

func parseGoModRequirementLine(line string) (goModuleRequirement, bool) {
	lineWithoutComment, comment := splitGoModuleLineComment(line)
	fields := strings.Fields(lineWithoutComment)
	if len(fields) < 2 {
		return goModuleRequirement{}, false
	}
	return goModuleRequirement{
		ModulePath: fields[0],
		Version:    fields[1],
		Indirect:   strings.Contains(comment, "indirect"),
	}, true
}

func parseGoModRetractionLine(line string) (goModuleRetraction, bool) {
	lineWithoutComment, comment := splitGoModuleLineComment(line)
	lineWithoutComment = strings.TrimSpace(lineWithoutComment)
	if lineWithoutComment == "" {
		return goModuleRetraction{}, false
	}
	if strings.HasPrefix(lineWithoutComment, "[") {
		end := strings.Index(lineWithoutComment, "]")
		if end < 0 {
			return goModuleRetraction{}, false
		}
		parts := strings.Split(lineWithoutComment[1:end], ",")
		if len(parts) != 2 {
			return goModuleRetraction{}, false
		}
		low := strings.TrimSpace(parts[0])
		high := strings.TrimSpace(parts[1])
		if low == "" || high == "" {
			return goModuleRetraction{}, false
		}
		return goModuleRetraction{
			Version:   low + ".." + high,
			Rationale: strings.TrimSpace(comment),
		}, true
	}
	fields := strings.Fields(lineWithoutComment)
	if len(fields) == 0 {
		return goModuleRetraction{}, false
	}
	return goModuleRetraction{
		Version:   fields[0],
		Rationale: strings.TrimSpace(comment),
	}, true
}

func splitGoModuleLineComment(line string) (string, string) {
	before, after, ok := strings.Cut(line, "//")
	if !ok {
		return strings.TrimSpace(line), ""
	}
	return strings.TrimSpace(before), strings.TrimSpace(after)
}

func goModuleDeprecatedComment(line string) string {
	_, after, ok := strings.Cut(line, "//")
	if !ok {
		return ""
	}
	after = strings.TrimSpace(after)
	if !strings.HasPrefix(after, "Deprecated:") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(after, "Deprecated:"))
}

func goModuleRetractionDetails(version string, metadata goModuleMetadata, parsedMod parsedGoMod) (bool, string) {
	if metadata.Retracted {
		return true, strings.TrimSpace(metadata.RetractionRationale)
	}
	for _, retraction := range parsedMod.Retractions {
		if goModuleRetractionMatchesVersion(retraction.Version, version) {
			return true, retraction.Rationale
		}
	}
	return false, ""
}

func (a GoModuleAdapter) metadataDetails(normalized goModuleNormalized, refs []schema.SourceRef) map[string]any {
	details := map[string]any{
		"source":                  goModuleSourceName,
		"ecosystem":               "go",
		"module_path":             normalized.ModulePath,
		"package_name":            normalized.ModulePath,
		"version":                 normalized.Version,
		"purl":                    normalized.PURL,
		"selected_version_source": normalized.SelectedVersionSource,
		"source_url_status":       normalized.SourceURLStatus,
		"request_posture":         goModuleRequestPosture,
		"terms_url":               goModuleTermsURL,
		"retrieved_at":            normalized.RetrievedAt,
		"ttl_seconds":             normalized.TTLSeconds,
		"redistribution":          sources.RedistributionUnknown,
		"public_display":          sources.PublicDisplayAllowed,
	}
	if normalized.VersionTime != "" {
		details["version_time"] = normalized.VersionTime
	}
	if len(normalized.Versions) > 0 {
		details["versions"] = normalized.Versions
		details["version_count"] = len(normalized.Versions)
		details["version_list_status"] = "reported_by_go_module_services"
	} else {
		details["version_list_status"] = "not_reported"
	}
	if normalized.GoModReported {
		details["go_mod_status"] = "reported_by_go_module_services"
		if normalized.GoModModulePath != "" {
			details["go_mod_module_path"] = normalized.GoModModulePath
		}
		if normalized.GoVersion != "" {
			details["go_version"] = normalized.GoVersion
		}
	} else {
		details["go_mod_status"] = "not_reported"
	}
	if len(normalized.Requirements) > 0 {
		details["requirements_count"] = len(normalized.Requirements)
		details["requirements_status"] = "reported_by_go_mod_redacted"
	} else {
		details["requirements_status"] = "not_reported"
	}
	if normalized.DeprecationMessage != "" {
		details["deprecated"] = true
		details["deprecation_message"] = normalized.DeprecationMessage
	} else {
		details["deprecated"] = false
	}
	if normalized.Retracted {
		details["retracted"] = true
		if normalized.RetractionRationale != "" {
			details["retraction_rationale"] = normalized.RetractionRationale
		}
	} else {
		details["retracted"] = false
	}
	if len(refs) > 1 {
		details["source_refs"] = goModuleSourceRefDetails(refs)
	}
	return details
}

func (a GoModuleAdapter) deprecatedDetails(normalized goModuleNormalized) map[string]any {
	details := map[string]any{
		"source":              goModuleSourceName,
		"ecosystem":           "go",
		"module_path":         normalized.ModulePath,
		"package_name":        normalized.ModulePath,
		"version":             normalized.Version,
		"purl":                normalized.PURL,
		"deprecated":          true,
		"deprecation_message": normalized.DeprecationMessage,
		"request_posture":     goModuleRequestPosture,
		"terms_url":           goModuleTermsURL,
		"retrieved_at":        normalized.RetrievedAt,
		"ttl_seconds":         normalized.TTLSeconds,
		"redistribution":      sources.RedistributionUnknown,
		"public_display":      sources.PublicDisplayAllowed,
	}
	return details
}

func (a GoModuleAdapter) retractionDetails(normalized goModuleNormalized) map[string]any {
	details := map[string]any{
		"source":          goModuleSourceName,
		"ecosystem":       "go",
		"module_path":     normalized.ModulePath,
		"package_name":    normalized.ModulePath,
		"version":         normalized.Version,
		"purl":            normalized.PURL,
		"retracted":       true,
		"request_posture": goModuleRequestPosture,
		"terms_url":       goModuleTermsURL,
		"retrieved_at":    normalized.RetrievedAt,
		"ttl_seconds":     normalized.TTLSeconds,
		"redistribution":  sources.RedistributionUnknown,
		"public_display":  sources.PublicDisplayAllowed,
	}
	if normalized.RetractionRationale != "" {
		details["retraction_rationale"] = normalized.RetractionRationale
	}
	return details
}

func goModuleRequirementDetails(requirements []goModuleRequirement) []map[string]any {
	details := make([]map[string]any, 0, len(requirements))
	for _, requirement := range requirements {
		details = append(details, map[string]any{
			"module_path": requirement.ModulePath,
			"version":     requirement.Version,
			"indirect":    requirement.Indirect,
		})
	}
	return details
}

func (a GoModuleAdapter) sourceRefs(normalized goModuleNormalized) []schema.SourceRef {
	refs := []schema.SourceRef{
		a.versionSourceRef(normalized),
		a.moduleSourceRef(normalized),
	}
	if len(normalized.Versions) > 0 {
		refs = append(refs, a.versionListSourceRef(normalized))
	}
	if normalized.GoModReported {
		refs = append(refs, a.goModSourceRef(normalized))
	}
	if len(normalized.Requirements) > 0 {
		refs = append(refs, a.goModSourceRef(normalized))
	}
	return dedupeGoModuleSourceRefs(refs)
}

func (a GoModuleAdapter) versionSourceRef(normalized goModuleNormalized) schema.SourceRef {
	sourceID := goModuleVersionSourceID(normalized.ModulePath, normalized.Version)
	return a.sourceRef(sourceRefID(goModuleSourceName, sourceID), sourceID, normalized.SourceURL, "Source: Go module services version metadata from proxy.golang.org; preserve module path, version, source URL, retrieval time, and attribution. Do not imply Google or Go project endorsement.", normalized)
}

func (a GoModuleAdapter) moduleSourceRef(normalized goModuleNormalized) schema.SourceRef {
	sourceID := goModulePackageSourceID(normalized.ModulePath)
	return a.sourceRef(sourceRefID(goModuleSourceName, sourceID), sourceID, goModuleListURL(normalized.ModulePath), "Source: Go module services module metadata from proxy.golang.org; module metadata is non-authoritative package context and should be refreshed before relying on mutable endpoints.", normalized)
}

func (a GoModuleAdapter) versionListSourceRef(normalized goModuleNormalized) schema.SourceRef {
	sourceID := goModulePackageSourceID(normalized.ModulePath) + "#versions"
	return a.sourceRef(sourceRefID(goModuleSourceName, sourceID), sourceID, goModuleListURL(normalized.ModulePath), "Source: Go module proxy version list metadata from proxy.golang.org; version lists are service metadata and not an allow/deny signal.", normalized)
}

func (a GoModuleAdapter) goModSourceRef(normalized goModuleNormalized) schema.SourceRef {
	sourceID := goModuleVersionSourceID(normalized.ModulePath, normalized.Version) + "#go.mod"
	return a.sourceRef(sourceRefID(goModuleSourceName, sourceID), sourceID, goModuleModURL(normalized.ModulePath, normalized.Version), "Source: Go module proxy go.mod metadata from proxy.golang.org; requirements, retractions, and deprecation comments are publisher-provided module metadata.", normalized)
}

func (a GoModuleAdapter) localJSONSourceRef(data []byte) schema.SourceRef {
	sum := sha256.Sum256(bytes.TrimSpace(data))
	sourceID := "local-json:" + hex.EncodeToString(sum[:])[:16]
	return schema.SourceRef{
		ID:                  "go-module-services-json-" + hex.EncodeToString(sum[:])[:16],
		Source:              goModuleSourceName,
		SourceID:            sourceID,
		URL:                 "https://example.invalid/attach-open-score/go-module-services/" + url.PathEscape(sourceID),
		RetrievedAt:         a.now().UTC().Format(time.RFC3339),
		TTLSeconds:          a.ttlSeconds,
		LicenseOrTermsURL:   goModuleTermsURL,
		Attribution:         "Source: local/synthetic Go module services metadata JSON fixture for Attach Open Score tests; review Go module service terms before using real metadata.",
		AttributionRequired: true,
		Redistribution:      sources.RedistributionUnknown,
		PublicDisplay:       sources.PublicDisplayAllowed,
	}
}

func (a GoModuleAdapter) sourceRef(id, sourceID, sourceURL, attribution string, normalized goModuleNormalized) schema.SourceRef {
	return schema.SourceRef{
		ID:                  id,
		Source:              goModuleSourceName,
		SourceID:            sourceID,
		URL:                 sourceURL,
		RetrievedAt:         normalized.RetrievedAt,
		TTLSeconds:          normalized.TTLSeconds,
		LicenseOrTermsURL:   goModuleTermsURL,
		Attribution:         attribution,
		AttributionRequired: true,
		Redistribution:      sources.RedistributionUnknown,
		PublicDisplay:       sources.PublicDisplayAllowed,
	}
}

func (a GoModuleAdapter) sourceUnavailableEvidence(sourceRef schema.SourceRef, normalized *goModuleNormalized, failureKind string, extra map[string]any) schema.Evidence {
	details := map[string]any{
		"source":          goModuleSourceName,
		"failure_kind":    failureKind,
		"request_posture": goModuleRequestPosture,
		"terms_url":       goModuleTermsURL,
	}
	if normalized != nil {
		details["ecosystem"] = "go"
		details["module_path"] = normalized.ModulePath
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
			Message:        "Go module services metadata was unavailable, malformed, private, or missing required package identity data.",
			SourceRefIDs:   []string{sourceRef.ID},
			Details:        details,
		},
		SourceRef: &sourceRef,
	}
}

func goModuleEvidenceWithSourceRefs(reason schema.Reason, refs []schema.SourceRef) schema.Evidence {
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

func dedupeGoModuleSourceRefs(refs []schema.SourceRef) []schema.SourceRef {
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

func goModuleSourceRefDetails(refs []schema.SourceRef) []map[string]string {
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

func mergeGoModuleVersions(lists ...goModuleVersionList) []string {
	versions := []string{}
	for _, list := range lists {
		versions = append(versions, list...)
	}
	return normalizeGoModuleStringList(versions)
}

func splitGoModuleVersionList(value string) []string {
	lines := strings.Split(value, "\n")
	values := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		values = append(values, line)
	}
	return normalizeGoModuleStringList(values)
}

func normalizeGoModuleStringList(values []string) []string {
	normalized := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func dedupeGoModuleRequirements(requirements []goModuleRequirement) []goModuleRequirement {
	out := make([]goModuleRequirement, 0, len(requirements))
	seen := map[string]struct{}{}
	for _, requirement := range requirements {
		if strings.TrimSpace(requirement.ModulePath) == "" || strings.TrimSpace(requirement.Version) == "" {
			continue
		}
		key := requirement.ModulePath + "\x00" + requirement.Version + "\x00" + fmt.Sprint(requirement.Indirect)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, requirement)
	}
	return out
}

func sanitizeGoModulePublisherText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	if strings.Contains(value, "@") || strings.Contains(lower, "://") || strings.Contains(value, "?") || strings.Contains(value, "#") {
		return "redacted publisher-provided module comment"
	}
	for _, marker := range []string{".internal", ".corp", ".local", ".lan", ".home", "secret", "private", "internal", "confidential"} {
		if strings.Contains(lower, marker) {
			return "redacted publisher-provided module comment"
		}
	}
	return value
}

func sanitizeGoModuleRequirements(requirements []goModuleRequirement) []goModuleRequirement {
	out := make([]goModuleRequirement, 0, len(requirements))
	for _, requirement := range requirements {
		if !isPublicGoModulePathAllowed(requirement.ModulePath) {
			continue
		}
		out = append(out, requirement)
	}
	return out
}

func goModuleRetractionMatchesVersion(retractionVersion, version string) bool {
	retractionVersion = strings.TrimSpace(retractionVersion)
	version = strings.TrimSpace(version)
	if retractionVersion == version {
		return true
	}
	low, high, ok := strings.Cut(retractionVersion, "..")
	if !ok {
		return false
	}
	return compareGoModuleVersions(version, low) >= 0 && compareGoModuleVersions(version, high) <= 0
}

func compareGoModuleVersions(left, right string) int {
	leftCore, leftPre := splitGoModuleSemver(strings.TrimSpace(left))
	rightCore, rightPre := splitGoModuleSemver(strings.TrimSpace(right))
	leftParts := strings.Split(leftCore, ".")
	rightParts := strings.Split(rightCore, ".")
	max := len(leftParts)
	if len(rightParts) > max {
		max = len(rightParts)
	}
	for i := 0; i < max; i++ {
		lp := goModuleVersionPart(leftParts, i)
		rp := goModuleVersionPart(rightParts, i)
		if lp < rp {
			return -1
		}
		if lp > rp {
			return 1
		}
	}
	if leftPre == rightPre {
		return 0
	}
	if leftPre == "" {
		return 1
	}
	if rightPre == "" {
		return -1
	}
	return compareGoModulePrerelease(leftPre, rightPre)
}

func splitGoModuleSemver(version string) (string, string) {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	core, prerelease, _ := strings.Cut(version, "-")
	if plus := strings.Index(prerelease, "+"); plus >= 0 {
		prerelease = prerelease[:plus]
	}
	if plus := strings.Index(core, "+"); plus >= 0 {
		core = core[:plus]
	}
	return core, prerelease
}

func compareGoModulePrerelease(left, right string) int {
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	max := len(leftParts)
	if len(rightParts) > max {
		max = len(rightParts)
	}
	for i := 0; i < max; i++ {
		if i >= len(leftParts) {
			return -1
		}
		if i >= len(rightParts) {
			return 1
		}
		ln, lok := parseGoModuleNumericIdentifier(leftParts[i])
		rn, rok := parseGoModuleNumericIdentifier(rightParts[i])
		switch {
		case lok && rok:
			if ln < rn {
				return -1
			}
			if ln > rn {
				return 1
			}
		case lok && !rok:
			return -1
		case !lok && rok:
			return 1
		default:
			if leftParts[i] < rightParts[i] {
				return -1
			}
			if leftParts[i] > rightParts[i] {
				return 1
			}
		}
	}
	return 0
}

func parseGoModuleNumericIdentifier(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	out := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, false
		}
		out = out*10 + int(r-'0')
	}
	return out, true
}

func goModuleVersionPart(parts []string, index int) int {
	if index >= len(parts) {
		return 0
	}
	part := parts[index]
	value := 0
	for _, r := range part {
		if r < '0' || r > '9' {
			break
		}
		value = value*10 + int(r-'0')
	}
	return value
}

func sanitizeGoModuleFixtureSourceURL(raw, fallback string) (string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback, "generated"
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || !isGoModuleServiceHost(parsed.Host) {
		return fallback, "fallback_sanitized"
	}
	hadQueryOrFragment := parsed.RawQuery != "" || parsed.Fragment != ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	sanitized := parsed.String()
	if sanitized == "" || sanitized != fallback {
		return fallback, "fallback_sanitized"
	}
	if hadQueryOrFragment {
		return sanitized, "sanitized"
	}
	return sanitized, "reported"
}

func isGoModuleServiceHost(host string) bool {
	switch strings.ToLower(host) {
	case "proxy.golang.org", "index.golang.org", "sum.golang.org":
		return true
	default:
		return false
	}
}

func isPublicGoModulePathAllowed(modulePath string) bool {
	value := strings.TrimSpace(modulePath)
	if value == "" {
		return false
	}
	if strings.ContainsAny(value, " \t\r\n\\?#") || strings.Contains(value, "://") || strings.Contains(value, "@") {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) == 0 || parts[0] == "" {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	if isSafeSyntheticGoModulePath(value) {
		return true
	}
	host := strings.ToLower(parts[0])
	if !strings.Contains(host, ".") || host == "localhost" || strings.Contains(host, ":") {
		return false
	}
	for _, suffix := range []string{".internal", ".corp", ".local", ".lan", ".home"} {
		if strings.HasSuffix(host, suffix) {
			return false
		}
	}
	for _, label := range strings.Split(host, ".") {
		for _, marker := range []string{"private", "internal", "secret", "secrets", "confidential"} {
			if strings.Contains(label, marker) {
				return false
			}
		}
	}
	for _, part := range parts[1:] {
		part = strings.ToLower(part)
		for _, marker := range []string{"private", "internal", "secret", "secrets", "confidential"} {
			if strings.Contains(part, marker) {
				return false
			}
		}
	}
	return true
}

func isSafeSyntheticGoModulePath(modulePath string) bool {
	host := strings.ToLower(strings.Split(modulePath, "/")[0])
	return host == "example.com" || host == "example.org" || host == "example.net"
}

func goModulePackageSourceID(modulePath string) string {
	return "proxy.golang.org/" + strings.TrimSpace(modulePath)
}

func goModuleVersionSourceID(modulePath, version string) string {
	return goModulePackageSourceID(modulePath) + "@" + strings.TrimSpace(version)
}

func goModuleListURL(modulePath string) string {
	return goModuleProxyBase + "/" + goModuleProxyPath(modulePath) + "/@v/list"
}

func goModuleVersionURL(modulePath, version string) string {
	return goModuleProxyBase + "/" + goModuleProxyPath(modulePath) + "/@v/" + url.PathEscape(strings.TrimSpace(version)) + ".info"
}

func goModuleModURL(modulePath, version string) string {
	return goModuleProxyBase + "/" + goModuleProxyPath(modulePath) + "/@v/" + url.PathEscape(strings.TrimSpace(version)) + ".mod"
}

func goModuleProxyPath(modulePath string) string {
	parts := strings.Split(strings.TrimSpace(modulePath), "/")
	for i, part := range parts {
		parts[i] = strings.ReplaceAll(url.PathEscape(goModuleProxyEscapeUppercase(part)), "%21", "!")
	}
	return strings.Join(parts, "/")
}

func goModuleProxyEscapeUppercase(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if r >= 'A' && r <= 'Z' {
			builder.WriteByte('!')
			builder.WriteRune(r + ('a' - 'A'))
			continue
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

func goModulePURL(modulePath, version string) string {
	return "pkg:golang/" + strings.TrimSpace(modulePath) + "@" + url.PathEscape(strings.TrimSpace(version))
}
