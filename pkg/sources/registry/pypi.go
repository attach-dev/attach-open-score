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
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/sources"
)

const (
	pypiSourceName     = "pypi-registry"
	pypiTermsURL       = "https://policies.python.org/pypi.org/Terms-of-Service/"
	pypiJSONBase       = "https://pypi.org/pypi"
	pypiSimpleBase     = "https://pypi.org/simple"
	pypiRequestPosture = "fixture_first_pypi_json_and_index_metadata_only_no_live_calls_no_account_or_contact_scraping"
)

var pypiNameSeparator = regexp.MustCompile(`[-_.]+`)

type PyPIOptions struct {
	Now        func() time.Time
	TTLSeconds int
}

type PyPIAdapter struct {
	now        func() time.Time
	ttlSeconds int
}

type pypiMetadata struct {
	Info            pypiInfo              `json:"info,omitempty"`
	LastSerial      *float64              `json:"last_serial,omitempty"`
	Releases        map[string][]pypiFile `json:"releases,omitempty"`
	URLs            []pypiFile            `json:"urls,omitempty"`
	Meta            pypiIndexMeta         `json:"meta,omitempty"`
	Name            string                `json:"name,omitempty"`
	Versions        []string              `json:"versions,omitempty"`
	Files           []pypiFile            `json:"files,omitempty"`
	IndexLastSerial *float64              `json:"_last-serial,omitempty"`
	ETag            string                `json:"etag,omitempty"`
}

type pypiInfo struct {
	Name           string            `json:"name,omitempty"`
	Version        string            `json:"version,omitempty"`
	License        string            `json:"license,omitempty"`
	RequiresPython string            `json:"requires_python,omitempty"`
	ProjectURLs    map[string]string `json:"project_urls,omitempty"`
	HomePage       string            `json:"home_page,omitempty"`
}

type pypiIndexMeta struct {
	APIVersion string `json:"api-version,omitempty"`
}

type pypiFile struct {
	Filename            string            `json:"filename,omitempty"`
	PackageType         string            `json:"packagetype,omitempty"`
	PythonVersion       string            `json:"python_version,omitempty"`
	RequiresPython      string            `json:"requires_python,omitempty"`
	IndexRequiresPython string            `json:"requires-python,omitempty"`
	UploadTimeISO8601   string            `json:"upload_time_iso_8601,omitempty"`
	UploadTime          string            `json:"upload-time,omitempty"`
	URL                 string            `json:"url,omitempty"`
	Digests             map[string]string `json:"digests,omitempty"`
	Hashes              map[string]string `json:"hashes,omitempty"`
	Yanked              pypiYankedValue   `json:"yanked,omitempty"`
	YankedReason        string            `json:"yanked_reason,omitempty"`
}

type pypiYankedValue struct {
	Yanked bool
	Reason string
}

type pypiNormalized struct {
	Name                   string
	Version                string
	PURL                   string
	SelectedVersionSource  string
	MetadataFormat         string
	IndexAPIVersion        string
	LastSerial             *float64
	ETagPresent            bool
	License                string
	LicenseStatus          string
	LicenseReported        bool
	RequiresPython         string
	RequiresPythonStatus   string
	RequiresPythonReported bool
	ProjectURLs            map[string]string
	RepositoryURL          string
	RepositoryStatus       string
	RepositoryReported     bool
	Files                  []pypiFileNormalized
	YankedFileCount        int
	YankedReason           string
}

type pypiFileNormalized struct {
	Filename       string
	PackageType    string
	PythonVersion  string
	RequiresPython string
	UploadedAt     string
	SHA256         string
	Blake2b256     string
	Yanked         bool
	YankedReason   string
}

type pypiValidation struct {
	ok          bool
	failureKind string
	missing     []string
	conflicts   []string
}

func NewPyPIAdapter(options PyPIOptions) (PyPIAdapter, error) {
	now := options.Now
	if now == nil {
		now = time.Now
	}

	ttlSeconds := options.TTLSeconds
	if ttlSeconds == 0 {
		ttlSeconds = DefaultTTLSeconds
	}
	if ttlSeconds < 0 {
		return PyPIAdapter{}, fmt.Errorf("pypi registry ttl_seconds must be non-negative")
	}

	return PyPIAdapter{
		now:        now,
		ttlSeconds: ttlSeconds,
	}, nil
}

func (a PyPIAdapter) EvidenceFromJSON(data []byte, coordinate Coordinate) ([]schema.Evidence, error) {
	sourceRef := a.localJSONSourceRef(data)
	metadata, err := parsePyPIMetadata(data)
	if err != nil {
		return []schema.Evidence{a.sourceUnavailableEvidence(sourceRef, nil, "parse_failure", map[string]any{
			"parse_error": err.Error(),
		})}, nil
	}

	return a.evidence(metadata, coordinate, sourceRef), nil
}

func parsePyPIMetadata(data []byte) (pypiMetadata, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return pypiMetadata{}, errors.New("PyPI registry metadata JSON is empty")
	}
	if data[0] == '[' {
		return pypiMetadata{}, errors.New("PyPI registry metadata JSON must be an object")
	}

	var metadata pypiMetadata
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&metadata); err != nil {
		return pypiMetadata{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return pypiMetadata{}, errors.New("PyPI registry metadata JSON contains trailing data")
	}
	return metadata, nil
}

func (y *pypiYankedValue) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if data[0] == 't' || data[0] == 'f' {
		var value bool
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		y.Yanked = value
		return nil
	}
	if data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		value = strings.TrimSpace(value)
		if value != "" {
			y.Yanked = true
			y.Reason = value
		}
		return nil
	}
	return fmt.Errorf("PyPI yanked metadata must be a boolean, string, or null")
}

func (a PyPIAdapter) evidence(metadata pypiMetadata, coordinate Coordinate, fallbackSourceRef schema.SourceRef) []schema.Evidence {
	normalized, validation := normalizePyPIMetadata(metadata, coordinate)
	if !validation.ok {
		return []schema.Evidence{a.sourceUnavailableEvidence(fallbackSourceRef, nil, validation.failureKind, validation.details())}
	}

	sourceRefs := a.sourceRefs(normalized)
	details := a.metadataDetails(normalized, sourceRefs)

	evidence := []schema.Evidence{pypiEvidenceWithSourceRefs(schema.Reason{
		Code:           reasons.RepositoryMappingUncertain,
		Severity:       "MEDIUM",
		DecisionEffect: schema.DecisionEffectUnknown,
		Message:        fmt.Sprintf("PyPI public registry metadata for %s %s was normalized as non-authoritative package context only.", normalized.Name, normalized.Version),
		SourceRefIDs:   sourceRefIDs(sourceRefs),
		Details:        details,
	}, sourceRefs)}

	if normalized.YankedFileCount > 0 {
		versionRef := sourceRefs[0]
		evidence = append(evidence, pypiEvidenceWithSourceRefs(schema.Reason{
			Code:           reasons.PackageUnpublishedOrYanked,
			Severity:       "HIGH",
			DecisionEffect: schema.DecisionEffectAsk,
			Message:        fmt.Sprintf("PyPI public registry metadata marks release files for %s %s as yanked.", normalized.Name, normalized.Version),
			SourceRefIDs:   []string{versionRef.ID},
			Details:        a.yankedDetails(normalized),
		}, []schema.SourceRef{versionRef}))
	}

	return evidence
}

func normalizePyPIMetadata(metadata pypiMetadata, coordinate Coordinate) (pypiNormalized, pypiValidation) {
	metadataFormat := detectPyPIFormat(metadata)
	selectedVersion, selectedVersionSource := selectPyPIVersion(metadata, coordinate, metadataFormat)

	conflicts := []string{}
	if coordinate.Ecosystem != "" && !strings.EqualFold(strings.TrimSpace(coordinate.Ecosystem), "pypi") {
		conflicts = append(conflicts, "coordinate.ecosystem")
	}

	name := ""
	addPyPIIdentityValue(&name, &conflicts, "coordinate.name", coordinate.Name)
	addPyPIIdentityValue(&name, &conflicts, "info.name", metadata.Info.Name)
	addPyPIIdentityValue(&name, &conflicts, "name", metadata.Name)

	version := strings.TrimSpace(selectedVersion)
	if shouldComparePyPIInfoVersion(metadata, selectedVersionSource) {
		addPyPIVersionValue(&version, &conflicts, "info.version", metadata.Info.Version)
	}
	if pypiVersionListContains(metadata.Versions, selectedVersion) {
		addPyPIVersionValue(&version, &conflicts, "versions", selectedVersion)
	}

	if len(conflicts) > 0 {
		return pypiNormalized{}, pypiValidation{failureKind: "conflicting_required_data", conflicts: conflicts}
	}

	metadataHasName := strings.TrimSpace(metadata.Info.Name) != "" || strings.TrimSpace(metadata.Name) != ""
	metadataHasVersion := pypiMetadataIncludesVersion(metadata, selectedVersion, metadataFormat)

	missing := []string{}
	if name == "" || !metadataHasName {
		missing = append(missing, "name")
	}
	if version == "" || !metadataHasVersion {
		missing = append(missing, "version")
	}
	if len(missing) > 0 {
		return pypiNormalized{}, pypiValidation{failureKind: "missing_required_data", missing: missing}
	}

	files := normalizePyPIReleaseFiles(selectedPyPIReleaseFiles(metadata, version, metadataFormat))
	license, licenseStatus, licenseReported := pypiLicenseDetails(metadata)
	requiresPython, requiresPythonStatus, requiresPythonReported := pypiRequiresPythonDetails(metadata, files)
	projectURLs := sanitizePyPIProjectURLs(metadata.Info.ProjectURLs, metadata.Info.HomePage)
	repositoryURL, repositoryStatus, repositoryReported := pypiRepositoryDetails(metadata.Info.ProjectURLs, metadata.Info.HomePage)
	yankedCount, yankedReason := pypiYankedSummary(files)

	normalized := pypiNormalized{
		Name:                   name,
		Version:                version,
		PURL:                   pypiPURL(name, version),
		SelectedVersionSource:  selectedVersionSource,
		MetadataFormat:         metadataFormat,
		IndexAPIVersion:        strings.TrimSpace(metadata.Meta.APIVersion),
		LastSerial:             selectPyPILastSerial(metadata),
		ETagPresent:            strings.TrimSpace(metadata.ETag) != "",
		License:                license,
		LicenseStatus:          licenseStatus,
		LicenseReported:        licenseReported,
		RequiresPython:         requiresPython,
		RequiresPythonStatus:   requiresPythonStatus,
		RequiresPythonReported: requiresPythonReported,
		ProjectURLs:            projectURLs,
		RepositoryURL:          repositoryURL,
		RepositoryStatus:       repositoryStatus,
		RepositoryReported:     repositoryReported,
		Files:                  files,
		YankedFileCount:        yankedCount,
		YankedReason:           yankedReason,
	}
	return normalized, pypiValidation{ok: true}
}

func detectPyPIFormat(metadata pypiMetadata) string {
	if strings.TrimSpace(metadata.Info.Name) != "" || strings.TrimSpace(metadata.Info.Version) != "" || len(metadata.Releases) > 0 || len(metadata.URLs) > 0 || metadata.LastSerial != nil {
		return "pypi_json"
	}
	if strings.TrimSpace(metadata.Meta.APIVersion) != "" || strings.TrimSpace(metadata.Name) != "" || len(metadata.Versions) > 0 || len(metadata.Files) > 0 || metadata.IndexLastSerial != nil || strings.TrimSpace(metadata.ETag) != "" {
		return "pypi_index_json"
	}
	return "pypi_json"
}

func selectPyPIVersion(metadata pypiMetadata, coordinate Coordinate, metadataFormat string) (string, string) {
	if version := strings.TrimSpace(coordinate.Version); version != "" {
		return version, "requested_version"
	}
	if metadataFormat == "pypi_json" {
		if version := strings.TrimSpace(metadata.Info.Version); version != "" {
			return version, "info.version"
		}
		if len(metadata.Releases) == 1 {
			for version := range metadata.Releases {
				return strings.TrimSpace(version), "single_release"
			}
		}
	}
	if len(metadata.Versions) == 1 {
		return strings.TrimSpace(metadata.Versions[0]), "single_version"
	}
	return "", ""
}

func pypiMetadataIncludesVersion(metadata pypiMetadata, version, metadataFormat string) bool {
	version = strings.TrimSpace(version)
	if version == "" {
		return false
	}
	if strings.TrimSpace(metadata.Info.Version) == version {
		return true
	}
	if _, ok := metadata.Releases[version]; ok {
		return true
	}
	if len(metadata.URLs) > 0 && metadataFormat == "pypi_json" {
		infoVersion := strings.TrimSpace(metadata.Info.Version)
		return infoVersion == "" || infoVersion == version
	}
	if pypiVersionListContains(metadata.Versions, version) {
		return true
	}
	for _, file := range metadata.Files {
		if pypiFileMatchesVersion(file.Filename, version) {
			return true
		}
	}
	return false
}

func pypiVersionListContains(versions []string, version string) bool {
	version = strings.TrimSpace(version)
	if version == "" {
		return false
	}
	for _, candidate := range versions {
		if strings.TrimSpace(candidate) == version {
			return true
		}
	}
	return false
}

func selectedPyPIReleaseFiles(metadata pypiMetadata, version, metadataFormat string) []pypiFile {
	version = strings.TrimSpace(version)
	if metadataFormat == "pypi_json" {
		if files, ok := metadata.Releases[version]; ok {
			return files
		}
		infoVersion := strings.TrimSpace(metadata.Info.Version)
		if len(metadata.URLs) > 0 && (infoVersion == "" || infoVersion == version) {
			return metadata.URLs
		}
		return nil
	}

	files := make([]pypiFile, 0, len(metadata.Files))
	for _, file := range metadata.Files {
		if pypiFileMatchesVersion(file.Filename, version) {
			files = append(files, file)
		}
	}
	if len(files) == 0 && len(metadata.Versions) == 1 && strings.TrimSpace(metadata.Versions[0]) == version {
		return nil
	}
	return files
}

func shouldComparePyPIInfoVersion(metadata pypiMetadata, selectedVersionSource string) bool {
	if strings.TrimSpace(metadata.Info.Version) == "" {
		return false
	}
	if selectedVersionSource == "info.version" {
		return true
	}
	return len(metadata.Releases) == 0
}

func addPyPIIdentityValue(current *string, conflicts *[]string, field, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	value = normalizePyPIProjectName(value)
	if *current == "" {
		*current = value
		return
	}
	if normalizePyPIProjectName(*current) != value {
		*conflicts = append(*conflicts, field)
	}
}

func addPyPIVersionValue(current *string, conflicts *[]string, field, value string) {
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

func pypiLicenseDetails(metadata pypiMetadata) (string, string, bool) {
	license := strings.TrimSpace(metadata.Info.License)
	if license == "" {
		return "", "not_reported", false
	}
	return license, "reported_by_pypi", true
}

func pypiRequiresPythonDetails(metadata pypiMetadata, files []pypiFileNormalized) (string, string, bool) {
	if value := strings.TrimSpace(metadata.Info.RequiresPython); value != "" {
		return value, "reported_by_pypi", true
	}
	values := map[string]struct{}{}
	for _, file := range files {
		if file.RequiresPython != "" {
			values[file.RequiresPython] = struct{}{}
		}
	}
	if len(values) == 0 {
		return "", "not_reported", false
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) == 1 {
		return out[0], "reported_by_pypi_release_files", true
	}
	return strings.Join(out, ", "), "reported_by_pypi_release_files_multiple_values", true
}

func sanitizePyPIProjectURLs(projectURLs map[string]string, homePage string) map[string]string {
	values := map[string]string{}
	keys := make([]string, 0, len(projectURLs))
	for key := range projectURLs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		label := sanitizePyPIProjectURLLabel(key)
		if label == "" {
			continue
		}
		if sanitized := sanitizeSourceURL(projectURLs[key], ""); sanitized != "" {
			values[label] = sanitized
		}
	}
	if _, ok := values["Homepage"]; !ok {
		if sanitized := sanitizeSourceURL(homePage, ""); sanitized != "" {
			values["Homepage"] = sanitized
		}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func pypiRepositoryDetails(projectURLs map[string]string, homePage string) (string, string, bool) {
	candidates := preferredPyPIProjectURLCandidates(projectURLs, homePage)
	if len(candidates) == 0 {
		return "", "not_reported", false
	}
	for _, raw := range candidates {
		normalized, err := NormalizeRepositoryURL(raw)
		if err == nil {
			return normalized, "reported_by_pypi_project_urls", true
		}
	}
	return "", "invalid_or_sensitive", true
}

func sanitizePyPIProjectURLLabel(label string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return ""
	}
	lower := strings.ToLower(label)
	if strings.Contains(label, "@") || strings.Contains(lower, "://") || strings.Contains(label, "?") || strings.Contains(label, "#") {
		return "redacted-project-url-label"
	}
	for _, marker := range []string{"token", "secret", "password", "credential", "private", "confidential"} {
		if strings.Contains(lower, marker) {
			return "redacted-project-url-label"
		}
	}
	return label
}

func preferredPyPIProjectURLCandidates(projectURLs map[string]string, homePage string) []string {
	type candidate struct {
		rank  int
		label string
		value string
	}
	candidates := []candidate{}
	for label, value := range projectURLs {
		label = strings.TrimSpace(label)
		value = strings.TrimSpace(value)
		if label == "" || value == "" {
			continue
		}
		rank := pypiProjectURLRank(label)
		if rank < 100 {
			candidates = append(candidates, candidate{rank: rank, label: label, value: value})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].rank != candidates[j].rank {
			return candidates[i].rank < candidates[j].rank
		}
		return candidates[i].label < candidates[j].label
	})
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate.value)
	}
	return out
}

func pypiProjectURLRank(label string) int {
	normalized := strings.ToLower(strings.TrimSpace(label))
	normalized = strings.ReplaceAll(normalized, "_", " ")
	normalized = strings.ReplaceAll(normalized, "-", " ")
	switch normalized {
	case "source", "source code", "sources":
		return 0
	case "repository", "repo", "code":
		return 1
	case "homepage", "home page":
		return 100
	default:
		return 100
	}
}

func selectPyPILastSerial(metadata pypiMetadata) *float64 {
	if metadata.LastSerial != nil {
		return metadata.LastSerial
	}
	return metadata.IndexLastSerial
}

func normalizePyPIReleaseFiles(files []pypiFile) []pypiFileNormalized {
	out := make([]pypiFileNormalized, 0, len(files))
	seen := map[string]struct{}{}
	for _, file := range files {
		normalized := normalizePyPIReleaseFile(file)
		if normalized.Filename == "" {
			continue
		}
		key := strings.Join([]string{
			normalized.Filename,
			normalized.SHA256,
			normalized.Blake2b256,
			normalized.RequiresPython,
			fmt.Sprintf("%t", normalized.Yanked),
			normalized.YankedReason,
		}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, normalized)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Filename != out[j].Filename {
			return out[i].Filename < out[j].Filename
		}
		return out[i].SHA256 < out[j].SHA256
	})
	return out
}

func normalizePyPIReleaseFile(file pypiFile) pypiFileNormalized {
	digests := normalizePyPIDigests(file.Digests, file.Hashes)
	yanked := file.Yanked.Yanked
	yankedReason := sanitizePyPIYankedReason(firstNonEmpty(file.Yanked.Reason, file.YankedReason))
	if yankedReason != "" {
		yanked = true
	}
	return pypiFileNormalized{
		Filename:       strings.TrimSpace(file.Filename),
		PackageType:    strings.TrimSpace(file.PackageType),
		PythonVersion:  strings.TrimSpace(file.PythonVersion),
		RequiresPython: strings.TrimSpace(firstNonEmpty(file.RequiresPython, file.IndexRequiresPython)),
		UploadedAt:     strings.TrimSpace(firstNonEmpty(file.UploadTimeISO8601, file.UploadTime)),
		SHA256:         digests["sha256"],
		Blake2b256:     digests["blake2b_256"],
		Yanked:         yanked,
		YankedReason:   yankedReason,
	}
}

func normalizePyPIDigests(values ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, value := range values {
		for key, digest := range value {
			key = strings.ToLower(strings.TrimSpace(key))
			digest = strings.TrimSpace(digest)
			if key == "" || digest == "" {
				continue
			}
			out[key] = digest
		}
	}
	return out
}

func sanitizePyPIYankedReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return ""
	}
	lower := strings.ToLower(reason)
	if strings.Contains(reason, "@") || strings.Contains(lower, "://") || strings.Contains(reason, "?") || strings.Contains(reason, "#") {
		return "redacted publisher-provided yanked reason"
	}
	return reason
}

func pypiYankedSummary(files []pypiFileNormalized) (int, string) {
	count := 0
	reasons := map[string]struct{}{}
	for _, file := range files {
		if !file.Yanked {
			continue
		}
		count++
		if file.YankedReason != "" {
			reasons[file.YankedReason] = struct{}{}
		}
	}
	if len(reasons) == 0 {
		return count, ""
	}
	out := make([]string, 0, len(reasons))
	for reason := range reasons {
		out = append(out, reason)
	}
	sort.Strings(out)
	return count, strings.Join(out, "; ")
}

func pypiFileMatchesVersion(filename, version string) bool {
	return pypiFileVersion(filename) == strings.TrimSpace(version)
}

func pypiFileVersion(filename string) string {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return ""
	}
	base := filename
	if strings.HasSuffix(base, ".whl") {
		base = strings.TrimSuffix(base, ".whl")
		parts := strings.Split(base, "-")
		if len(parts) >= 2 {
			return strings.TrimSpace(parts[1])
		}
		return ""
	}
	for _, suffix := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".tgz"} {
		if strings.HasSuffix(base, suffix) {
			base = strings.TrimSuffix(base, suffix)
			break
		}
	}
	index := strings.LastIndex(base, "-")
	if index < 0 {
		index = strings.LastIndex(base, "_")
	}
	if index < 0 || index+1 >= len(base) {
		return ""
	}
	return strings.TrimSpace(base[index+1:])
}

func (v pypiValidation) details() map[string]any {
	details := map[string]any{
		"source":          pypiSourceName,
		"request_posture": pypiRequestPosture,
		"terms_url":       pypiTermsURL,
	}
	if len(v.missing) > 0 {
		details["missing_fields"] = v.missing
	}
	if len(v.conflicts) > 0 {
		details["conflicting_fields"] = v.conflicts
	}
	return details
}

func (a PyPIAdapter) metadataDetails(normalized pypiNormalized, refs []schema.SourceRef) map[string]any {
	details := map[string]any{
		"source":                    pypiSourceName,
		"ecosystem":                 "pypi",
		"package_name":              normalized.Name,
		"version":                   normalized.Version,
		"purl":                      normalized.PURL,
		"selected_version_source":   normalized.SelectedVersionSource,
		"metadata_format":           normalized.MetadataFormat,
		"release_file_count":        len(normalized.Files),
		"yanked_file_count":         normalized.YankedFileCount,
		"requires_python_status":    normalized.RequiresPythonStatus,
		"license_metadata_status":   normalized.LicenseStatus,
		"repository_mapping_status": normalized.RepositoryStatus,
		"serial_ttl_posture":        "short_ttl_serial_or_etag_aware_refresh_recommended",
		"request_posture":           pypiRequestPosture,
		"terms_url":                 pypiTermsURL,
		"retrieved_at":              a.now().UTC().Format(time.RFC3339),
		"ttl_seconds":               a.ttlSeconds,
		"redistribution":            sources.RedistributionUnknown,
		"public_display":            sources.PublicDisplayAllowed,
	}
	if normalized.IndexAPIVersion != "" {
		details["index_api_version"] = normalized.IndexAPIVersion
	}
	if normalized.LastSerial != nil {
		details["last_serial"] = *normalized.LastSerial
	}
	if normalized.ETagPresent {
		details["etag_present"] = true
	}
	if normalized.License != "" {
		details["license"] = normalized.License
	}
	if normalized.RequiresPython != "" {
		details["requires_python"] = normalized.RequiresPython
	}
	if normalized.RepositoryURL != "" {
		details["repository_url"] = normalized.RepositoryURL
	}
	if len(normalized.ProjectURLs) > 0 {
		details["project_urls"] = normalized.ProjectURLs
	}
	if len(normalized.Files) > 0 {
		details["release_files"] = pypiReleaseFileDetails(normalized.Files)
	}
	if normalized.YankedReason != "" {
		details["yanked_reason"] = normalized.YankedReason
	}
	if len(refs) > 1 {
		details["source_refs"] = pypiSourceRefDetails(refs)
	}
	return details
}

func (a PyPIAdapter) yankedDetails(normalized pypiNormalized) map[string]any {
	details := map[string]any{
		"source":            pypiSourceName,
		"ecosystem":         "pypi",
		"package_name":      normalized.Name,
		"version":           normalized.Version,
		"purl":              normalized.PURL,
		"metadata_format":   normalized.MetadataFormat,
		"yanked_file_count": normalized.YankedFileCount,
		"request_posture":   pypiRequestPosture,
		"terms_url":         pypiTermsURL,
		"retrieved_at":      a.now().UTC().Format(time.RFC3339),
		"ttl_seconds":       a.ttlSeconds,
		"redistribution":    sources.RedistributionUnknown,
		"public_display":    sources.PublicDisplayAllowed,
	}
	if normalized.YankedReason != "" {
		details["yanked_reason"] = normalized.YankedReason
	}
	yankedFiles := []string{}
	for _, file := range normalized.Files {
		if file.Yanked {
			yankedFiles = append(yankedFiles, file.Filename)
		}
	}
	if len(yankedFiles) > 0 {
		details["yanked_files"] = yankedFiles
	}
	return details
}

func pypiReleaseFileDetails(files []pypiFileNormalized) []map[string]any {
	details := make([]map[string]any, 0, len(files))
	for _, file := range files {
		item := map[string]any{
			"filename": file.Filename,
			"yanked":   file.Yanked,
		}
		if file.PackageType != "" {
			item["packagetype"] = file.PackageType
		}
		if file.PythonVersion != "" {
			item["python_version"] = file.PythonVersion
		}
		if file.RequiresPython != "" {
			item["requires_python"] = file.RequiresPython
		}
		if file.UploadedAt != "" {
			item["uploaded_at"] = file.UploadedAt
		}
		if file.SHA256 != "" {
			item["sha256"] = file.SHA256
		}
		if file.Blake2b256 != "" {
			item["blake2b_256"] = file.Blake2b256
		}
		if file.YankedReason != "" {
			item["yanked_reason"] = file.YankedReason
		}
		details = append(details, item)
	}
	return details
}

func (a PyPIAdapter) sourceRefs(normalized pypiNormalized) []schema.SourceRef {
	refs := []schema.SourceRef{a.versionSourceRef(normalized)}
	refs = append(refs, a.packageSourceRef(normalized))
	if normalized.LicenseReported {
		refs = append(refs, a.licenseSourceRef(normalized))
	}
	if normalized.RequiresPythonReported {
		refs = append(refs, a.requiresPythonSourceRef(normalized))
	}
	if normalized.RepositoryReported {
		refs = append(refs, a.repositorySourceRef(normalized))
	}
	return dedupePyPISourceRefs(refs)
}

func (a PyPIAdapter) versionSourceRef(normalized pypiNormalized) schema.SourceRef {
	if normalized.MetadataFormat == "pypi_index_json" {
		sourceID := pypiIndexVersionSourceID(normalized.Name, normalized.Version)
		return a.sourceRef(sourceRefID(pypiSourceName, sourceID), sourceID, pypiIndexURL(normalized.Name), "Source: PyPI Simple/Index project metadata from pypi.org; preserve project name, selected version, retrieval time, TTL, and attribution. Do not imply PyPI endorsement.")
	}
	sourceID := pypiVersionSourceID(normalized.Name, normalized.Version)
	return a.sourceRef(sourceRefID(pypiSourceName, sourceID), sourceID, pypiVersionURL(normalized.Name, normalized.Version), "Source: PyPI JSON release metadata from pypi.org; preserve project name, version, release-file metadata, retrieval time, TTL, and attribution. Do not imply PyPI endorsement.")
}

func (a PyPIAdapter) packageSourceRef(normalized pypiNormalized) schema.SourceRef {
	if normalized.MetadataFormat == "pypi_index_json" {
		sourceID := pypiIndexPackageSourceID(normalized.Name)
		return a.sourceRef(sourceRefID(pypiSourceName, sourceID), sourceID, pypiIndexURL(normalized.Name), "Source: PyPI Simple/Index project metadata from pypi.org; project-level metadata is mutable and should use serial or ETag-aware refresh.")
	}
	sourceID := pypiPackageSourceID(normalized.Name)
	return a.sourceRef(sourceRefID(pypiSourceName, sourceID), sourceID, pypiPackageURL(normalized.Name), "Source: PyPI JSON project metadata from pypi.org; project-level metadata is mutable and should use X-PyPI-Last-Serial-aware refresh.")
}

func (a PyPIAdapter) licenseSourceRef(normalized pypiNormalized) schema.SourceRef {
	sourceID, sourceURL := pypiVersionFactSource(normalized, "#license")
	return a.sourceRef(sourceRefID(pypiSourceName, sourceID), sourceID, sourceURL, "Source: PyPI JSON project metadata license field from pypi.org; license strings are publisher-provided metadata.")
}

func (a PyPIAdapter) requiresPythonSourceRef(normalized pypiNormalized) schema.SourceRef {
	sourceID, sourceURL := pypiVersionFactSource(normalized, "#requires-python")
	return a.sourceRef(sourceRefID(pypiSourceName, sourceID), sourceID, sourceURL, "Source: PyPI project or release-file metadata requires-python field from pypi.org; compatibility strings are publisher-provided metadata.")
}

func (a PyPIAdapter) repositorySourceRef(normalized pypiNormalized) schema.SourceRef {
	sourceID, sourceURL := pypiVersionFactSource(normalized, "#project-urls")
	return a.sourceRef(sourceRefID(pypiSourceName, sourceID), sourceID, sourceURL, "Source: PyPI project_urls metadata from pypi.org; repository mapping is non-authoritative.")
}

func (a PyPIAdapter) localJSONSourceRef(data []byte) schema.SourceRef {
	sum := sha256.Sum256(bytes.TrimSpace(data))
	sourceID := "local-json:" + hex.EncodeToString(sum[:])[:16]
	return a.sourceRef("pypi-registry-json-"+hex.EncodeToString(sum[:])[:16], sourceID, "https://example.invalid/attach-open-score/pypi-registry/"+url.PathEscape(sourceID), "Source: local/synthetic PyPI public registry metadata JSON fixture for Attach Open Score tests; review PyPI terms before using real metadata.")
}

func (a PyPIAdapter) sourceRef(id, sourceID, sourceURL, attribution string) schema.SourceRef {
	return schema.SourceRef{
		ID:                  id,
		Source:              pypiSourceName,
		SourceID:            sourceID,
		URL:                 sourceURL,
		RetrievedAt:         a.now().UTC().Format(time.RFC3339),
		TTLSeconds:          a.ttlSeconds,
		LicenseOrTermsURL:   pypiTermsURL,
		Attribution:         attribution,
		AttributionRequired: true,
		Redistribution:      sources.RedistributionUnknown,
		PublicDisplay:       sources.PublicDisplayAllowed,
	}
}

func (a PyPIAdapter) sourceUnavailableEvidence(sourceRef schema.SourceRef, normalized *pypiNormalized, failureKind string, extra map[string]any) schema.Evidence {
	details := map[string]any{
		"source":          pypiSourceName,
		"failure_kind":    failureKind,
		"request_posture": pypiRequestPosture,
		"terms_url":       pypiTermsURL,
	}
	if normalized != nil {
		details["ecosystem"] = "pypi"
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
			Message:        "PyPI public registry metadata was unavailable, malformed, or missing required package identity data.",
			SourceRefIDs:   []string{sourceRef.ID},
			Details:        details,
		},
		SourceRef: &sourceRef,
	}
}

func pypiEvidenceWithSourceRefs(reason schema.Reason, refs []schema.SourceRef) schema.Evidence {
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

func dedupePyPISourceRefs(refs []schema.SourceRef) []schema.SourceRef {
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

func pypiSourceRefDetails(refs []schema.SourceRef) []map[string]string {
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

func pypiPackageSourceID(name string) string {
	return "pypi.org/pypi/" + normalizePyPIProjectName(name)
}

func pypiVersionSourceID(name, version string) string {
	return pypiPackageSourceID(name) + "/" + strings.TrimSpace(version)
}

func pypiIndexPackageSourceID(name string) string {
	return "pypi.org/simple/" + normalizePyPIProjectName(name)
}

func pypiIndexVersionSourceID(name, version string) string {
	return pypiIndexPackageSourceID(name) + "#" + strings.TrimSpace(version)
}

func pypiVersionFactSource(normalized pypiNormalized, suffix string) (string, string) {
	if normalized.MetadataFormat == "pypi_index_json" {
		return pypiIndexVersionSourceID(normalized.Name, normalized.Version) + suffix, pypiIndexURL(normalized.Name)
	}
	return pypiVersionSourceID(normalized.Name, normalized.Version) + suffix, pypiVersionURL(normalized.Name, normalized.Version)
}

func pypiPackageURL(name string) string {
	return pypiJSONBase + "/" + pypiPathEscape(normalizePyPIProjectName(name)) + "/json"
}

func pypiVersionURL(name, version string) string {
	return pypiJSONBase + "/" + pypiPathEscape(normalizePyPIProjectName(name)) + "/" + pypiPathEscape(version) + "/json"
}

func pypiIndexURL(name string) string {
	return pypiSimpleBase + "/" + pypiPathEscape(normalizePyPIProjectName(name)) + "/"
}

func pypiPURL(name, version string) string {
	return "pkg:pypi/" + pypiPathEscape(normalizePyPIProjectName(name)) + "@" + pypiPathEscape(version)
}

func normalizePyPIProjectName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.Trim(pypiNameSeparator.ReplaceAllString(name, "-"), "-")
}

func pypiPathEscape(value string) string {
	return url.PathEscape(strings.TrimSpace(value))
}
