package ghsa

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
	"strings"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/sources"
)

const (
	DefaultTTLSeconds = 86400

	SourceName        = "github-advisory-database"
	licenseOrTermsURL = "https://github.com/github/advisory-database/blob/main/LICENSE.md"
	repositoryURL     = "https://github.com/github/advisory-database"
	advisoryBaseURL   = "https://github.com/advisories/"
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

type normalizedCoordinate struct {
	Ecosystem    string
	EcosystemKey string
	Name         string
	Version      string
}

type Advisory struct {
	SchemaVersion    string          `json:"schema_version,omitempty"`
	ID               string          `json:"id,omitempty"`
	GHSAID           string          `json:"ghsa_id,omitempty"`
	CVEID            string          `json:"cve_id,omitempty"`
	URL              string          `json:"url,omitempty"`
	HTMLURL          string          `json:"html_url,omitempty"`
	Summary          string          `json:"summary,omitempty"`
	Details          string          `json:"details,omitempty"`
	Description      string          `json:"description,omitempty"`
	Aliases          []string        `json:"aliases,omitempty"`
	Identifiers      []Identifier    `json:"identifiers,omitempty"`
	Severity         SeverityValues  `json:"severity,omitempty"`
	CVSS             CVSS            `json:"cvss,omitempty"`
	Affected         []Affected      `json:"affected,omitempty"`
	Vulnerabilities  []Vulnerability `json:"vulnerabilities,omitempty"`
	References       References      `json:"references,omitempty"`
	Published        string          `json:"published,omitempty"`
	Modified         string          `json:"modified,omitempty"`
	PublishedAt      string          `json:"published_at,omitempty"`
	UpdatedAt        string          `json:"updated_at,omitempty"`
	DatabaseSpecific map[string]any  `json:"database_specific,omitempty"`
}

type Identifier struct {
	Type       string `json:"type,omitempty"`
	Value      string `json:"value,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}

type SeverityValues struct {
	Text    string
	Entries []Severity
}

type Severity struct {
	Type  string `json:"type,omitempty"`
	Score string `json:"score,omitempty"`
}

type CVSS struct {
	Score        float64 `json:"score,omitempty"`
	VectorString string  `json:"vector_string,omitempty"`
}

type Affected struct {
	Package           Package        `json:"package,omitempty"`
	Ranges            []Range        `json:"ranges,omitempty"`
	Versions          []string       `json:"versions,omitempty"`
	Severity          SeverityValues `json:"severity,omitempty"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  map[string]any `json:"database_specific,omitempty"`
}

type Package struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	PURL      string `json:"purl,omitempty"`
}

type Range struct {
	Type   string       `json:"type,omitempty"`
	Events []RangeEvent `json:"events,omitempty"`
}

type RangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type Vulnerability struct {
	Package                Package     `json:"package,omitempty"`
	VulnerableVersionRange string      `json:"vulnerable_version_range,omitempty"`
	FirstPatchedVersion    *Identifier `json:"first_patched_version,omitempty"`
	VulnerableFunctions    []string    `json:"vulnerable_functions,omitempty"`
}

type References []Reference

type Reference struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url,omitempty"`
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
		return Adapter{}, fmt.Errorf("GHSA ttl_seconds must be non-negative")
	}

	return Adapter{
		now:        now,
		ttlSeconds: ttlSeconds,
	}, nil
}

func (a Adapter) Evidence(coordinate Coordinate, advisories []Advisory) ([]schema.Evidence, error) {
	normalized, err := normalizeCoordinate(coordinate)
	if err != nil {
		return nil, err
	}

	return a.evidenceForAdvisories(advisories, normalized, a.recordSetSourceRef(normalized)), nil
}

func (a Adapter) EvidenceFromJSON(coordinate Coordinate, data []byte) ([]schema.Evidence, error) {
	normalized, err := normalizeCoordinate(coordinate)
	if err != nil {
		return nil, err
	}

	sourceRef := a.localJSONSourceRef(normalized, data)
	advisories, err := parseAdvisories(data)
	if err != nil {
		return []schema.Evidence{a.sourceUnavailableEvidence(sourceRef, normalized, "parse_failure", map[string]any{
			"parse_error": err.Error(),
		})}, nil
	}

	return a.evidenceForAdvisories(advisories, normalized, sourceRef), nil
}

func parseAdvisories(data []byte) ([]Advisory, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("empty GHSA advisory JSON")
	}

	if data[0] == '[' {
		var advisories []Advisory
		if err := decodeJSON(data, &advisories); err != nil {
			return nil, err
		}
		return advisories, nil
	}

	var object map[string]json.RawMessage
	if err := decodeJSON(data, &object); err != nil {
		return nil, err
	}

	for _, field := range []string{"advisories", "records"} {
		if raw, ok := object[field]; ok {
			var advisories []Advisory
			if err := decodeJSON(raw, &advisories); err != nil {
				return nil, fmt.Errorf("decode %s: %w", field, err)
			}
			return advisories, nil
		}
	}

	var advisory Advisory
	if err := decodeJSON(data, &advisory); err != nil {
		return nil, err
	}
	return []Advisory{advisory}, nil
}

func decodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("GHSA advisory JSON contains trailing data")
	}
	return nil
}

func (v *SeverityValues) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}

	if data[0] == '"' {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
		v.Text = text
		return nil
	}

	var entries []Severity
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}
	v.Entries = entries
	return nil
}

func (r *References) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}

	if data[0] == '[' {
		var refs []Reference
		if err := json.Unmarshal(data, &refs); err == nil {
			*r = refs
			return nil
		}

		var urls []string
		if err := json.Unmarshal(data, &urls); err != nil {
			return err
		}
		refs = make([]Reference, 0, len(urls))
		for _, refURL := range urls {
			refs = append(refs, Reference{Type: "WEB", URL: refURL})
		}
		*r = refs
		return nil
	}

	return fmt.Errorf("GHSA references must be an array")
}

func (a Adapter) evidenceForAdvisories(advisories []Advisory, coordinate normalizedCoordinate, sourceRef schema.SourceRef) []schema.Evidence {
	if len(advisories) == 0 {
		return []schema.Evidence{a.noKnownVulnerabilitiesEvidence(sourceRef, coordinate)}
	}

	evidence, unusable := a.advisoryEvidenceList(advisories, coordinate, sourceRef)
	if len(evidence) == 0 && !unusable.found {
		return []schema.Evidence{a.noKnownVulnerabilitiesEvidence(sourceRef, coordinate)}
	}
	if unusable.found {
		details := map[string]any{
			"advisory_index":  unusable.index,
			"unusable_reason": unusable.reason,
		}
		if unusable.advisoryID != "" {
			details["advisory_id"] = unusable.advisoryID
		}
		evidence = append(evidence, a.sourceUnavailableEvidence(unusable.sourceRef, coordinate, "malformed_record", details))
	}
	return evidence
}

type unusableAdvisory struct {
	found      bool
	index      int
	reason     string
	advisoryID string
	sourceRef  schema.SourceRef
}

func (a Adapter) advisoryEvidenceList(advisories []Advisory, coordinate normalizedCoordinate, fallbackSourceRef schema.SourceRef) ([]schema.Evidence, unusableAdvisory) {
	evidence := make([]schema.Evidence, 0, len(advisories))
	var unusable unusableAdvisory

	for i, advisory := range advisories {
		advisoryID := advisoryID(advisory)
		sourceRef := fallbackSourceRef
		if advisoryID != "" {
			sourceRef = a.advisorySourceRef(advisory, advisoryID)
		}
		if advisoryID == "" {
			if !unusable.found {
				unusable = unusableAdvisory{
					found:     true,
					index:     i,
					reason:    "missing_advisory_id",
					sourceRef: sourceRef,
				}
			}
			continue
		}

		match := advisoryAffectsCoordinate(advisory, coordinate)
		switch {
		case match.affected:
			evidence = append(evidence, a.vulnerabilityEvidence(advisory, advisoryID, coordinate, match))
		case match.unusable:
			if !unusable.found {
				unusable = unusableAdvisory{
					found:      true,
					index:      i,
					reason:     match.reason,
					advisoryID: advisoryID,
					sourceRef:  sourceRef,
				}
			}
		}
	}

	return evidence, unusable
}

type affectedMatch struct {
	affected        bool
	unusable        bool
	reason          string
	affectedEntries []Affected
	vulnerabilities []Vulnerability
}

type packageMatchState int

const (
	packageNoMatch packageMatchState = iota
	packageMatches
	packageUnusable
)

type versionMatchState int

const (
	versionNoMatch versionMatchState = iota
	versionMatches
	versionUnusable
)

func advisoryAffectsCoordinate(advisory Advisory, coordinate normalizedCoordinate) affectedMatch {
	if len(advisory.Affected) == 0 && len(advisory.Vulnerabilities) == 0 {
		return affectedMatch{unusable: true, reason: "missing_affected_entries"}
	}

	var unusableReason string
	var affectedEntries []Affected
	var vulnerabilities []Vulnerability

	for _, affected := range advisory.Affected {
		switch packageMatchesCoordinate(affected.Package, coordinate) {
		case packageMatches:
			switch affectedVersionMatches(affected, coordinate.Version) {
			case versionMatches:
				affectedEntries = append(affectedEntries, affected)
			case versionUnusable:
				if unusableReason == "" {
					unusableReason = "unsupported_affected_version_data"
				}
			}
		case packageUnusable:
			if unusableReason == "" {
				unusableReason = "missing_affected_package"
			}
		}
	}

	for _, vulnerability := range advisory.Vulnerabilities {
		switch packageMatchesCoordinate(vulnerability.Package, coordinate) {
		case packageMatches:
			switch vulnerabilityVersionMatches(vulnerability, coordinate.Version) {
			case versionMatches:
				vulnerabilities = append(vulnerabilities, vulnerability)
			case versionUnusable:
				if unusableReason == "" {
					unusableReason = "unsupported_vulnerable_version_range"
				}
			}
		case packageUnusable:
			if unusableReason == "" {
				unusableReason = "missing_vulnerability_package"
			}
		}
	}

	if len(affectedEntries) > 0 || len(vulnerabilities) > 0 {
		return affectedMatch{affected: true, affectedEntries: affectedEntries, vulnerabilities: vulnerabilities}
	}
	if unusableReason != "" {
		return affectedMatch{unusable: true, reason: unusableReason}
	}
	return affectedMatch{}
}

func packageMatchesCoordinate(pkg Package, coordinate normalizedCoordinate) packageMatchState {
	ecosystem := strings.TrimSpace(pkg.Ecosystem)
	name := strings.TrimSpace(pkg.Name)
	if ecosystem == "" || name == "" {
		return packageUnusable
	}
	if ecosystemKey(ecosystem) != coordinate.EcosystemKey {
		return packageNoMatch
	}
	if !packageNameMatches(coordinate.EcosystemKey, name, coordinate.Name) {
		return packageNoMatch
	}
	return packageMatches
}

func affectedVersionMatches(affected Affected, version string) versionMatchState {
	version = strings.TrimSpace(version)
	if len(affected.Versions) > 0 {
		for _, affectedVersion := range affected.Versions {
			if strings.TrimSpace(affectedVersion) == version {
				return versionMatches
			}
		}
		if len(affected.Ranges) == 0 {
			return versionNoMatch
		}
	}

	if len(affected.Ranges) == 0 {
		return versionUnusable
	}

	unsupported := false
	for _, affectedRange := range affected.Ranges {
		matches, ok := rangeAffectsVersion(affectedRange, version)
		if matches {
			return versionMatches
		}
		if !ok {
			unsupported = true
		}
	}
	if unsupported {
		return versionUnusable
	}
	return versionNoMatch
}

func vulnerabilityVersionMatches(vulnerability Vulnerability, version string) versionMatchState {
	expression := strings.TrimSpace(vulnerability.VulnerableVersionRange)
	if expression == "" {
		return versionUnusable
	}
	matches, ok := versionRangeAffectsVersion(expression, version)
	if !ok {
		return versionUnusable
	}
	if matches {
		return versionMatches
	}
	return versionNoMatch
}

func rangeAffectsVersion(affectedRange Range, version string) (bool, bool) {
	if strings.EqualFold(strings.TrimSpace(affectedRange.Type), "GIT") {
		return false, false
	}
	if len(affectedRange.Events) == 0 {
		return false, false
	}

	rangeOpen := false
	active := false
	for _, event := range affectedRange.Events {
		switch {
		case strings.TrimSpace(event.Introduced) != "":
			introduced := strings.TrimSpace(event.Introduced)
			rangeOpen = true
			if introduced == "0" {
				active = true
				continue
			}
			cmp, ok := compareVersion(version, introduced)
			if !ok {
				return false, false
			}
			active = cmp >= 0
		case strings.TrimSpace(event.Fixed) != "":
			if !rangeOpen {
				return false, false
			}
			rangeOpen = false
			if !active {
				continue
			}
			cmp, ok := compareVersion(version, event.Fixed)
			if !ok {
				return false, false
			}
			if cmp < 0 {
				return true, true
			}
			active = false
		case strings.TrimSpace(event.LastAffected) != "":
			if !rangeOpen {
				return false, false
			}
			rangeOpen = false
			if !active {
				continue
			}
			cmp, ok := compareVersion(version, event.LastAffected)
			if !ok {
				return false, false
			}
			if cmp <= 0 {
				return true, true
			}
			active = false
		case strings.TrimSpace(event.Limit) != "":
			return false, false
		default:
			return false, false
		}
	}

	return active, true
}

func versionRangeAffectsVersion(expression, version string) (bool, bool) {
	clauses := strings.Split(expression, "||")
	unsupported := false
	for _, clause := range clauses {
		matches, ok := versionRangeClauseAffectsVersion(clause, version)
		if matches {
			return true, true
		}
		if !ok {
			unsupported = true
		}
	}
	if unsupported {
		return false, false
	}
	return false, true
}

func versionRangeClauseAffectsVersion(clause, version string) (bool, bool) {
	clause = strings.TrimSpace(clause)
	if clause == "" {
		return false, false
	}

	constraints := strings.Split(clause, ",")
	for _, constraint := range constraints {
		matches, ok := versionConstraintMatches(strings.TrimSpace(constraint), version)
		if !ok {
			return false, false
		}
		if !matches {
			return false, true
		}
	}
	return true, true
}

func versionConstraintMatches(constraint, version string) (bool, bool) {
	if constraint == "" {
		return false, false
	}

	operators := []string{">=", "<=", "==", "=", ">", "<"}
	for _, operator := range operators {
		if strings.HasPrefix(constraint, operator) {
			target := strings.TrimSpace(strings.TrimPrefix(constraint, operator))
			return compareConstraint(operator, version, target)
		}
	}

	if strings.ContainsAny(constraint, " <>=") {
		return false, false
	}
	return compareConstraint("=", version, constraint)
}

func compareConstraint(operator, version, target string) (bool, bool) {
	cmp, ok := compareVersion(version, target)
	if !ok {
		return false, false
	}

	switch operator {
	case ">=":
		return cmp >= 0, true
	case "<=":
		return cmp <= 0, true
	case "==", "=":
		return cmp == 0, true
	case ">":
		return cmp > 0, true
	case "<":
		return cmp < 0, true
	default:
		return false, false
	}
}

func (a Adapter) noKnownVulnerabilitiesEvidence(sourceRef schema.SourceRef, coordinate normalizedCoordinate) schema.Evidence {
	return schema.Evidence{
		Reason: schema.Reason{
			Code:           reasons.NoKnownVulnerabilities,
			Severity:       "INFO",
			DecisionEffect: schema.DecisionEffectNone,
			Message:        fmt.Sprintf("GitHub Advisory Database local records did not contain a matching advisory for %s package %s@%s.", coordinate.Ecosystem, coordinate.Name, coordinate.Version),
			SourceRefIDs:   []string{sourceRef.ID},
			Details:        coordinateDetails(coordinate),
		},
		SourceRef: &sourceRef,
	}
}

func (a Adapter) vulnerabilityEvidence(advisory Advisory, advisoryID string, coordinate normalizedCoordinate, match affectedMatch) schema.Evidence {
	sourceRef := a.advisorySourceRef(advisory, advisoryID)
	upstreamSourceRefs := a.upstreamSourceRefs(advisory, advisoryID)
	sourceRefIDs := []string{sourceRef.ID}
	for _, upstreamSourceRef := range upstreamSourceRefs {
		sourceRefIDs = append(sourceRefIDs, upstreamSourceRef.ID)
	}

	class, explicitSeverity := classifyAdvisory(advisory, match.affectedEntries)
	code, severity, effect := vulnerabilityReason(class)
	details := advisoryDetails(advisory, advisoryID, coordinate, match, explicitSeverity)
	if len(upstreamSourceRefs) > 0 {
		details["upstream_source_refs"] = sourceRefDetails(upstreamSourceRefs)
	}

	return schema.Evidence{
		Reason: schema.Reason{
			Code:           code,
			Severity:       severity,
			DecisionEffect: effect,
			Message:        vulnerabilityMessage(advisoryID, severity, coordinate),
			SourceRefIDs:   sourceRefIDs,
			Details:        details,
		},
		SourceRef:  &sourceRef,
		SourceRefs: upstreamSourceRefs,
	}
}

func vulnerabilityReason(class severityClass) (string, string, schema.DecisionEffect) {
	switch class {
	case severityClassCritical:
		return reasons.KnownVulnerabilityCritical, "CRITICAL", schema.DecisionEffectDeny
	case severityClassHigh:
		return reasons.KnownVulnerabilityHigh, "HIGH", schema.DecisionEffectAsk
	default:
		return reasons.KnownVulnerabilityModerate, "MEDIUM", schema.DecisionEffectAsk
	}
}

func vulnerabilityMessage(advisoryID, severity string, coordinate normalizedCoordinate) string {
	return fmt.Sprintf("GitHub Advisory Database advisory %s affects %s package %s@%s with %s severity.", advisoryID, coordinate.Ecosystem, coordinate.Name, coordinate.Version, strings.ToLower(severity))
}

func advisoryDetails(advisory Advisory, advisoryID string, coordinate normalizedCoordinate, match affectedMatch, explicitSeverity bool) map[string]any {
	details := coordinateDetails(coordinate)
	details["advisory_id"] = advisoryID
	details["explicit_severity"] = explicitSeverity
	if !explicitSeverity {
		details["severity_default"] = "moderate"
	}

	if aliases := advisoryAliases(advisory, advisoryID); len(aliases) > 0 {
		details["aliases"] = aliases
	}
	if summary := strings.TrimSpace(advisory.Summary); summary != "" {
		details["summary"] = summary
	}
	if published := firstNonEmpty(advisory.Published, advisory.PublishedAt); published != "" {
		details["published"] = published
	}
	if modified := firstNonEmpty(advisory.Modified, advisory.UpdatedAt); modified != "" {
		details["modified"] = modified
	}
	if advisory.Severity.Text != "" {
		details["github_severity"] = advisory.Severity.Text
	}
	if len(advisory.Severity.Entries) > 0 {
		details["severity"] = advisory.Severity.Entries
	}
	if advisory.CVSS.Score > 0 {
		details["cvss_score"] = advisory.CVSS.Score
	}
	if advisory.CVSS.VectorString != "" {
		details["cvss_vector"] = advisory.CVSS.VectorString
	}
	if databaseSeverity, ok := severityFromMap(advisory.DatabaseSpecific); ok {
		details["database_specific_severity"] = databaseSeverity
	}
	if affectedSeverity := affectedSeverityDetails(match.affectedEntries); len(affectedSeverity) > 0 {
		details["affected_severity"] = affectedSeverity
	}
	if len(match.affectedEntries) > 0 {
		details["matched_affected_entries"] = len(match.affectedEntries)
	}
	if len(match.vulnerabilities) > 0 {
		details["matched_vulnerabilities"] = len(match.vulnerabilities)
	}
	if references := referenceDetails(advisory.References); len(references) > 0 {
		details["references"] = references
	}

	return details
}

func coordinateDetails(coordinate normalizedCoordinate) map[string]any {
	return map[string]any{
		"ecosystem":     coordinate.Ecosystem,
		"ecosystem_key": coordinate.EcosystemKey,
		"package_name":  coordinate.Name,
		"version":       coordinate.Version,
	}
}

func affectedSeverityDetails(affected []Affected) []Severity {
	if len(affected) == 0 {
		return nil
	}
	details := []Severity{}
	for _, item := range affected {
		details = append(details, item.Severity.Entries...)
	}
	return details
}

func referenceDetails(references []Reference) []map[string]string {
	if len(references) == 0 {
		return nil
	}

	details := make([]map[string]string, 0, len(references))
	for _, reference := range references {
		referenceURL := strings.TrimSpace(reference.URL)
		if referenceURL == "" {
			continue
		}
		item := map[string]string{"url": referenceURL}
		if reference.Type != "" {
			item["type"] = reference.Type
		}
		details = append(details, item)
	}
	return details
}

func (a Adapter) sourceUnavailableEvidence(sourceRef schema.SourceRef, coordinate normalizedCoordinate, failureKind string, extra map[string]any) schema.Evidence {
	details := coordinateDetails(coordinate)
	details["source"] = SourceName
	details["failure_kind"] = failureKind
	for key, value := range extra {
		details[key] = value
	}

	return schema.Evidence{
		Reason: schema.Reason{
			Code:           reasons.SourceUnavailable,
			Severity:       "MEDIUM",
			DecisionEffect: schema.DecisionEffectUnknown,
			Message:        "GitHub Advisory Database local records were unavailable or returned unusable data.",
			SourceRefIDs:   []string{sourceRef.ID},
			Details:        details,
		},
		SourceRef: &sourceRef,
	}
}

func (a Adapter) recordSetSourceRef(coordinate normalizedCoordinate) schema.SourceRef {
	sourceID := coordinateSourceID(coordinate)
	return a.sourceRef(recordSetSourceRefID(sourceID), sourceID, repositoryURL, "Source: GitHub Advisory Database local record set; preserve CC-BY-4.0 attribution when data is displayed or redistributed")
}

func (a Adapter) localJSONSourceRef(coordinate normalizedCoordinate, data []byte) schema.SourceRef {
	sum := sha256.Sum256(bytes.TrimSpace(data))
	sourceID := coordinateSourceID(coordinate) + "#json:" + hex.EncodeToString(sum[:])[:16]
	return a.sourceRef(localJSONSourceRefID(sourceID), sourceID, repositoryURL, "Source: GitHub Advisory Database local JSON records; preserve CC-BY-4.0 attribution when data is displayed or redistributed")
}

func (a Adapter) advisorySourceRef(advisory Advisory, advisoryID string) schema.SourceRef {
	return a.sourceRef(advisorySourceRefID(advisoryID), advisoryID, advisoryURL(advisory, advisoryID), "Source: GitHub Advisory Database advisory record; CC-BY-4.0 attribution required and upstream advisory IDs/URLs are preserved")
}

func (a Adapter) upstreamSourceRefs(advisory Advisory, advisoryID string) []schema.SourceRef {
	refs := make([]schema.SourceRef, 0, len(advisory.Aliases)+len(advisory.Identifiers)+len(advisory.References)+1)
	seen := map[string]struct{}{}

	for _, alias := range advisoryAliases(advisory, advisoryID) {
		id := upstreamSourceRefID("alias", alias)
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		refs = append(refs, a.sourceRef(id, alias, upstreamAliasURL(alias), "Upstream advisory identifier preserved from GitHub Advisory Database; verify upstream source terms before redistribution"))
	}

	for _, reference := range advisory.References {
		referenceURL := strings.TrimSpace(reference.URL)
		if !isValidURI(referenceURL) {
			continue
		}
		sourceID := strings.TrimSpace(reference.Type)
		if sourceID == "" {
			sourceID = referenceURL
		} else {
			sourceID = sourceID + ":" + referenceURL
		}
		id := upstreamSourceRefID("reference", sourceID)
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		refs = append(refs, a.sourceRef(id, sourceID, referenceURL, "Upstream advisory URL preserved from GitHub Advisory Database; verify upstream source terms before redistribution"))
	}

	return refs
}

func sourceRefDetails(sourceRefs []schema.SourceRef) []map[string]string {
	details := make([]map[string]string, 0, len(sourceRefs))
	for _, sourceRef := range sourceRefs {
		details = append(details, map[string]string{
			"id":        sourceRef.ID,
			"source_id": sourceRef.SourceID,
			"url":       sourceRef.URL,
		})
	}
	return details
}

func (a Adapter) sourceRef(id, sourceID, sourceURL, attribution string) schema.SourceRef {
	return schema.SourceRef{
		ID:                  id,
		Source:              SourceName,
		SourceID:            sourceID,
		URL:                 sourceURL,
		RetrievedAt:         a.now().UTC().Format(time.RFC3339),
		TTLSeconds:          a.ttlSeconds,
		LicenseOrTermsURL:   licenseOrTermsURL,
		Attribution:         attribution,
		AttributionRequired: true,
		Redistribution:      sources.RedistributionUnknown,
		PublicDisplay:       sources.PublicDisplayAllowed,
	}
}

func normalizeCoordinate(coordinate Coordinate) (normalizedCoordinate, error) {
	ecosystem := strings.TrimSpace(coordinate.Ecosystem)
	name := strings.TrimSpace(coordinate.Name)
	version := strings.TrimSpace(coordinate.Version)
	if ecosystem == "" {
		return normalizedCoordinate{}, fmt.Errorf("GHSA coordinate ecosystem is required")
	}
	if name == "" {
		return normalizedCoordinate{}, fmt.Errorf("GHSA coordinate name is required")
	}
	if version == "" {
		return normalizedCoordinate{}, fmt.Errorf("GHSA coordinate version is required")
	}
	return normalizedCoordinate{
		Ecosystem:    ecosystem,
		EcosystemKey: ecosystemKey(ecosystem),
		Name:         name,
		Version:      version,
	}, nil
}

func ecosystemKey(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm":
		return "npm"
	case "pypi", "pip", "python":
		return "pypi"
	case "crates", "crates.io", "rust":
		return "crates"
	case "go", "golang", "gomod":
		return "go"
	case "maven":
		return "maven"
	case "rubygems", "ruby", "gem":
		return "rubygems"
	default:
		return strings.ToLower(strings.TrimSpace(ecosystem))
	}
}

func packageNameMatches(ecosystemKey, affectedName, coordinateName string) bool {
	affectedName = strings.TrimSpace(affectedName)
	coordinateName = strings.TrimSpace(coordinateName)
	switch ecosystemKey {
	case "pypi":
		return normalizePyPIName(affectedName) == normalizePyPIName(coordinateName)
	default:
		return affectedName == coordinateName
	}
}

func normalizePyPIName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var builder strings.Builder
	lastWasSeparator := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !lastWasSeparator {
				builder.WriteByte('-')
				lastWasSeparator = true
			}
			continue
		}
		builder.WriteRune(r)
		lastWasSeparator = false
	}
	return builder.String()
}

func advisoryID(advisory Advisory) string {
	for _, candidate := range []string{advisory.ID, advisory.GHSAID} {
		if normalized := normalizeAdvisoryID(candidate); normalized != "" {
			return normalized
		}
	}
	for _, identifier := range advisory.Identifiers {
		value := identifierValue(identifier)
		if strings.HasPrefix(strings.ToUpper(value), "GHSA-") {
			return normalizeAdvisoryID(value)
		}
	}
	return ""
}

func normalizeAdvisoryID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToUpper(value), "GHSA-") {
		return strings.ToUpper(value)
	}
	return value
}

func advisoryAliases(advisory Advisory, advisoryID string) []string {
	aliases := make([]string, 0, len(advisory.Aliases)+len(advisory.Identifiers)+1)
	seen := map[string]struct{}{strings.ToUpper(strings.TrimSpace(advisoryID)): {}}
	appendAlias := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		normalized := value
		if strings.HasPrefix(strings.ToUpper(value), "CVE-") || strings.HasPrefix(strings.ToUpper(value), "GHSA-") {
			normalized = strings.ToUpper(value)
		}
		key := strings.ToUpper(normalized)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		aliases = append(aliases, normalized)
	}

	appendAlias(advisory.CVEID)
	for _, alias := range advisory.Aliases {
		appendAlias(alias)
	}
	for _, identifier := range advisory.Identifiers {
		appendAlias(identifierValue(identifier))
	}
	return aliases
}

func identifierValue(identifier Identifier) string {
	if strings.TrimSpace(identifier.Value) != "" {
		return strings.TrimSpace(identifier.Value)
	}
	return strings.TrimSpace(identifier.Identifier)
}

func advisoryURL(advisory Advisory, advisoryID string) string {
	for _, candidate := range []string{advisory.HTMLURL, advisory.URL} {
		candidate = strings.TrimSpace(candidate)
		if isValidURI(candidate) && strings.Contains(candidate, "github.com/advisories/") {
			return candidate
		}
	}
	for _, reference := range advisory.References {
		referenceURL := strings.TrimSpace(reference.URL)
		if isValidURI(referenceURL) && strings.Contains(referenceURL, "github.com/advisories/") {
			return referenceURL
		}
	}
	return advisoryBaseURL + url.PathEscape(advisoryID)
}

func upstreamAliasURL(alias string) string {
	alias = strings.TrimSpace(alias)
	upper := strings.ToUpper(alias)
	if strings.HasPrefix(upper, "CVE-") {
		return "https://www.cve.org/CVERecord?id=" + url.QueryEscape(alias)
	}
	if strings.HasPrefix(upper, "GHSA-") {
		return advisoryBaseURL + url.PathEscape(alias)
	}
	return repositoryURL
}

func recordSetSourceRefID(sourceID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(sourceID)))
	return "ghsa-records-" + hex.EncodeToString(sum[:])[:16]
}

func localJSONSourceRefID(sourceID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(sourceID)))
	return "ghsa-json-" + hex.EncodeToString(sum[:])[:16]
}

func advisorySourceRefID(advisoryID string) string {
	normalized := sourceRefIDReplacer.ReplaceAllString(strings.ToLower(strings.TrimSpace(advisoryID)), "-")
	normalized = strings.Trim(normalized, "-")
	if normalized == "" {
		sum := sha256.Sum256([]byte(advisoryID))
		normalized = hex.EncodeToString(sum[:])[:16]
	}
	return "ghsa-" + normalized
}

func upstreamSourceRefID(kind, value string) string {
	sum := sha256.Sum256([]byte(kind + ":" + strings.TrimSpace(value)))
	return "ghsa-upstream-" + hex.EncodeToString(sum[:])[:16]
}

func coordinateSourceID(coordinate normalizedCoordinate) string {
	return fmt.Sprintf("%s:%s@%s", coordinate.EcosystemKey, coordinate.Name, coordinate.Version)
}

func isValidURI(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.Scheme != "" && parsed.Host != ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
