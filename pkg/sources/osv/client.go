package osv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/sources"
)

const (
	DefaultBaseURL          = "https://api.osv.dev"
	DefaultTTLSeconds       = 86400
	DefaultMaxResponseBytes = int64(1 << 20)

	SourceName        = "osv.dev"
	licenseOrTermsURL = "https://google.github.io/osv.dev/"
)

var sourceRefIDReplacer = regexp.MustCompile(`[^a-z0-9._-]+`)

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type Options struct {
	HTTPClient       HTTPClient
	BaseURL          string
	Now              func() time.Time
	TTLSeconds       int
	MaxResponseBytes int64
}

type Client struct {
	httpClient       HTTPClient
	baseURL          *url.URL
	now              func() time.Time
	ttlSeconds       int
	maxResponseBytes int64
}

type Coordinate struct {
	Ecosystem string
	Name      string
	Version   string
}

type normalizedCoordinate struct {
	Ecosystem    string
	OSVEcosystem string
	Name         string
	Version      string
}

type queryRequest struct {
	Version   string       `json:"version"`
	Package   queryPackage `json:"package"`
	PageToken string       `json:"page_token,omitempty"`
}

type queryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type queryResponse struct {
	Vulns         []vulnerability `json:"vulns"`
	NextPageToken string          `json:"next_page_token,omitempty"`
}

type vulnerability struct {
	ID               string         `json:"id"`
	Aliases          []string       `json:"aliases,omitempty"`
	Summary          string         `json:"summary,omitempty"`
	Published        string         `json:"published,omitempty"`
	Modified         string         `json:"modified,omitempty"`
	Severity         []osvSeverity  `json:"severity,omitempty"`
	Affected         []osvAffected  `json:"affected,omitempty"`
	References       []osvReference `json:"references,omitempty"`
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
}

type osvAffected struct {
	Package           osvPackage     `json:"package,omitempty"`
	Ranges            []osvRange     `json:"ranges,omitempty"`
	Versions          []string       `json:"versions,omitempty"`
	Severity          []osvSeverity  `json:"severity,omitempty"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	PURL      string `json:"purl,omitempty"`
}

type osvRange struct {
	Type   string          `json:"type,omitempty"`
	Events []osvRangeEvent `json:"events,omitempty"`
}

type osvRangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func NewClient(options Options) (Client, error) {
	baseURL := options.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	parsedBaseURL, err := url.Parse(baseURL)
	if err != nil {
		return Client{}, fmt.Errorf("parse OSV base URL: %w", err)
	}
	if parsedBaseURL.Scheme == "" || parsedBaseURL.Host == "" {
		return Client{}, fmt.Errorf("OSV base URL must include scheme and host")
	}

	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	now := options.Now
	if now == nil {
		now = time.Now
	}

	ttlSeconds := options.TTLSeconds
	if ttlSeconds == 0 {
		ttlSeconds = DefaultTTLSeconds
	}
	if ttlSeconds < 0 {
		return Client{}, fmt.Errorf("OSV ttl_seconds must be non-negative")
	}

	maxResponseBytes := options.MaxResponseBytes
	if maxResponseBytes == 0 {
		maxResponseBytes = DefaultMaxResponseBytes
	}
	if maxResponseBytes < 0 {
		return Client{}, fmt.Errorf("OSV max response bytes must be non-negative")
	}

	return Client{
		httpClient:       httpClient,
		baseURL:          parsedBaseURL,
		now:              now,
		ttlSeconds:       ttlSeconds,
		maxResponseBytes: maxResponseBytes,
	}, nil
}

func (c Client) EvidenceForPackage(ctx context.Context, pkg schema.PackageIdentity) ([]schema.Evidence, error) {
	return c.Evidence(ctx, Coordinate{
		Ecosystem: pkg.Ecosystem,
		Name:      pkg.Name,
		Version:   pkg.Version,
	})
}

func (c Client) Evidence(ctx context.Context, coordinate Coordinate) ([]schema.Evidence, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	normalized, err := normalizeCoordinate(coordinate)
	if err != nil {
		return nil, err
	}

	querySourceRef := c.querySourceRef(normalized)
	allVulns := []vulnerability{}
	pageToken := ""
	seenPageTokens := map[string]struct{}{}
	for page := 0; page < 32; page++ {
		requestBody, err := json.Marshal(queryRequest{
			Version: normalized.Version,
			Package: queryPackage{
				Name:      normalized.Name,
				Ecosystem: normalized.OSVEcosystem,
			},
			PageToken: pageToken,
		})
		if err != nil {
			return nil, fmt.Errorf("encode OSV query: %w", err)
		}

		request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.queryEndpoint(), bytes.NewReader(requestBody))
		if err != nil {
			return nil, fmt.Errorf("create OSV query request: %w", err)
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Content-Type", "application/json")

		response, err := c.httpClient.Do(request)
		if err != nil {
			return c.evidenceWithSourceUnavailable(allVulns, querySourceRef, normalized, "request_failed", 0, nil), nil
		}

		if response.StatusCode < 200 || response.StatusCode > 299 {
			if response.Body != nil {
				defer response.Body.Close()
			}
			return c.evidenceWithSourceUnavailable(allVulns, querySourceRef, normalized, "http_status", response.StatusCode, nil), nil
		}
		if response.Body == nil {
			return c.evidenceWithSourceUnavailable(allVulns, querySourceRef, normalized, "read_failed", 0, nil), nil
		}

		responseBody, tooLarge, err := readLimited(response.Body, c.maxResponseBytes)
		_ = response.Body.Close()
		if err != nil {
			return c.evidenceWithSourceUnavailable(allVulns, querySourceRef, normalized, "read_failed", 0, nil), nil
		}
		if tooLarge {
			return c.evidenceWithSourceUnavailable(allVulns, querySourceRef, normalized, "response_too_large", 0, map[string]any{
				"max_response_bytes": c.maxResponseBytes,
			}), nil
		}

		var result queryResponse
		if err := json.Unmarshal(responseBody, &result); err != nil {
			return c.evidenceWithSourceUnavailable(allVulns, querySourceRef, normalized, "malformed_response", 0, nil), nil
		}
		allVulns = append(allVulns, result.Vulns...)

		pageToken = strings.TrimSpace(result.NextPageToken)
		if pageToken == "" {
			break
		}
		if _, ok := seenPageTokens[pageToken]; ok {
			return c.evidenceWithSourceUnavailable(allVulns, querySourceRef, normalized, "pagination_loop", 0, nil), nil
		}
		seenPageTokens[pageToken] = struct{}{}
		if page == 31 {
			return c.evidenceWithSourceUnavailable(allVulns, querySourceRef, normalized, "pagination_limit", 0, map[string]any{
				"max_pages": 32,
			}), nil
		}
	}

	if len(allVulns) == 0 {
		return []schema.Evidence{c.noKnownVulnerabilitiesEvidence(querySourceRef, normalized)}, nil
	}

	evidence, unusable := c.vulnerabilityEvidenceList(allVulns, normalized)
	if len(evidence) == 0 && !unusable.found {
		return []schema.Evidence{c.noKnownVulnerabilitiesEvidence(querySourceRef, normalized)}, nil
	}
	if unusable.found {
		evidence = append(evidence, c.sourceUnavailableEvidence(querySourceRef, normalized, "malformed_response", 0, map[string]any{
			"vulnerability_index": unusable.index,
			"unusable_reason":     unusable.reason,
		}))
	}
	return evidence, nil
}

func (c Client) evidenceWithSourceUnavailable(vulns []vulnerability, sourceRef schema.SourceRef, coordinate normalizedCoordinate, failureKind string, statusCode int, extra map[string]any) []schema.Evidence {
	evidence, _ := c.vulnerabilityEvidenceList(vulns, coordinate)
	return append(evidence, c.sourceUnavailableEvidence(sourceRef, coordinate, failureKind, statusCode, extra))
}

type unusableVulnerability struct {
	found  bool
	index  int
	reason string
}

func (c Client) vulnerabilityEvidenceList(vulns []vulnerability, coordinate normalizedCoordinate) ([]schema.Evidence, unusableVulnerability) {
	evidence := make([]schema.Evidence, 0, len(vulns))
	var unusable unusableVulnerability
	for i, vuln := range vulns {
		vuln.ID = strings.TrimSpace(vuln.ID)
		if vuln.ID == "" {
			if !unusable.found {
				unusable = unusableVulnerability{found: true, index: i, reason: "missing_vulnerability_id"}
			}
			continue
		}
		match := vulnerabilityAffectsCoordinate(vuln, coordinate)
		switch {
		case match.affected:
			evidence = append(evidence, c.vulnerabilityEvidence(vuln, coordinate))
		case match.unusable:
			if !unusable.found {
				unusable = unusableVulnerability{found: true, index: i, reason: match.reason}
			}
		}
	}
	return evidence, unusable
}

func normalizeCoordinate(coordinate Coordinate) (normalizedCoordinate, error) {
	ecosystem := strings.TrimSpace(coordinate.Ecosystem)
	name := strings.TrimSpace(coordinate.Name)
	version := strings.TrimSpace(coordinate.Version)

	if ecosystem == "" {
		return normalizedCoordinate{}, fmt.Errorf("OSV coordinate ecosystem is required")
	}
	if name == "" {
		return normalizedCoordinate{}, fmt.Errorf("OSV coordinate name is required")
	}
	if version == "" {
		return normalizedCoordinate{}, fmt.Errorf("OSV coordinate version is required")
	}

	return normalizedCoordinate{
		Ecosystem:    ecosystem,
		OSVEcosystem: mapEcosystem(ecosystem),
		Name:         name,
		Version:      version,
	}, nil
}

func mapEcosystem(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "npm":
		return "npm"
	case "pypi", "python":
		return "PyPI"
	case "crates", "crates.io", "rust":
		return "crates.io"
	case "go", "golang":
		return "Go"
	case "maven":
		return "Maven"
	case "rubygems", "ruby", "gem":
		return "RubyGems"
	default:
		return ecosystem
	}
}

type affectedMatch struct {
	affected bool
	unusable bool
	reason   string
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

func vulnerabilityAffectsCoordinate(vuln vulnerability, coordinate normalizedCoordinate) affectedMatch {
	if len(vuln.Affected) == 0 {
		return affectedMatch{unusable: true, reason: "missing_affected_entries"}
	}

	var unusableReason string
	for _, affected := range vuln.Affected {
		switch affectedPackageMatches(affected.Package, coordinate) {
		case packageMatches:
			switch affectedVersionMatches(affected, coordinate.Version) {
			case versionMatches:
				return affectedMatch{affected: true}
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

	if unusableReason != "" {
		return affectedMatch{unusable: true, reason: unusableReason}
	}
	return affectedMatch{}
}

func affectedPackageMatches(pkg osvPackage, coordinate normalizedCoordinate) packageMatchState {
	ecosystem := strings.TrimSpace(pkg.Ecosystem)
	name := strings.TrimSpace(pkg.Name)
	if ecosystem == "" || name == "" {
		return packageUnusable
	}
	if !strings.EqualFold(mapEcosystem(ecosystem), coordinate.OSVEcosystem) {
		return packageNoMatch
	}
	if !packageNameMatches(coordinate.OSVEcosystem, name, coordinate.Name) {
		return packageNoMatch
	}
	return packageMatches
}

func packageNameMatches(osvEcosystem, affectedName, coordinateName string) bool {
	affectedName = strings.TrimSpace(affectedName)
	coordinateName = strings.TrimSpace(coordinateName)
	switch osvEcosystem {
	case "PyPI":
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

func affectedVersionMatches(affected osvAffected, version string) versionMatchState {
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
	if len(affected.Ranges) > 0 {
		// OSV /v1/query is already version-scoped. If OSV returned a matching
		// package entry with range data for the queried version, preserve the
		// vulnerability evidence instead of trying to reimplement every ecosystem's
		// range semantics locally and accidentally downgrading a real match.
		return versionMatches
	}
	return versionUnusable
}

func (c Client) queryEndpoint() string {
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/v1/query"
	endpoint.RawQuery = ""
	endpoint.Fragment = ""
	return endpoint.String()
}

func (c Client) noKnownVulnerabilitiesEvidence(sourceRef schema.SourceRef, coordinate normalizedCoordinate) schema.Evidence {
	return schema.Evidence{
		Reason: schema.Reason{
			Code:           reasons.NoKnownVulnerabilities,
			Severity:       "INFO",
			DecisionEffect: schema.DecisionEffectNone,
			Message:        fmt.Sprintf("OSV.dev reported no known vulnerabilities for %s package %s@%s.", coordinate.OSVEcosystem, coordinate.Name, coordinate.Version),
			SourceRefIDs:   []string{sourceRef.ID},
			Details:        coordinateDetails(coordinate),
		},
		SourceRef: &sourceRef,
	}
}

func (c Client) vulnerabilityEvidence(vuln vulnerability, coordinate normalizedCoordinate) schema.Evidence {
	vuln.Affected = matchingAffectedEntries(vuln.Affected, coordinate)
	sourceRef := c.vulnerabilitySourceRef(vuln.ID)
	upstreamSourceRefs := c.upstreamSourceRefs(vuln)
	sourceRefIDs := []string{sourceRef.ID}
	for _, upstreamSourceRef := range upstreamSourceRefs {
		sourceRefIDs = append(sourceRefIDs, upstreamSourceRef.ID)
	}
	code, severity, effect := vulnerabilityReason(vuln)
	details := vulnerabilityDetails(vuln, coordinate)
	if len(upstreamSourceRefs) > 0 {
		details["upstream_source_refs"] = sourceRefDetails(upstreamSourceRefs)
	}

	return schema.Evidence{
		Reason: schema.Reason{
			Code:           code,
			Severity:       severity,
			DecisionEffect: effect,
			Message:        vulnerabilityMessage(vuln.ID, severity, coordinate),
			SourceRefIDs:   sourceRefIDs,
			Details:        details,
		},
		SourceRef:  &sourceRef,
		SourceRefs: upstreamSourceRefs,
	}
}

func matchingAffectedEntries(affected []osvAffected, coordinate normalizedCoordinate) []osvAffected {
	matches := make([]osvAffected, 0, len(affected))
	for _, item := range affected {
		if affectedPackageMatches(item.Package, coordinate) != packageMatches {
			continue
		}
		if affectedVersionMatches(item, coordinate.Version) != versionMatches {
			continue
		}
		matches = append(matches, item)
	}
	return matches
}

func vulnerabilityReason(vuln vulnerability) (string, string, schema.DecisionEffect) {
	if isKnownMalicious(vuln) {
		return reasons.KnownMaliciousPackage, "CRITICAL", schema.DecisionEffectDeny
	}

	switch classifyVulnerability(vuln) {
	case severityClassCritical:
		return reasons.KnownVulnerabilityCritical, "CRITICAL", schema.DecisionEffectDeny
	case severityClassHigh:
		return reasons.KnownVulnerabilityHigh, "HIGH", schema.DecisionEffectAsk
	default:
		return reasons.KnownVulnerabilityModerate, "MEDIUM", schema.DecisionEffectAsk
	}
}

func vulnerabilityMessage(advisoryID, severity string, coordinate normalizedCoordinate) string {
	return fmt.Sprintf("OSV.dev reports advisory %s affects %s package %s@%s with %s severity.", advisoryID, coordinate.OSVEcosystem, coordinate.Name, coordinate.Version, strings.ToLower(severity))
}

func vulnerabilityDetails(vuln vulnerability, coordinate normalizedCoordinate) map[string]any {
	details := coordinateDetails(coordinate)
	details["advisory_id"] = vuln.ID

	if len(vuln.Aliases) > 0 {
		details["aliases"] = vuln.Aliases
	}
	if strings.TrimSpace(vuln.Summary) != "" {
		details["summary"] = vuln.Summary
	}
	if vuln.Published != "" {
		details["published"] = vuln.Published
	}
	if vuln.Modified != "" {
		details["modified"] = vuln.Modified
	}
	if len(vuln.Severity) > 0 {
		details["severity"] = vuln.Severity
	}
	if affectedSeverity := affectedSeverityDetails(vuln.Affected); len(affectedSeverity) > 0 {
		details["affected_severity"] = affectedSeverity
	}
	if databaseSeverity, ok := databaseSpecificSeverity(vuln); ok {
		details["database_specific_severity"] = databaseSeverity
	}
	if malicious, ok := vuln.DatabaseSpecific["malicious"].(bool); ok {
		details["database_specific_malicious"] = malicious
	}
	if origins, ok := vuln.DatabaseSpecific["malicious-packages-origins"]; ok {
		details["malicious_package_origins"] = origins
	}
	if references := referenceDetails(vuln.References); len(references) > 0 {
		details["references"] = references
	}

	return details
}

func coordinateDetails(coordinate normalizedCoordinate) map[string]any {
	return map[string]any{
		"ecosystem":     coordinate.Ecosystem,
		"osv_ecosystem": coordinate.OSVEcosystem,
		"package_name":  coordinate.Name,
		"version":       coordinate.Version,
	}
}

func affectedSeverityDetails(affected []osvAffected) []osvSeverity {
	if len(affected) == 0 {
		return nil
	}
	details := []osvSeverity{}
	for _, item := range affected {
		details = append(details, item.Severity...)
	}
	return details
}

func referenceDetails(references []osvReference) []map[string]string {
	if len(references) == 0 {
		return nil
	}

	details := make([]map[string]string, 0, len(references))
	for _, reference := range references {
		if strings.TrimSpace(reference.URL) == "" {
			continue
		}
		item := map[string]string{"url": reference.URL}
		if reference.Type != "" {
			item["type"] = reference.Type
		}
		details = append(details, item)
	}
	return details
}

func (c Client) sourceUnavailableEvidence(sourceRef schema.SourceRef, coordinate normalizedCoordinate, failureKind string, statusCode int, extra map[string]any) schema.Evidence {
	details := coordinateDetails(coordinate)
	details["source"] = SourceName
	details["failure_kind"] = failureKind
	if statusCode != 0 {
		details["status_code"] = statusCode
	}
	for key, value := range extra {
		details[key] = value
	}

	return schema.Evidence{
		Reason: schema.Reason{
			Code:           reasons.SourceUnavailable,
			Severity:       "MEDIUM",
			DecisionEffect: schema.DecisionEffectUnknown,
			Message:        "OSV.dev vulnerability query was unavailable or returned unusable data.",
			SourceRefIDs:   []string{sourceRef.ID},
			Details:        details,
		},
		SourceRef: &sourceRef,
	}
}

func (c Client) querySourceRef(coordinate normalizedCoordinate) schema.SourceRef {
	return c.sourceRef(querySourceRefID(coordinate), coordinateSourceID(coordinate), c.queryEndpoint(), "Source: OSV.dev query response")
}

func (c Client) vulnerabilitySourceRef(advisoryID string) schema.SourceRef {
	return c.sourceRef(vulnerabilitySourceRefID(advisoryID), advisoryID, vulnerabilityURL(advisoryID), "Source: OSV.dev aggregate advisory record; upstream advisory IDs and URLs are preserved where OSV provides them; verify per-record upstream license/attribution before redistribution")
}

func (c Client) upstreamSourceRefs(vuln vulnerability) []schema.SourceRef {
	refs := make([]schema.SourceRef, 0, len(vuln.Aliases)+len(vuln.References))
	seen := map[string]struct{}{}
	for _, alias := range vuln.Aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			continue
		}
		id := upstreamSourceRefID("alias", alias)
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		refs = append(refs, c.sourceRef(id, alias, upstreamAliasURL(alias), "Upstream advisory identifier preserved from OSV.dev; verify upstream source terms before redistribution"))
	}
	for _, reference := range vuln.References {
		referenceURL := strings.TrimSpace(reference.URL)
		if referenceURL == "" {
			continue
		}
		if parsed, err := url.ParseRequestURI(referenceURL); err != nil || parsed.Scheme == "" || parsed.Host == "" {
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
		refs = append(refs, c.sourceRef(id, sourceID, referenceURL, "Upstream advisory URL preserved from OSV.dev; verify upstream source terms before redistribution"))
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

func (c Client) sourceRef(id, sourceID, sourceURL, attribution string) schema.SourceRef {
	return schema.SourceRef{
		ID:                  id,
		Source:              SourceName,
		SourceID:            sourceID,
		URL:                 sourceURL,
		RetrievedAt:         c.now().UTC().Format(time.RFC3339),
		TTLSeconds:          c.ttlSeconds,
		LicenseOrTermsURL:   licenseOrTermsURL,
		Attribution:         attribution,
		AttributionRequired: true,
		Redistribution:      sources.RedistributionUnknown,
		PublicDisplay:       sources.PublicDisplayAllowed,
	}
}

func querySourceRefID(coordinate normalizedCoordinate) string {
	sum := sha256.Sum256([]byte(coordinateSourceID(coordinate)))
	return "osv-query-" + hex.EncodeToString(sum[:])[:16]
}

func coordinateSourceID(coordinate normalizedCoordinate) string {
	return fmt.Sprintf("%s:%s@%s", coordinate.OSVEcosystem, coordinate.Name, coordinate.Version)
}

func vulnerabilitySourceRefID(advisoryID string) string {
	normalized := sourceRefIDReplacer.ReplaceAllString(strings.ToLower(strings.TrimSpace(advisoryID)), "-")
	normalized = strings.Trim(normalized, "-")
	if normalized == "" {
		sum := sha256.Sum256([]byte(advisoryID))
		normalized = hex.EncodeToString(sum[:])[:16]
	}
	return "osv-" + normalized
}

func upstreamSourceRefID(kind, value string) string {
	sum := sha256.Sum256([]byte(kind + ":" + strings.TrimSpace(value)))
	return "osv-upstream-" + hex.EncodeToString(sum[:])[:16]
}

func upstreamAliasURL(alias string) string {
	alias = strings.TrimSpace(alias)
	upper := strings.ToUpper(alias)
	if strings.HasPrefix(upper, "CVE-") {
		return "https://www.cve.org/CVERecord?id=" + url.QueryEscape(alias)
	}
	if strings.HasPrefix(upper, "GHSA-") {
		return "https://github.com/advisories/" + url.PathEscape(alias)
	}
	return "https://osv.dev/vulnerability/" + url.PathEscape(alias)
}

func vulnerabilityURL(advisoryID string) string {
	return "https://osv.dev/vulnerability/" + url.PathEscape(advisoryID)
}

func readLimited(reader io.Reader, maxBytes int64) ([]byte, bool, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(body)) > maxBytes {
		return nil, true, nil
	}
	return body, false, nil
}
