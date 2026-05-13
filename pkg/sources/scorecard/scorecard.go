package scorecard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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

	SourceName        = "openssf-scorecard"
	licenseOrTermsURL = "https://github.com/ossf/scorecard/blob/main/LICENSE"
	checksDocsURL     = "https://github.com/ossf/scorecard/blob/main/docs/checks.md"

	lowOverallScoreThreshold = 5.0
	lowCheckScoreThreshold   = 5.0
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

type Report struct {
	Date      string        `json:"date,omitempty"`
	Repo      Repository    `json:"repo,omitempty"`
	Scorecard ScorecardInfo `json:"scorecard,omitempty"`
	Score     *float64      `json:"score,omitempty"`
	Checks    []Check       `json:"checks,omitempty"`
}

type Repository struct {
	Name   string `json:"name,omitempty"`
	URL    string `json:"url,omitempty"`
	Commit string `json:"commit,omitempty"`
}

type ScorecardInfo struct {
	Version string `json:"version,omitempty"`
	Commit  string `json:"commit,omitempty"`
}

type Check struct {
	Name          string        `json:"name,omitempty"`
	Score         *float64      `json:"score,omitempty"`
	Reason        string        `json:"reason,omitempty"`
	Details       Details       `json:"details,omitempty"`
	Documentation Documentation `json:"documentation,omitempty"`
}

type Documentation struct {
	URL   string `json:"url,omitempty"`
	Short string `json:"short,omitempty"`
}

type Details []string

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
		return Adapter{}, fmt.Errorf("OpenSSF Scorecard ttl_seconds must be non-negative")
	}

	return Adapter{
		now:        now,
		ttlSeconds: ttlSeconds,
	}, nil
}

func (a Adapter) Evidence(report Report) ([]schema.Evidence, error) {
	return []schema.Evidence{a.evidence(report, a.reportSourceRef(report))}, nil
}

func (a Adapter) EvidenceFromJSON(data []byte) ([]schema.Evidence, error) {
	sourceRef := a.localJSONSourceRef(data)
	report, err := parseReport(data)
	if err != nil {
		return []schema.Evidence{a.sourceUnavailableEvidence(sourceRef, reportContext{}, "parse_failure", map[string]any{
			"parse_error": err.Error(),
		})}, nil
	}

	return []schema.Evidence{a.evidence(report, sourceRef)}, nil
}

func parseReport(data []byte) (Report, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return Report{}, errors.New("empty OpenSSF Scorecard JSON")
	}
	if data[0] == '[' {
		return Report{}, errors.New("OpenSSF Scorecard JSON must be an object")
	}

	var report Report
	if err := decodeJSON(data, &report); err != nil {
		return Report{}, err
	}
	return report, nil
}

func decodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("OpenSSF Scorecard JSON contains trailing data")
	}
	return nil
}

func (r *Repository) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		r.Name = value
		return nil
	}

	type repository Repository
	var value repository
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*r = Repository(value)
	return nil
}

func (d *Details) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}

	var stringsValue []string
	if err := json.Unmarshal(data, &stringsValue); err == nil {
		*d = normalizeStringList(stringsValue)
		return nil
	}

	var stringValue string
	if err := json.Unmarshal(data, &stringValue); err == nil {
		if value := strings.TrimSpace(stringValue); value != "" {
			*d = Details{value}
		}
		return nil
	}

	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	*d = Details{string(encoded)}
	return nil
}

func (a Adapter) evidence(report Report, sourceRef schema.SourceRef) schema.Evidence {
	context := normalizeReportContext(report)
	reportSourceRef := sourceRef
	if context.repositoryIdentity != "" && (reportSourceRef.SourceID == "" || strings.HasPrefix(reportSourceRef.SourceID, "local-json:")) {
		reportSourceRef = a.reportSourceRef(report)
	}
	if context.repositoryIdentity == "" {
		return a.sourceUnavailableEvidence(sourceRef, context, "missing_repository_identity", map[string]any{
			"source": SourceName,
		})
	}
	if report.Score == nil && len(report.Checks) == 0 {
		return a.sourceUnavailableEvidence(reportSourceRef, context, "missing_required_data", map[string]any{
			"missing_fields": []string{"score_or_checks"},
			"source":         SourceName,
		})
	}

	sourceRefs := dedupeSourceRefs(append([]schema.SourceRef{reportSourceRef}, a.checkSourceRefs(report, context)...))
	sourceRefIDs := sourceRefIDs(sourceRefs)
	details := reportDetails(report, context)

	selectedChecks := selectedCheckResults(report.Checks)
	if len(selectedChecks) > 0 {
		details["selected_checks"] = checkResultDetails(selectedChecks)
	}
	lowChecks, unknownChecks := splitCheckResults(selectedChecks)
	if len(lowChecks) > 0 {
		details["low_checks"] = checkResultDetails(lowChecks)
	}
	if len(unknownChecks) > 0 {
		details["unknown_checks"] = checkResultDetails(unknownChecks)
	}
	if len(sourceRefs) > 1 {
		details["source_refs"] = sourceRefDetails(sourceRefs)
	}

	reasonCode := reasons.RepositoryMappingUncertain
	severity := "MEDIUM"
	effect := schema.DecisionEffectUnknown
	message := fmt.Sprintf("OpenSSF Scorecard local report for %s was normalized as repository-health evidence only; v0 does not allow packages based on Scorecard data alone.", context.repositoryIdentity)
	if hasLowRepositoryHealth(report, lowChecks) {
		reasonCode = reasons.LowRepositoryHealth
		effect = schema.DecisionEffectAsk
		message = fmt.Sprintf("OpenSSF Scorecard local report found low repository-health signals for %s; this is ASK evidence only.", context.repositoryIdentity)
		details["health_status"] = "low"
	} else if len(unknownChecks) > 0 || report.Score == nil {
		details["health_status"] = "unknown"
	} else {
		details["health_status"] = "observed_no_low_selected_checks"
	}

	return evidenceWithSourceRefs(schema.Reason{
		Code:           reasonCode,
		Severity:       severity,
		DecisionEffect: effect,
		Message:        message,
		SourceRefIDs:   sourceRefIDs,
		Details:        details,
	}, sourceRefs)
}

func hasLowRepositoryHealth(report Report, lowChecks []checkResult) bool {
	if scorePresentAndBelow(report.Score, lowOverallScoreThreshold) {
		return true
	}
	return len(lowChecks) > 0
}

func scorePresentAndBelow(score *float64, threshold float64) bool {
	if score == nil || math.IsNaN(*score) || math.IsInf(*score, 0) {
		return false
	}
	return *score >= 0 && *score < threshold
}

func (a Adapter) sourceUnavailableEvidence(sourceRef schema.SourceRef, context reportContext, failureKind string, details map[string]any) schema.Evidence {
	if details == nil {
		details = map[string]any{}
	}
	details["failure_kind"] = failureKind
	if context.repositoryIdentity != "" {
		addContextDetails(details, context)
	}

	return evidenceWithSourceRefs(schema.Reason{
		Code:           reasons.SourceUnavailable,
		Severity:       "MEDIUM",
		DecisionEffect: schema.DecisionEffectUnknown,
		Message:        "OpenSSF Scorecard local report could not be normalized into repository-health evidence.",
		SourceRefIDs:   []string{sourceRef.ID},
		Details:        details,
	}, []schema.SourceRef{sourceRef})
}

type reportContext struct {
	repositoryIdentity string
	repositoryURL      string
	repositoryCommit   string
	reportDate         string
	scorecardVersion   string
	scorecardCommit    string
}

func normalizeReportContext(report Report) reportContext {
	repositoryIdentity, repositoryURL := normalizeRepositoryIdentity(firstNonEmpty(report.Repo.URL, report.Repo.Name))
	return reportContext{
		repositoryIdentity: repositoryIdentity,
		repositoryURL:      repositoryURL,
		repositoryCommit:   strings.TrimSpace(report.Repo.Commit),
		reportDate:         strings.TrimSpace(report.Date),
		scorecardVersion:   strings.TrimSpace(report.Scorecard.Version),
		scorecardCommit:    strings.TrimSpace(report.Scorecard.Commit),
	}
}

func reportDetails(report Report, context reportContext) map[string]any {
	details := map[string]any{
		"source": SourceName,
	}
	addContextDetails(details, context)
	if report.Score != nil && !math.IsNaN(*report.Score) && !math.IsInf(*report.Score, 0) {
		details["scorecard_score"] = *report.Score
	}
	details["low_overall_score_threshold"] = lowOverallScoreThreshold
	details["low_check_score_threshold"] = lowCheckScoreThreshold
	details["evidence_posture"] = "repository_health_only_not_allow_or_deny"
	return details
}

func addContextDetails(details map[string]any, context reportContext) {
	details["repository_identity"] = context.repositoryIdentity
	if context.repositoryURL != "" {
		details["repository_url"] = context.repositoryURL
	}
	if context.repositoryCommit != "" {
		details["repository_commit"] = context.repositoryCommit
	}
	if context.reportDate != "" {
		details["scorecard_date"] = context.reportDate
	}
	if context.scorecardVersion != "" {
		details["scorecard_version"] = context.scorecardVersion
	}
	if context.scorecardCommit != "" {
		details["scorecard_commit"] = context.scorecardCommit
	}
}

type checkResult struct {
	Name             string
	Score            *float64
	Reason           string
	Details          []string
	DocumentationURL string
	Documentation    string
}

func selectedCheckResults(checks []Check) []checkResult {
	results := make([]checkResult, 0, len(checks))
	for _, check := range checks {
		name := strings.TrimSpace(check.Name)
		if name == "" || !isSelectedCheck(name) {
			continue
		}
		result := checkResult{
			Name:             canonicalCheckName(name),
			Score:            check.Score,
			Reason:           strings.TrimSpace(check.Reason),
			Details:          normalizeStringList([]string(check.Details)),
			DocumentationURL: sanitizePublicURL(check.Documentation.URL, ""),
			Documentation:    strings.TrimSpace(check.Documentation.Short),
		}
		results = append(results, result)
	}
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})
	return results
}

func splitCheckResults(results []checkResult) ([]checkResult, []checkResult) {
	low := []checkResult{}
	unknown := []checkResult{}
	for _, result := range results {
		switch {
		case result.Score == nil:
			unknown = append(unknown, result)
		case math.IsNaN(*result.Score), math.IsInf(*result.Score, 0), *result.Score < 0:
			unknown = append(unknown, result)
		case *result.Score < lowCheckScoreThreshold:
			low = append(low, result)
		}
	}
	return low, unknown
}

func checkResultDetails(results []checkResult) []map[string]any {
	details := make([]map[string]any, 0, len(results))
	for _, result := range results {
		item := map[string]any{
			"name": result.Name,
		}
		if result.Score != nil && !math.IsNaN(*result.Score) && !math.IsInf(*result.Score, 0) {
			item["score"] = *result.Score
		}
		if result.Reason != "" {
			item["reason"] = result.Reason
		}
		if len(result.Details) > 0 {
			item["details"] = result.Details
		}
		if result.DocumentationURL != "" {
			item["documentation_url"] = result.DocumentationURL
		}
		if result.Documentation != "" {
			item["documentation"] = result.Documentation
		}
		details = append(details, item)
	}
	return details
}

var selectedCheckNames = map[string]string{
	"binary-artifacts":       "Binary-Artifacts",
	"branch-protection":      "Branch-Protection",
	"ci-tests":               "CI-Tests",
	"cii-best-practices":     "CII-Best-Practices",
	"code-review":            "Code-Review",
	"dangerous-workflow":     "Dangerous-Workflow",
	"dependency-update-tool": "Dependency-Update-Tool",
	"fuzzing":                "Fuzzing",
	"maintained":             "Maintained",
	"pinned-dependencies":    "Pinned-Dependencies",
	"sast":                   "SAST",
	"security-policy":        "Security-Policy",
	"signed-releases":        "Signed-Releases",
	"token-permissions":      "Token-Permissions",
	"vulnerabilities":        "Vulnerabilities",
}

func isSelectedCheck(name string) bool {
	_, ok := selectedCheckNames[checkKey(name)]
	return ok
}

func canonicalCheckName(name string) string {
	if canonical, ok := selectedCheckNames[checkKey(name)]; ok {
		return canonical
	}
	return strings.TrimSpace(name)
}

func checkKey(name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	key = strings.ReplaceAll(key, "_", "-")
	key = strings.ReplaceAll(key, " ", "-")
	return key
}

func (a Adapter) reportSourceRef(report Report) schema.SourceRef {
	context := normalizeReportContext(report)
	sourceID := stableReportSourceID(report, context)
	return schema.SourceRef{
		ID:                  sourceRefID(SourceName, sourceID),
		Source:              SourceName,
		SourceID:            sourceID,
		URL:                 reportSourceURL(context, sourceID),
		RetrievedAt:         a.retrievedAt(context.reportDate),
		TTLSeconds:          a.ttlSeconds,
		LicenseOrTermsURL:   licenseOrTermsURL,
		Attribution:         "Source: OpenSSF Scorecard local/synthetic report. OpenSSF Scorecard is an OpenSSF project; review Scorecard output-data and platform API terms before hosted or bulk redistribution.",
		AttributionRequired: true,
		Redistribution:      sources.RedistributionUnknown,
		PublicDisplay:       sources.PublicDisplayAllowed,
	}
}

func (a Adapter) localJSONSourceRef(data []byte) schema.SourceRef {
	sum := sha256.Sum256(bytes.TrimSpace(data))
	sourceID := "local-json:" + hex.EncodeToString(sum[:])[:16]
	return schema.SourceRef{
		ID:                  sourceRefID(SourceName, sourceID),
		Source:              SourceName,
		SourceID:            sourceID,
		URL:                 "https://example.invalid/attach-open-score/openssf-scorecard/" + url.PathEscape(sourceID),
		RetrievedAt:         a.now().UTC().Format(time.RFC3339),
		TTLSeconds:          a.ttlSeconds,
		LicenseOrTermsURL:   licenseOrTermsURL,
		Attribution:         "Source: OpenSSF Scorecard local/synthetic JSON. OpenSSF Scorecard is an OpenSSF project; review Scorecard output-data and platform API terms before hosted or bulk redistribution.",
		AttributionRequired: true,
		Redistribution:      sources.RedistributionUnknown,
		PublicDisplay:       sources.PublicDisplayAllowed,
	}
}

func (a Adapter) checkSourceRefs(report Report, context reportContext) []schema.SourceRef {
	results := selectedCheckResults(report.Checks)
	refs := make([]schema.SourceRef, 0, len(results))
	for _, result := range results {
		sourceID := context.repositoryIdentity + "#" + result.Name
		if context.repositoryIdentity == "" {
			sourceID = stableCheckSourceID(result)
		}
		refs = append(refs, schema.SourceRef{
			ID:                  sourceRefID(SourceName, sourceID),
			Source:              SourceName,
			SourceID:            sourceID,
			URL:                 sanitizePublicURL(result.DocumentationURL, checkDocumentationURL(result.Name)),
			RetrievedAt:         a.retrievedAt(context.reportDate),
			TTLSeconds:          a.ttlSeconds,
			LicenseOrTermsURL:   licenseOrTermsURL,
			Attribution:         "Source: OpenSSF Scorecard check result from local/synthetic report. Preserve check name, score, reason, and retrieval metadata when displaying this evidence.",
			AttributionRequired: true,
			Redistribution:      sources.RedistributionUnknown,
			PublicDisplay:       sources.PublicDisplayAllowed,
		})
	}
	return refs
}

func (a Adapter) retrievedAt(reportDate string) string {
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(reportDate)); err == nil {
		return parsed.UTC().Format(time.RFC3339)
	}
	return a.now().UTC().Format(time.RFC3339)
}

func reportSourceURL(context reportContext, sourceID string) string {
	if context.repositoryURL != "" {
		return context.repositoryURL
	}
	return "https://example.invalid/attach-open-score/openssf-scorecard/" + url.PathEscape(sourceID)
}

func checkDocumentationURL(name string) string {
	return checksDocsURL
}

func stableReportSourceID(report Report, context reportContext) string {
	if context.repositoryIdentity != "" {
		if context.reportDate != "" {
			return context.repositoryIdentity + "@" + context.reportDate
		}
		return context.repositoryIdentity
	}

	parts := []string{context.reportDate, context.scorecardVersion, context.scorecardCommit}
	if report.Score != nil {
		parts = append(parts, fmt.Sprintf("%.4f", *report.Score))
	}
	for _, check := range report.Checks {
		parts = append(parts, strings.TrimSpace(check.Name), scoreString(check.Score), strings.TrimSpace(check.Reason))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "report:" + hex.EncodeToString(sum[:])[:16]
}

func stableCheckSourceID(result checkResult) string {
	parts := []string{result.Name, scoreString(result.Score), result.Reason}
	parts = append(parts, result.Details...)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "check:" + hex.EncodeToString(sum[:])[:16]
}

func scoreString(score *float64) string {
	if score == nil {
		return ""
	}
	return fmt.Sprintf("%.4f", *score)
}

func sourceRefID(source, sourceID string) string {
	value := strings.ToLower(source + "-" + sourceID)
	value = sourceRefIDReplacer.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	if value == "" {
		return "openssf-scorecard-unknown"
	}
	return value
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

func sourceRefDetails(refs []schema.SourceRef) []map[string]any {
	details := make([]map[string]any, 0, len(refs))
	for _, ref := range refs {
		details = append(details, map[string]any{
			"id":        ref.ID,
			"source":    ref.Source,
			"source_id": ref.SourceID,
			"url":       ref.URL,
		})
	}
	return details
}

func dedupeSourceRefs(refs []schema.SourceRef) []schema.SourceRef {
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

func evidenceWithSourceRefs(reason schema.Reason, refs []schema.SourceRef) schema.Evidence {
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

func normalizeRepositoryIdentity(raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", ""
	}
	value = strings.TrimPrefix(value, "git+")
	value = strings.TrimSuffix(value, ".git")
	if strings.HasPrefix(value, "git://") {
		value = "https://" + strings.TrimPrefix(value, "git://")
	}
	if strings.HasPrefix(value, "git@") {
		parts := strings.SplitN(strings.TrimPrefix(value, "git@"), ":", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			value = "https://" + parts[0] + "/" + parts[1]
		}
	}
	if !strings.Contains(value, "://") && strings.Contains(value, ".") {
		value = "https://" + value
	}

	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return "", ""
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", ""
	}
	parsed.Scheme = "https"
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.Path = strings.TrimRight(parsed.EscapedPath(), "/")
	parsed.Path = strings.TrimSuffix(parsed.Path, ".git")
	if parsed.Path == "" || parsed.Path == "/" {
		return strings.TrimSpace(raw), ""
	}

	repositoryURL := parsed.String()
	identity := strings.TrimPrefix(repositoryURL, "https://")
	return identity, repositoryURL
}

func sanitizePublicURL(raw, fallback string) string {
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
	parsed.Scheme = "https"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func normalizeStringList(values []string) []string {
	out := make([]string, 0, len(values))
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
		out = append(out, value)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
