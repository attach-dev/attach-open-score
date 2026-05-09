package osv

import (
	"math"
	"strconv"
	"strings"
)

type severityClass string

const (
	severityClassCritical severityClass = "critical"
	severityClassHigh     severityClass = "high"
	severityClassModerate severityClass = "moderate"
)

func classifyVulnerability(vuln vulnerability) severityClass {
	highest := severityClassModerate
	if value, ok := databaseSpecificSeverity(vuln); ok {
		if class, ok := severityClassFromString(value); ok {
			highest = maxSeverityClass(highest, class)
		}
	}

	for _, severity := range vuln.Severity {
		if class, ok := severityClassFromString(severity.Score); ok {
			highest = maxSeverityClass(highest, class)
		}
	}
	for _, affected := range vuln.Affected {
		if value, ok := ecosystemSpecificSeverity(affected); ok {
			if class, ok := severityClassFromString(value); ok {
				highest = maxSeverityClass(highest, class)
			}
		}
		for _, severity := range affected.Severity {
			if class, ok := severityClassFromString(severity.Score); ok {
				highest = maxSeverityClass(highest, class)
			}
		}
	}

	return highest
}

func maxSeverityClass(left, right severityClass) severityClass {
	if severityRank(right) > severityRank(left) {
		return right
	}
	return left
}

func severityRank(class severityClass) int {
	switch class {
	case severityClassCritical:
		return 3
	case severityClassHigh:
		return 2
	default:
		return 1
	}
}

func databaseSpecificSeverity(vuln vulnerability) (string, bool) {
	return severityFromMap(vuln.DatabaseSpecific)
}

func ecosystemSpecificSeverity(affected osvAffected) (string, bool) {
	return severityFromMap(affected.EcosystemSpecific)
}

func severityFromMap(values map[string]any) (string, bool) {
	if len(values) == 0 {
		return "", false
	}
	value, ok := values["severity"]
	if !ok {
		return "", false
	}
	severity, ok := value.(string)
	if !ok || strings.TrimSpace(severity) == "" {
		return "", false
	}
	return severity, true
}

func isKnownMalicious(vuln vulnerability) bool {
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(vuln.ID)), "MAL-") {
		return true
	}
	if len(vuln.DatabaseSpecific) == 0 {
		return false
	}
	if malicious, ok := vuln.DatabaseSpecific["malicious"].(bool); ok && malicious {
		return true
	}
	if origins, ok := vuln.DatabaseSpecific["malicious-packages-origins"]; ok {
		return hasNonEmptyOrigin(origins)
	}
	return false
}

func hasNonEmptyOrigin(value any) bool {
	switch typed := value.(type) {
	case []any:
		return len(typed) > 0
	case []map[string]any:
		return len(typed) > 0
	case []string:
		return len(typed) > 0
	default:
		return false
	}
}

func severityClassFromString(value string) (severityClass, bool) {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	switch normalized {
	case "CRITICAL":
		return severityClassCritical, true
	case "HIGH":
		return severityClassHigh, true
	case "MODERATE", "MEDIUM", "LOW":
		return severityClassModerate, true
	}

	if score, err := strconv.ParseFloat(normalized, 64); err == nil {
		return severityClassFromNumericScore(score), true
	}
	if score, ok := cvssV3BaseScore(normalized); ok {
		return severityClassFromNumericScore(score), true
	}
	if class, ok := cvssV4SeverityClass(normalized); ok {
		return class, true
	}
	if strings.HasPrefix(normalized, "AV:") && strings.Contains(normalized, "/AU:") {
		return cvssV2SeverityClass("CVSS:2.0/" + normalized)
	}
	if class, ok := cvssV2SeverityClass(normalized); ok {
		return class, true
	}

	return "", false
}

func cvssV4SeverityClass(vector string) (severityClass, bool) {
	metrics, ok := cvssVectorMetrics(vector, "CVSS:4.")
	if !ok {
		return "", false
	}
	impactKeys := []string{"VC", "VI", "VA", "SC", "SI", "SA"}
	highCount := 0
	lowCount := 0
	for _, key := range impactKeys {
		switch metrics[key] {
		case "H":
			highCount++
		case "L":
			lowCount++
		case "N":
		default:
			return "", false
		}
	}
	if highCount >= 3 {
		return severityClassCritical, true
	}
	if highCount > 0 || lowCount >= 3 {
		return severityClassHigh, true
	}
	return severityClassModerate, true
}

func cvssV2SeverityClass(vector string) (severityClass, bool) {
	metrics, ok := cvssVectorMetrics(vector, "CVSS:2.")
	if !ok {
		return "", false
	}
	impactKeys := []string{"C", "I", "A"}
	completeCount := 0
	partialCount := 0
	for _, key := range impactKeys {
		switch metrics[key] {
		case "C":
			completeCount++
		case "P":
			partialCount++
		case "N":
		default:
			return "", false
		}
	}
	if completeCount == 3 {
		return severityClassCritical, true
	}
	if completeCount > 0 || partialCount >= 2 {
		return severityClassHigh, true
	}
	return severityClassModerate, true
}

func cvssVectorMetrics(vector, prefix string) (map[string]string, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) < 2 || !strings.HasPrefix(parts[0], prefix) {
		return nil, false
	}
	metrics := map[string]string{}
	for _, part := range parts[1:] {
		key, value, ok := strings.Cut(part, ":")
		if !ok || key == "" || value == "" {
			return nil, false
		}
		metrics[key] = value
	}
	return metrics, true
}

func severityClassFromNumericScore(score float64) severityClass {
	if score >= 9.0 {
		return severityClassCritical
	}
	if score >= 7.0 {
		return severityClassHigh
	}
	return severityClassModerate
}

func cvssV3BaseScore(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 || !strings.HasPrefix(parts[0], "CVSS:3.") {
		return 0, false
	}

	metrics := map[string]string{}
	for _, part := range parts[1:] {
		key, value, ok := strings.Cut(part, ":")
		if !ok {
			return 0, false
		}
		metrics[key] = value
	}

	scope := metrics["S"]
	if scope != "U" && scope != "C" {
		return 0, false
	}

	av, ok := metricValue(metrics, "AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	if !ok {
		return 0, false
	}
	ac, ok := metricValue(metrics, "AC", map[string]float64{"L": 0.77, "H": 0.44})
	if !ok {
		return 0, false
	}
	ui, ok := metricValue(metrics, "UI", map[string]float64{"N": 0.85, "R": 0.62})
	if !ok {
		return 0, false
	}
	confidentiality, ok := metricValue(metrics, "C", impactMetricValues())
	if !ok {
		return 0, false
	}
	integrity, ok := metricValue(metrics, "I", impactMetricValues())
	if !ok {
		return 0, false
	}
	availability, ok := metricValue(metrics, "A", impactMetricValues())
	if !ok {
		return 0, false
	}

	prValues := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		prValues = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, ok := metricValue(metrics, "PR", prValues)
	if !ok {
		return 0, false
	}

	impactSubScore := 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
	var impact float64
	if scope == "U" {
		impact = 6.42 * impactSubScore
	} else {
		impact = 7.52*(impactSubScore-0.029) - 3.25*math.Pow(impactSubScore-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui
	if scope == "U" {
		return roundUpCVSS(math.Min(impact+exploitability, 10)), true
	}
	return roundUpCVSS(math.Min(1.08*(impact+exploitability), 10)), true
}

func metricValue(metrics map[string]string, key string, values map[string]float64) (float64, bool) {
	value, ok := metrics[key]
	if !ok {
		return 0, false
	}
	score, ok := values[value]
	return score, ok
}

func impactMetricValues() map[string]float64 {
	return map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
}

func roundUpCVSS(score float64) float64 {
	return math.Ceil((score-1e-10)*10) / 10
}
