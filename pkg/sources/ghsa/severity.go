package ghsa

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

func classifyAdvisory(advisory Advisory, affectedEntries []Affected) (severityClass, bool) {
	highest := severityClassModerate
	explicit := false

	if value, ok := severityFromMap(advisory.DatabaseSpecific); ok {
		if class, ok := severityClassFromString(value); ok {
			highest = maxSeverityClass(highest, class)
			explicit = true
		}
	}
	if class, ok := severityClassFromString(advisory.Severity.Text); ok {
		highest = maxSeverityClass(highest, class)
		explicit = true
	}
	for _, severity := range advisory.Severity.Entries {
		if class, ok := severityClassFromString(severity.Score); ok {
			highest = maxSeverityClass(highest, class)
			explicit = true
		}
	}
	if advisory.CVSS.Score > 0 {
		highest = maxSeverityClass(highest, severityClassFromNumericScore(advisory.CVSS.Score))
		explicit = true
	}
	if class, ok := severityClassFromString(advisory.CVSS.VectorString); ok {
		highest = maxSeverityClass(highest, class)
		explicit = true
	}

	for _, affected := range affectedEntries {
		if value, ok := severityFromMap(affected.EcosystemSpecific); ok {
			if class, ok := severityClassFromString(value); ok {
				highest = maxSeverityClass(highest, class)
				explicit = true
			}
		}
		if value, ok := severityFromMap(affected.DatabaseSpecific); ok {
			if class, ok := severityClassFromString(value); ok {
				highest = maxSeverityClass(highest, class)
				explicit = true
			}
		}
		if class, ok := severityClassFromString(affected.Severity.Text); ok {
			highest = maxSeverityClass(highest, class)
			explicit = true
		}
		for _, severity := range affected.Severity.Entries {
			if class, ok := severityClassFromString(severity.Score); ok {
				highest = maxSeverityClass(highest, class)
				explicit = true
			}
		}
	}

	return highest, explicit
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
	privilegesRequired, ok := privilegesRequiredMetric(metrics["PR"], scope)
	if !ok {
		return 0, false
	}

	impactSubScoreMultiplier := 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
	var impact float64
	if scope == "U" {
		impact = 6.42 * impactSubScoreMultiplier
	} else {
		impact = 7.52*(impactSubScoreMultiplier-0.029) - 3.25*math.Pow(impactSubScoreMultiplier-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * privilegesRequired * ui
	if scope == "U" {
		return roundUp1(math.Min(impact+exploitability, 10)), true
	}
	return roundUp1(math.Min(1.08*(impact+exploitability), 10)), true
}

func metricValue(metrics map[string]string, key string, values map[string]float64) (float64, bool) {
	value, ok := values[metrics[key]]
	return value, ok
}

func impactMetricValues() map[string]float64 {
	return map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
}

func privilegesRequiredMetric(value, scope string) (float64, bool) {
	switch value {
	case "N":
		return 0.85, true
	case "L":
		if scope == "C" {
			return 0.68, true
		}
		return 0.62, true
	case "H":
		if scope == "C" {
			return 0.5, true
		}
		return 0.27, true
	default:
		return 0, false
	}
}

func roundUp1(value float64) float64 {
	return math.Ceil(value*10) / 10
}
