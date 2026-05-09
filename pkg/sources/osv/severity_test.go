package osv

import "testing"

func TestClassifyVulnerabilitySeverity(t *testing.T) {
	tests := []struct {
		name string
		vuln vulnerability
		want severityClass
	}{
		{
			name: "MAL id uses malicious path",
			vuln: vulnerability{ID: "MAL-2024-5347"},
			want: severityClassModerate,
		},
		{
			name: "malicious package origins uses malicious path",
			vuln: vulnerability{DatabaseSpecific: map[string]any{"malicious-packages-origins": []any{map[string]any{"source": "synthetic"}}}},
			want: severityClassModerate,
		},
		{
			name: "malicious marker uses critical reason path separately",
			vuln: vulnerability{DatabaseSpecific: map[string]any{"malicious": true}},
			want: severityClassModerate,
		},
		{
			name: "database specific severity wins over CVSS",
			vuln: vulnerability{
				DatabaseSpecific: map[string]any{"severity": "CRITICAL"},
				Severity:         []osvSeverity{{Type: "CVSS_V3", Score: "4.0"}},
			},
			want: severityClassCritical,
		},
		{
			name: "numeric high after earlier moderate chooses highest",
			vuln: vulnerability{Severity: []osvSeverity{{Type: "CVSS_V3", Score: "6.9"}, {Type: "CVSS_V3", Score: "7.1"}}},
			want: severityClassHigh,
		},
		{
			name: "numeric moderate",
			vuln: vulnerability{Severity: []osvSeverity{{Type: "CVSS_V3", Score: "6.9"}}},
			want: severityClassModerate,
		},
		{
			name: "cvss vector critical",
			vuln: vulnerability{Severity: []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}},
			want: severityClassCritical,
		},
		{
			name: "cvss v4 vector critical from multiple high impacts",
			vuln: vulnerability{Severity: []osvSeverity{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"}}},
			want: severityClassCritical,
		},
		{
			name: "low-impact cvss v4 vector remains moderate",
			vuln: vulnerability{Severity: []osvSeverity{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:P/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N"}}},
			want: severityClassModerate,
		},
		{
			name: "cvss v2 vector high not critical for partial impacts",
			vuln: vulnerability{Severity: []osvSeverity{{Type: "CVSS_V2", Score: "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"}}},
			want: severityClassHigh,
		},
		{
			name: "cvss v2 OSV score without prefix is parsed",
			vuln: vulnerability{Severity: []osvSeverity{{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}},
			want: severityClassHigh,
		},
		{
			name: "affected severity participates in highest severity",
			vuln: vulnerability{
				Severity: []osvSeverity{{Type: "CVSS_V3", Score: "4.0"}},
				Affected: []osvAffected{{Severity: []osvSeverity{{Type: "CVSS_V3", Score: "9.8"}}}},
			},
			want: severityClassCritical,
		},
		{
			name: "affected ecosystem specific severity participates in highest severity",
			vuln: vulnerability{
				Severity: []osvSeverity{{Type: "CVSS_V3", Score: "4.0"}},
				Affected: []osvAffected{{EcosystemSpecific: map[string]any{"severity": "HIGH"}}},
			},
			want: severityClassHigh,
		},
		{
			name: "invalid score defaults moderate",
			vuln: vulnerability{Severity: []osvSeverity{{Type: "CVSS_V3", Score: "not-a-score"}}},
			want: severityClassModerate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyVulnerability(tt.vuln); got != tt.want {
				t.Fatalf("classifyVulnerability() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestIsKnownMalicious(t *testing.T) {
	if !isKnownMalicious(vulnerability{ID: "MAL-2024-5347"}) {
		t.Fatalf("expected MAL-prefixed OSV id to be detected")
	}
	if !isKnownMalicious(vulnerability{DatabaseSpecific: map[string]any{"malicious-packages-origins": []any{map[string]any{"source": "synthetic"}}}}) {
		t.Fatalf("expected malicious-package origins marker to be detected")
	}
	if !isKnownMalicious(vulnerability{DatabaseSpecific: map[string]any{"malicious": true}}) {
		t.Fatalf("expected malicious marker to be detected")
	}
	if isKnownMalicious(vulnerability{DatabaseSpecific: map[string]any{"malicious": "true"}}) {
		t.Fatalf("string malicious marker should not be treated as true")
	}
}
