package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
)

func TestScoreCommandHappyPaths(t *testing.T) {
	cases := []struct {
		name    string
		request schema.Request
		want    schema.Decision
	}{
		{
			name:    "allow",
			request: testScoreRequest(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectNone),
			want:    schema.DecisionAllow,
		},
		{
			name:    "ask",
			request: testScoreRequest(reasons.InstallScriptPresent, "MEDIUM", schema.DecisionEffectAsk),
			want:    schema.DecisionAsk,
		},
		{
			name:    "deny",
			request: testScoreRequest(reasons.KnownVulnerabilityCritical, "CRITICAL", schema.DecisionEffectDeny),
			want:    schema.DecisionDeny,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			path := writeRequestFile(t, tt.request)
			code, stdout, stderr := runCommand(t, []string{"score", "--input", path}, "")
			if code != 0 {
				t.Fatalf("run exited %d, stderr: %s", code, stderr)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q, want empty", stderr)
			}
			if !strings.HasSuffix(stdout, "\n") {
				t.Fatalf("stdout missing final newline: %q", stdout)
			}
			if !strings.Contains(stdout, "\n  \"schema_version\"") {
				t.Fatalf("stdout is not pretty-printed JSON: %s", stdout)
			}

			var verdict schema.Verdict
			if err := json.Unmarshal([]byte(stdout), &verdict); err != nil {
				t.Fatalf("stdout did not contain a JSON verdict: %v\n%s", err, stdout)
			}
			if verdict.Decision != tt.want {
				t.Fatalf("decision = %s, want %s", verdict.Decision, tt.want)
			}
		})
	}
}

func TestScoreCommandReadsStdin(t *testing.T) {
	input := mustMarshalRequest(t, testScoreRequest(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectNone))

	code, stdout, stderr := runCommand(t, []string{"score", "--input", "-"}, string(input))
	if code != 0 {
		t.Fatalf("run exited %d, stderr: %s", code, stderr)
	}

	var verdict schema.Verdict
	if err := json.Unmarshal([]byte(stdout), &verdict); err != nil {
		t.Fatalf("stdout did not contain a JSON verdict: %v\n%s", err, stdout)
	}
	if verdict.Decision != schema.DecisionAllow {
		t.Fatalf("decision = %s, want ALLOW", verdict.Decision)
	}
}

func TestScoreCommandPolicyProfile(t *testing.T) {
	path := writeRequestFile(t, testScoreRequest(reasons.InstallScriptPresent, "MEDIUM", schema.DecisionEffectAsk))

	code, stdout, stderr := runCommand(t, []string{"score", "--input", path, "--policy-profile", "ci-strict"}, "")
	if code != 0 {
		t.Fatalf("run exited %d, stderr: %s", code, stderr)
	}

	var verdict schema.Verdict
	if err := json.Unmarshal([]byte(stdout), &verdict); err != nil {
		t.Fatalf("stdout did not contain a JSON verdict: %v\n%s", err, stdout)
	}
	if verdict.PolicyProfile != "ci-strict" {
		t.Fatalf("policy_profile = %q, want ci-strict", verdict.PolicyProfile)
	}
	if verdict.Decision != schema.DecisionDeny {
		t.Fatalf("decision = %s, want DENY for ci-strict ASK evidence", verdict.Decision)
	}
}

func TestScoreCommandMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")

	code, stdout, stderr := runCommand(t, []string{"score", "--input", missing}, "")
	if code != 1 {
		t.Fatalf("run exited %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "missing.json") {
		t.Fatalf("stderr = %q, want missing file path", stderr)
	}
}

func TestScoreCommandMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"package":`), 0o600); err != nil {
		t.Fatalf("write malformed JSON: %v", err)
	}

	code, stdout, stderr := runCommand(t, []string{"score", "--input", path}, "")
	if code != 1 {
		t.Fatalf("run exited %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "invalid JSON request") {
		t.Fatalf("stderr = %q, want bad JSON error", stderr)
	}
}

func TestScoreCommandRejectsUnknownJSONFields(t *testing.T) {
	path := writeJSONFile(t, `{
		"package": {
			"ecosystem": "npm",
			"name": "synthetic-package",
			"version": "1.0.0",
			"purl": "pkg:npm/synthetic-package@1.0.0",
			"resolved": true
		},
		"evidences": []
	}`)

	code, stdout, stderr := runCommand(t, []string{"score", "--input", path}, "")
	if code != 1 {
		t.Fatalf("run exited %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "unknown field \"evidences\"") {
		t.Fatalf("stderr = %q, want unknown field error", stderr)
	}
}

func TestScoreCommandRejectsVerdictShapedInput(t *testing.T) {
	path := filepath.Join("..", "..", "fixtures", "v0", "allow-clean-synthetic.json")

	code, stdout, stderr := runCommand(t, []string{"score", "--input", path}, "")
	if code != 1 {
		t.Fatalf("run exited %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "unknown field \"schema_version\"") {
		t.Fatalf("stderr = %q, want verdict-shaped input rejection", stderr)
	}
}

func TestScoreCommandRejectsEmptyEvidence(t *testing.T) {
	path := writeJSONFile(t, `{
		"package": {
			"ecosystem": "npm",
			"name": "synthetic-package",
			"version": "1.0.0",
			"purl": "pkg:npm/synthetic-package@1.0.0",
			"resolved": true
		},
		"evidence": []
	}`)

	code, stdout, stderr := runCommand(t, []string{"score", "--input", path}, "")
	if code != 1 {
		t.Fatalf("run exited %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "requires at least one evidence item") {
		t.Fatalf("stderr = %q, want evidence validation error", stderr)
	}
}

func TestScoreCommandRejectsUnknownPreSubcommandFlag(t *testing.T) {
	path := writeRequestFile(t, testScoreRequest(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectNone))

	code, stdout, stderr := runCommand(t, []string{"--bogus", "score", "--input", path}, "")
	if code != 1 {
		t.Fatalf("run exited %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "flag provided but not defined: -bogus") {
		t.Fatalf("stderr = %q, want unknown flag error", stderr)
	}
}

func TestScoreCommandRejectsMissingRequiredZeroValueFields(t *testing.T) {
	path := writeJSONFile(t, `{
		"package": {
			"ecosystem": "npm",
			"name": "synthetic-package",
			"version": "1.0.0",
			"purl": "pkg:npm/synthetic-package@1.0.0"
		},
		"evidence": [{
			"reason": {
				"code": "NO_KNOWN_VULNERABILITIES",
				"severity": "INFO",
				"decision_effect": "NONE",
				"message": "Synthetic evidence.",
				"source_ref_ids": ["synthetic-source"]
			},
			"source_ref": {
				"id": "synthetic-source",
				"source": "synthetic-fixture",
				"url": "https://example.invalid/source",
				"retrieved_at": "2026-05-06T11:50:00Z",
				"license_or_terms_url": "https://example.invalid/terms",
				"attribution": "Synthetic fixture data.",
				"redistribution": "allowed",
				"public_display": "allowed"
			}
		}]
	}`)

	code, stdout, stderr := runCommand(t, []string{"score", "--input", path}, "")
	if code != 1 {
		t.Fatalf("run exited %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "package.resolved is required") {
		t.Fatalf("stderr = %q, want required resolved error", stderr)
	}
}

func TestScoreCommandRejectsMissingSourceRefRequiredFields(t *testing.T) {
	request := testScoreRequest(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectNone)
	data := string(mustMarshalRequest(t, request))
	data = strings.ReplaceAll(data, `,"ttl_seconds":86400`, "")
	path := writeJSONFile(t, data)

	code, stdout, stderr := runCommand(t, []string{"score", "--input", path}, "")
	if code != 1 {
		t.Fatalf("run exited %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "source_ref.ttl_seconds is required") {
		t.Fatalf("stderr = %q, want required ttl_seconds error", stderr)
	}
}

func TestScoreCommandRejectsNullRequiredZeroValueFields(t *testing.T) {
	request := testScoreRequest(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectNone)
	data := string(mustMarshalRequest(t, request))
	data = strings.ReplaceAll(data, `"resolved":true`, `"resolved":null`)
	data = strings.ReplaceAll(data, `"ttl_seconds":86400`, `"ttl_seconds":null`)
	data = strings.ReplaceAll(data, `"attribution_required":false`, `"attribution_required":null`)
	path := writeJSONFile(t, data)

	code, stdout, stderr := runCommand(t, []string{"score", "--input", path}, "")
	if code != 1 {
		t.Fatalf("run exited %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "package.resolved must be a boolean") {
		t.Fatalf("stderr = %q, want null bool rejection", stderr)
	}
}

func TestScoreCommandRejectsIgnoredModeField(t *testing.T) {
	request := testScoreRequest(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectNone)
	data := string(mustMarshalRequest(t, request))
	data = strings.TrimSuffix(data, "}") + `,"mode":"ci-strict"}`
	path := writeJSONFile(t, data)

	code, stdout, stderr := runCommand(t, []string{"score", "--input", path}, "")
	if code != 1 {
		t.Fatalf("run exited %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "use --policy-profile") {
		t.Fatalf("stderr = %q, want mode rejection", stderr)
	}
}

func TestScoreCommandRejectsExperimentalReasonWithoutProvenance(t *testing.T) {
	for _, effect := range []schema.DecisionEffect{schema.DecisionEffectAllow, schema.DecisionEffectAsk, schema.DecisionEffectDeny, schema.DecisionEffectUnknown} {
		t.Run(string(effect), func(t *testing.T) {
			request := testScoreRequest("X_SYNTHETIC_"+string(effect), "HIGH", effect)
			request.Evidence[0].Reason.SourceRefIDs = nil
			request.Evidence[0].SourceRef = nil
			path := writeRequestFile(t, request)

			code, stdout, stderr := runCommand(t, []string{"score", "--input", path}, "")
			if code != 1 {
				t.Fatalf("run exited %d, want 1", code)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty", stdout)
			}
			if !strings.Contains(stderr, "requires source_ref provenance") {
				t.Fatalf("stderr = %q, want experimental provenance rejection", stderr)
			}
		})
	}
}

func TestScoreCommandEngineValidationError(t *testing.T) {
	path := writeRequestFile(t, schema.Request{
		Package: schema.PackageIdentity{
			Name:     "synthetic-package",
			PURL:     "pkg:npm/synthetic-package@1.0.0",
			Resolved: true,
			Version:  "1.0.0",
		},
		Evidence: []schema.Evidence{{
			Reason: schema.Reason{
				Code:           reasons.NoKnownVulnerabilities,
				Severity:       "INFO",
				DecisionEffect: schema.DecisionEffectNone,
				Message:        "Synthetic evidence for CLI validation tests.",
			},
		}},
	})

	code, stdout, stderr := runCommand(t, []string{"score", "--input", path}, "")
	if code != 1 {
		t.Fatalf("run exited %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "package ecosystem is required") {
		t.Fatalf("stderr = %q, want engine validation error", stderr)
	}
}

func TestDefaultCommandStillValidatesFixtures(t *testing.T) {
	code, stdout, stderr := runCommand(t, []string{"--root", filepath.Join("..", "..")}, "")
	if code != 0 {
		t.Fatalf("run exited %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "valid fixtures/v0/allow-clean-synthetic.json ALLOW") {
		t.Fatalf("stdout = %q, want fixture validation output", stdout)
	}
}

func runCommand(t *testing.T, args []string, stdin string) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func writeRequestFile(t *testing.T, request schema.Request) string {
	t.Helper()
	return writeJSONFile(t, string(mustMarshalRequest(t, request)))
}

func writeJSONFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write request: %v", err)
	}
	return path
}

func mustMarshalRequest(t *testing.T, request schema.Request) []byte {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return data
}

func testScoreRequest(code, severity string, effect schema.DecisionEffect) schema.Request {
	sourceRef := schema.SourceRef{
		ID:                  "synthetic-source",
		Source:              "synthetic-fixture",
		SourceID:            "synthetic-source",
		URL:                 "https://example.invalid/attach-open-score/synthetic-source",
		RetrievedAt:         "2026-05-06T11:50:00Z",
		TTLSeconds:          86400,
		LicenseOrTermsURL:   "https://example.invalid/terms",
		Attribution:         "Synthetic fixture data for Attach Open Score tests.",
		AttributionRequired: false,
		Redistribution:      "allowed",
		PublicDisplay:       "allowed",
	}
	return schema.Request{
		Package: schema.PackageIdentity{
			Ecosystem:     "npm",
			Name:          "synthetic-package",
			Version:       "1.0.0",
			PURL:          "pkg:npm/synthetic-package@1.0.0",
			RequestedSpec: "^1.0.0",
			Resolved:      true,
		},
		Evidence: []schema.Evidence{{
			Reason: schema.Reason{
				Code:           code,
				Severity:       severity,
				DecisionEffect: effect,
				Message:        "Synthetic evidence for CLI scorer tests.",
				SourceRefIDs:   []string{sourceRef.ID},
			},
			SourceRef: &sourceRef,
		}},
	}
}
