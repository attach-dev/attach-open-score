package score

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/attach-dev/attach-open-score/internal/fixtures"
	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
)

var fixedNow = time.Date(2026, 5, 6, 11, 50, 0, 0, time.UTC)

func TestEvaluateDeniesCriticalReasonAndEmitsSchemaValidVerdict(t *testing.T) {
	engine := NewEngine(Options{Now: func() time.Time { return fixedNow }})

	verdict, err := engine.Evaluate(Request{
		Package: testPackage(),
		Evidence: []Evidence{{
			Reason: schema.Reason{
				Code:           reasons.KnownVulnerabilityCritical,
				Severity:       "CRITICAL",
				DecisionEffect: schema.DecisionEffectDeny,
				Message:        "Synthetic package version matches a critical advisory.",
				SourceRefIDs:   []string{"synthetic-osv"},
			},
			SourceRef: ptr(testSourceRef("synthetic-osv")),
		}},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	if verdict.Decision != schema.DecisionDeny {
		t.Fatalf("decision = %s, want DENY", verdict.Decision)
	}
	if verdict.Score == nil || *verdict.Score < 85 {
		t.Fatalf("score = %v, want critical risk score >= 85", verdict.Score)
	}
	if verdict.Confidence != schema.ConfidenceHigh {
		t.Fatalf("confidence = %s, want HIGH", verdict.Confidence)
	}
	assertSchemaValid(t, verdict)
}

func TestEvaluateAskReasonTakesPrecedenceOverInformationalReasons(t *testing.T) {
	engine := NewEngine(Options{Now: func() time.Time { return fixedNow }})

	verdict, err := engine.Evaluate(Request{
		Package: testPackage(),
		Evidence: []Evidence{
			{
				Reason: schema.Reason{
					Code:           reasons.NoKnownVulnerabilities,
					Severity:       "INFO",
					DecisionEffect: schema.DecisionEffectNone,
					Message:        "Synthetic vulnerability check found no known advisory.",
					SourceRefIDs:   []string{"synthetic-registry"},
				},
				SourceRef: ptr(testSourceRef("synthetic-registry")),
			},
			{
				Reason: schema.Reason{
					Code:           reasons.InstallScriptPresent,
					Severity:       "MEDIUM",
					DecisionEffect: schema.DecisionEffectAsk,
					Message:        "Synthetic package declares an install script.",
					SourceRefIDs:   []string{"synthetic-registry"},
				},
				SourceRef: ptr(testSourceRef("synthetic-registry")),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	if verdict.Decision != schema.DecisionAsk {
		t.Fatalf("decision = %s, want ASK", verdict.Decision)
	}
	if verdict.Score == nil || *verdict.Score < 25 || *verdict.Score > 59 {
		t.Fatalf("score = %v, want moderate risk band 25-59", verdict.Score)
	}
	assertSchemaValid(t, verdict)
}

func TestEvaluateAllowsInformationalReasonsOnly(t *testing.T) {
	engine := NewEngine(Options{Now: func() time.Time { return fixedNow }})

	verdict, err := engine.Evaluate(Request{
		Package: testPackage(),
		Evidence: []Evidence{{
			Reason: schema.Reason{
				Code:           reasons.NoKnownVulnerabilities,
				Severity:       "INFO",
				DecisionEffect: schema.DecisionEffectNone,
				Message:        "Synthetic vulnerability check found no known advisory.",
				SourceRefIDs:   []string{"synthetic-registry"},
			},
			SourceRef: ptr(testSourceRef("synthetic-registry")),
		}},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	if verdict.Decision != schema.DecisionAllow {
		t.Fatalf("decision = %s, want ALLOW", verdict.Decision)
	}
	if verdict.Score == nil || *verdict.Score > 24 {
		t.Fatalf("score = %v, want low risk band 0-24", verdict.Score)
	}
	assertSchemaValid(t, verdict)
}

func TestEvaluateUnknownWhenEvidenceIsInsufficient(t *testing.T) {
	engine := NewEngine(Options{Now: func() time.Time { return fixedNow }})

	verdict, err := engine.Evaluate(Request{Package: testPackage()})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	if verdict.Decision != schema.DecisionUnknown {
		t.Fatalf("decision = %s, want UNKNOWN", verdict.Decision)
	}
	if verdict.Score != nil {
		t.Fatalf("score = %v, want nil when evidence is insufficient", *verdict.Score)
	}
	if verdict.Confidence != schema.ConfidenceLow {
		t.Fatalf("confidence = %s, want LOW", verdict.Confidence)
	}
	if len(verdict.Reasons) != 1 || verdict.Reasons[0].Code != reasons.InsufficientData {
		t.Fatalf("reasons = %#v, want single INSUFFICIENT_DATA reason", verdict.Reasons)
	}
	assertSchemaValid(t, verdict)
}

func TestEvaluateAskOverridesUnknownInAnyOrder(t *testing.T) {
	cases := []struct {
		name     string
		evidence []Evidence
	}{
		{
			name: "unknown then ask",
			evidence: []Evidence{
				testEvidence(reasons.SourceUnavailable, "MEDIUM", schema.DecisionEffectUnknown, "Synthetic source unavailable.", "synthetic-source"),
				testEvidence(reasons.InstallScriptPresent, "MEDIUM", schema.DecisionEffectAsk, "Synthetic package declares an install script.", "synthetic-registry"),
			},
		},
		{
			name: "ask then unknown",
			evidence: []Evidence{
				testEvidence(reasons.InstallScriptPresent, "MEDIUM", schema.DecisionEffectAsk, "Synthetic package declares an install script.", "synthetic-registry"),
				testEvidence(reasons.SourceUnavailable, "MEDIUM", schema.DecisionEffectUnknown, "Synthetic source unavailable.", "synthetic-source"),
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine(Options{Now: func() time.Time { return fixedNow }})
			verdict, err := engine.Evaluate(Request{Package: testPackage(), Evidence: tt.evidence})
			if err != nil {
				t.Fatalf("Evaluate returned error: %v", err)
			}
			if verdict.Decision != schema.DecisionAsk {
				t.Fatalf("decision = %s, want ASK", verdict.Decision)
			}
			assertSchemaValid(t, verdict)
		})
	}
}

func TestEvaluateMapsSourceUnavailableByPolicyProfile(t *testing.T) {
	evidence := []Evidence{testEvidence(reasons.SourceUnavailable, "MEDIUM", schema.DecisionEffectUnknown, "Synthetic source unavailable.", "synthetic-source")}

	localVerdict, err := NewEngine(Options{Now: func() time.Time { return fixedNow }}).Evaluate(Request{Package: testPackage(), Evidence: evidence})
	if err != nil {
		t.Fatalf("local Evaluate returned error: %v", err)
	}
	if localVerdict.Decision != schema.DecisionAsk {
		t.Fatalf("local decision = %s, want ASK for provider/source uncertainty", localVerdict.Decision)
	}
	assertSchemaValid(t, localVerdict)

	ciVerdict, err := NewEngine(Options{Now: func() time.Time { return fixedNow }, PolicyProfile: ProfileCIStrict, EngineVersion: "test-engine"}).Evaluate(Request{Package: testPackage(), Evidence: evidence})
	if err != nil {
		t.Fatalf("ci Evaluate returned error: %v", err)
	}
	if ciVerdict.PolicyProfile != ProfileCIStrict {
		t.Fatalf("policy_profile = %q, want %q", ciVerdict.PolicyProfile, ProfileCIStrict)
	}
	if ciVerdict.EngineVersion != "test-engine" {
		t.Fatalf("engine_version = %q, want test-engine", ciVerdict.EngineVersion)
	}
	if ciVerdict.Decision != schema.DecisionUnknown {
		t.Fatalf("ci decision = %s, want UNKNOWN", ciVerdict.Decision)
	}
	assertSchemaValid(t, ciVerdict)
}

func TestEvaluateRejectsSchemaInvalidEvidence(t *testing.T) {
	cases := []struct {
		name    string
		request Request
	}{
		{
			name:    "unsupported ecosystem",
			request: Request{Package: schema.PackageIdentity{Ecosystem: "gem", Name: "synthetic", Version: "1.0.0", PURL: "pkg:gem/synthetic@1.0.0", Resolved: true}},
		},
		{
			name:    "unknown reason code",
			request: Request{Package: testPackage(), Evidence: []Evidence{testEvidence("NOT_A_CODE", "INFO", schema.DecisionEffectNone, "Unknown code.", "synthetic-source")}},
		},
		{
			name:    "missing reason message",
			request: Request{Package: testPackage(), Evidence: []Evidence{testEvidence(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectNone, "", "synthetic-source")}},
		},
		{
			name: "invalid source ref url",
			request: Request{Package: testPackage(), Evidence: []Evidence{func() Evidence {
				e := testEvidence(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectNone, "Synthetic check.", "synthetic-source")
				e.SourceRef.URL = "not a url"
				return e
			}()}},
		},
		{
			name: "invalid repository url",
			request: Request{Package: func() schema.PackageIdentity {
				pkg := testPackage()
				pkg.RepositoryURL = "not a url"
				return pkg
			}()},
		},
		{
			name: "non json serializable reason details",
			request: Request{Package: testPackage(), Evidence: []Evidence{func() Evidence {
				e := testEvidence(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectNone, "Synthetic check.", "synthetic-source")
				e.Reason.Details = map[string]any{"callback": func() {}}
				return e
			}()}},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewEngine(Options{Now: func() time.Time { return fixedNow }}).Evaluate(tt.request)
			if err == nil {
				t.Fatalf("Evaluate returned nil error for invalid input")
			}
		})
	}
}

func assertSchemaValid(t *testing.T, verdict schema.Verdict) {
	t.Helper()
	data, err := json.Marshal(verdict)
	if err != nil {
		t.Fatalf("marshal verdict: %v", err)
	}
	if _, err := fixtures.ValidateBytes("generated-verdict.json", data); err != nil {
		t.Fatalf("generated verdict failed fixture validation: %v\n%s", err, string(data))
	}
}

func testPackage() schema.PackageIdentity {
	return schema.PackageIdentity{
		Ecosystem:     "npm",
		Name:          "synthetic-package",
		Version:       "1.0.0",
		PURL:          "pkg:npm/synthetic-package@1.0.0",
		RequestedSpec: "^1.0.0",
		Resolved:      true,
	}
}

func testSourceRef(id string) schema.SourceRef {
	return schema.SourceRef{
		ID:                  id,
		Source:              "synthetic-fixture",
		SourceID:            id,
		URL:                 "https://example.invalid/attach-open-score/" + id,
		RetrievedAt:         fixedNow.Format(time.RFC3339),
		TTLSeconds:          86400,
		LicenseOrTermsURL:   "https://example.invalid/terms",
		Attribution:         "Synthetic fixture data for Attach Open Score tests.",
		AttributionRequired: false,
		Redistribution:      "allowed",
		PublicDisplay:       "allowed",
	}
}

func testEvidence(code, severity string, effect schema.DecisionEffect, message, sourceRefID string) Evidence {
	return Evidence{
		Reason: schema.Reason{
			Code:           code,
			Severity:       severity,
			DecisionEffect: effect,
			Message:        message,
			SourceRefIDs:   []string{sourceRefID},
		},
		SourceRef: ptr(testSourceRef(sourceRefID)),
	}
}

func ptr[T any](value T) *T {
	return &value
}
