package score

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/attach-dev/attach-open-score/internal/fixtures"
	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
	"github.com/attach-dev/attach-open-score/pkg/signals"
)

var fixedNow = time.Date(2026, 5, 6, 11, 50, 0, 0, time.UTC)

func TestEvaluateDeniesCriticalReasonAndEmitsSchemaValidVerdict(t *testing.T) {
	engine := mustEngine(t, Options{Now: func() time.Time { return fixedNow }})

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
	engine := mustEngine(t, Options{Now: func() time.Time { return fixedNow }})

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
	engine := mustEngine(t, Options{Now: func() time.Time { return fixedNow }})

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

func TestEvaluateAsksWhenEvidenceIsInsufficient(t *testing.T) {
	engine := mustEngine(t, Options{Now: func() time.Time { return fixedNow }})

	verdict, err := engine.Evaluate(Request{Package: testPackage()})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	if verdict.Decision != schema.DecisionAsk {
		t.Fatalf("decision = %s, want ASK for local insufficient evidence", verdict.Decision)
	}
	if verdict.Score == nil || *verdict.Score != 45 {
		t.Fatalf("score = %v, want moderate uncertainty score 45", verdict.Score)
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
			engine := mustEngine(t, Options{Now: func() time.Time { return fixedNow }})
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

func TestEvaluateDeniesRemainHighConfidenceRegardlessOfEvidenceOrder(t *testing.T) {
	cases := []struct {
		name     string
		evidence []Evidence
	}{
		{
			name: "deny then unknown",
			evidence: []Evidence{
				testEvidence(reasons.KnownVulnerabilityCritical, "CRITICAL", schema.DecisionEffectDeny, "Synthetic critical advisory.", "synthetic-osv"),
				testEvidence(reasons.SourceUnavailable, "MEDIUM", schema.DecisionEffectUnknown, "Synthetic source unavailable.", "synthetic-source"),
			},
		},
		{
			name: "unknown then deny",
			evidence: []Evidence{
				testEvidence(reasons.SourceUnavailable, "MEDIUM", schema.DecisionEffectUnknown, "Synthetic source unavailable.", "synthetic-source"),
				testEvidence(reasons.KnownVulnerabilityCritical, "CRITICAL", schema.DecisionEffectDeny, "Synthetic critical advisory.", "synthetic-osv"),
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			verdict, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }}).Evaluate(Request{Package: testPackage(), Evidence: tt.evidence})
			if err != nil {
				t.Fatalf("Evaluate returned error: %v", err)
			}
			if verdict.Decision != schema.DecisionDeny {
				t.Fatalf("decision = %s, want DENY", verdict.Decision)
			}
			if verdict.Confidence != schema.ConfidenceHigh {
				t.Fatalf("confidence = %s, want HIGH", verdict.Confidence)
			}
			assertSchemaValid(t, verdict)
		})
	}
}

func TestEvaluateAuditOnlyDoesNotEmitBlockingDecision(t *testing.T) {
	verdict, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }, PolicyProfile: ProfileAuditOnly}).Evaluate(Request{
		Package:  testPackage(),
		Evidence: []Evidence{testEvidence(reasons.KnownVulnerabilityCritical, "CRITICAL", schema.DecisionEffectDeny, "Synthetic critical advisory.", "synthetic-osv")},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if verdict.PolicyProfile != ProfileAuditOnly {
		t.Fatalf("policy_profile = %q, want %q", verdict.PolicyProfile, ProfileAuditOnly)
	}
	if verdict.Decision != schema.DecisionAllow {
		t.Fatalf("audit-only decision = %s, want ALLOW", verdict.Decision)
	}
	if verdict.Score == nil || *verdict.Score < 85 {
		t.Fatalf("audit-only score = %v, want original high risk score retained", verdict.Score)
	}
	if len(verdict.Reasons) != 1 || verdict.Reasons[0].DecisionEffect != schema.DecisionEffectDeny {
		t.Fatalf("audit-only reasons = %#v, want original DENY reason retained", verdict.Reasons)
	}
	assertSchemaValid(t, verdict)
}

func TestEvaluateAuditOnlyMapsUnknownToNonBlockingDecision(t *testing.T) {
	verdict, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }, PolicyProfile: ProfileAuditOnly}).Evaluate(Request{
		Package:  testPackage(),
		Evidence: []Evidence{testEvidence(reasons.SourceUnavailable, "MEDIUM", schema.DecisionEffectUnknown, "Synthetic source unavailable.", "synthetic-source")},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if verdict.Decision != schema.DecisionAllow {
		t.Fatalf("audit-only decision = %s, want ALLOW", verdict.Decision)
	}
	if verdict.Score != nil {
		t.Fatalf("audit-only score = %v, want nil for underlying unknown evidence", *verdict.Score)
	}
	if len(verdict.Reasons) != 1 || verdict.Reasons[0].DecisionEffect != schema.DecisionEffectUnknown {
		t.Fatalf("audit-only reasons = %#v, want original UNKNOWN reason retained", verdict.Reasons)
	}
	assertSchemaValid(t, verdict)
}

func TestEvaluatePreservesUnknownForSourceUnavailable(t *testing.T) {
	evidence := []Evidence{testEvidence(reasons.SourceUnavailable, "MEDIUM", schema.DecisionEffectUnknown, "Synthetic source unavailable.", "synthetic-source")}

	localVerdict, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }}).Evaluate(Request{Package: testPackage(), Evidence: evidence})
	if err != nil {
		t.Fatalf("local Evaluate returned error: %v", err)
	}
	if localVerdict.Decision != schema.DecisionAsk {
		t.Fatalf("local decision = %s, want ASK for source unavailability", localVerdict.Decision)
	}
	if localVerdict.Score == nil || *localVerdict.Score != 45 {
		t.Fatalf("local score = %v, want moderate uncertainty score 45", localVerdict.Score)
	}
	assertSchemaValid(t, localVerdict)

	ciVerdict, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }, PolicyProfile: ProfileCIStrict, EngineVersion: "test-engine"}).Evaluate(Request{Package: testPackage(), Evidence: evidence})
	if err != nil {
		t.Fatalf("ci Evaluate returned error: %v", err)
	}
	if ciVerdict.PolicyProfile != ProfileCIStrict {
		t.Fatalf("policy_profile = %q, want %q", ciVerdict.PolicyProfile, ProfileCIStrict)
	}
	if ciVerdict.EngineVersion != "test-engine" {
		t.Fatalf("engine_version = %q, want test-engine", ciVerdict.EngineVersion)
	}
	if ciVerdict.Decision != schema.DecisionDeny {
		t.Fatalf("ci decision = %s, want DENY", ciVerdict.Decision)
	}
	assertSchemaValid(t, ciVerdict)
}

func TestEvaluateCapsAskScoreBandEvenWithCallerSuppliedCriticalSeverity(t *testing.T) {
	verdict, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }}).Evaluate(Request{
		Package:  testPackage(),
		Evidence: []Evidence{testEvidence(reasons.KnownVulnerabilityHigh, "CRITICAL", schema.DecisionEffectAsk, "Synthetic high advisory supplied with inconsistent critical severity.", "synthetic-osv")},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if verdict.Decision != schema.DecisionAsk {
		t.Fatalf("decision = %s, want ASK", verdict.Decision)
	}
	if verdict.Score == nil || *verdict.Score != askScoreCeiling {
		t.Fatalf("score = %v, want ASK ceiling %d", verdict.Score, askScoreCeiling)
	}
	assertSchemaValid(t, verdict)
}

func TestEvaluateCIStrictPreservesRiskScoreWhenUpgradingAskToDeny(t *testing.T) {
	verdict, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }, PolicyProfile: ProfileCIStrict}).Evaluate(Request{
		Package:  testPackage(),
		Evidence: []Evidence{testEvidence(reasons.KnownVulnerabilityHigh, "CRITICAL", schema.DecisionEffectAsk, "Synthetic high advisory supplied with inconsistent critical severity.", "synthetic-osv")},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if verdict.Decision != schema.DecisionDeny {
		t.Fatalf("decision = %s, want DENY", verdict.Decision)
	}
	if verdict.Score == nil || *verdict.Score != severityCriticalScore {
		t.Fatalf("score = %v, want preserved critical risk score %d", verdict.Score, severityCriticalScore)
	}
	assertSchemaValid(t, verdict)
}

func TestEvaluateReleaseRecencyStaleAsksAndCIStrictDenies(t *testing.T) {
	reason, err := signals.DeriveReleaseRecency(fixedNow.Add(-(731 * 24 * time.Hour)), fixedNow, "synthetic-registry", nil)
	if err != nil {
		t.Fatalf("DeriveReleaseRecency returned error: %v", err)
	}
	evidence := []Evidence{{
		Reason:    reason,
		SourceRef: ptr(testSourceRef("synthetic-registry")),
	}}

	localVerdict, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }}).Evaluate(Request{
		Package:  testPackage(),
		Evidence: evidence,
	})
	if err != nil {
		t.Fatalf("local Evaluate returned error: %v", err)
	}
	if localVerdict.Decision != schema.DecisionAsk {
		t.Fatalf("local decision = %s, want ASK", localVerdict.Decision)
	}
	assertSchemaValid(t, localVerdict)

	ciVerdict, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }, PolicyProfile: ProfileCIStrict}).Evaluate(Request{
		Package:  testPackage(),
		Evidence: evidence,
	})
	if err != nil {
		t.Fatalf("ci Evaluate returned error: %v", err)
	}
	if ciVerdict.Decision != schema.DecisionDeny {
		t.Fatalf("ci decision = %s, want DENY", ciVerdict.Decision)
	}
	assertSchemaValid(t, ciVerdict)
}

func TestNewEngineRejectsUnknownPolicyProfile(t *testing.T) {
	_, err := NewEngine(Options{Now: func() time.Time { return fixedNow }, PolicyProfile: "local_dev_default"})
	if err == nil {
		t.Fatalf("NewEngine returned nil error for unknown policy profile")
	}
}

func TestEvaluateCIStrictReportsPolicyHookLimitation(t *testing.T) {
	verdict, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }, PolicyProfile: ProfileCIStrict}).Evaluate(Request{
		Package:  testPackage(),
		Evidence: []Evidence{testEvidence(reasons.SourceUnavailable, "MEDIUM", schema.DecisionEffectUnknown, "Synthetic source unavailable.", "synthetic-source")},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if len(verdict.Limitations) != 2 {
		t.Fatalf("limitations = %#v, want base limitation plus ci-strict hook limitation", verdict.Limitations)
	}
	ciLimitation := verdict.Limitations[1]
	for _, want := range []string{"allowlists", "protected ecosystem", "production dependency group"} {
		if !strings.Contains(ciLimitation, want) {
			t.Fatalf("ci-strict limitation = %q, want mention of %q", ciLimitation, want)
		}
	}
	assertSchemaValid(t, verdict)
}

func TestEvaluatePreservesExplicitZeroTopLevelTTL(t *testing.T) {
	zero := 0
	verdict, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }, TTLSeconds: &zero}).Evaluate(Request{
		Package:  testPackage(),
		Evidence: []Evidence{testEvidence(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectNone, "Synthetic check.", "synthetic-source")},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if verdict.TTLSeconds != 0 {
		t.Fatalf("ttl_seconds = %d, want explicit zero", verdict.TTLSeconds)
	}
	assertSchemaValid(t, verdict)
}

func TestEvaluateDefaultsNegativeTopLevelTTL(t *testing.T) {
	negative := -1
	verdict, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }, TTLSeconds: &negative}).Evaluate(Request{
		Package:  testPackage(),
		Evidence: []Evidence{testEvidence(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectNone, "Synthetic check.", "synthetic-source")},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if verdict.TTLSeconds != DefaultTTLSeconds {
		t.Fatalf("ttl_seconds = %d, want default %d", verdict.TTLSeconds, DefaultTTLSeconds)
	}
	assertSchemaValid(t, verdict)
}

func TestEvaluateAcceptsZeroSourceTTL(t *testing.T) {
	evidence := testEvidence(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectNone, "Synthetic check.", "synthetic-source")
	evidence.SourceRef.TTLSeconds = 0

	verdict, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }}).Evaluate(Request{Package: testPackage(), Evidence: []Evidence{evidence}})
	if err != nil {
		t.Fatalf("Evaluate returned error for zero source_ref ttl_seconds: %v", err)
	}
	assertSchemaValid(t, verdict)
}

func TestEvaluateDeduplicatesIdenticalSourceRefs(t *testing.T) {
	first := testEvidence(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectNone, "Synthetic check.", "synthetic-source")
	second := testEvidence(reasons.InstallScriptPresent, "MEDIUM", schema.DecisionEffectAsk, "Synthetic package declares an install script.", "synthetic-source")

	verdict, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }}).Evaluate(Request{
		Package:  testPackage(),
		Evidence: []Evidence{first, second},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if len(verdict.SourceRefs) != 1 {
		t.Fatalf("source_refs length = %d, want deduplicated single ref", len(verdict.SourceRefs))
	}
	assertSchemaValid(t, verdict)
}

func TestEvaluateRejectsConflictingDuplicateSourceRefs(t *testing.T) {
	first := testEvidence(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectNone, "Synthetic check.", "synthetic-source")
	second := testEvidence(reasons.InstallScriptPresent, "MEDIUM", schema.DecisionEffectAsk, "Synthetic package declares an install script.", "synthetic-source")
	second.SourceRef.URL = "https://example.invalid/attach-open-score/other-source"

	_, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }}).Evaluate(Request{
		Package:  testPackage(),
		Evidence: []Evidence{first, second},
	})
	if err == nil {
		t.Fatalf("Evaluate returned nil error for conflicting duplicate source_ref")
	}
	if !strings.Contains(err.Error(), "conflicting source_ref") {
		t.Fatalf("error = %v, want conflicting source_ref", err)
	}
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
			name:    "malformed experimental reason code",
			request: Request{Package: testPackage(), Evidence: []Evidence{testEvidence("X_bad-code", "INFO", schema.DecisionEffectNone, "Malformed experimental code.", "synthetic-source")}},
		},
		{
			name:    "deny reason with non deny effect",
			request: Request{Package: testPackage(), Evidence: []Evidence{testEvidence(reasons.KnownVulnerabilityCritical, "CRITICAL", schema.DecisionEffectNone, "Critical advisory effect typo.", "synthetic-osv")}},
		},
		{
			name:    "known ask reason with deny effect",
			request: Request{Package: testPackage(), Evidence: []Evidence{testEvidence(reasons.VersionTooNew, "MEDIUM", schema.DecisionEffectDeny, "Version too new effect typo.", "synthetic-registry")}},
		},
		{
			name:    "known none reason with ask effect",
			request: Request{Package: testPackage(), Evidence: []Evidence{testEvidence(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectAsk, "No known vulnerabilities effect typo.", "synthetic-source")}},
		},
		{
			name: "registry reason without source refs",
			request: Request{Package: testPackage(), Evidence: []Evidence{{Reason: schema.Reason{
				Code:           reasons.InstallScriptPresent,
				Severity:       "MEDIUM",
				DecisionEffect: schema.DecisionEffectAsk,
				Message:        "Install script finding lacks registry/package metadata provenance.",
			}}}},
		},
		{
			name: "project health reason without source refs",
			request: Request{Package: testPackage(), Evidence: []Evidence{{Reason: schema.Reason{
				Code:           reasons.LowRepositoryHealth,
				Severity:       "MEDIUM",
				DecisionEffect: schema.DecisionEffectAsk,
				Message:        "Repository health finding lacks project-health provenance.",
			}}}},
		},
		{
			name: "identity risk reason without source refs",
			request: Request{Package: testPackage(), Evidence: []Evidence{{Reason: schema.Reason{
				Code:           reasons.PossibleTyposquat,
				Severity:       "HIGH",
				DecisionEffect: schema.DecisionEffectAsk,
				Message:        "Typosquat finding lacks popularity/namespace provenance.",
			}}}},
		},
		{
			name: "advisory reason without source refs",
			request: Request{Package: testPackage(), Evidence: []Evidence{{Reason: schema.Reason{
				Code:           reasons.KnownVulnerabilityCritical,
				Severity:       "CRITICAL",
				DecisionEffect: schema.DecisionEffectDeny,
				Message:        "Synthetic critical advisory without provenance.",
			}}}},
		},
		{
			name: "experimental allow reason without source refs",
			request: Request{Package: testPackage(), Evidence: []Evidence{{Reason: schema.Reason{
				Code:           "X_EXPERIMENTAL_ALLOW",
				Severity:       "INFO",
				DecisionEffect: schema.DecisionEffectAllow,
				Message:        "Experimental allow finding lacks provenance.",
			}}}},
		},
		{
			name: "experimental deny reason without source refs",
			request: Request{Package: testPackage(), Evidence: []Evidence{{Reason: schema.Reason{
				Code:           "X_EXPERIMENTAL_DENY",
				Severity:       "HIGH",
				DecisionEffect: schema.DecisionEffectDeny,
				Message:        "Experimental deny finding lacks provenance.",
			}}}},
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
			name: "hostless source ref url",
			request: Request{Package: testPackage(), Evidence: []Evidence{func() Evidence {
				e := testEvidence(reasons.NoKnownVulnerabilities, "INFO", schema.DecisionEffectNone, "Synthetic check.", "synthetic-source")
				e.SourceRef.URL = "https://"
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
			_, err := mustEngine(t, Options{Now: func() time.Time { return fixedNow }}).Evaluate(tt.request)
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

func mustEngine(t *testing.T, options Options) Engine {
	t.Helper()
	engine, err := NewEngine(options)
	if err != nil {
		t.Fatalf("NewEngine returned error: %v", err)
	}
	return engine
}

func ptr[T any](value T) *T {
	return &value
}
