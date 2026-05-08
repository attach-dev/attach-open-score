package signals

import (
	"strings"
	"testing"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
)

func TestDeriveReleaseRecency(t *testing.T) {
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name                string
		lastReleaseAt       time.Time
		opts                *Options
		wantCode            string
		wantSeverity        string
		wantEffect          schema.DecisionEffect
		wantMessage         string
		wantAgeDays         int
		wantStaleAfterDays  int
		wantFreshWithinDays int
	}{
		{
			name:          "stale boundary just past default",
			lastReleaseAt: now.Add(-731 * 24 * time.Hour),
			wantCode:      reasons.ReleaseRecencyStale,
			wantSeverity:  "MEDIUM",
			wantEffect:    schema.DecisionEffectAsk,
			wantMessage:   "older than the stale threshold",
			wantAgeDays:   731,
		},
		{
			name:          "sub-day past stale threshold stays near-stale until whole day crosses",
			lastReleaseAt: now.Add(-(730*24*time.Hour + time.Hour)),
			wantCode:      reasons.ReleaseRecencyNearStale,
			wantSeverity:  "LOW",
			wantEffect:    schema.DecisionEffectNone,
			wantMessage:   "between the fresh window",
			wantAgeDays:   730,
		},
		{
			name:          "fresh boundary just within default",
			lastReleaseAt: now.Add(-(365*24*time.Hour - time.Hour)),
			wantCode:      reasons.ReleaseRecencyFresh,
			wantSeverity:  "INFO",
			wantEffect:    schema.DecisionEffectNone,
			wantMessage:   "within the fresh window",
			wantAgeDays:   364,
		},
		{
			name:          "in between fresh and stale windows",
			lastReleaseAt: now.Add(-500 * 24 * time.Hour),
			wantCode:      reasons.ReleaseRecencyNearStale,
			wantSeverity:  "LOW",
			wantEffect:    schema.DecisionEffectNone,
			wantMessage:   "between the fresh window",
			wantAgeDays:   500,
		},
		{
			name:          "nil opts use defaults",
			lastReleaseAt: now.Add(-100 * 24 * time.Hour),
			wantCode:      reasons.ReleaseRecencyFresh,
			wantSeverity:  "INFO",
			wantEffect:    schema.DecisionEffectNone,
			wantMessage:   "within the fresh window",
			wantAgeDays:   100,
		},
		{
			name:                "custom thresholds classify stale",
			lastReleaseAt:       now.Add(-45 * 24 * time.Hour),
			opts:                &Options{StaleAfter: 30 * 24 * time.Hour, FreshWithin: 7 * 24 * time.Hour},
			wantCode:            reasons.ReleaseRecencyStale,
			wantSeverity:        "MEDIUM",
			wantEffect:          schema.DecisionEffectAsk,
			wantMessage:         "older than the stale threshold",
			wantAgeDays:         45,
			wantStaleAfterDays:  30,
			wantFreshWithinDays: 7,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			reason, err := DeriveReleaseRecency(tt.lastReleaseAt, now, "registry-release", tt.opts)
			if err != nil {
				t.Fatalf("DeriveReleaseRecency returned error: %v", err)
			}
			if reason.Code != tt.wantCode {
				t.Fatalf("code = %s, want %s", reason.Code, tt.wantCode)
			}
			if reason.Severity != tt.wantSeverity {
				t.Fatalf("severity = %s, want %s", reason.Severity, tt.wantSeverity)
			}
			if reason.DecisionEffect != tt.wantEffect {
				t.Fatalf("decision_effect = %s, want %s", reason.DecisionEffect, tt.wantEffect)
			}
			if !strings.Contains(reason.Message, tt.wantMessage) {
				t.Fatalf("message = %q, want substring %q", reason.Message, tt.wantMessage)
			}
			if len(reason.SourceRefIDs) != 1 || reason.SourceRefIDs[0] != "registry-release" {
				t.Fatalf("source_ref_ids = %#v, want registry-release", reason.SourceRefIDs)
			}
			if reason.Details["last_release_at"] != tt.lastReleaseAt.UTC().Format(time.RFC3339Nano) {
				t.Fatalf("last_release_at = %#v, want %s", reason.Details["last_release_at"], tt.lastReleaseAt.UTC().Format(time.RFC3339Nano))
			}
			if reason.Details["age_days"] != tt.wantAgeDays {
				t.Fatalf("age_days = %#v, want %d", reason.Details["age_days"], tt.wantAgeDays)
			}
			if tt.wantStaleAfterDays == 0 {
				tt.wantStaleAfterDays = 730
			}
			if tt.wantFreshWithinDays == 0 {
				tt.wantFreshWithinDays = 365
			}
			if reason.Details["stale_after_days"] != tt.wantStaleAfterDays {
				t.Fatalf("stale_after_days = %#v, want %d", reason.Details["stale_after_days"], tt.wantStaleAfterDays)
			}
			if reason.Details["fresh_within_days"] != tt.wantFreshWithinDays {
				t.Fatalf("fresh_within_days = %#v, want %d", reason.Details["fresh_within_days"], tt.wantFreshWithinDays)
			}
		})
	}
}

func TestDeriveReleaseRecencyErrors(t *testing.T) {
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name          string
		lastReleaseAt time.Time
		now           time.Time
		sourceRefID   string
		opts          *Options
	}{
		{
			name: "zero lastReleaseAt",
			now:  now,
		},
		{
			name:          "future lastReleaseAt",
			lastReleaseAt: now.Add(time.Hour),
			now:           now,
			sourceRefID:   "registry-release",
		},
		{
			name:          "empty sourceRefID",
			lastReleaseAt: now.Add(-100 * 24 * time.Hour),
			now:           now,
		},
		{
			name:          "bad options",
			lastReleaseAt: now.Add(-100 * 24 * time.Hour),
			now:           now,
			sourceRefID:   "registry-release",
			opts:          &Options{StaleAfter: 30 * 24 * time.Hour, FreshWithin: 30 * 24 * time.Hour},
		},
		{
			name:          "negative stale threshold",
			lastReleaseAt: now.Add(-100 * 24 * time.Hour),
			now:           now,
			sourceRefID:   "registry-release",
			opts:          &Options{StaleAfter: -1 * time.Hour, FreshWithin: -2 * time.Hour},
		},
		{
			name:          "sub-day thresholds",
			lastReleaseAt: now.Add(-100 * 24 * time.Hour),
			now:           now,
			sourceRefID:   "registry-release",
			opts:          &Options{StaleAfter: 25 * time.Hour, FreshWithin: time.Hour},
		},
		{
			name:          "zero now",
			lastReleaseAt: now.Add(-100 * 24 * time.Hour),
			sourceRefID:   "registry-release",
			opts:          nil,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			sourceRefID := tt.sourceRefID
			if sourceRefID == "" && tt.name != "empty sourceRefID" {
				sourceRefID = "registry-release"
			}
			_, err := DeriveReleaseRecency(tt.lastReleaseAt, tt.now, sourceRefID, tt.opts)
			if err == nil {
				t.Fatalf("DeriveReleaseRecency returned nil error")
			}
		})
	}
}
