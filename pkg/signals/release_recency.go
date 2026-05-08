package signals

import (
	"fmt"
	"strings"
	"time"

	"github.com/attach-dev/attach-open-score/pkg/reasons"
	"github.com/attach-dev/attach-open-score/pkg/schema"
)

const (
	defaultStaleAfter  = 730 * 24 * time.Hour
	defaultFreshWithin = 365 * 24 * time.Hour
)

// Options configures deterministic signal derivation thresholds.
type Options struct {
	StaleAfter  time.Duration
	FreshWithin time.Duration
}

// DeriveReleaseRecency returns a Reason describing release-recency
// for a package, given the last release timestamp and the evaluation
// time. Thresholds can be overridden via Options; defaults below.
// Returns an error if lastReleaseAt is zero or in the future.
func DeriveReleaseRecency(lastReleaseAt, now time.Time, sourceRefID string, opts *Options) (schema.Reason, error) {
	if lastReleaseAt.IsZero() {
		return schema.Reason{}, fmt.Errorf("lastReleaseAt is required")
	}
	if now.IsZero() {
		return schema.Reason{}, fmt.Errorf("now is required")
	}
	if strings.TrimSpace(sourceRefID) == "" {
		return schema.Reason{}, fmt.Errorf("sourceRefID is required")
	}
	if lastReleaseAt.After(now) {
		return schema.Reason{}, fmt.Errorf("lastReleaseAt must not be in the future")
	}

	options := Options{
		StaleAfter:  defaultStaleAfter,
		FreshWithin: defaultFreshWithin,
	}
	if opts != nil {
		if opts.StaleAfter != 0 {
			options.StaleAfter = opts.StaleAfter
		}
		if opts.FreshWithin != 0 {
			options.FreshWithin = opts.FreshWithin
		}
	}
	if options.StaleAfter <= 0 {
		return schema.Reason{}, fmt.Errorf("stale threshold must be positive")
	}
	if options.FreshWithin <= 0 {
		return schema.Reason{}, fmt.Errorf("fresh threshold must be positive")
	}
	if options.StaleAfter%(24*time.Hour) != 0 || options.FreshWithin%(24*time.Hour) != 0 {
		return schema.Reason{}, fmt.Errorf("release-recency thresholds must be whole-day durations")
	}
	if options.StaleAfter <= options.FreshWithin {
		return schema.Reason{}, fmt.Errorf("stale threshold must be greater than fresh threshold")
	}

	age := now.Sub(lastReleaseAt)
	ageDays := int(age / (24 * time.Hour))
	staleAfterDays := int(options.StaleAfter / (24 * time.Hour))
	freshWithinDays := int(options.FreshWithin / (24 * time.Hour))

	reason := schema.Reason{
		Code:           reasons.ReleaseRecencyNearStale,
		Severity:       "LOW",
		DecisionEffect: schema.DecisionEffectNone,
		Message:        fmt.Sprintf("Last release was %d days ago, between the fresh window (%d days) and stale threshold (%d days).", ageDays, freshWithinDays, staleAfterDays),
		SourceRefIDs:   []string{sourceRefID},
		Details: map[string]any{
			"last_release_at":   lastReleaseAt.UTC().Format(time.RFC3339Nano),
			"age_days":          ageDays,
			"stale_after_days":  staleAfterDays,
			"fresh_within_days": freshWithinDays,
		},
	}

	switch {
	case ageDays > staleAfterDays:
		reason.Code = reasons.ReleaseRecencyStale
		reason.Severity = "MEDIUM"
		reason.DecisionEffect = schema.DecisionEffectAsk
		reason.Message = fmt.Sprintf("Last release was %d days ago, older than the stale threshold of %d days.", ageDays, staleAfterDays)
	case ageDays <= freshWithinDays:
		reason.Code = reasons.ReleaseRecencyFresh
		reason.Severity = "INFO"
		reason.Message = fmt.Sprintf("Last release was %d days ago, within the fresh window of %d days.", ageDays, freshWithinDays)
	}

	return reason, nil
}
