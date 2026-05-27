# Decision semantics

Status: v0 draft
License: Apache-2.0

Attach Open Score is decision-first. The score helps explain and rank risk, but downstream tools should enforce `decision` and reason effects.

## Decisions

### ALLOW

Meaning: no known blocking signals were found and evidence confidence is sufficient for the selected policy profile.

Default behavior:

- Local development: proceed silently or with optional informational output.
- CI/team mode: proceed and record audit output.

ALLOW does not mean “safe forever.” It means “no current policy-blocking signal from allowed sources.”

### ASK

Meaning: there is plausible risk, uncertainty, or a policy-sensitive condition that should be surfaced to a human or stricter team policy.

Common causes:

- package/version is too new
- install scripts or native build hooks are present
- package metadata is incomplete
- maintainer/repository health signals are weak
- source data is stale or partly unavailable
- unresolved requested spec, tag, or branch dependency

Default behavior:

- Local development: ask/warn before continuing.
- CI/team mode: configurable; teams may treat ASK as fail.

### DENY

Meaning: high-confidence dangerous condition matched a deny rule.

Common causes:

- known exploited/critical vulnerability in evaluated version
- known malicious package/advisory match from an allowed source
- package artifact rule with high-confidence malicious behavior
- package identity confusion with high-confidence typosquat or dependency-confusion signal

Default behavior:

- Local development: block by default, with override only if explicitly configured and audited.
- CI/team mode: fail.

### UNKNOWN

Meaning: Attach Open Score does not have enough reliable information to decide.

Common causes:

- package could not be resolved
- source providers unavailable
- source terms prevent the needed lookup/cache/display
- ecosystem is unsupported
- data is contradictory or too stale

Default behavior:

- Local development: treat as ASK/warn by default to avoid brittle developer UX.
- CI/team mode: configurable; stricter profiles may fail UNKNOWN.

## Decision precedence

When multiple reasons apply, use the strongest deterministic effect:

1. Any `DENY` effect with high confidence -> `DENY`.
2. Any `ASK` effect -> at least `ASK` unless a `DENY` reason applies.
3. Only informational/pass reasons with sufficient confidence -> `ALLOW`.
4. Insufficient data or provider failure -> `UNKNOWN` or `ASK`, depending on policy profile.

Do not average away a critical deny reason. Scoring by smoothie is how you get fruit-flavored incidents.

## Policy profiles

### `local-dev-default`

Goal: keep developers protected without encouraging them to disable the tool.

Defaults:

- DENY high-confidence bad signals.
- ASK on uncertainty, newness, install scripts, low confidence, or provider failures.
- Avoid failing closed on provider outage alone.

### `ci-strict`

Goal: protect team/shared branches and production-bound builds.

Defaults:

- DENY high-confidence bad signals.
- Treat ASK as failure unless allowlisted by policy.
- Treat UNKNOWN as failure for protected ecosystems or production dependency groups.

### `audit-only`

Goal: observe and tune policy before enforcement.

Defaults:

- Emit decisions/reasons/source_refs.
- Do not block; downstream tools may log only.

## Confidence and evidence

Confidence modifies enforcement. A high score with low confidence should usually become ASK/UNKNOWN, not DENY. A high-confidence malicious/advisory match may force DENY even if the aggregate score is not yet calibrated.

## Overrides and allowlists

Downstream tools may support overrides, but overrides must be outside the scoring method and recorded in audit logs. Attach Open Score should report the original decision, not mutate evidence to satisfy a local override.

## Provider unavailability

Provider/network failures are not evidence of safety or danger. Represent them with reasons such as `SOURCE_UNAVAILABLE` and lower confidence. Local default maps this to ASK/UNKNOWN; CI profiles may fail.

Offline request fixtures under `fixtures/policy-profiles/` exercise the local-vs-CI profile boundary for ASK and UNKNOWN evidence without changing scorer semantics or fetching live source data.
