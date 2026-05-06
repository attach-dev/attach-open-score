# Implementation language and package layout

Status: v0 direction
Scope: public Apache-2.0 Attach Open Score engine, CLI, fixtures, and adapters

## Decision

Use Go as the first implementation language for the deterministic Attach Open Score engine.

Why Go first:

- `attach-guard` is already Go, so a Go module can be embedded directly without a cross-runtime bridge.
- The first consumer is a local CLI/enforcement tool, not a Python data-science pipeline.
- Go makes it straightforward to ship a small static CLI/library for agent sandboxes and CI.
- Deterministic rule scoring, schema validation, and adapter interfaces fit Go well.
- A Go-first core does not prevent later Python tooling for research, analysis, benchmarks, or dataset exploration.

Non-goal for v0:

- No networked source adapters in the first layout PR.
- No hosted cache/client implementation.
- No proprietary vendor integrations.
- No AI/LLM-as-judge enforcement path.

## Module shape

Recommended module path:

```text
github.com/attach-dev/attach-open-score
```

Recommended top-level layout:

```text
cmd/attach-open-score/        # CLI entrypoint, later: score/validate/explain commands
pkg/score/                    # public Go API for evaluating package evidence into verdicts
pkg/schema/                   # generated or hand-maintained schema/domain types
pkg/reasons/                  # stable reason-code constants and helpers
pkg/sources/                  # source reference and attribution types
internal/engine/              # deterministic scoring implementation details
internal/fixtures/            # fixture loading/validation helpers for tests
adapters/                     # optional source adapters once source terms are reviewed
  osv/                        # OSV.dev adapter, first likely networked adapter
  githubadvisory/             # GitHub Advisory Database adapter
  depsdev/                    # deps.dev adapter
  scorecard/                  # OpenSSF Scorecard adapter
spec/v0/score.schema.json     # machine-readable public output schema
fixtures/v0/*.json            # synthetic public fixtures and expected verdicts
docs/*.md                     # public method, source policy, schema, semantics, limitations
```

Only create directories when the first real files land. Empty directory scaffolding should not be committed just to make a tree look busy. Decorative scaffolding is how repos become storage units with ambitions.

## Package responsibilities

### `pkg/score`

Public API boundary for deterministic scoring.

Likely types:

```go
type Request struct {
    Package PackageIdentity
    Evidence []Evidence
    Mode Mode // local, ci, team when needed
}

type Result struct {
    SchemaVersion string
    Package PackageIdentity
    Decision Decision
    Score *int
    Confidence Confidence // LOW, MEDIUM, HIGH
    Reasons []Reason
    SourceRefs []SourceRef
    EvaluatedAt time.Time
    TTLSeconds int
}
```

Responsibilities:

- Accept normalized public/terms-permitted evidence.
- Produce one Attach Open Score verdict.
- Preserve source references and attribution metadata.
- Keep decisions deterministic and testable.

Must not:

- Fetch network sources directly.
- Read secrets or environment variables.
- Contain proprietary vendor-specific score logic.
- Use an LLM to decide ALLOW/ASK/DENY/UNKNOWN.

### `pkg/schema`

Public schema/domain model helpers.

Responsibilities:

- Keep Go structs aligned with `spec/v0/score.schema.json`.
- Provide JSON marshal/unmarshal helpers if useful.
- Avoid silent schema drift between docs, fixtures, and code.

### `pkg/reasons`

Stable reason-code constants and helpers.

Responsibilities:

- Define constants for codes in `docs/REASON_CODES.md`.
- Make reason-code typos hard in engine/tests.
- Keep reason severity/category mapping deterministic.

### `pkg/sources`

Source reference and attribution metadata.

Responsibilities:

- Define `SourceRef` types compatible with `docs/SOURCES.md`.
- Track source ID, URL, retrieval time, TTL, attribution, redistribution/public-display posture, and terms URL.
- Make provenance mandatory for evidence-based verdicts.

### `internal/engine`

Private implementation of scoring rules.

Responsibilities:

- Combine evidence into deterministic verdicts.
- Apply precedence rules, for example known malware / critical exploitability can force DENY.
- Keep risk score polarity consistent: higher score means higher risk.
- Preserve verdict-first semantics for consumers such as `attach-guard`.

### `adapters/*`

Source-specific acquisition/normalization adapters.

Responsibilities:

- Use official APIs/feeds where available.
- Record `source_refs` for every finding.
- Have mocked deterministic unit tests.
- Keep network tests opt-in.
- Include source-specific terms/attribution notes before merge.

Adapters should return normalized evidence, not final Attach decisions. The engine owns final decisions.

## CLI shape

The CLI should be thin over the library.

Possible future commands:

```text
attach-open-score validate fixtures/v0/*.json
attach-open-score score --input evidence.json
attach-open-score explain fixtures/v0/deny-known-critical-vulnerability.json
attach-open-score sources list
```

v0 CLI priorities:

1. Validate fixture/schema conformance.
2. Score local synthetic evidence without network access.
3. Explain reasons and source refs.
4. Later: optional source adapter calls.

## attach-guard integration posture

`attach-guard` should consume Attach Open Score verdicts with a verdict-first bridge:

| Attach Open Score | attach-guard local behavior | attach-guard CI/team behavior |
|---|---|---|
| `ALLOW` | allow | allow |
| `ASK` | ask/warn | configurable; often deny or require approval |
| `DENY` | deny | deny |
| `UNKNOWN` | ask/warn | configurable; often deny or require approval |

Important polarity warning:

- Attach Open Score `score`: higher means riskier.
- Current `attach-guard` Socket-style `PackageScore` fields are safety-ish: lower means worse.

Do not map Open Score `score` directly into current `PackageScore.SupplyChain` / `Overall` threshold logic. Either use verdict-first integration or an explicit transform such as `safety_score = 100 - risk_score` with tests proving the polarity.

## Test strategy

Default tests must be offline and deterministic.

Expected first test layers:

1. Fixture JSON parses.
2. Fixture JSON validates against `spec/v0/score.schema.json`.
3. Reason codes in fixtures exist in `docs/REASON_CODES.md` / package constants.
4. Engine produces expected verdicts for synthetic evidence.
5. Source refs are required for source-derived reasons.
6. Network adapter tests are opt-in and skipped by default.

## Source/legal gates before code

Before adding any source adapter:

- Update or confirm `docs/SOURCES.md` for that source.
- Document official API/feed, allowed fields, attribution, cache TTL, rate limits, auth requirements, redistribution/public-display posture, and fixture policy.
- Add mocked tests using synthetic or terms-safe examples.
- Do not commit proprietary vendor outputs, screenshots, copied score values, or calibration labels.

## First implementation PR after this layout

Recommended next implementation PR:

```text
feat: add Go module and fixture validator skeleton
```

Suggested files:

```text
go.mod
cmd/attach-open-score/main.go
pkg/schema/types.go
pkg/reasons/reasons.go
pkg/sources/source_ref.go
internal/fixtures/validate.go
internal/fixtures/validate_test.go
```

Suggested behavior:

- Parse `spec/v0/score.schema.json` and `fixtures/v0/*.json` enough to validate required fields and reason/source-ref structure.
- No network calls.
- No scoring adapters.
- Tests should pass with `go test ./...` once Go is available.

## Open questions

- Whether to generate Go types from JSON Schema or keep hand-written structs and use schema validation in tests.
- Whether the CLI binary should be `attach-open-score` or eventually folded into an `attach score` subcommand.
- Whether Python helper scripts are useful later for fixture generation/evaluation reports.

Default answer for v0: keep the Go core simple and hand-written, then add generation only if schema drift becomes painful. Keep `Confidence` aligned with the public schema enum (`LOW`, `MEDIUM`, `HIGH`) rather than inventing a parallel numeric confidence field.
