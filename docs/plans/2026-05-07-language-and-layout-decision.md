# ADR: Implementation language and package layout

- Date: 2026-05-07
- Status: Accepted (retroactive)
- Card: t_687f0f84
- Scope: public Apache-2.0 `attach-open-score` repo only

This record retroactively captures the de-facto language and package layout
decision already shipped in this repo. It complements the broader narrative
in [`docs/IMPLEMENTATION_LAYOUT.md`](../IMPLEMENTATION_LAYOUT.md); that file
remains the long-form description, this file is the short ADR-style record.

## Decision

Attach Open Score is implemented as a **Go-first deterministic core** with
the JSON Schema at `spec/v0/score.schema.json` acting as the
**cross-language interface contract** between the engine and any non-Go
consumer.

Concretely:

- The deterministic scoring engine, schema/domain types, reason-code
  constants, source-reference types, fixture validator, and CLI live in Go,
  under the layout already on `main`:
  - `pkg/score/` — public scoring API.
  - `pkg/schema/` — Go domain types aligned with `spec/v0/score.schema.json`.
  - `pkg/sources/` — source reference and attribution metadata types.
  - `pkg/reasons/` — stable reason-code constants.
  - `internal/fixtures/` — fixture loading/validation helpers.
  - `cmd/attach-open-score/` — thin CLI over the library.
- `spec/v0/score.schema.json` is the durable, language-neutral output
  contract. Any non-Go consumer (TypeScript dashboard, Python research
  tooling, hosted client) interoperates through that schema, not through a
  Go API.

## Status

Accepted, retroactive. The repo already ships Go code under the layout
above. This ADR records the choice rather than introducing it.

## Context

- `attach-guard` (the first enforcement consumer) is Go. Embedding a Go
  library avoids a cross-runtime bridge for the path that has to stay
  fast and offline-friendly.
- `attach-run` is also Go, so the same module can be imported there
  without re-implementation.
- `attach-platform` is private and TBD; for hosted scoring/cache/dashboard
  use cases it can either embed the Go core or consume verdicts as JSON
  matching `spec/v0/score.schema.json`.
- Synthetic fixtures under `fixtures/v0/*.json` already pin the
  cross-language contract: any future client in another language must
  parse and validate these files identically.
- Source-policy and attribution requirements (OSV, GitHub Advisory
  Database, deps.dev, OpenSSF Scorecard) live in `docs/SOURCES.md` and
  `pkg/sources/`. Those obligations are language-agnostic and travel with
  the schema, not with the Go module.

## Tradeoffs considered

### TypeScript-first core
- Pros: easier dashboard/IDE/extension integration; one language for a
  hosted Node service plus browser tooling; large npm ecosystem for
  package metadata.
- Cons: weaker fit for a static CLI embedded inside `attach-guard`;
  Node runtime is a heavier dependency in agent sandboxes and CI; we
  would still need a Go shim or subprocess in `attach-guard` and
  `attach-run`. Rejected as the core; not rejected as a future client of
  the JSON schema.

### Python-first core
- Pros: natural fit for research, dataset exploration, calibration,
  benchmarks, and notebook-driven analysis; rich ecosystem for security
  data wrangling.
- Cons: same embedding problem as TypeScript for the Go consumers;
  packaging a deterministic offline CLI in Python is heavier than in Go;
  cold-start and dependency footprint are worse for short-lived agent
  invocations. Rejected as the core; explicitly preserved as a future
  option for tooling that consumes the JSON schema.

### Schema-first only with code generation
- Pros: forces the schema to be the source of truth; no hand-maintained
  drift between Go structs and JSON Schema; easy multi-language client
  generation.
- Cons: generators add a build-time dependency and tend to produce types
  that are awkward to expose as a stable public Go API; for v0 the
  surface is small enough that hand-written Go structs validated against
  the schema in tests is cheaper and clearer. Rejected for v0; revisit
  if schema drift becomes painful, as already noted in
  `docs/IMPLEMENTATION_LAYOUT.md`.

### Honest costs of Go-first
- No native `npm` or `PyPI` package on day one. Adoption from a
  TypeScript or Python codebase requires either a subprocess call to the
  CLI, an HTTP boundary against a hosted client, or a future generated
  client from the JSON schema. That is real adoption friction we are
  accepting.
- Researchers and data folks who would default to Python notebooks have
  to either shell out to `attach-open-score` or read fixture/verdict
  JSON directly. Acceptable for v0 because the deterministic engine and
  source policy matter more than notebook ergonomics.
- A second-language client is not free when we eventually want one;
  schema discipline has to stay tight so a generated or hand-written
  client cannot diverge silently.

## Implications for clients

- **`attach-guard` (Go)**: imports the Go module directly and consumes
  verdicts via the `pkg/score` API. Verdict-first integration as
  described in `docs/IMPLEMENTATION_LAYOUT.md` (ALLOW/ASK/DENY/UNKNOWN);
  do not map the risk-polarity numeric `score` into existing safety-ish
  thresholds without an explicit transform.
- **`attach-run` (Go)**: same posture as `attach-guard`. Direct Go
  import; no bridge.
- **`attach-platform` (TBD, private)**: not constrained to Go. It may
  embed the Go core, run it as a subprocess, or consume verdicts as
  JSON conforming to `spec/v0/score.schema.json` from a hosted client.
  Either way, the public schema and source-attribution rules are the
  contract; private platform code must not leak into this repo.
- **Future TypeScript / Python clients**: must validate against
  `spec/v0/score.schema.json` and preserve `source_refs` and
  attribution exactly as the Go core does. They are clients of the
  contract, not re-implementations of decision semantics.

## Non-goals

- No API redesign of `pkg/score`, `pkg/schema`, `pkg/sources`, or
  `pkg/reasons`.
- No new code, no new Go dependencies, no schema changes.
- No new networked source adapters.
- No proprietary vendor integrations.
- No AI/LLM-as-judge enforcement path; deterministic rule scoring still
  owns ALLOW/ASK/DENY/UNKNOWN.

## Public-safety posture

- Public Apache-2.0; no proprietary vendor scores or data referenced.
- No secrets, tokens, or private platform internals.
- OSV / GitHub Advisory Database / deps.dev / OpenSSF Scorecard
  attribution language is preserved via `docs/SOURCES.md` and
  `pkg/sources/`; this ADR adds no new sources and changes no
  attribution requirements.

## References

- `docs/IMPLEMENTATION_LAYOUT.md` — long-form layout and integration
  rationale.
- `docs/SOURCES.md` — allowed source families and attribution policy.
- `docs/SCORE_SCHEMA.md` — v0 verdict shape.
- `docs/DECISION_SEMANTICS.md` — ALLOW/ASK/DENY/UNKNOWN behavior.
- `spec/v0/score.schema.json` — machine-readable cross-language contract.
