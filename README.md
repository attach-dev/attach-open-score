# attach-open-score

Transparent dependency-risk scoring engine for AI coding agents.

Attach Open Score is the public, Apache-2.0 scoring method and deterministic engine that supports Attach Guard's dependency-install decisions.

Start here:

- `docs/SOURCES.md` — allowed source families, banned sources, attribution posture, and legal review gates.
- `docs/IMPLEMENTATION_LAYOUT.md` — Go-first implementation language/package layout and attach-guard integration posture.
- `docs/SCORE_SCHEMA.md` — v0 score/verdict shape, package identity, reasons, source refs, and TTL semantics.
- `docs/DECISION_SEMANTICS.md` — ALLOW / ASK / DENY / UNKNOWN behavior and policy profiles.
- `docs/REASON_CODES.md` — v0 deterministic reason-code taxonomy.
- `docs/LIMITATIONS.md` — what v0 can and cannot guarantee.
- `spec/v0/score.schema.json` — machine-readable JSON Schema draft.
- `fixtures/v0/` — synthetic public-safe example verdicts.

Status: draft public spec. Source policy, schema, and fixtures come before networked adapters.
