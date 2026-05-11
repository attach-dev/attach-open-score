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
- `docs/plans/local-dogfood-score-walkthrough.md` — offline local dogfood walkthrough for inspecting synthetic ALLOW / ASK / DENY / UNKNOWN fixture verdicts.
- `docs/plans/2026-05-07-language-and-layout-decision.md` — ADR recording the Go-first core + JSON schema as the cross-language contract (retroactive).

Initial tooling:

```bash
go test ./...
go run ./cmd/attach-open-score --root .
go run ./cmd/attach-open-score score --input request.json
```

- `fixtures/v0/` — synthetic public-safe example verdicts.
- `score --input` evaluates a local, offline v0 request JSON. The request shape is intentionally separate from fixture verdict JSON:
  - top-level `package` is required and uses the package identity fields from `docs/SCORE_SCHEMA.md`;
  - top-level `evidence` is required for CLI scoring and must contain one or more normalized evidence items;
  - each evidence item contains a deterministic `reason` and, when the reason depends on source data, matching `source_ref` and/or `source_refs` entries preserving attribution and terms metadata;
  - unknown JSON fields, `mode`, and verdict-shaped fixture inputs are rejected;
  - experimental `X_*` reasons with blocking/non-informational effects must carry source-ref provenance;
  - `--policy-profile` accepts `default`, `local-dev-default`, `ci-strict`, or `audit-only`.

Minimal local request example:

```json
{
  "package": {
    "ecosystem": "npm",
    "name": "synthetic-package",
    "version": "1.0.0",
    "purl": "pkg:npm/synthetic-package@1.0.0",
    "resolved": true
  },
  "evidence": [
    {
      "reason": {
        "code": "NO_KNOWN_VULNERABILITIES",
        "severity": "INFO",
        "decision_effect": "NONE",
        "message": "Synthetic local evidence for scorer CLI smoke tests.",
        "source_ref_ids": ["synthetic-source"]
      },
      "source_ref": {
        "id": "synthetic-source",
        "source": "synthetic-fixture",
        "url": "https://example.invalid/attach-open-score/synthetic-source",
        "retrieved_at": "2026-05-06T11:50:00Z",
        "ttl_seconds": 86400,
        "license_or_terms_url": "https://example.invalid/terms",
        "attribution": "Synthetic fixture data for Attach Open Score examples.",
        "attribution_required": false,
        "redistribution": "allowed",
        "public_display": "allowed"
      }
    }
  ]
}
```

Status: draft public spec with a first OSV adapter. Source policy, schema,
fixtures, and adapter behavior must stay reviewed together.
