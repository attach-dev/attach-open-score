# Attach Open Score v0 score schema

Status: v0 draft
License: Apache-2.0
Audience: implementers, adapter authors, attach-guard integrators, hosted API designers

Attach Open Score emits an explainable verdict for a package/version evaluation. The schema is intentionally decision-first: the `decision` controls policy behavior; the numeric `score` is a supporting signal for sorting, dashboards, and thresholds.

The normative machine-readable draft lives at `spec/v0/score.schema.json`.

## Top-level object

Required fields:

| Field | Type | Meaning |
|---|---:|---|
| `schema_version` | string | Schema identifier, currently `attach-open-score/v0`.
| `package` | object | Evaluated package identity.
| `decision` | enum | One of `ALLOW`, `ASK`, `DENY`, `UNKNOWN`.
| `score` | integer \| null | 0-100 risk score where higher means riskier. `null` is allowed when information is insufficient. |
| `confidence` | enum | `LOW`, `MEDIUM`, or `HIGH` confidence in the decision.
| `reasons` | array | Deterministic reason-code findings that explain the verdict.
| `source_refs` | array | Source/provenance records used by the evaluation.
| `evaluated_at` | string | RFC 3339 UTC timestamp for the evaluation.
| `ttl_seconds` | integer | Suggested time before re-evaluation.
| `limitations` | array | Known caveats for this evaluation.

Optional fields:

| Field | Type | Meaning |
|---|---:|---|
| `policy_profile` | string | Profile used to map score/signals to decision, e.g. `local-dev-default` or `ci-strict`.
| `engine_version` | string | Scoring engine/spec implementation version.
| `debug` | object | Optional local-only debug data. Must not contain secrets, private package names, or proprietary vendor outputs.

## Package identity

The `package` object identifies what was evaluated:

```json
{
  "ecosystem": "npm",
  "name": "example-package",
  "version": "1.2.3",
  "purl": "pkg:npm/example-package@1.2.3",
  "requested_spec": "^1.2.0",
  "resolved": true
}
```

Rules:

- `ecosystem`, `name`, `purl`, and `resolved` are required.
- `version` is required when a concrete package version was evaluated.
- `requested_spec` may record the user-requested range/tag before resolution.
- `resolved=false` means no concrete version was identified; the decision will usually be `UNKNOWN` or `ASK`.

## Decision and score

`decision` is policy-facing. `score` is risk-facing.

- `ALLOW`: no known blocking signals and confidence is sufficient.
- `ASK`: plausible risk or uncertainty requiring human/team policy choice.
- `DENY`: high-confidence dangerous condition.
- `UNKNOWN`: insufficient information to produce a reliable verdict.

Score range:

- `0-24`: low observed risk
- `25-59`: moderate/uncertain risk
- `60-84`: high risk / review strongly recommended
- `85-100`: critical risk / deny by default when confidence is high

These bands are defaults, not a license to ignore reason codes. A single high-severity reason may force `DENY` regardless of aggregate score.

Implementation note: the v0 offline deterministic scorer currently caps actual `ASK` decisions into the `25-59` moderate/uncertain band until canonical per-reason severity mappings and policy calibration are finalized. High-risk `ASK` signals should still be treated as human/team-policy review items based on their reason codes; policy profiles that upgrade those signals to `DENY` may preserve higher risk-facing scores.

## Confidence

Confidence is about evidence quality, not package safety.

- `LOW`: sparse, stale, conflicting, unavailable, or unresolved inputs.
- `MEDIUM`: enough public-source evidence for a useful verdict, with some caveats.
- `HIGH`: deterministic high-signal evidence exists, such as a matching critical advisory or artifact rule.

## Reasons

Each item in `reasons` must use a code from `docs/REASON_CODES.md` or an explicitly namespaced experimental code.

```json
{
  "code": "KNOWN_VULNERABILITY_CRITICAL",
  "severity": "CRITICAL",
  "decision_effect": "DENY",
  "message": "Package version is affected by a known critical vulnerability.",
  "source_ref_ids": ["osv-ghsa-abcd"],
  "details": {
    "advisory_id": "GHSA-abcd-1234"
  }
}
```

Rules:

- `code`, `severity`, `decision_effect`, and `message` are required.
- `source_ref_ids` should link reasons to source refs whenever the reason uses external data.
- `details` must be JSON-serializable and must not contain secrets, private hosted data, or proprietary vendor scores.

## Source refs

`source_refs` preserve attribution and explainability. They are defined first in `docs/SOURCES.md` and included in the schema so every verdict can carry provenance.

Minimum source ref fields:

```json
{
  "id": "osv-ghsa-abcd",
  "source": "osv.dev",
  "source_id": "GHSA-abcd-1234",
  "url": "https://osv.dev/vulnerability/GHSA-abcd-1234",
  "retrieved_at": "2026-05-05T00:00:00Z",
  "ttl_seconds": 86400,
  "license_or_terms_url": "https://google.github.io/osv.dev/",
  "attribution": "Source: OSV.dev / upstream advisory record",
  "attribution_required": true,
  "redistribution": "unknown",
  "public_display": "allowed"
}
```

Every non-default ALLOW/ASK/DENY should be traceable to either source refs or deterministic local inspection rules.

## TTL semantics

`ttl_seconds` is a re-evaluation hint, not a cache entitlement.

- Short TTLs are appropriate for new packages, live advisories, and repository-health signals.
- Longer TTLs may be appropriate for immutable package artifact hashes if source terms permit.
- `ttl_seconds` must not override upstream terms or adapter-specific cache limits.

## Fixture policy

Fixtures under `fixtures/v0/` are synthetic and safe for public redistribution. Real package fixtures require clear license/source provenance and an explicit source-policy note before merge.
