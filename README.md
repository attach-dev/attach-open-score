# attach-open-score

Transparent dependency-risk scoring for agent-driven installs.

Attach Open Score gives AI coding agents a public, deterministic way to answer a simple question before a dependency is installed: should this package be allowed, denied, reviewed by a human, or treated as unknown?

It is the scoring engine behind Attach Guard. The project turns public-source evidence and local artifact inspection into explainable verdicts with stable reason codes, source references, retrieval metadata, TTLs, and source-attribution posture. The point is not to build another opaque vendor score. The point is to make the dependency decision inspectable.

## Why It Exists

Coding agents can add packages quickly. That is useful, but it also changes the risk model: an agent may reach for a fresh package, a typo-adjacent dependency, a package with install scripts, or a version that public advisory feeds have not caught yet.

Attach Open Score is the public trust layer for that moment. It combines deterministic rules with allowed public/open source families, then emits a verdict that enforcement tools can use.

The engine is intentionally boring where it matters:

- no hidden proprietary vendor scores
- no AI model deciding ALLOW / ASK / DENY / UNKNOWN
- no private customer manifests in the public repo
- no raw upstream dataset redistribution without source review
- no package script execution during artifact analysis

## What It Produces

An Attach Open Score verdict is decision-first:

| Field | Meaning |
|---|---|
| `decision` | `ALLOW`, `ASK`, `DENY`, or `UNKNOWN` |
| `score` | 0-100 risk score; higher means riskier |
| `confidence` | `LOW`, `MEDIUM`, or `HIGH` evidence confidence |
| `reasons` | deterministic reason codes explaining the verdict |
| `source_refs` | provenance, attribution, TTL, and terms metadata for source-backed evidence |
| `limitations` | known caveats for the evaluation |

Decision matters more than the number. Downstream tools such as Attach Guard should consume the verdict first and use the score for sorting, reporting, and policy tuning.

## Installation

Requirements:

- Go 1.22 or newer
- Git, if building from a local checkout

Install the CLI from source:

```bash
go install github.com/attach-dev/attach-open-score/cmd/attach-open-score@latest
```

Or build from a checkout:

```bash
git clone https://github.com/attach-dev/attach-open-score.git
cd attach-open-score
go test ./...
go build ./cmd/attach-open-score
```

Run the local fixture validator:

```bash
go run ./cmd/attach-open-score --root .
```

Score a local request:

```bash
go run ./cmd/attach-open-score score --input request.json
```

Analyze a local npm tarball involved in an attempted install:

```bash
go run ./cmd/attach-open-score npm-artifact \
  --input package.tgz \
  --package synthetic-package \
  --version 1.0.0
```

Validate provider-consumer fixture metadata:

```bash
go run ./cmd/attach-open-score fixtures manifest \
  --input fixtures/manifests/provider-consumer-v0.json
```

## CLI Commands

| Command | Purpose |
|---|---|
| `attach-open-score --root .` | Validate repository fixtures under `fixtures/v0/` |
| `attach-open-score score --input request.json` | Evaluate normalized local evidence into a verdict |
| `attach-open-score score-bundle --input bundle.json` | Compose offline adapter evidence and score it together |
| `attach-open-score npm-artifact --input package.tgz --package name --version version` | Inspect one local npm tarball without executing it |
| `attach-open-score fixtures manifest --input fixtures/manifests/provider-consumer-v0.json` | Validate and summarize fixture metadata |

Policy profiles:

- `default`
- `local-dev-default`
- `ci-strict`
- `audit-only`

Example:

```bash
go run ./cmd/attach-open-score score \
  --input request.json \
  --policy-profile ci-strict
```

## Current Adapter Support

The current adapter posture is fixture-first and source-reference-first. Most adapters normalize local or injected source-shaped data; they do not perform live network calls by default. OSV is the current network-capable source adapter foundation and still preserves source references for every finding.

| Adapter family | Package | Current support |
|---|---|---|
| OSV.dev | `pkg/sources/osv` | Official OSV query client for package coordinates, vulnerability normalization, severity mapping, source refs, and mocked tests |
| GitHub Advisory Database | `pkg/sources/ghsa` | Local GHSA/advisory-shaped JSON normalization, version/range handling, severity mapping, attribution-aware source refs |
| deps.dev / Open Source Insights | `pkg/sources/depsdev` | Local deps.dev-shaped package/version metadata normalization for non-authoritative repository/dependency/license context |
| OpenSSF Scorecard | `pkg/sources/scorecard` | Local or synthetic Scorecard-shaped report normalization for repository-health ASK/UNKNOWN evidence |
| npm registry metadata | `pkg/sources/registry` | Local npm packument/version-shaped metadata normalization, deprecation and package context signals |
| PyPI registry metadata | `pkg/sources/registry` | Local PyPI JSON and Simple/Index-shaped metadata normalization, yanked-file and release metadata signals |
| crates.io index metadata | `pkg/sources/registry` | Local sparse-index/git-index package record normalization, yanked status, checksum, features, dependency metadata |
| Go module services metadata | `pkg/sources/registry` | Local Go proxy/index/go.mod-shaped metadata normalization, deprecation/retraction context where represented |
| npm artifact analysis | `pkg/sources/npmartifact` | On-demand local `.tgz` inspection for lifecycle scripts, suspicious install-time markers, fresh publish metadata, resource limits, and artifact source refs |
| Evidence composition | `pkg/sources/compose` | Offline composition of normalized adapter evidence into one scorer request while preserving source refs |

### npm Artifact Analysis

The npm artifact analyzer is built for the exact package version an agent is about to install. It inspects a local `.tgz` file and can emit:

- `NO_SUSPICIOUS_ARTIFACT_SIGNALS`
- `INSTALL_SCRIPT_PRESENT`
- `SUSPICIOUS_INSTALL_SCRIPT`
- `VERSION_TOO_NEW`

It does not monitor the npm firehose, download dependencies, run package scripts, run a dynamic sandbox, or call an AI model. It also does not ingest npm audit/security-feed data.

## Architecture

Attach Open Score is a Go module with a thin CLI over deterministic library packages.

```text
cmd/attach-open-score/        CLI entrypoint
pkg/score/                    public scoring API and policy-profile evaluation
pkg/schema/                   score/request/domain types aligned with spec/v0
pkg/reasons/                  stable reason-code constants and helpers
pkg/sources/                  source refs plus adapter families
pkg/sources/compose/          offline evidence composition
internal/fixtures/            fixture and manifest validation helpers
fixtures/v0/                  synthetic public-safe example verdicts
fixtures/policy-profiles/     local-vs-CI policy examples
spec/v0/score.schema.json     machine-readable v0 schema
docs/                         source policy, decision semantics, limitations, plans
```

Flow:

```text
package coordinate or local artifact
        |
        v
source adapter or local analyzer
        |
        v
normalized evidence + source_refs
        |
        v
deterministic scoring engine
        |
        v
ALLOW / ASK / DENY / UNKNOWN verdict
```

The adapter boundary is deliberate. Adapters gather or normalize source-specific evidence. The scoring engine owns final decision semantics. That keeps source terms, attribution, and policy behavior reviewable.

## Source Policy

Attach Open Score only uses allowed public/open source families unless a future policy update explicitly says otherwise.

Allowed v0 source families include:

- OSV.dev
- GitHub Advisory Database
- deps.dev / Open Source Insights
- OpenSSF Scorecard
- public registry metadata for npm, PyPI, crates.io, and Go modules
- package tarball/source inspection where terms allow it

Hard bans by default:

- copied proprietary vendor scores
- proprietary vendor-only enrichment as default scoring input
- BYO-token vendor responses in public fixtures or shared caches
- private package names, customer manifests, credentials, or hosted cache internals
- raw upstream dataset redistribution unless source terms have been reviewed

See `docs/SOURCES.md` for the source and attribution policy.

## Future Plans

Near-term work should stay small and reviewable:

- keep expanding fixture coverage across ecosystems and policy profiles
- add more provider-consumer examples for real install decision shapes
- improve package-range handling for pip, Cargo, and Go module edge cases
- add opt-in live source lookups only after source terms, caching, attribution, and rate-limit behavior are reviewed
- build tighter Attach Guard integration around verdict-first policy behavior
- add hosted/provider APIs outside this public method repo without leaking private user context into public fixtures or docs
- keep npm artifact analysis on-demand before considering any broader registry monitoring architecture

Non-goals for v0:

- no proprietary vendor score clone
- no default hosted provider in this repo
- no hidden model-based judgment path
- no claim that a clean verdict proves a package is safe

## Minimal Request Example

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

## Documentation

- `docs/SOURCES.md` - allowed source families, banned sources, attribution posture, and legal review gates
- `docs/IMPLEMENTATION_LAYOUT.md` - Go-first package layout and Attach Guard integration posture
- `docs/SCORE_SCHEMA.md` - v0 score/verdict shape, package identity, reasons, source refs, and TTL semantics
- `docs/DECISION_SEMANTICS.md` - ALLOW / ASK / DENY / UNKNOWN behavior and policy profiles
- `docs/REASON_CODES.md` - deterministic reason-code taxonomy
- `docs/LIMITATIONS.md` - what v0 can and cannot guarantee
- `docs/examples/multi-ecosystem-provider-consumer-fixtures.md` - offline fixture-backed examples
- `spec/v0/score.schema.json` - machine-readable JSON Schema draft
- `docs/plans/local-dogfood-score-walkthrough.md` - local fixture walkthrough
- `docs/plans/2026-05-07-language-and-layout-decision.md` - Go-first ADR

## Status

Public v0 method in active development. The source policy, schema, fixtures, deterministic scoring, adapter foundations, provider-consumer manifests, npm artifact analyzer, and policy-profile fixtures should stay reviewed together.

This repo still does not ship a hosted/default provider, live registry polling, proprietary score ingestion, or raw upstream dataset redistribution.
