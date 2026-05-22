# Multi-ecosystem provider-consumer fixtures

Status: release-ready fixture examples
Scope: offline public-safe verdict examples for provider consumers

These examples show how provider consumers can read Attach Open Score v0 verdicts for common package-coordinate families without calling a registry, hosted service, advisory API, package manager, or repository tool. They are committed verdict fixtures built from already-normalized public-safe evidence. They are not raw upstream registry responses and they are not real package evaluations.

Validate them locally from the repository root:

```bash
go run ./cmd/attach-open-score --root .
go test ./...
```

## Fixture set

| Fixture | Coordinate family | Package identity | What it demonstrates |
|---|---|---|---|
| `fixtures/v0/ask-provider-consumer-npm.json` | npm | `pkg:npm/synthetic-npm-provider-consumer@1.4.0` | npm registry metadata normalized as non-authoritative package context with terms and attribution source refs. |
| `fixtures/v0/ask-provider-consumer-pypi.json` | PyPI | `pkg:pypi/synthetic-pypi-provider-consumer@2.1.0` | PyPI JSON-style release metadata normalized without account, contact, popularity, or raw response fields. |
| `fixtures/v0/ask-provider-consumer-crates.json` | crates.io / Cargo | `pkg:cargo/synthetic-cargo-provider-consumer@0.8.0` | crates.io index dependency-resolution metadata normalized without Cargo network operations, owner data, package archives, or source inspection. |
| `fixtures/v0/ask-provider-consumer-go-module.json` | Go module | `pkg:golang/example.com/provider/consumer@v0.3.0` | Go module service metadata normalized from safe synthetic module coordinates without direct VCS, checksum mirror, zip, or source archive data. |
| `fixtures/v0/ask-provider-consumer-yarn-npm-coordinate.json` | Yarn consumer using npm coordinates | `pkg:npm/%40attach-dev/yarn-provider-consumer@3.2.1` | Yarn consumer coordinate syntax represented as an npm package identity; no Yarn lockfile or private manifest data is included. |

All five examples use `REPOSITORY_MAPPING_UNCERTAIN` with `decision_effect: "UNKNOWN"`. Under the local deterministic scorer profile this yields `decision: "ASK"`, `score: 45`, and `confidence: "LOW"`. That is intentional: registry/package-manager metadata is useful context, but it is not a standalone allow signal in v0.

## Source posture

- The fixtures use synthetic package identities and `example.com` / `attach-dev` example repositories only.
- No live registry/API fetching, package tarball download, source inspection, repository clone, hosted cache lookup, or audit/security-feed ingestion is represented.
- `source_refs` preserve source family, source IDs, URLs, retrieval time, TTL, terms URL, attribution text, `attribution_required`, redistribution posture, and public-display posture.
- Redistribution remains `unknown` for upstream-derived source families until source terms are reviewed for the intended use.
- PyPI examples intentionally exclude personal contact fields, account/user metadata, popularity metrics, and raw API documents.
- The Yarn fixture is still an npm ecosystem verdict because Yarn consumes npm package coordinates; it does not add a Yarn source adapter or lockfile data model.

These fixtures are suitable for offline schema/consumer testing and documentation examples. They should not be used as proof that a real package is safe.
