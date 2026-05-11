# Source and attribution policy

Status: v0 draft
License: This repository policy document is Apache-2.0; third-party source data remains under upstream licenses/terms.
Audience: maintainers, contributors, agents, and future adapter authors

## Purpose

Attach Open Score must be a first-party, transparent dependency-risk method built from allowed public/open source families. It must not become a wrapper around copied proprietary vendor scores.

This file defines the allowed v0 source families, hard bans, attribution requirements, caching posture, and review gates for adding adapters or generated datasets.

This is an engineering/source-policy document, not legal advice. If source terms materially affect caching, redistribution, commercial use, hosted use, or public display, stop and get explicit review before shipping.

## Hard bans

Do not scrape, copy, transcribe, resell, redistribute, benchmark against, calibrate from, train on, tune weights from, or use as the default hosted scoring input any proprietary vendor risk score or proprietary vendor-only dataset without explicit written permission and a repo policy update.

Banned-by-default examples:

- Socket supply-chain scores, except as a local BYO-token provider outside the default Attach Open Score dataset/method.
- Snyk scores or proprietary vulnerability enrichment.
- Aikido scores or proprietary enrichment.
- Sonatype scores or proprietary enrichment.
- Endor scores or proprietary enrichment.
- Any vendor dashboard/manual lookup result copied into fixtures, docs, model outputs, or scoring weights.

Allowed use of those vendors, if ever needed, must be opt-in/BYO-token, clearly separated from Attach Open Score, and reviewed for terms/partnership constraints. BYO-token vendor outputs must not enter the default Attach Open Score method, public fixtures, public cache, aggregate eval labels, scoring-weight calibration, docs examples, or hosted/shared outputs unless an explicit reviewed partner policy exists.

## v0 allowed source families

### OSV.dev

Intended use:

- Query vulnerabilities by package ecosystem/name/version.
- Use vulnerability IDs, aliases, severity data when provided, affected ranges, references, and advisory metadata as source references.

Policy:

- Keep OSV records as source references, not silent hidden inputs.
- Cache only with provenance and refresh metadata.
- Do not imply OSV endorsement.
- Preserve upstream advisory IDs and URLs in `source_refs`.

Adapter note:

- The v0 OSV adapter uses the official `POST /v1/query` API for single package coordinates only: ecosystem, package name, and version.
- Accepted response fields are limited to vulnerability IDs, aliases, summary text, severity/CVSS values, references, published/modified timestamps, and `database_specific` severity/malicious markers where present.
- The adapter rechecks OSV `affected.package` before emitting vulnerability evidence. For records returned by version-scoped `POST /v1/query`, exact `affected.versions` matches and matching-package `affected.ranges` are treated as vulnerability evidence; affected entries with neither versions nor ranges are treated as unusable source data.
- It records `source: "osv.dev"`, OSV vulnerability IDs or query coordinates as `source_id`, OSV vulnerability/query/reference URLs, retrieval time, a 24-hour default TTL, and OSV-specific attribution text for query responses, vulnerability records, aliases, and upstream references.
- The adapter does not require API credentials, does not send user/account/project context, and unit tests use injected HTTP clients instead of live network calls.
- The adapter sets no custom retry loop today; callers should respect OSV API availability, use bounded timeouts, and add rate-limit/backoff policy before bulk hosted use.
- Normalized OSV fixtures should use synthetic responses unless a real record is explicitly needed with provenance and current terms review.
- Public display of source references is allowed for IDs/URLs/attribution; redistribution of bulk normalized OSV-derived data remains `unknown` until large-scale mirroring/redistribution terms are reviewed.

Reference checked during drafting:

- `https://google.github.io/osv.dev/`
- `https://api.osv.dev/v1/query`

Review gate:

- Before large-scale mirroring or redistribution of normalized OSV-derived data, confirm the applicable OSV dataset/license and attribution requirements for each record/source.

### GitHub Advisory Database

Intended use:

- Public vulnerability advisory data.
- Advisory IDs, CVEs/GHSAs, affected packages/ranges, severity, references, and metadata.

Known posture:

- The GitHub Advisory Database repository publishes license terms in its repo. The current Attach planning context expects CC-BY-4.0 attribution obligations for advisory database data.

Policy:

- Preserve GHSA IDs and GitHub advisory URLs in `source_refs`.
- Attribute GitHub Advisory Database in docs and any hosted/public data display that includes or derives from it.
- Do not strip attribution when normalizing records.

Reference checked during drafting:

- `https://github.com/github/advisory-database/blob/main/LICENSE.md`

Review gate:

- Before redistributing bundled advisory snapshots, verify current license text from the upstream repo and include required attribution/notice language.

### deps.dev / Open Source Insights

Intended use:

- Dependency graph metadata, package/project metadata, versions, dependencies, and ecosystem insights exposed by the deps.dev API.

Known posture:

- Current Attach planning context expects deps.dev generated data to require CC-BY-4.0 attribution and to be subject to Google API terms. Docs indicate API access and may permit caching subject to those terms.

Policy:

- Preserve deps.dev package/version/project URLs or API identifiers in `source_refs`.
- Attribute deps.dev / Open Source Insights / Google as required by upstream terms.
- Treat cached deps.dev-derived data as attributable generated data, not as Attach-owned raw data.

Reference checked during drafting:

- `https://docs.deps.dev/api/v3/`

Review gate:

- Before storing a hosted cache or publishing normalized dumps, verify current Google API terms, deps.dev data license, caching limits, and attribution text.

### OpenSSF Scorecard

Intended use:

- Repository/project security-health signals where package-to-repo mapping is reliable enough.
- Signals may include maintained status, dangerous workflow patterns, branch protection, pinned dependencies, token permissions, fuzzing, SAST, and related checks.

Policy:

- Keep Scorecard as one input family, not the whole score.
- Preserve Scorecard result timestamps, repo URL, check names, and score/details as `source_refs`.
- Avoid over-weighting repository health when package identity/repository mapping is uncertain.

Reference checked during drafting:

- `https://github.com/ossf/scorecard/blob/main/LICENSE`

Review gate:

- Verify Scorecard output-data terms and any GitHub API terms before hosted bulk scoring/caching.

### Public registry metadata

Potential registries:

- npm registry metadata
- PyPI metadata
- crates.io metadata
- Go module proxy/index/checksum database metadata

Intended use:

- Package identity and version metadata.
- Publish times where exposed.
- Maintainer/owner metadata where terms allow.
- Deprecation/yank status where exposed.
- Project links and repository links where exposed.

Policy:

- Respect each registry's Terms of Service, acceptable-use rules, rate limits, robots/API guidance, and attribution requirements.
- Cache minimally by default and store `source_refs`, fetch time, and TTL.
- Do not use registry data to dox maintainers or expose private/non-public metadata.
- Do not scrape pages where a documented API exists and terms prefer API access.

References checked during drafting:

- PyPI Terms: `https://policies.python.org/pypi.org/Terms-of-Service/`
- Go module services: `https://proxy.golang.org/`
- npm terms page was attempted but returned HTTP 403 from this runtime; must be checked manually before npm registry adapter publication.
- crates.io policy URL attempted during drafting returned HTTP 404 for `https://crates.io/policies`; must be checked manually before crates.io adapter publication.

Review gate:

- Every registry adapter must include a terms note in this file or in an adapter-local README before merge.

### Package tarball/source inspection

Intended use:

- Deterministic local inspection of package artifacts where license and registry terms allow download/analysis.
- Examples: install scripts, suspicious binaries, obfuscated code markers, unexpected network behavior markers, lifecycle scripts, and high-risk file patterns.

Policy:

- Record package artifact URL, digest, fetch time, package version, and license metadata where available.
- Do not redistribute full package contents unless the package license and registry terms permit it.
- Fixtures should prefer tiny synthetic packages or metadata-only examples unless redistribution rights are clear.

Review gate:

- Any committed real package fixture must include license/source provenance and justification.

## Source references required in output

Every score/verdict produced by Attach Open Score should be explainable through `source_refs`.

Minimum source reference fields:

```json
{
  "source": "osv.dev",
  "source_id": "GHSA-xxxx-yyyy-zzzz",
  "url": "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz",
  "retrieved_at": "2026-05-05T00:00:00Z",
  "ttl_seconds": 86400,
  "license_or_terms_url": "https://example.com/upstream-license-or-terms",
  "attribution": "Source: OSV.dev / upstream advisory record",
  "attribution_required": true,
  "redistribution": "allowed | restricted | unknown",
  "public_display": "allowed | restricted | unknown"
}
```

Do not produce a DENY/ALLOW decision that cannot be traced to source references, deterministic local rules, or explicitly documented defaults.

## Caching policy

Default v0 posture:

- Cache source responses only with source name, upstream URL/API identifier, retrieved_at, and TTL.
- Keep TTL conservative until source-specific terms are reviewed.
- Treat cache as derived/provenance-bearing data, not as Attach-owned raw data.
- Do not publish bulk cache dumps until source terms are reviewed.
- Hosted cache must preserve attribution and source references in API output.
- Never place BYO-token vendor responses in shared/public caches.
- Keep public-source cache data separate from private hosted/user evaluation data.
- Never publish per-user lookups, private registry/package names, customer manifests, or private package metadata from hosted evaluation flows.

Suggested default TTL classes, subject to source terms:

- Vulnerability/advisory data: short-to-medium TTL with explicit refresh.
- Registry package metadata: short TTL for new versions; longer TTL for immutable version records if terms permit.
- Scorecard/repository health: short TTL because repo posture changes.
- Package artifact inspection: cache by immutable digest where terms permit.

## Attribution posture

Public docs and hosted output should include attribution for source families used. Minimum project-level attribution language:

> Attach Open Score uses public/open dependency security and package metadata sources including OSV.dev, GitHub Advisory Database, deps.dev / Open Source Insights, OpenSSF Scorecard, and public package registry metadata where permitted. Source-specific references and retrieval metadata are preserved in each verdict where available. Third-party data remains subject to upstream licenses and terms.

If CC-BY-4.0 data is included or derived, preserve attribution in docs/output and avoid implying upstream endorsement.


## Public/private boundary

This public repo may contain public source adapters, deterministic engine code, synthetic fixtures, public-source fixtures with provenance, methodology docs, and source-policy docs.

This public repo must not contain:

- user-specific evaluations or customer manifests
- private registry names, private package names, or private dependency graphs
- hosted cache internals or private enrichment data
- API keys, tokens, credentials, or `.env` files
- BYO-token vendor responses
- proprietary vendor scores, eval labels, screenshots, copied examples, or calibration data

Private hosted/platform implementation details belong outside this repo.

## Adapter acceptance checklist

Before merging a new source adapter:

- [ ] Source terms/license reviewed and summarized.
- [ ] Adapter terms note states official API/feed used, allowed fields, attribution text, cache TTL, redistribution/public-display posture, rate limits, auth requirements, and fixtures policy.
- [ ] Adapter uses official API/feed where available.
- [ ] Adapter records `source_refs` for every finding.
- [ ] Adapter has deterministic tests with mocked responses.
- [ ] Network tests are opt-in, not default unit tests.
- [ ] Cache TTL and redistribution posture documented.
- [ ] Attribution requirements documented.
- [ ] No proprietary vendor scores copied or used as training/fixture data.
- [ ] No secrets, API keys, or private hosted data committed.

## Legal/source blockers

Block the card/PR instead of guessing if:

- Terms forbid or are unclear about commercial hosted use.
- Terms forbid or are unclear about caching or redistribution.
- Required attribution cannot be preserved in the planned output.
- A source blends public data with proprietary enrichment and does not separate them clearly.
- A fixture would require committing third-party package contents without clear redistribution rights.
- A worker suggests copying vendor score values from a dashboard, blog, screenshot, API response, or benchmark.
- A worker suggests calibrating, benchmarking, training, or tuning Attach Open Score against proprietary vendor scores.

## Initial v0 source priority

Recommended first implementation order:

1. OSV.dev vulnerability lookup with source references.
2. Static fixtures and deterministic reason codes.
3. GitHub Advisory Database attribution-compatible ingestion or lookup path.
4. deps.dev metadata once caching/attribution posture is confirmed.
5. OpenSSF Scorecard as repository-health signal after package-to-repo mapping rules exist.
6. Registry metadata adapters with source-specific terms notes.

Do not start with proprietary scoring providers. That route is fast in the same way a cliff is fast.
