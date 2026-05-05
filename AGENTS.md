# AGENTS.md — attach-open-score rules

This is the public Apache-2.0 transparent dependency-risk scoring repo.

## Role
- score schema
- decision semantics
- reason codes
- source attribution policy
- public/open source adapters
- deterministic scoring engine
- fixtures, benchmarks, expected verdicts
- methodology and limitations docs

## License posture
- Public Apache-2.0 project.
- Preserve NOTICE/attribution requirements.
- Attribute CC-BY-4.0 sources such as GitHub Advisory Database and deps.dev generated data where used.

## Hard rules
- Do not scrape/copy/resell proprietary vendor scores.
- Do not include Socket/Snyk/Aikido/Sonatype/Endor scores unless explicit written permission exists and policy is updated.
- Do not include private user evaluations or hosted cache internals.
- Do not include secrets.
- Do not use AI as the primary enforcement decision engine in v0; deterministic/rule scoring owns decisions.

## Allowed v0 source families
- OSV.dev
- GitHub Advisory Database
- deps.dev
- OpenSSF Scorecard
- registry metadata for npm/PyPI/crates.io/Go modules within policy
- package tarball/source inspection where allowed

## Output semantics
The public method should produce:
- package identity / purl
- decision: ALLOW / ASK / DENY / UNKNOWN
- numeric score if useful
- confidence
- reason codes
- source_refs
- evaluated_at
- ttl_seconds

Decision matters more than the score.

## Implementation workflow
- Start with spec/docs/fixtures before networked adapters.
- Unit tests should not require network by default.
- Network adapters should be isolated and mockable.
- Every source adapter must record source_refs and attribution-relevant metadata.
- Use iterative review loops before accepting changes.

## Handoff
Report changed files, test commands, source terms assumptions, and any attribution obligations introduced.
