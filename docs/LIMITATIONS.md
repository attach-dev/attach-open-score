# Limitations

Status: v0 draft
License: Apache-2.0

Attach Open Score is a transparent dependency-risk method, not an oracle. It reduces avoidable risk during agent-driven installs; it does not prove that a package is safe.

## What v0 can do

- Surface known vulnerability/malware signals from allowed public/open sources.
- Explain decisions using deterministic reason codes and source references.
- Warn on uncertainty, package newness, install scripts, source staleness, and unsupported ecosystems.
- Provide public, reviewable semantics for Attach Guard and hosted APIs.

## What v0 cannot guarantee

- It cannot detect all malicious packages or zero-days.
- It cannot guarantee package maintainers, repositories, or tarballs have not been compromised after evaluation.
- It cannot replace sandboxing, least-privilege execution, lockfiles, code review, or human judgment.
- It cannot use proprietary vendor scores as hidden labels, calibration targets, or default hosted inputs.
- It cannot safely redistribute upstream datasets unless source terms permit it and attribution is preserved.

## Data limitations

Allowed public sources can be incomplete, stale, rate-limited, unavailable, or inconsistent. Provider failure is represented as uncertainty, not as safety or danger.

Package-to-repository mapping is often ambiguous. Repository-health signals must be down-weighted when the mapping is weak.

Registry metadata may omit publish time, maintainer details, deprecation status, or artifact provenance depending on ecosystem and terms.

## Policy limitations

The same score can map to different enforcement behavior in local development and CI/team settings. This is intentional. Local defaults should avoid fail-closed behavior on unknowns/provider outages; CI may be stricter.

Overrides and allowlists are downstream policy decisions. Attach Open Score should emit the original evidence-based verdict and let enforcement layers record overrides separately.

## Legal/source limitations

This repo documents source posture but does not provide legal advice. If a source's terms are unclear for caching, redistribution, hosted commercial use, public display, or fixture publication, block the adapter/card until reviewed.

## AI/LLM limitation

AI may help summarize or draft docs, but v0 enforcement decisions must be deterministic/rule-based. Do not use an LLM as the primary allow/ask/deny decision engine.
