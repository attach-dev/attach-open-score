# Reason-code taxonomy

Status: v0 draft
License: Apache-2.0

Reason codes explain why Attach Open Score returned a decision. Codes are stable public contract values; messages may be improved over time.

## Severity

- `INFO`: explains benign or contextual data.
- `LOW`: weak signal; normally no blocking effect alone.
- `MEDIUM`: meaningful risk or uncertainty; often ASK.
- `HIGH`: strong risk; often ASK or DENY depending on confidence.
- `CRITICAL`: high-confidence dangerous condition; normally DENY.

## Decision effects

- `ALLOW`: supports allowing the package.
- `ASK`: should surface to human/team policy.
- `DENY`: should block under default enforcement.
- `UNKNOWN`: prevents reliable decision.
- `NONE`: informational only.

## v0 codes

### Vulnerability/advisory

| Code | Severity | Default effect | Meaning |
|---|---|---|---|
| `KNOWN_MALICIOUS_PACKAGE` | CRITICAL | DENY | Allowed public source identifies the package/version as malicious. |
| `KNOWN_VULNERABILITY_CRITICAL` | CRITICAL | DENY | Evaluated version is affected by critical known vulnerability. |
| `KNOWN_VULNERABILITY_HIGH` | HIGH | ASK | Evaluated version is affected by high-severity known vulnerability. |
| `KNOWN_VULNERABILITY_MODERATE` | MEDIUM | ASK | Evaluated version is affected by moderate known vulnerability. |
| `NO_KNOWN_VULNERABILITIES` | INFO | NONE | Checked allowed vulnerability sources found no matching advisory. |

### Package/version freshness

| Code | Severity | Default effect | Meaning |
|---|---|---|---|
| `PACKAGE_TOO_NEW` | MEDIUM | ASK | Package first publish time is below policy age threshold. |
| `VERSION_TOO_NEW` | MEDIUM | ASK | Version publish time is below policy age threshold. |
| `PACKAGE_UNPUBLISHED_OR_YANKED` | HIGH | ASK | Package/version appears yanked, unpublished, or removed. |
| `DEPRECATED_PACKAGE` | MEDIUM | ASK | Registry metadata marks package/version deprecated. |

### Install/artifact behavior

| Code | Severity | Default effect | Meaning |
|---|---|---|---|
| `INSTALL_SCRIPT_PRESENT` | MEDIUM | ASK | Package has install/lifecycle/native build script. |
| `SUSPICIOUS_INSTALL_SCRIPT` | HIGH | ASK | Script contains high-risk deterministic markers. |
| `SUSPICIOUS_BINARY_ARTIFACT` | HIGH | ASK | Package contains unexpected binary or executable artifact. |
| `ARTIFACT_DIGEST_MISMATCH` | CRITICAL | DENY | Artifact digest does not match expected source/registry metadata. |

### Identity and ecosystem risk

| Code | Severity | Default effect | Meaning |
|---|---|---|---|
| `POSSIBLE_TYPOSQUAT` | HIGH | ASK | Name resembles a popular package or protected namespace. |
| `DEPENDENCY_CONFUSION_RISK` | HIGH | ASK | Package identity overlaps with likely private/internal namespace risk. |
| `UNRESOLVED_PACKAGE` | MEDIUM | UNKNOWN | Requested package/version could not be resolved. |
| `UNSUPPORTED_ECOSYSTEM` | MEDIUM | UNKNOWN | Ecosystem is not supported by the current method/profile. |

### Repository/project health

| Code | Severity | Default effect | Meaning |
|---|---|---|---|
| `LOW_REPOSITORY_HEALTH` | MEDIUM | ASK | Repository health signals are weak where package-to-repo mapping is reliable. |
| `REPOSITORY_MAPPING_UNCERTAIN` | LOW | NONE | Package-to-repository mapping is uncertain, so repo signals were down-weighted. |
| `MAINTAINER_ACTIVITY_LOW` | LOW | NONE | Maintainer or release activity appears low; informational in v0. |
| `RELEASE_RECENCY_STALE` | MEDIUM | ASK | Last observed package release is older than the configured stale-release threshold. |
| `RELEASE_RECENCY_FRESH` | INFO/LOW | NONE | Last observed package release is within or near the configured fresh-release window. |

### Source and confidence

| Code | Severity | Default effect | Meaning |
|---|---|---|---|
| `SOURCE_UNAVAILABLE` | MEDIUM | UNKNOWN | Required source was unavailable or timed out. |
| `SOURCE_TERMS_BLOCKED` | HIGH | UNKNOWN | Source terms/licensing block the intended use. |
| `SOURCE_STALE` | MEDIUM | ASK | Source data exceeded TTL or refresh window. |
| `INSUFFICIENT_DATA` | MEDIUM | UNKNOWN | Available evidence is insufficient for a reliable verdict. |
| `CONFLICTING_SOURCE_DATA` | HIGH | ASK | Allowed sources disagree materially. |

## Adding codes

New codes must include:

- stable uppercase snake-case name
- category
- default severity
- default decision effect
- source requirements, if any
- fixture demonstrating the code
- note in `docs/SOURCES.md` if a new source family is introduced

Experimental codes must be prefixed with `X_` and should not be used in public API guarantees.
