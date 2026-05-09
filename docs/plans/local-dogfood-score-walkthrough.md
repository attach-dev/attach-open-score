# Local dogfood score walkthrough

Status: PR-ready docs plan
Audience: maintainers and local dogfood testers
Scope: public-safe, offline fixture walkthrough for Attach Open Score v0

This walkthrough shows how to inspect the current Attach Open Score fixture verdicts locally and confirm that the repository can represent all four v0 decisions: `ALLOW`, `ASK`, `DENY`, and `UNKNOWN`.

It intentionally uses only files already committed under `fixtures/v0/` and the current offline fixture validator. It does not call hosted services, query real packages, use private package names, copy proprietary vendor output, or change scoring semantics.

## What exists today

Current shipped behavior:

- `fixtures/v0/*.json` are synthetic, public-safe verdict examples.
- `go run ./cmd/attach-open-score --root .` validates the fixture set and prints each fixture path with its decision.
- The full verdict JSON in each fixture includes `decision`, `score`, `confidence`, `reasons`, `source_refs`, `evaluated_at`, `ttl_seconds`, and `limitations`.
- The Go scorer API and `score --input` CLI can produce verdicts from normalized local evidence request JSON.
- There is not yet a public CLI command that scores arbitrary package names or fetches network evidence.

Non-goals for this walkthrough:

- No network calls in this walkthrough; it uses local synthetic fixtures even
  though repository code now includes an isolated OSV adapter.
- No real package evaluation claims.
- No hosted Attach platform behavior.
- No proprietary vendor scores or copied dashboard output.
- No private registry/package/customer data.

## Prerequisites

- Go, for the fixture validator and test suite.
- Python 3, only for small local JSON inspection snippets below. The snippets use the standard library.

## Step 1: validate the fixture verdicts

From the repository root:

```bash
go run ./cmd/attach-open-score --root .
```

Expected decision coverage from the current fixture set:

```text
valid fixtures/v0/allow-clean-synthetic.json ALLOW
valid fixtures/v0/allow-fresh-release-recency.json ALLOW
valid fixtures/v0/allow-near-stale-release-recency.json ALLOW
valid fixtures/v0/ask-new-version-install-script.json ASK
valid fixtures/v0/ask-stale-release-recency.json ASK
valid fixtures/v0/deny-known-critical-vulnerability.json DENY
valid fixtures/v0/unknown-source-unavailable.json UNKNOWN
```

This command is a fixture/schema smoke test. It does not make network calls and
does not score new package names from a registry.

## Step 2: print the local score summary

The current CLI prints fixture decisions, not the numeric score. To inspect the score fields that are already present in the fixture verdict JSON, run:

```bash
python3 - <<'PY'
import json
from pathlib import Path

for path in sorted(Path('fixtures/v0').glob('*.json')):
    verdict = json.loads(path.read_text())
    score = verdict['score'] if verdict['score'] is not None else 'null'
    print(f"{path}: decision={verdict['decision']} score={score} confidence={verdict['confidence']}")
PY
```

Expected output:

```text
fixtures/v0/allow-clean-synthetic.json: decision=ALLOW score=8 confidence=MEDIUM
fixtures/v0/allow-fresh-release-recency.json: decision=ALLOW score=5 confidence=MEDIUM
fixtures/v0/allow-near-stale-release-recency.json: decision=ALLOW score=20 confidence=MEDIUM
fixtures/v0/ask-new-version-install-script.json: decision=ASK score=56 confidence=MEDIUM
fixtures/v0/ask-stale-release-recency.json: decision=ASK score=45 confidence=MEDIUM
fixtures/v0/deny-known-critical-vulnerability.json: decision=DENY score=96 confidence=HIGH
fixtures/v0/unknown-source-unavailable.json: decision=UNKNOWN score=null confidence=LOW
```

Interpretation:

- `ALLOW` means no current policy-blocking signal from the modeled allowed sources. It does not mean the package is safe forever.
- `ASK` means a human or stricter team policy should review the uncertainty or risk signal.
- `DENY` means a high-confidence deny rule matched.
- `UNKNOWN` means there is not enough reliable information to produce a safer verdict.
- `score` is risk-facing: higher means riskier. `null` is valid for insufficient information.

## Step 3: inspect reason codes and provenance

Each non-default verdict should be explainable through reason codes and either `source_refs` or documented deterministic local rules. To print the public-safe explanation trail:

```bash
python3 - <<'PY'
import json
from pathlib import Path

for path in sorted(Path('fixtures/v0').glob('*.json')):
    verdict = json.loads(path.read_text())
    print(f"\n{path} -> {verdict['decision']}")
    for reason in verdict['reasons']:
        refs = ','.join(reason.get('source_ref_ids', [])) or '-'
        print(f"  reason={reason['code']} effect={reason['decision_effect']} severity={reason['severity']} refs={refs}")
    for source in verdict.get('source_refs', []):
        print(f"  source_ref={source['id']} source={source['source']} public_display={source['public_display']}")
PY
```

Use this output to confirm that a fixture does not hide unsupported inputs. The current synthetic fixtures use `example.invalid` URLs and synthetic source names so they remain safe to publish.

## Step 4: dogfood with local-safe data only

The CLI now supports explicit offline scoring from normalized local evidence request JSON via `score --input`. That input is not a fixture verdict and must use the v0 request contract: top-level `package` plus one or more `evidence` items, with source-backed reasons preserving matching `source_ref` metadata. Unknown fields, ignored `mode`, and verdict-shaped fixture files are rejected so typos do not silently score as empty evidence; experimental `X_*` reasons with blocking/non-informational effects must carry source-ref provenance.

For local dogfood, use only public-safe inputs:

1. Read the existing synthetic fixtures as canonical examples of the v0 output shape.
2. Create a temporary, uncommitted copy of a fixture and change only synthetic
   fields such as package name, version, reason messages, and `details` values.
   Keep identity fields consistent with each other: if `name` or `version`
   changes, update the matching `purl` and any related synthetic source IDs/URLs
   too.
3. Validate the temporary copy by placing it under a temporary repo-shaped directory with `fixtures/v0/` and running `go run ./cmd/attach-open-score --root <temp-root>`.

Temporary local data must remain public-safe if it is committed later:

- Use synthetic package identities unless real-package source terms and attribution are reviewed.
- Use allowed source families from `docs/SOURCES.md`.
- Preserve `source_refs` when a reason depends on external-style data.
- Do not include private package names, customer manifests, hosted cache internals, secrets, proprietary vendor outputs, or copied vendor scores.
- Do not infer safety from provider failure; represent unavailable data as `UNKNOWN`/`ASK` uncertainty.

## Step 5: run the offline test suite

Before sending a change, run:

```bash
go test ./...
```

The default tests are expected to be offline and deterministic. Network adapter tests, when added later, should be opt-in and skipped by default.

## Review checklist

- The walkthrough states that current fixtures are synthetic and not real package evaluations.
- Commands are offline and reproducible from the repository root.
- Decision/score examples match `fixtures/v0/*.json`.
- The document does not introduce proprietary vendor names beyond the repository's existing source-policy ban language.
- Source/provenance language stays aligned with `docs/SOURCES.md` and `docs/SCORE_SCHEMA.md`.
- No scoring semantics or enforcement thresholds changed.

## Follow-up candidates

These remain out of scope for this local walkthrough:

- Add a first-class CLI command to print fixture summaries without a Python snippet.
- Add richer `score --input` examples once the input evidence format is stable.
- Add opt-in network adapters after source terms, attribution, tests, and fixture policy are reviewed.
