# Measurement — molt-verify (Python layer-1 draft)

DeepSeek draft from the Nov 11, 2026 MOLT-50 panel feeding (project #1: molt-verify layer 1).
Measured Nov 11, 2026 against the real artifacts (the molt-verify layer-1 bundle and
the real Foundry verifier, `independent-verifier.ts`). The code in this directory is
preserved verbatim as pasted. No bugs were fixed.

## Verdict

**Runs, and is self-consistent — but it verifies only its own fixtures. It is
incompatible with real Foundry packages. Do not ship as-is.**

## What ran

- `SELFTEST PASSED` — good package passes, all ten tampered fixtures fail naming
  their expected check.
- `pytest`: 1 passed.
- Fixtures are byte-identical across two runs (deterministic generation: fixed
  keys, fixed timestamps, fixed payloads).

## The incompatibility (measured against a real package)

The Python verifier was run against a real package built with the actual
MoltLedger (which the real verifier confirms valid). The Python verifier
FAILED it with 6 schema issues, including "no event files found".

The formats differ end to end:

| | This draft | Real Foundry packages |
|---|---|---|
| Event files | `events/*.json` (one file per event) | `events.jsonl` (one JSON object per line) |
| Manifest | `version`, `package_id`, `chain_id`, `count`, `head_hash` | `artifacts`, `agent_pubkeys` |
| Event fields | `chain_id`, `action`, `key_id`, `timestamp` | `pub`, `sig`, `ts`, `type` |
| Hash | `sha256(domain + JCS(body))` with a `"sha256:"` prefix | `sha256(priorHash + stableJson)` bare hex |

This draft verifies only its own fixtures — a parallel format that nothing in
MOLT produces. It does not extract the real verifier; it is a from-scratch
reimplementation in a different format.

## Fixture quality

Only 3 of the 10 tampered fixtures fail with ONLY their expected check. The
other 7 trip extra checks (the selftest asserts the expected check *appears*,
not that it is alone). So "fails naming the right check" is weaker than claimed.

## What is worth folding into the real bundle

- The check-ID table (`E_SCHEMA`, `E_CANON`, `E_HASH_MISMATCH`, `E_CHAIN_BROKEN`,
  `E_ORDER`, `E_DUPLICATE`, `E_SIG_INVALID`, `E_UNKNOWN_KEY`, `E_MANIFEST_HEAD`,
  `E_TRUNCATED`) — the real verifier returns prose reasons and has no stable IDs.
- The negative corpus: one tampered fixture per check, not one total.
- The scope paragraph in the SPEC (what layer 1 proves and does not prove).
- CLI exit codes (0 pass / 1 fail / 2 usage) and `--json` output.

## What this is not

- It is not layer 1. Layer 1 is the TypeScript extraction of the real Foundry
  verifier, which verifies real packages.
- Its RFC 8785 canonicalizer is real (UTF-16 key sort, non-ASCII left alone),
  which is more than can be said for the real verifier's hand-rolled
  "JCS-style" canonicalizer — but the two disagree on non-ASCII strings and
  non-ASCII keys, which is itself a landmine for any second implementation.
