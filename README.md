> **DEEPSEEK DRAFT — DO NOT SHIP AS-IS**
>
> This is a DeepSeek draft from the Nov 11, 2026 MOLT-50 panel feeding (project #1: molt-verify layer 1). It was measured against the real artifacts and is NOT the production implementation. Do not ship as-is — read MEASUREMENT.md first.
>
> One-line verdict: Runs and is self-consistent, but verifies only its own fixtures — it is incompatible with real Foundry packages.

# molt-verify (layer 1, Python draft)

Standalone verifier + CLI + fixture generator for MoltLedger packages. Offline.
Deterministic.

## Run it

    pip install -e .
    molt-verify generate fixtures
    molt-verify selftest fixtures

Expected: `SELFTEST PASSED` — good passes, every tampered fixture fails
naming its check.

## Verify a package

    molt-verify verify path/to/pkg --keyring fixtures/keys.json
    molt-verify verify path/to/pkg --keyring fixtures/keys.json --json
    molt-verify verify path/to/pkg --keyring fixtures/keys.json --check E_SIG_INVALID

Exit codes: 0 pass, 1 fail, 2 usage.

## What layer 1 does not prove

A full rewrite from genesis passes layer 1. That is what layer 2
(anchoring) is for. Say so out loud.

## Layout

    molt_verify/        verifier, CLI, fixture generator, selftest
    tests/              selftest corpus test
    pyproject.toml      package metadata
