"""Runs the whole corpus. If a tampered fixture ever passes, we're lying."""
import json
from pathlib import Path

from .verify import verify_package


def run_selftest(root) -> list[tuple]:
    root = Path(root)
    keyring = json.loads((root / "keys.json").read_text())
    problems: list[tuple] = []

    good = verify_package(root / "good", keyring)
    if not good.passed:
        problems.append(("good", "expected PASS, got FAIL", sorted(good.check_ids)))

    for d in sorted((root / "tampered").iterdir()):
        if not d.is_dir():
            continue
        expected = (d / "expected_check.txt").read_text().strip()
        v = verify_package(d, keyring)
        if v.passed:
            problems.append((d.name, "expected FAIL, got PASS", []))
        elif expected not in v.check_ids:
            problems.append((d.name, f"expected {expected}", sorted(v.check_ids)))

    return problems
