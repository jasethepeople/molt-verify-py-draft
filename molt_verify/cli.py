import argparse
import json
import sys
from pathlib import Path

from .generate import generate_all
from .selftest import run_selftest
from .verify import verify_package


def _print_verdict(v, as_json, target_check=None):
    if as_json:
        print(json.dumps(v.to_dict(), indent=2))
    else:
        status = "PASS" if v.passed else "FAIL"
        print(f"{status}  ({len(v.issues)} issue(s))")
        for i in v.issues:
            print(f"  [{i.check}] {i.where}: {i.message}")
    if target_check is not None:
        return 0 if target_check in v.check_ids else 1
    return 0 if v.passed else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="molt-verify")
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="verify a package")
    v.add_argument("package")
    v.add_argument("--keyring", required=True)
    v.add_argument("--json", action="store_true")
    v.add_argument("--check", help="exit 0 iff this check ID appears")

    s = sub.add_parser("selftest", help="run good + tampered corpus")
    s.add_argument("fixtures")
    s.add_argument("--json", action="store_true")

    g = sub.add_parser("generate", help="regenerate fixtures")
    g.add_argument("out")

    a = ap.parse_args(argv)

    if a.cmd == "generate":
        generate_all(a.out)
        print(f"wrote fixtures to {a.out}")
        return 0

    if a.cmd == "selftest":
        problems = run_selftest(a.fixtures)
        if a.json:
            print(json.dumps({"ok": not problems,
                              "problems": [list(p) for p in problems]}, indent=2))
        else:
            if problems:
                print(f"SELFTEST FAILED ({len(problems)} problem(s))")
                for name, why, checks in problems:
                    print(f"  {name}: {why}  checks={checks}")
            else:
                print("SELFTEST PASSED")
        return 0 if not problems else 1

    keyring = json.loads(Path(a.keyring).read_text())
    verdict = verify_package(a.package, keyring)
    return _print_verdict(verdict, a.json, a.check)


if __name__ == "__main__":
    sys.exit(main())
