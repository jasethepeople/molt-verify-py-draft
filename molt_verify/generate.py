"""Hermetic, deterministic fixture generator. Never touches the laptop ledger."""
import base64
import hashlib
import json
import shutil
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import checks as C
from .verify import DOMAIN_SIG, ZERO_HASH, event_hash_bytes, hash_str

BASE_TS = 1767225600                       # 2026-01-01T00:00:00Z
CHAIN_ID = hashlib.sha256(b"molt-verify/fixture/chain/v1").hexdigest()
PACKAGE_ID = hashlib.sha256(b"molt-verify/fixture/package/v1").hexdigest()

SEEDS = {
    "k1": hashlib.sha256(b"molt-verify-fixture-k1").digest(),
    "k2": hashlib.sha256(b"molt-verify-fixture-k2").digest(),
}


def public_keyring() -> dict:
    out = {}
    for kid, seed in SEEDS.items():
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        pk = sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        out[kid] = base64.b64encode(pk).decode()
    return out


def _make_event(seq: int, prev: str, key_id: str) -> dict:
    ev = {
        "version": 1, "chain_id": CHAIN_ID, "seq": seq, "prev_hash": prev,
        "timestamp": BASE_TS + seq,
        "actor": "agent-a" if seq % 2 else "agent-b",
        "action": "invoke",
        "payload": {"n": seq, "note": f"event {seq}"},
        "key_id": key_id,
    }
    digest = event_hash_bytes(ev)
    sk = Ed25519PrivateKey.from_private_bytes(SEEDS[key_id])
    ev["hash"] = hash_str(digest)
    ev["sig"] = base64.b64encode(sk.sign(DOMAIN_SIG + digest)).decode()
    return ev


def build_good(pkg_dir: Path) -> None:
    (pkg_dir / "events").mkdir(parents=True, exist_ok=True)
    events, prev = [], ZERO_HASH
    for seq in range(1, 6):
        ev = _make_event(seq, prev, "k1" if seq % 2 else "k2")
        events.append(ev)
        prev = ev["hash"]
    for ev in events:
        (pkg_dir / "events" / f"{ev['seq']:08d}.json").write_text(
            json.dumps(ev, indent=2, sort_keys=True) + "\n"
        )
    manifest = {
        "version": 1, "package_id": PACKAGE_ID, "chain_id": CHAIN_ID,
        "count": len(events), "head_hash": events[-1]["hash"],
        "created_at": BASE_TS + len(events),
        "generator": "molt-verify/fixtures/v1",
    }
    (pkg_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )


# ---- tamper helpers -------------------------------------------------------

def _load(pkg_dir: Path):
    m = json.loads((pkg_dir / "manifest.json").read_text())
    evs = [(f, json.loads(f.read_text()))
           for f in sorted((pkg_dir / "events").glob("*.json"))]
    return m, evs


def _save_manifest(pkg_dir: Path, m: dict) -> None:
    (pkg_dir / "manifest.json").write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")


def _save_events(pkg_dir: Path, evs) -> None:
    for f, _ in evs:
        if f.exists():
            f.unlink()
    for f, ev in evs:
        f.write_text(json.dumps(ev, indent=2, sort_keys=True) + "\n")


def t_schema(pkg_dir):
    _, evs = _load(pkg_dir)
    del evs[2][1]["actor"]
    _save_events(pkg_dir, evs)


def t_canon(pkg_dir):
    _, evs = _load(pkg_dir)
    evs[1][1]["payload"] = {"n": 2.5, "note": "float"}
    _save_events(pkg_dir, evs)


def t_hash(pkg_dir):
    _, evs = _load(pkg_dir)
    evs[2][1]["payload"]["note"] = "tampered"
    _save_events(pkg_dir, evs)


def t_chain(pkg_dir):
    _, evs = _load(pkg_dir)
    evs[3][1]["prev_hash"] = "sha256:" + "ff" * 32
    _save_events(pkg_dir, evs)


def t_order(pkg_dir):
    _, evs = _load(pkg_dir)
    evs[4][1]["seq"] = 7
    _save_events(pkg_dir, evs)


def t_duplicate(pkg_dir):
    _, evs = _load(pkg_dir)
    evs[4][1]["seq"] = 4
    _save_events(pkg_dir, evs)


def t_sig(pkg_dir):
    _, evs = _load(pkg_dir)
    ev = evs[1][1]
    sig = bytearray(base64.b64decode(ev["sig"]))
    sig[-1] ^= 0x01
    ev["sig"] = base64.b64encode(bytes(sig)).decode()
    _save_events(pkg_dir, evs)


def t_unknown_key(pkg_dir):
    _, evs = _load(pkg_dir)
    evs[2][1]["key_id"] = "k9"
    _save_events(pkg_dir, evs)


def t_manifest_head(pkg_dir):
    m, _ = _load(pkg_dir)
    m["head_hash"] = "sha256:" + "ab" * 32
    _save_manifest(pkg_dir, m)


def t_truncated(pkg_dir):
    files = sorted((pkg_dir / "events").glob("*.json"))
    files[-1].unlink()


TAMPERS = [
    ("schema",        t_schema,        C.E_SCHEMA),
    ("canon",         t_canon,         C.E_CANON),
    ("hash",          t_hash,          C.E_HASH_MISMATCH),
    ("chain",         t_chain,         C.E_CHAIN_BROKEN),
    ("order",         t_order,         C.E_ORDER),
    ("duplicate",     t_duplicate,     C.E_DUPLICATE),
    ("sig",           t_sig,           C.E_SIG_INVALID),
    ("unknown_key",   t_unknown_key,   C.E_UNKNOWN_KEY),
    ("manifest_head", t_manifest_head, C.E_MANIFEST_HEAD),
    ("truncated",     t_truncated,     C.E_TRUNCATED),
]


def generate_all(root) -> None:
    root = Path(root)
    if (root / "good").exists():
        shutil.rmtree(root / "good")
    if (root / "tampered").exists():
        shutil.rmtree(root / "tampered")
    root.mkdir(parents=True, exist_ok=True)

    build_good(root / "good")
    (root / "keys.json").write_text(
        json.dumps(public_keyring(), indent=2, sort_keys=True) + "\n"
    )

    tdir = root / "tampered"
    tdir.mkdir()
    for name, fn, expected in TAMPERS:
        dst = tdir / name
        shutil.copytree(root / "good", dst)
        fn(dst)
        (dst / "expected_check.txt").write_text(expected + "\n")


if __name__ == "__main__":
    generate_all(sys.argv[1] if len(sys.argv) > 1 else "fixtures")
