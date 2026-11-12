"""Verify a MoltLedger package. Collects ALL issues, never first-fail."""
import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import CanonicalError, jcs
from . import checks as C

DOMAIN_EVENT = b"molt-verify/event/v1\n"
DOMAIN_SIG   = b"molt-verify/event-sig/v1\n"
ZERO_HASH    = "sha256:" + "0" * 64


def event_hash_bytes(ev: dict) -> bytes:
    body = {k: v for k, v in ev.items() if k not in ("hash", "sig")}
    return hashlib.sha256(DOMAIN_EVENT + jcs(body).encode("utf-8")).digest()


def hash_str(digest: bytes) -> str:
    return "sha256:" + digest.hex()


@dataclass
class Issue:
    check: str
    where: str
    message: str

    def to_dict(self):
        return {"check": self.check, "where": self.where, "message": self.message}


@dataclass
class Verdict:
    passed: bool
    issues: list = field(default_factory=list)

    @property
    def check_ids(self) -> set:
        return {i.check for i in self.issues}

    def to_dict(self):
        return {"passed": self.passed, "issues": [i.to_dict() for i in self.issues]}


# ---- schema ---------------------------------------------------------------

_MANIFEST_REQ = {
    "version": int, "package_id": str, "chain_id": str,
    "count": int, "head_hash": str,
}
_EVENT_REQ = {
    "version": int, "chain_id": str, "seq": int, "prev_hash": str,
    "timestamp": int, "actor": str, "action": str, "payload": dict,
    "key_id": str, "hash": str, "sig": str,
}


def _check_schema(obj, req, where, issues):
    for key, typ in req.items():
        if key not in obj:
            issues.append(Issue(C.E_SCHEMA, where, f"missing field {key!r}"))
        elif not isinstance(obj[key], typ) or isinstance(obj[key], bool) and typ is int:
            issues.append(
                Issue(C.E_SCHEMA, where,
                      f"field {key!r} must be {typ.__name__}, got {type(obj[key]).__name__}")
            )


# ---- pipeline -------------------------------------------------------------

def verify_package(pkg_dir, keyring: dict) -> Verdict:
    pkg_dir = Path(pkg_dir)
    issues: list[Issue] = []

    try:
        manifest = json.loads((pkg_dir / "manifest.json").read_text())
    except Exception as e:
        return Verdict(False, [Issue(C.E_SCHEMA, "manifest", f"cannot read: {e}")])

    _check_schema(manifest, _MANIFEST_REQ, "manifest", issues)

    ev_dir = pkg_dir / "events"
    files = sorted(ev_dir.glob("*.json")) if ev_dir.is_dir() else []
    if not files:
        issues.append(Issue(C.E_SCHEMA, "events", "no event files found"))

    events: list[tuple[str, dict]] = []
    for f in files:
        try:
            events.append((f.name, json.loads(f.read_text())))
        except Exception as e:
            issues.append(Issue(C.E_SCHEMA, f.name, f"cannot parse: {e}"))

    for name, ev in events:
        _check_schema(ev, _EVENT_REQ, name, issues)

    # duplicates by seq
    seen: dict[int, str] = {}
    for name, ev in events:
        s = ev.get("seq")
        if not isinstance(s, int):
            continue
        if s in seen:
            issues.append(Issue(C.E_DUPLICATE, name, f"duplicate seq {s} (also {seen[s]})"))
        else:
            seen[s] = name

    # positional order: seq must equal 1..N
    for idx, (name, ev) in enumerate(events, start=1):
        s = ev.get("seq")
        if isinstance(s, int) and s != idx:
            issues.append(Issue(C.E_ORDER, name, f"expected seq {idx}, got {s}"))

    # prev-hash chain
    prev_expected = ZERO_HASH
    for name, ev in events:
        if "seq" not in ev:
            continue
        ph = ev.get("prev_hash")
        if isinstance(ph, str) and ph != prev_expected:
            issues.append(Issue(
                C.E_CHAIN_BROKEN, name,
                f"prev_hash {ph[:23]}... != expected {prev_expected[:23]}..."
            ))
        if isinstance(ev.get("hash"), str):
            prev_expected = ev["hash"]

    # chain_id consistency (manifest vs events)
    m_chain = manifest.get("chain_id")
    for name, ev in events:
        if isinstance(ev.get("chain_id"), str) and ev["chain_id"] != m_chain:
            issues.append(Issue(C.E_CHAIN_BROKEN, name,
                                f"chain_id {ev['chain_id']} != manifest {m_chain}"))

    # per-event: canonical, hash, signature
    for name, ev in events:
        try:
            body = {k: v for k, v in ev.items() if k not in ("hash", "sig")}
            jcs(body)
        except CanonicalError as e:
            issues.append(Issue(C.E_CANON, name, str(e)))
            continue

        digest = event_hash_bytes(ev)
        recomputed = hash_str(digest)
        if ev.get("hash") != recomputed:
            issues.append(Issue(
                C.E_HASH_MISMATCH, name,
                f"stored {ev.get('hash')} != recomputed {recomputed}"
            ))

        kid = ev.get("key_id")
        if not isinstance(kid, str) or kid not in keyring:
            issues.append(Issue(C.E_UNKNOWN_KEY, name, f"key_id {kid!r} not in keyring"))
            continue

        try:
            pub_raw = base64.b64decode(keyring[kid], validate=True)
            pub = Ed25519PublicKey.from_public_bytes(pub_raw)
            sig = base64.b64decode(ev.get("sig", ""), validate=True)
            pub.verify(sig, DOMAIN_SIG + digest)
        except Exception as e:
            issues.append(Issue(
                C.E_SIG_INVALID, name,
                f"signature invalid ({type(e).__name__})"
            ))

    # manifest count / head
    count = manifest.get("count")
    if isinstance(count, int) and count != len(events):
        if count > len(events):
            issues.append(Issue(
                C.E_TRUNCATED, "manifest",
                f"manifest count {count} > {len(events)} events present"
            ))
        else:
            issues.append(Issue(
                C.E_ORDER, "manifest",
                f"manifest count {count} < {len(events)} events present"
            ))

    head = manifest.get("head_hash")
    if events and isinstance(head, str):
        last = events[-1][1].get("hash")
        if last != head:
            issues.append(Issue(
                C.E_MANIFEST_HEAD, "manifest",
                f"head_hash {head} != last event hash {last}"
            ))

    return Verdict(passed=not issues, issues=issues)
