"""Verify a Regent evidence bundle offline (`regent-evidence-bundle/1`).

A bundle is one JSON document from `GET …/decisions/{id}/bundle` or `…/audit/events/{id}/bundle`.
For every event it carries the payload, the exact bytes that were hashed, the Merkle proof
to the batch root, Regent's signed checkpoint over that root and its chain position, the
epoch proof and the OpenTimestamps proof, plus the keys. For a decision it also carries
the retained receipt and the receipt issuer's keys.

What is checked, in order, per event:

  1. canonical bytes     sha256(payload_canonical) == payload_hash, and the canonical
                         text parses to the payload (so the bytes are not a decoy)
  2. batch proof         payload_hash → merkle_proof → batch.root (sha256 over the
                         concatenated hex strings, odd node paired with itself)
  3. checkpoint          RS256 JWS, typ checkpoint+jwt, against the checkpoint JWKS;
                         its batch_id, seq, root and head must be the batch's
  4. epoch proof         norm(batch.root) → epoch.proof → epoch.root
  5. receipt             the retained receipt verifies (receipt JWKS), names the
                         bundle's decision, and is byte-for-byte the one inside the
                         anchored receipt event — so the receipt itself is anchored

Across events: checkpoints of consecutive batches link (prev_head of N == head of N-1).

Optionally, with an RPC endpoint: the append transaction of each batch is fetched and
must have succeeded and carry the batch root in an instruction to the audit program; the
same for the epoch's anchor transaction. That is the step that needs no trust in Regent
at all.

Keys: by default the JWKS embedded in the bundle are used. Pass the JWKS you saved
earlier to trust those instead — a bundle that ships its own keys proves consistency,
not provenance.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from . import _keys, verify
from .approval import PINS_REFUSED, VERIFIES_SIGNATURE, ApprovalResult, summary, verify_approval
from .strict import _SAFE_INT, Malformed, _int, _same, compact_jws, pem_certificates, rs256_ok, show

BUNDLE_VERSION = "regent-evidence-bundle/1"
CHECKPOINT_TYP = "checkpoint+jwt"


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def norm_hex(h: Any) -> str:
    h = h.lower() if isinstance(h, str) else ""
    return h[2:] if h.startswith("0x") else h


def _text(v: Any) -> str | None:
    """A non-empty string, or None: what "is it there" means for an optional text field."""
    return v if isinstance(v, str) and v else None


def _whole(v: Any) -> int | None:
    """An integer a double holds exactly (1 and 1.0 are the same JSON number), or None."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf")) or not v.is_integer()):
        return None
    return int(v) if abs(v) <= _SAFE_INT else None


# ── the shape of a bundle: every field this program reads has one type ──────────────────
# s = string, i = integer, o = object, ls = list of strings; "?" = may be null or absent.
_TOP = {"bundle_version": "s?", "decision_id": "s?", "keys": "o?", "programs": "o?"}
_EVENT = {"event_id": "s", "event_type": "s?", "payload": "o?", "payload_canonical": "s?", "payload_hash": "s?",
          "batch": "o?", "epoch": "o?"}
_BATCH = {"batch_id": "s?", "seq": "i?", "root": "s?", "merkle_index": "i?", "merkle_proof": "ls?", "chain_tx": "s?",
          "chain_head": "s?", "legacy_anchor_tx": "s?", "checkpoint": "s?"}
_EPOCH = {"epoch_index": "i?", "proof": "ls?", "leaf_index": "i?", "root": "s?", "tx": "s?", "tsa_token_b64": "s?"}
_KINDS = {"s": "a string", "i": "an integer", "o": "an object", "ls": "a list of strings"}
_MAX_EVENTS = 10_000
_MAX_LABEL = 128


def _is(kind: str, v: Any) -> bool:
    if kind == "s":
        return isinstance(v, str)
    if kind == "i":
        return _whole(v) is not None
    if kind == "o":
        return isinstance(v, dict)
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _fields(obj: dict[str, Any], spec: dict[str, str], where: str) -> None:
    for name, kind in spec.items():
        v = obj.get(name)
        if v is None:
            if kind.endswith("?"):
                continue
            raise Malformed(f"{where}{name} is missing")
        if not _is(kind.rstrip("?"), v):
            raise Malformed(f"{where}{name} must be {_KINDS[kind.rstrip('?')]}")
        for text in ([v] if isinstance(v, str) else v if isinstance(v, list) else []):
            try:
                text.encode("utf-8")  # a lone surrogate is not text: it cannot be hashed or compared
            except UnicodeEncodeError as exc:
                raise Malformed(f"{where}{name} is not valid text") from exc


def _label(v: Any, where: str) -> None:
    """Identifiers are short. A long one is not an identifier, it is room to write in."""
    if isinstance(v, str) and len(v) > _MAX_LABEL:
        raise Malformed(f"{where} is longer than {_MAX_LABEL} characters")


def _shape(bundle: Any) -> None:
    """Raise Malformed unless the bundle is of the shape the format defines. Two programs
    that coerce a wrong type differently would give two answers for one file; neither
    coerces, both refuse."""
    if not isinstance(bundle, dict):
        raise Malformed("it is not an object")
    _fields(bundle, _TOP, "")
    _label(bundle.get("decision_id"), "decision_id")
    if isinstance(bundle.get("programs"), dict):
        _fields(bundle["programs"], {"audit_anchor": "s?"}, "programs.")
    events = bundle.get("events")
    if events is None:
        return
    if not isinstance(events, list):
        raise Malformed("events must be a list")
    if len(events) > _MAX_EVENTS:
        raise Malformed(f"more than {_MAX_EVENTS} events")
    for i, e in enumerate(events):
        if not isinstance(e, dict):
            raise Malformed(f"events[{i}] must be an object")
        _fields(e, _EVENT, f"events[{i}].")
        _label(e["event_id"], f"events[{i}].event_id")
        _label(e.get("event_type"), f"events[{i}].event_type")
        if isinstance(e.get("batch"), dict):
            _fields(e["batch"], _BATCH, f"events[{i}].batch.")
        if isinstance(e.get("epoch"), dict):
            _fields(e["epoch"], _EPOCH, f"events[{i}].epoch.")


def _refuse_constant(name: str) -> Any:
    raise ValueError("NaN and Infinity are not JSON")


def _parses_to(canonical: str, payload: Any) -> bool:
    """The canonical string says what the payload shown beside it says (JSON equality,
    numbers by their value as a double, nesting up to 64)."""
    try:
        parsed = json.loads(canonical, parse_constant=_refuse_constant, parse_int=_int)
    except (ValueError, RecursionError):
        return False
    return _same(parsed, payload)


_B64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def merkle_root_from(leaf: str, proof: list[str], index: int) -> str:
    cur = leaf
    for sib in proof:
        cur = _sha256_hex(cur + sib) if index % 2 == 0 else _sha256_hex(sib + cur)
        index //= 2
    return cur


def _verify_jws(token: Any, jwks: Any, *, typ: str) -> tuple[bool, dict[str, Any], dict[str, Any], str | None, str | None]:
    """(ok, header, claims, kid, error) for a compact RS256 JWS against a JWKS."""
    try:
        header, claims, sig, signed = compact_jws(token)
    except Malformed as exc:
        text = str(exc)
        return False, {}, {}, None, "not a compact JWS" if text.startswith("not a compact JWS") else f"cannot decode: {text}"
    kid = header.get("kid")
    if header.get("typ") != typ:
        return False, header, claims, kid, f"typ is '{show(header.get('typ'))}', expected '{typ}'"
    if header.get("alg") != "RS256":
        return False, header, claims, kid, f"alg is '{show(header.get('alg'))}', expected RS256"
    for k in _keys(jwks):
        if k.get("kty") != "RSA" or (kid and k.get("kid") != kid):
            continue
        if rs256_ok(k, signed, sig):
            return True, header, claims, k.get("kid") if isinstance(k.get("kid"), str) else None, None
    return False, header, claims, kid, "signature does not verify against the checkpoint key(s)"


@dataclass
class EventResult:
    event_id: str
    event_type: str | None = None
    canonical_ok: bool | None = None
    merkle_ok: bool | None = None
    checkpoint_ok: bool | None = None
    checkpoint_kid: str | None = None
    epoch_ok: bool | None = None
    # RFC 3161: a public TSA's signed time over the epoch root (None = no token in the bundle)
    tsa_ok: bool | None = None
    tsa_time: str | None = None
    tsa_signer: str | None = None
    seq: int | None = None
    chain_tx: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass
class BundleResult:
    valid: bool = False
    decision_id: str | None = None
    events: list[EventResult] = field(default_factory=list)
    receipt_valid: bool | None = None
    receipt_anchored: bool | None = None
    receipt_claims: dict[str, Any] = field(default_factory=dict)
    links_ok: bool | None = None
    rpc_ok: bool | None = None
    rpc_checks: list[dict[str, Any]] = field(default_factory=list)
    # the owner's approval behind the receipt (approval.py); None when the bundle carries
    # none and the receipt names none
    approval: ApprovalResult | None = None
    # "receipt" when a valid receipt for this decision was there to check the approval against,
    # None when there was none (the approval is then reported as not verified)
    approval_anchor: str | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid, "decision_id": self.decision_id,
            "events": [{**e.__dict__, "ok": e.ok} for e in self.events],
            "receipt_valid": self.receipt_valid, "receipt_anchored": self.receipt_anchored,
            "receipt_claims": self.receipt_claims, "links_ok": self.links_ok,
            "rpc_ok": self.rpc_ok, "rpc_checks": self.rpc_checks,
            "approval": self.approval.to_dict() if self.approval is not None else None,
            "approval_anchor": self.approval_anchor,
            "errors": self.errors, "warnings": self.warnings,
        }


def _check_event(e: dict[str, Any], checkpoint_jwks: Any, tsa_roots: Any = None) -> EventResult:
    r = EventResult(event_id=e["event_id"], event_type=e.get("event_type"))
    payload, canonical, ph = e.get("payload"), e.get("payload_canonical"), e.get("payload_hash") or ""
    # 1. canonical bytes
    if not isinstance(canonical, str) or not ph:
        r.canonical_ok = False
        r.errors.append("payload_canonical or payload_hash missing")
    else:
        hash_ok = norm_hex(ph) == _sha256_hex(canonical)
        parse_ok = _parses_to(canonical, payload)
        r.canonical_ok = hash_ok and parse_ok
        if not hash_ok:
            r.errors.append("sha256(payload_canonical) != payload_hash")
        if not parse_ok:
            r.errors.append("payload_canonical does not parse to payload")
    batch = e.get("batch")
    if not batch:
        r.errors.append("event is not in a sealed batch yet")
        return r
    r.seq, r.chain_tx = _whole(batch.get("seq")), batch.get("chain_tx")
    # 2. batch proof
    root = merkle_root_from(ph, batch.get("merkle_proof") or [], _whole(batch.get("merkle_index")) or 0)
    r.merkle_ok = norm_hex(root) == norm_hex(batch.get("root"))
    if r.merkle_ok is False and not r.errors:
        r.errors.append("merkle proof does not reach the batch root")
    # 3. checkpoint
    cp = batch.get("checkpoint")
    if not cp:
        r.checkpoint_ok = None
        r.errors.append("batch has no signed checkpoint yet")
    else:
        ok, _h, c, kid, err = _verify_jws(cp, checkpoint_jwks, typ=CHECKPOINT_TYP)
        r.checkpoint_kid = kid
        if not ok:
            r.checkpoint_ok = False
            r.errors.append(f"checkpoint: {err}")
        else:
            mism = []
            if not _same(c.get("batch_id"), batch.get("batch_id")):
                mism.append("batch_id")
            if not _same(c.get("seq"), batch.get("seq")):
                mism.append("seq")
            if norm_hex(c.get("root")) != norm_hex(batch.get("root")):
                mism.append("root")
            if _text(c.get("head")) and _text(batch.get("chain_head")) and norm_hex(c.get("head")) != norm_hex(batch.get("chain_head")):
                mism.append("head")
            if _text(c.get("chain_tx")) and _text(batch.get("chain_tx")) and c.get("chain_tx") != batch.get("chain_tx"):
                mism.append("chain_tx")
            r.checkpoint_ok = not mism
            if mism:
                r.errors.append("checkpoint does not describe this batch: " + ", ".join(mism))
    # 4. epoch
    ep = e.get("epoch")
    if ep:
        er = merkle_root_from(norm_hex(batch.get("root")), ep.get("proof") or [], _whole(ep.get("leaf_index")) or 0)
        r.epoch_ok = norm_hex(er) == norm_hex(ep.get("root"))
        if r.epoch_ok is False and "epoch proof does not reach the epoch root" not in r.errors:
            r.errors.append("epoch proof does not reach the epoch root")
        # 4b. RFC 3161: the TSA's clock over the same root, checked offline
        if ep.get("tsa_token_b64"):
            from .tsa import verify_token
            try:
                if not _B64.fullmatch(ep["tsa_token_b64"]) or not re.fullmatch(r"[0-9a-f]{64}", norm_hex(ep.get("root"))):
                    raise ValueError("not base64, or the epoch root is not 32 bytes of hex")
                token = base64.b64decode(ep["tsa_token_b64"], validate=True)
                tr = verify_token(token, bytes.fromhex(norm_hex(ep.get("root"))), roots=tsa_roots)
            except Exception:  # noqa: BLE001
                r.tsa_ok = False
                r.errors.append("rfc3161: token unreadable")
            else:
                r.tsa_ok = tr.ok
                r.tsa_signer = tr.signer
                r.tsa_time = tr.gen_time.isoformat().replace("+00:00", "Z") if tr.gen_time else None
                r.errors.extend(f"rfc3161: {x}" for x in tr.errors)
    return r


def _check_links(events: list[dict[str, Any]], checkpoint_jwks: Any) -> tuple[bool | None, list[str]]:
    """Checkpoints of consecutive batches must chain: prev_head(N) == head(N-1)."""
    by_seq: dict[int, dict[str, Any]] = {}
    tokens: dict[int, str] = {}
    errors: list[str] = []
    conflicting: set[int] = set()
    for e in events:
        b = e.get("batch") or {}
        seq = _whole(b.get("seq"))
        if b.get("checkpoint") and seq is not None:
            if tokens.setdefault(seq, b["checkpoint"]) != b["checkpoint"]:
                if seq not in conflicting:
                    conflicting.add(seq)
                    errors.append(f"conflicting checkpoints for seq {seq} inside the bundle")
                continue
            if seq in by_seq:
                continue  # the same checkpoint again: already read
            ok, _h, c, _k, _err = _verify_jws(b["checkpoint"], checkpoint_jwks, typ=CHECKPOINT_TYP)
            if ok:
                by_seq[seq] = c
    seqs = sorted(by_seq)
    checked = False
    for a, b in zip(seqs, seqs[1:], strict=False):
        if b == a + 1:
            checked = True
            if norm_hex(by_seq[b].get("prev_head")) != norm_hex(by_seq[a].get("head")):
                errors.append(f"checkpoint {b} prev_head does not equal checkpoint {a} head")
    return (not errors) if checked else None, errors


# ── optional: the public network ────────────────────────────────────────────

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    out = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + out


def _rpc(url: str, method: str, params: list[Any]) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read()).get("result")


def check_tx_carries_root(rpc_url: str, signature: str, program_id: str, root_hex: str) -> dict[str, Any]:
    """Fetch the transaction and look for the 32 root bytes in an instruction to the audit
    program. Works for chain appends, epoch anchors and the legacy per-batch anchor alike."""
    out: dict[str, Any] = {"tx": signature, "found": False, "succeeded": None, "root_in_instruction": False}
    try:
        res = _rpc(rpc_url, "getTransaction", [signature, {"encoding": "json", "maxSupportedTransactionVersion": 0}])
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"rpc: {exc}"
        return out
    if not res:
        out["error"] = "transaction not found"
        return out
    out["found"] = True
    out["succeeded"] = (res.get("meta") or {}).get("err") is None
    msg = (res.get("transaction") or {}).get("message") or {}
    keys = list(msg.get("accountKeys") or [])
    want = bytes.fromhex(norm_hex(root_hex))
    for ix in msg.get("instructions") or []:
        try:
            if keys[int(ix.get("programIdIndex"))] != program_id:
                continue
            if want in b58decode(ix.get("data") or ""):
                out["root_in_instruction"] = True
                break
        except Exception:  # noqa: BLE001
            continue
    out["ok"] = bool(out["succeeded"] and out["root_in_instruction"])
    return out


def verify_bundle(bundle: Any, *, receipt_jwks: Any = None, checkpoint_jwks: Any = None,
                  rpc: str | None = None, now: float | None = None, tsa_roots: Any = None,
                  approver_keys: list[str] | None = None, origins: list[str] | None = None,
                  rp_ids: list[str] | None = None) -> BundleResult:
    """`tsa_roots`: the roots to trust for RFC 3161 tokens on epochs, in place of the packaged
    DigiCert and Sectigo roots (None = the packaged ones): PEM text (str or bytes),
    cryptography Certificate objects, or a list of those.
    Never raises: whatever is handed in, the answer is a result, and a file that is not a
    bundle is an INVALID one."""
    try:
        roots = _roots(tsa_roots)
    except _BadRoots as exc:
        res = BundleResult(decision_id=bundle.get("decision_id") if isinstance(bundle, dict) and isinstance(bundle.get("decision_id"), str)
                           else None, errors=[str(exc)])
    else:
        res = _verify_any(bundle, receipt_jwks=receipt_jwks, checkpoint_jwks=checkpoint_jwks, rpc=rpc, now=now,
                          tsa_roots=roots, approver_keys=approver_keys, origins=origins, rp_ids=rp_ids)
    if not VERIFIES_SIGNATURE and any(x is not None for x in (approver_keys, origins, rp_ids)) and PINS_REFUSED not in res.errors:
        # a requirement this version cannot enforce is refused on every path, a malformed bundle's included
        res.errors.append(PINS_REFUSED)
        res.valid = False
    return res


class _BadRoots(ValueError):
    pass


def _roots(tsa_roots: Any) -> Any:
    """Roots to trust for RFC 3161 tokens, read the same way in both languages: None for the
    packaged roots; else PEM text (str or bytes), a certificate, or a list of those. Every
    certificate block of every item must read, and every item must hold one: a root list
    with something unusable in it is refused, not trimmed."""
    if tsa_roots is None:
        return None
    from cryptography import x509

    items = list(tsa_roots) if isinstance(tsa_roots, (list, tuple)) else [tsa_roots]
    out: list[Any] = []
    for i, item in enumerate(items):
        if isinstance(item, x509.Certificate):
            out.append(item)
            continue
        if isinstance(item, (bytes, bytearray)):
            try:
                item = bytes(item).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise _BadRoots(f"tsa roots: item {i} holds no usable certificate") from exc
        if not isinstance(item, str):
            raise _BadRoots(f"tsa roots: item {i} is neither PEM text nor a certificate")
        try:
            for der in pem_certificates(item):
                out.append(x509.load_der_x509_certificate(der))
        except (Malformed, ValueError) as exc:
            raise _BadRoots(f"tsa roots: item {i} holds no usable certificate") from exc
    return out


def _verify_any(bundle: Any, **kw: Any) -> BundleResult:
    try:
        _shape(bundle)
    except Malformed as exc:
        return BundleResult(errors=[f"bundle is malformed: {exc}"])
    except Exception as exc:  # noqa: BLE001
        return BundleResult(errors=[f"bundle could not be read ({type(exc).__name__})"])
    try:
        return _verify_bundle(bundle, **kw)
    except Exception as exc:  # noqa: BLE001 — a verifier answers INVALID, it does not crash
        return BundleResult(decision_id=bundle.get("decision_id"), errors=[f"bundle could not be read ({type(exc).__name__})"])


def _verify_bundle(bundle: dict[str, Any], *, receipt_jwks: Any, checkpoint_jwks: Any, rpc: str | None,
                   now: float | None, tsa_roots: Any, approver_keys: Any, origins: Any, rp_ids: Any) -> BundleResult:
    res = BundleResult(decision_id=bundle.get("decision_id"))
    if bundle.get("bundle_version") != BUNDLE_VERSION:
        res.errors.append(f"unknown bundle_version '{show(bundle.get('bundle_version'))}'")
        return res
    keys = bundle.get("keys") or {}
    ck = checkpoint_jwks if checkpoint_jwks is not None else keys.get("checkpoint_jwks")
    rk = receipt_jwks if receipt_jwks is not None else keys.get("receipt_jwks")
    if checkpoint_jwks is None:
        res.warnings.append("checkpoint key taken from the bundle itself; pass --checkpoint-jwks to use a saved one")
    events = list(bundle.get("events") or [])
    if not events:
        res.errors.append("bundle has no events")
        return res
    for e in events:
        er = _check_event(e, ck, tsa_roots)
        res.events.append(er)
        res.errors.extend(f"{er.event_id}: {x}" for x in er.errors)
    res.links_ok, link_errors = _check_links(events, ck)
    res.errors.extend(link_errors)
    # What offline verification binds, and what it cannot (05.11.2026): every event here
    # must be about THIS decision and appear once; a bundle with an event removed or
    # another decision's event pasted in used to verify VALID. Completeness (that no
    # event is missing) is not provable offline: the organization's trail is the record.
    if res.decision_id:
        for e in events:
            named = (e.get("payload") or {}).get("decision_id")
            if named is not None and named != "" and named != res.decision_id:
                said = named if isinstance(named, str) else "(not a string)"
                res.errors.append(f"{e['event_id']}: names decision {said}, this bundle is for {res.decision_id}")
    seen_ids: set[str] = set()
    for e in events:
        eid = e["event_id"]
        if eid in seen_ids:
            res.errors.append(f"{eid}: appears more than once in the bundle")
        seen_ids.add(eid)
    for e in events:
        ep = e.get("epoch") or {}
        if ep and not ep.get("tx") and not ep.get("tsa_token_b64"):
            res.warnings.append(f"{e.get('event_id')}: the epoch root is not anchored in this bundle (no transaction, "
                                "no RFC 3161 token); its proof only ties the batch to a root — pass --rpc or ask for a bundle with the anchor")
            break
    # A decision completed more than once (the provider refused the first call, the
    # agent retried) carries a receipt per attempt; the highest attempt is its state.
    receipts = [e for e in events if e.get("event_type") == "control.decision.receipt"]
    if len(receipts) > 1:
        def attempt(e: dict[str, Any]) -> int:
            return _whole((e.get("payload") or {}).get("attempt")) or 1

        latest = max(receipts, key=attempt)
        res.warnings.append(
            f"{len(receipts)} receipts in the trail (attempts "
            + ", ".join(str(attempt(e)) for e in receipts)
            + f"); the current one is {latest.get('event_id')} — earlier receipts are history, not the decision's state")
    # 5. receipt
    rec = bundle.get("receipt")
    if rec is not None and not isinstance(rec, dict):
        res.errors.append("receipt: it is not an object")
        rec = None
    anchor: dict[str, Any] | None = None   # the only thing an approval may be checked against
    if rec and isinstance(rec.get("token"), str) and rec["token"]:
        if rk is None:
            res.receipt_valid = None
            res.warnings.append("receipt present but no receipt JWKS (bundle or --jwks); receipt not verified")
        else:
            if receipt_jwks is None:
                res.warnings.append("receipt key taken from the bundle itself; pass --jwks to use a saved one")
            try:
                vr = verify(rec["token"], rk, now=now)
            except Exception as exc:  # noqa: BLE001 — a verifier answers INVALID, it does not crash
                vr = None
                res.receipt_valid = False
                res.errors.append(f"receipt: could not be read ({type(exc).__name__})")
            if vr is not None:
                res.receipt_valid = vr.valid
                res.receipt_claims = vr.claims if vr.signature_valid else {}
                res.errors.extend(f"receipt: {x}" for x in vr.errors)
                named = vr.claims.get("decision_id")
                names_this = bool(res.decision_id) and isinstance(named, str) and named == res.decision_id
                if vr.signature_valid and res.decision_id and not names_this:
                    res.errors.append("receipt names a different decision than the bundle")
                # An approval is anchored by a RECEIPT that is valid in full and names THIS
                # decision: not by an allow token, an expired or foreign-issuer token, or
                # another decision's receipt, each of which the receipt key may have signed.
                if vr.valid and vr.kind == "receipt" and names_this:
                    anchor = vr.claims
                    res.approval_anchor = "receipt"
        anchored_in = next((e for e in events if isinstance(rec.get("event_id"), str) and e["event_id"] == rec["event_id"]), None)
        if anchored_in is not None:
            inside = (anchored_in.get("payload") or {}).get("receipt")
            ev_ok = next((x.ok for x in res.events if x.event_id == anchored_in["event_id"]), False)
            same_token = isinstance(inside, str) and inside == rec["token"]
            res.receipt_anchored = bool(same_token and ev_ok)
            if not same_token:
                res.errors.append("receipt token is not the one inside the anchored receipt event")
            elif not ev_ok:
                res.errors.append("receipt event did not verify, so the receipt is not proven anchored")
        else:
            res.receipt_anchored = False
            res.warnings.append("receipt event not in bundle; receipt anchoring not checked")
    # 6. the owner's approval the receipt names (approval.py). The anchor is the claims of a
    # valid receipt for this decision (`anchor` above), and nothing else: an event's id and
    # type are labels beside its payload, not part of what is hashed into the trail, so no
    # event in the bundle may stand in for the receipt (a tenant can have any payload anchored).
    if bundle.get("approval") is not None or (anchor is not None and anchor.get("approval_digest") is not None):
        res.approval = verify_approval(bundle.get("approval"), anchor,
                                       approver_keys=approver_keys, origins=origins, rp_ids=rp_ids)
        if receipt_jwks is None:
            # The receipt's key came from the bundle itself: whoever wrote the bundle could
            # have written the key, the receipt and the approval together. Terms are a finding
            # only under a receipt you can trust, so none are returned, whatever the verdict.
            res.approval.terms = None
            for part in ([res.approval.signed] if res.approval.signed is not None else []) + list(res.approval.changes):
                part.terms = None
        if res.approval.valid is True and receipt_jwks is None:
            # Every check passed against that receipt. That shows the bundle agrees with
            # itself, not that Regent issued any of it.
            res.approval.valid = None
            res.approval.consistent = True
            res.approval.warnings.append("the approval is consistent with the receipt, but the receipt's key came from "
                                         "the bundle itself, so nothing here is verified: pass your saved receipt JWKS")
        res.errors.extend(res.approval.errors)
        res.warnings.extend(res.approval.warnings)
    elif not VERIFIES_SIGNATURE and any(x is not None for x in (approver_keys, origins, rp_ids)):
        # a requirement this version cannot enforce is refused, approval or none
        res.errors.append(PINS_REFUSED)
    # optional: the network
    if rpc:
        program_id = (bundle.get("programs") or {}).get("audit_anchor") or ""
        seen: set[str] = set()
        for e in events:
            b = e.get("batch") or {}
            for sig, root, kind in ((b.get("chain_tx"), b.get("root"), "chain_append"),
                                    (b.get("legacy_anchor_tx"), b.get("root"), "legacy_anchor")):
                if sig and sig not in seen:
                    seen.add(sig)
                    res.rpc_checks.append({"kind": kind, "seq": b.get("seq"), **check_tx_carries_root(rpc, sig, program_id, root)})
            ep = e.get("epoch") or {}
            if ep.get("tx") and ep["tx"] not in seen:
                seen.add(ep["tx"])
                res.rpc_checks.append({"kind": "epoch_anchor", "epoch_index": ep.get("epoch_index"),
                                       **check_tx_carries_root(rpc, ep["tx"], program_id, ep.get("root") or "")})
        res.rpc_ok = bool(res.rpc_checks) and all(c.get("ok") for c in res.rpc_checks)
        if res.rpc_checks and not res.rpc_ok:
            res.errors.append("on-chain check failed for at least one transaction")
    res.valid = not res.errors and all(x.ok for x in res.events)
    if res.approval is not None:
        # last, so that the one line a person reads first agrees with everything above it
        res.approval.verdict, res.approval.why = summary(res.approval, anchored=anchor is not None,
                                                         pinned=receipt_jwks is not None, bundle_valid=res.valid)
    return res
