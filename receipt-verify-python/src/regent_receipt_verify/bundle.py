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
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from . import _b64url_decode, _jwk_public_key, _jws_signature_ok, _keys, verify

BUNDLE_VERSION = "regent-evidence-bundle/1"
CHECKPOINT_TYP = "checkpoint+jwt"


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def norm_hex(h: str | None) -> str:
    h = (h or "").lower()
    return h[2:] if h.startswith("0x") else h


def merkle_root_from(leaf: str, proof: list[str], index: int) -> str:
    cur = leaf
    for sib in proof:
        cur = _sha256_hex(cur + sib) if index % 2 == 0 else _sha256_hex(sib + cur)
        index //= 2
    return cur


def _verify_jws(token: str, jwks: Any, *, typ: str) -> tuple[bool, dict[str, Any], dict[str, Any], str | None, str | None]:
    """(ok, header, claims, kid, error) for a compact RS256 JWS against a JWKS."""
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return False, {}, {}, None, "not a compact JWS"
    try:
        header = json.loads(_b64url_decode(parts[0]))
        claims = json.loads(_b64url_decode(parts[1]))
        sig = _b64url_decode(parts[2])
    except Exception as exc:  # noqa: BLE001
        return False, {}, {}, None, f"cannot decode: {exc}"
    if header.get("typ") != typ:
        return False, header, claims, header.get("kid"), f"typ is '{header.get('typ')}', expected '{typ}'"
    if header.get("alg") != "RS256":
        return False, header, claims, header.get("kid"), f"alg is '{header.get('alg')}', expected RS256"
    kid = header.get("kid")
    signed = f"{parts[0]}.{parts[1]}".encode("ascii")
    for k in _keys(jwks):
        if k.get("kty") != "RSA" or (kid and k.get("kid") != kid):
            continue
        try:
            if _jws_signature_ok("RS256", _jwk_public_key(k), signed, sig):
                return True, header, claims, k.get("kid"), None
        except Exception:  # noqa: BLE001
            continue
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
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid, "decision_id": self.decision_id,
            "events": [{**e.__dict__, "ok": e.ok} for e in self.events],
            "receipt_valid": self.receipt_valid, "receipt_anchored": self.receipt_anchored,
            "receipt_claims": self.receipt_claims, "links_ok": self.links_ok,
            "rpc_ok": self.rpc_ok, "rpc_checks": self.rpc_checks,
            "errors": self.errors, "warnings": self.warnings,
        }


def _check_event(e: dict[str, Any], checkpoint_jwks: Any, tsa_roots: Any = None) -> EventResult:
    r = EventResult(event_id=str(e.get("event_id")), event_type=e.get("event_type"))
    payload, canonical, ph = e.get("payload"), e.get("payload_canonical"), str(e.get("payload_hash") or "")
    # 1. canonical bytes
    if not isinstance(canonical, str) or not ph:
        r.canonical_ok = False
        r.errors.append("payload_canonical or payload_hash missing")
    else:
        hash_ok = norm_hex(ph) == _sha256_hex(canonical)
        try:
            parse_ok = json.loads(canonical) == payload
        except ValueError:
            parse_ok = False
        r.canonical_ok = hash_ok and parse_ok
        if not hash_ok:
            r.errors.append("sha256(payload_canonical) != payload_hash")
        if not parse_ok:
            r.errors.append("payload_canonical does not parse to payload")
    batch = e.get("batch")
    if not batch:
        r.errors.append("event is not in a sealed batch yet")
        return r
    r.seq, r.chain_tx = batch.get("seq"), batch.get("chain_tx")
    # 2. batch proof
    try:
        root = merkle_root_from(ph, list(batch.get("merkle_proof") or []), int(batch.get("merkle_index") or 0))
        r.merkle_ok = norm_hex(root) == norm_hex(batch.get("root"))
    except Exception as exc:  # noqa: BLE001
        r.merkle_ok = False
        r.errors.append(f"merkle proof unreadable: {exc}")
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
            if str(c.get("batch_id")) != str(batch.get("batch_id")):
                mism.append("batch_id")
            if c.get("seq") != batch.get("seq"):
                mism.append("seq")
            if norm_hex(c.get("root")) != norm_hex(batch.get("root")):
                mism.append("root")
            if c.get("head") and batch.get("chain_head") and norm_hex(c.get("head")) != norm_hex(batch.get("chain_head")):
                mism.append("head")
            if c.get("chain_tx") and batch.get("chain_tx") and c.get("chain_tx") != batch.get("chain_tx"):
                mism.append("chain_tx")
            r.checkpoint_ok = not mism
            if mism:
                r.errors.append("checkpoint does not describe this batch: " + ", ".join(mism))
    # 4. epoch
    ep = e.get("epoch")
    if ep:
        try:
            er = merkle_root_from(norm_hex(batch.get("root")), list(ep.get("proof") or []), int(ep.get("leaf_index") or 0))
            r.epoch_ok = norm_hex(er) == norm_hex(ep.get("root"))
        except Exception as exc:  # noqa: BLE001
            r.epoch_ok = False
            r.errors.append(f"epoch proof unreadable: {exc}")
        if r.epoch_ok is False and "epoch proof does not reach the epoch root" not in r.errors:
            r.errors.append("epoch proof does not reach the epoch root")
        # 4b. RFC 3161: the TSA's clock over the same root, checked offline
        if ep.get("tsa_token_b64"):
            from .tsa import verify_token
            try:
                token = base64.b64decode(ep["tsa_token_b64"])
                tr = verify_token(token, bytes.fromhex(norm_hex(ep.get("root"))), roots=tsa_roots)
            except Exception as exc:  # noqa: BLE001
                r.tsa_ok = False
                r.errors.append(f"rfc3161: token unreadable: {exc}")
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
    for e in events:
        b = e.get("batch") or {}
        if b.get("checkpoint") and b.get("seq") is not None:
            seq = int(b["seq"])
            if tokens.setdefault(seq, b["checkpoint"]) != b["checkpoint"]:
                msg = f"conflicting checkpoints for seq {seq} inside the bundle"
                if msg not in errors:
                    errors.append(msg)
                continue
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


def verify_bundle(bundle: dict[str, Any], *, receipt_jwks: Any = None, checkpoint_jwks: Any = None,
                  rpc: str | None = None, now: float | None = None, tsa_roots: Any = None) -> BundleResult:
    """`tsa_roots`: certificates to trust for RFC 3161 tokens on epochs (None = the packaged
    DigiCert and Sectigo roots; a list of cryptography Certificate objects to use your own)."""
    res = BundleResult(decision_id=bundle.get("decision_id"))
    if bundle.get("bundle_version") != BUNDLE_VERSION:
        res.errors.append(f"unknown bundle_version '{bundle.get('bundle_version')}'")
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
            if named and str(named) != str(res.decision_id):
                res.errors.append(f"{e.get('event_id')}: names decision {named}, this bundle is for {res.decision_id}")
    seen_ids: set[str] = set()
    for e in events:
        eid = str(e.get("event_id"))
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
        latest = max(receipts, key=lambda e: int((e.get("payload") or {}).get("attempt") or 1))
        res.warnings.append(
            f"{len(receipts)} receipts in the trail (attempts "
            + ", ".join(str((e.get('payload') or {}).get('attempt') or 1) for e in receipts)
            + f"); the current one is {latest.get('event_id')} — earlier receipts are history, not the decision's state")
    # 5. receipt
    rec = bundle.get("receipt")
    if rec and rec.get("token"):
        if rk is None:
            res.receipt_valid = None
            res.warnings.append("receipt present but no receipt JWKS (bundle or --jwks); receipt not verified")
        else:
            if receipt_jwks is None:
                res.warnings.append("receipt key taken from the bundle itself; pass --jwks to use a saved one")
            vr = verify(rec["token"], rk, now=now)
            res.receipt_valid = vr.valid
            res.receipt_claims = vr.claims if vr.signature_valid else {}
            res.errors.extend(f"receipt: {x}" for x in vr.errors)
            if vr.signature_valid and res.decision_id and vr.claims.get("decision_id") != res.decision_id:
                res.errors.append("receipt names a different decision than the bundle")
        anchored_in = next((e for e in events if e.get("event_id") == rec.get("event_id")), None)
        if anchored_in is not None:
            inside = (anchored_in.get("payload") or {}).get("receipt")
            ev_ok = next((x.ok for x in res.events if x.event_id == anchored_in.get("event_id")), False)
            res.receipt_anchored = bool(inside == rec["token"] and ev_ok)
            if inside != rec["token"]:
                res.errors.append("receipt token is not the one inside the anchored receipt event")
            elif not ev_ok:
                res.errors.append("receipt event did not verify, so the receipt is not proven anchored")
        else:
            res.receipt_anchored = False
            res.warnings.append("receipt event not in bundle; receipt anchoring not checked")
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
    return res
