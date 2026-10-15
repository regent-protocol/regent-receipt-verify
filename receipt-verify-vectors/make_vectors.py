"""Regenerate vectors.json with the REAL issuer (api_control.engine.tokens.TokenIssuer) and
the real canonical forms (regent_schemas.mandate_terms / policy_terms), so both verifier
packages are tested against exactly what production signs.

Run with the api-control venv:  apps/api-control/.venv/bin/python packages/receipt-verify-vectors/make_vectors.py
The RSA key is generated fresh each run and NOT stored: only the JWKS (public) is."""
import json
import os
import sys
from datetime import UTC, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "apps/api-control/src"))
sys.path.insert(0, os.path.join(ROOT, "packages/shared-schemas/src"))

import jwt as pyjwt  # noqa: E402
from api_control.engine.gate import canonical_args_hash  # noqa: E402
from api_control.engine.tokens import TokenIssuer  # noqa: E402
from regent_schemas import mandate_terms, policy_terms  # noqa: E402

issuer = TokenIssuer(ttl_seconds=60)
other = TokenIssuer(ttl_seconds=60)
ORG = "aaa95cdf-7459-4d55-ab7d-0d59f99d3bf6"

request = {"tool": "stripe", "action": "charge.create", "resource": None,
           "args": {"amount": 400, "currency": "KZT", "customer": "cus_42", "memo": "Ünïcode ok"}}
ah = canonical_args_hash(request["tool"], request["action"], request["resource"], request["args"])

snapshot = {"mandate_id": "9d1c3e2b-1111-4a4a-8b8b-000000000001", "version": 2, "agent_id": "agent_abc", "owner_id": "owner-1",
            "currency": "KZT", "settlement_chain": "solana", "status": "active", "per_tx_limit": "500.000000",
            "daily_limit": "1500.000000", "monthly_limit": None, "per_entity_limit": None, "entity_key": None,
            "relational_cap": False, "expires_at": None, "agent_may_read_limits": False}
msalt = "ab" * 32
mhash = mandate_terms.commitment(snapshot, msalt)
mandate_reveal = {"mandate_id": snapshot["mandate_id"], "version": 2, "canon": "terms-v2", "snapshot": snapshot,
                  "salt": msalt, "hash": mhash, "canonical_string": mandate_terms.canonical_string(snapshot, msalt)}
# terms-v3 (backlog 29): the same mandate one version later, now with a scope
snapshot_v3 = {**snapshot, "version": 3, "allowed_resources": ["agentcard_buy", "sku:coffee/"]}
mhash3 = mandate_terms.commitment(snapshot_v3, msalt)
mandate_reveal_v3 = {"mandate_id": snapshot["mandate_id"], "version": 3, "canon": "terms-v3", "snapshot": snapshot_v3,
                     "salt": msalt, "hash": mhash3, "canonical_string": mandate_terms.canonical_string(snapshot_v3, msalt)}
assert "|allowed_resources=agentcard_buy,sku:coffee/|salt=" in mandate_reveal_v3["canonical_string"]
# terms-v4 (per-counterparty caps): one version later, with a table of caps per seller
snapshot_v4 = {**snapshot_v3, "version": 4, "entity_limits": mandate_terms.format_entity_limits([
    {"match": "kaspi.kz", "per_tx_limit": "5000"}, {"match": "arbuz.kz", "per_tx_limit": "3000", "monthly_limit": "20000"},
    {"match": "*", "monthly_limit": "10000"}])}
mhash4 = mandate_terms.commitment(snapshot_v4, msalt)
mandate_reveal_v4 = {"mandate_id": snapshot["mandate_id"], "version": 4, "canon": "terms-v4", "snapshot": snapshot_v4,
                     "salt": msalt, "hash": mhash4, "canonical_string": mandate_terms.canonical_string(snapshot_v4, msalt)}
assert "|entity_limits=*=none;10000.000000,arbuz.kz=3000.000000;20000.000000,kaspi.kz=5000.000000;none|salt=" in mandate_reveal_v4["canonical_string"]

ptext = 'permit (principal, action, resource) when { context.agent_active == true };\n'
pprofile = {"counterparty_allowlist": True, "escalation_amount": "500.00", "signed_agents_only": False, "observe_mode": False}
psalt = "cd" * 32
phash = policy_terms.commitment(policy_terms.snapshot_from(ORG, 3, ptext, pprofile), psalt)
policy_reveal = {"org_id": ORG, "version": 3, "cedar_text": ptext, "profile": pprofile, "salt": psalt, "hash": phash}
starter_text = "permit (principal, action, resource) when { context.agent_active == true };"

common = dict(agent_id="agent_abc", tool="stripe", action="charge.create", decision_id="dec_0123456789ab",
              args_hash=ah, amount=400.0, currency="KZT", payee="KYC KZ", mandate_id=snapshot["mandate_id"],
              mandate_version=2, mandate_hash=mhash, policy_version=3, policy_hash=phash, policy_source="org",
              risk_model="guardian-1.2")
allow_token, exp = issuer.issue(**common)
receipt = issuer.issue_receipt(status="success", mismatch=False, **{k: v for k, v in common.items() if k not in ("tool", "action")},
                               tool="stripe", action="charge.create")
receipt_v3 = issuer.issue_receipt(status="success", mismatch=False, tool="stripe", action="charge.create",
                                  **{k: v for k, v in common.items()
                                     if k not in ("tool", "action", "mandate_version", "mandate_hash")},
                                  mandate_version=3, mandate_hash=mhash3)
receipt_v4 = issuer.issue_receipt(status="success", mismatch=False, tool="agentcard_buy", action="POST /buy",
                                  payee_source="rail",
                                  **{k: v for k, v in common.items()
                                     if k not in ("tool", "action", "mandate_version", "mandate_hash", "payee")},
                                  payee="arbuz.kz", mandate_version=4, mandate_hash=mhash4)
starter_receipt = issuer.issue_receipt(decision_id="dec_s", agent_id="agent_abc", status="success",
                                       policy_version=0, policy_hash=policy_terms.starter_hash(starter_text), policy_source="starter")
budget_token, _, _ = issuer.issue_budget_token(agent_id="agent_abc", resource="https://merchant.example", cnf_jwk={"kty": "OKP"},
                                               budget={"amount": "10.00", "currency": "KZT"}, mandate_id=snapshot["mandate_id"], ttl_seconds=600)
wrong_key = other.issue_receipt(decision_id="dec_w", agent_id="agent_abc", status="success")

# A receipt whose settlement a counterparty (merchant) confirmed with its own signature (P-1).
# Two counterparty keys so both algorithms get4agent-class issuers use are exercised: Ed25519
# (get4agent's issuer key) and P-256. A stranger holds a different key under the SAME kid.
import hashlib  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402

CP_ISS = "https://merchant.example"
iat = pyjwt.decode(allow_token, options={"verify_signature": False, "verify_aud": False})["iat"]
cp_ed = ed25519.Ed25519PrivateKey.generate()
cp_ed_jwk = pyjwt.algorithms.OKPAlgorithm.to_jwk(cp_ed.public_key(), as_dict=True); cp_ed_jwk["kid"] = "cp-ed25519"
cp_ec = ec.generate_private_key(ec.SECP256R1())
cp_ec_jwk = pyjwt.algorithms.ECAlgorithm.to_jwk(cp_ec.public_key(), as_dict=True); cp_ec_jwk["kid"] = "cp-p256"
stranger = ed25519.Ed25519PrivateKey.generate()
stranger_jwk = pyjwt.algorithms.OKPAlgorithm.to_jwk(stranger.public_key(), as_dict=True); stranger_jwk["kid"] = "cp-ed25519"
conf_payload = {"iss": CP_ISS, "iat": iat, "exp": iat + 7 * 86400, "decision_id": "dec_0123456789ab", "status": "success",
                "amount": 400.0, "currency": "KZT", "payee": "KYC KZ", "ref": "ord_1", "kind": "merchant"}


def _confirmed_receipt(key, alg, kid):
    conf = pyjwt.encode(conf_payload, key, algorithm=alg, headers={"kid": kid, "typ": "settlement-confirmation+jwt"})
    facts = {"confirmed_by": CP_ISS, "confirmation_kid": kid, "confirmation_hash": hashlib.sha256(conf.encode()).hexdigest(),
             "confirmation": conf, "confirmation_ref": "ord_1", "confirmation_kind": "merchant"}
    return issuer.issue_receipt(status="success", mismatch=False, settlement_source="counterparty", confirmation=facts,
                                agent_report_mismatch=False, tool="stripe", action="charge.create",
                                **{k: v for k, v in common.items() if k not in ("tool", "action")})


confirmed_ed = _confirmed_receipt(cp_ed, "EdDSA", "cp-ed25519")
confirmed_ec = _confirmed_receipt(cp_ec, "ES256", "cp-p256")
h, p, s = receipt.split(".")
tampered = h + "." + p[:-2] + ("AA" if p[-2:] != "AA" else "BB") + "." + s
iat = pyjwt.decode(allow_token, options={"verify_signature": False, "verify_aud": False})["iat"]

vectors = {
    "generated_at": datetime.now(UTC).isoformat(),
    "jwks": issuer.jwks(),
    "other_jwks": other.jwks(),
    "now": iat + 10,
    "issuer": "regent-control",
    "request": request,
    "args_hash": ah,
    "wrong_request": {**request, "args": {**request["args"], "amount": 401}},
    "mandate_reveal": mandate_reveal,
    "mandate_reveal_v3": mandate_reveal_v3,
    "mandate_reveal_v4": mandate_reveal_v4,
    "policy_reveal": policy_reveal,
    "starter_text": starter_text,
    "counterparty_jwks": {"keys": [cp_ed_jwk, cp_ec_jwk]},
    "stranger_jwks": {"keys": [stranger_jwk]},
    "cases": {
        "receipt_v3_scope": {"token": receipt_v3, "reveal": "mandate_reveal_v3",
                             "expect": {"kind": "receipt", "signature_valid": True, "mandate_match": True}},
        "receipt_v4_caps": {"token": receipt_v4, "reveal": "mandate_reveal_v4",
                            "expect": {"kind": "receipt", "signature_valid": True, "mandate_match": True,
                                       "payee": "arbuz.kz", "payee_source": "rail"}},
        "receipt_confirmed": {"token": confirmed_ed, "expect": {"kind": "receipt", "signature_valid": True, "confirmation_match": True,
                                                                "confirmation_alg": "EdDSA", "settlement_source": "counterparty"}},
        "receipt_confirmed_es256": {"token": confirmed_ec, "expect": {"kind": "receipt", "signature_valid": True, "confirmation_match": True,
                                                                      "confirmation_alg": "ES256"}},
        "receipt": {"token": receipt, "expect": {"kind": "receipt", "signature_valid": True, "expired": False,
                                                 "args_hash_match": True, "mandate_match": True, "policy_match": True}},
        "allow": {"token": allow_token, "expect": {"kind": "allow", "signature_valid": True, "expired": False,
                                                   "args_hash_match": True, "mandate_match": True, "policy_match": True}},
        "allow_expired": {"token": allow_token, "now": iat + 3600, "expect": {"kind": "allow", "signature_valid": True, "expired": True}},
        "starter_receipt": {"token": starter_receipt, "expect": {"kind": "receipt", "signature_valid": True, "policy_match_with_starter_text": True}},
        "budget": {"token": budget_token, "expect": {"kind": "budget", "signature_valid": True}},
        "wrong_key": {"token": wrong_key, "expect": {"signature_valid": False}},
        "tampered": {"token": tampered, "expect": {"signature_valid": False}},
    },
}
out = os.path.join(HERE, "vectors.json")
# ── Evidence bundle (backlog 28): minted with the REAL checkpoint signer and the real
# Merkle rules of api-audit, around a receipt from the real issuer. ─────────────────────
sys.path.insert(0, os.path.join(ROOT, "apps/api-audit/src"))
import uuid as _uuid  # noqa: E402

from api_audit.models import AuditBatch  # noqa: E402
from api_audit.services.bundle import canonical_payload  # noqa: E402
from api_audit.services.chain import epoch_tree  # noqa: E402
from api_audit.services.checkpoint import CheckpointSigner, claims_for  # noqa: E402
from api_audit.services.merkle import build_merkle_tree  # noqa: E402
import hashlib as _hashlib  # noqa: E402

DEC = "dec_b0b0b0b0b0b0"
b_receipt = issuer.issue_receipt(decision_id=DEC, agent_id="agent_abc", status="success", amount=6.61, currency="USD",
                                 payee="agentcard", mandate_id=snapshot["mandate_id"], tool="agentcard_buy",
                                 action="POST /buy", args_hash=ah, mismatch=False, environment="production")
b_payloads = [
    (f"ctrl-{DEC}", {"decision_id": DEC, "decision": "allow", "code": "OK", "tool": "agentcard_buy",
                     "action": "POST /buy", "amount": 6.61, "amount_usd": 100.0, "currency": "USD", "intent": "Kaffee ☕"}),
    (f"ctrl-{DEC}-settle-agentcard_webhook", {"decision_id": DEC, "status": "completed", "settled_amount": 6.61,
                                              "approved_amount": 6.61, "mandate_reconciled": True, "amount_mismatch": False}),
    (f"ctrl-{DEC}-receipt", {"decision_id": DEC, "org_id": ORG, "receipt": b_receipt, "kid": issuer.kid,
                             "receipt_jti": "jti-b", "status": "success", "amount": 6.61, "currency": "USD"}),
    ("ctrl-dec_other", {"decision_id": "dec_other", "decision": "deny"}),
]
b_canon = [canonical_payload(pl) for _, pl in b_payloads]
b_hashes = ["0x" + _hashlib.sha256(c.encode()).hexdigest() for c in b_canon]
b_root, b_proofs = build_merkle_tree(b_hashes)
prev_canon = canonical_payload({"x": 1})
prev_batch_root = "0x" + _hashlib.sha256(prev_canon.encode()).hexdigest()   # one-event batch: root IS the leaf
prev_head = "0x" + "22" * 32
head = "0x" + _hashlib.sha256(bytes.fromhex(prev_head[2:]) + bytes.fromhex(b_root[2:] if b_root.startswith("0x") else b_root)
                              + (7).to_bytes(8, "little")).hexdigest()
ck_signer = CheckpointSigner.ephemeral(issuer="https://api.regentprotocol.org/v1/audit")
batch_id = _uuid.uuid4()
batch = AuditBatch(id=batch_id, status="anchored", merkle_root=b_root, event_count=4, seq=7,
                   sealed_at=datetime.now(tz=UTC), chain_tx="5chainTxSignature", chain_head=head,
                   chain_appended_at=datetime.now(tz=UTC), arbitrum_tx_hash="legacyAnchorSig")
ck = ck_signer.sign(claims_for(batch, prev_head, issuer=ck_signer.issuer,
                               program_id="8N1PpbJZKmvJjG86XWpP82XrWzp8HY5FHZuzyQTgjJas", cluster="devnet"))
prev_batch = AuditBatch(id=_uuid.uuid4(), status="anchored", merkle_root=prev_batch_root, event_count=1, seq=6,
                        chain_tx="4prevTx", chain_head=prev_head, chain_appended_at=datetime.now(tz=UTC))
ck_prev = ck_signer.sign(claims_for(prev_batch, "0x" + "00" * 32, issuer=ck_signer.issuer,
                                    program_id="8N1PpbJZKmvJjG86XWpP82XrWzp8HY5FHZuzyQTgjJas", cluster="devnet"))
ep_root, ep_proofs = epoch_tree([prev_batch_root, b_root])


def _b_event(i, *, batch_root=b_root, checkpoint=ck, seq=7):
    eid, pl = b_payloads[i]
    return {"event_id": eid, "agent_id": "agent_abc", "event_type": "control.decision", "received_at": "2026-10-13T00:00:00Z",
            "status": "anchored", "payload": pl, "payload_canonical": b_canon[i], "payload_hash": b_hashes[i],
            "payload_hash_recomputed": True, "prev_hash": b_hashes[i - 1] if i else None,
            "batch": {"batch_id": str(batch_id), "seq": seq, "root": batch_root, "event_count": 4, "merkle_index": i,
                      "merkle_proof": b_proofs[i], "sealed_at": "2026-10-13T00:00:01Z", "legacy_anchor_tx": "legacyAnchorSig",
                      "chain_tx": "5chainTxSignature", "chain_head": head, "chain_appended_at": "2026-10-13T00:00:02Z",
                      "checkpoint": checkpoint, "checkpoint_kid": ck_signer.kid},
            "epoch": {"epoch_index": 3, "first_seq": 6, "last_seq": 7, "root": ep_root, "leaf_index": 1, "proof": ep_proofs[1],
                      "status": "anchored", "tx": "epochTxSig", "anchored_at": "2026-10-13T01:00:00Z", "ots_status": "pending",
                      "ots_proof_b64": None}}


prev_event = {"event_id": "ctrl-dec_prev", "agent_id": "agent_abc", "event_type": "control.decision",
              "received_at": "2026-10-12T00:00:00Z", "status": "anchored", "payload": {"x": 1},
              "payload_canonical": prev_canon, "payload_hash": prev_batch_root, "payload_hash_recomputed": True,
              "prev_hash": None,
              "batch": {"batch_id": str(prev_batch.id), "seq": 6, "root": prev_batch_root, "event_count": 1, "merkle_index": 0,
                        "merkle_proof": [], "sealed_at": None, "legacy_anchor_tx": None, "chain_tx": "4prevTx",
                        "chain_head": prev_head, "chain_appended_at": "2026-10-12T00:00:02Z", "checkpoint": ck_prev,
                        "checkpoint_kid": ck_signer.kid},
              "epoch": {"epoch_index": 3, "first_seq": 6, "last_seq": 7, "root": ep_root, "leaf_index": 0, "proof": ep_proofs[0],
                        "status": "anchored", "tx": "epochTxSig", "anchored_at": "2026-10-13T01:00:00Z", "ots_status": "pending",
                        "ots_proof_b64": None}}


def _bundle(events, receipt=True):
    events = json.loads(json.dumps(events))   # every case gets its own objects to tamper with
    return {"bundle_version": "regent-evidence-bundle/1", "generated_at": "2026-10-13T02:00:00Z", "decision_id": DEC,
            "issuer": {"audit": ck_signer.issuer, "control": "regent-control"},
            "programs": {"audit_anchor": "8N1PpbJZKmvJjG86XWpP82XrWzp8HY5FHZuzyQTgjJas"}, "cluster": "devnet",
            "keys": {"checkpoint_jwks": ck_signer.jwks(), "receipt_jwks": issuer.jwks()}, "events": events,
            "receipt": {"token": b_receipt, "kid": issuer.kid, "jti": "jti-b", "event_id": f"ctrl-{DEC}-receipt"} if receipt else None}


good = _bundle([_b_event(0), _b_event(1), _b_event(2)])
good_with_prev = _bundle([prev_event, _b_event(0), _b_event(2)])
tampered_payload = _bundle([_b_event(0), _b_event(2)])
tampered_payload["events"][0]["payload"]["amount"] = 6610.0      # payload no longer matches its canonical bytes
tampered_canonical = _bundle([_b_event(0), _b_event(2)])
tampered_canonical["events"][0]["payload_canonical"] = tampered_canonical["events"][0]["payload_canonical"].replace("6.61", "6.62")
wrong_batch_root = _bundle([_b_event(0, batch_root="0x" + "ab" * 32), _b_event(2)])
other_ck = CheckpointSigner.ephemeral(issuer=ck_signer.issuer)
foreign_checkpoint = _bundle([_b_event(0, checkpoint=other_ck.sign(claims_for(batch, prev_head, issuer=ck_signer.issuer,
                                                                             program_id="p", cluster="devnet"))), _b_event(2)])
swapped_receipt = _bundle([_b_event(0), _b_event(2)])
swapped_receipt["receipt"]["token"] = receipt      # a real receipt, but not the one anchored in the trail
ck_broken = ck_signer.sign(claims_for(batch, "0x" + "33" * 32, issuer=ck_signer.issuer, program_id="p", cluster="devnet"))
broken_link = _bundle([prev_event, _b_event(0, checkpoint=ck_broken), _b_event(2, checkpoint=ck_broken)])
conflicting_checkpoints = _bundle([_b_event(0), _b_event(2, checkpoint=ck_broken)])

vectors["bundle"] = {
    "checkpoint_jwks": ck_signer.jwks(), "other_checkpoint_jwks": other_ck.jwks(), "decision_id": DEC,
    "cases": {
        "good": {"bundle": good, "valid": True, "receipt_valid": True, "receipt_anchored": True, "links": None},
        "good_with_prev": {"bundle": good_with_prev, "valid": True, "receipt_valid": True, "receipt_anchored": True, "links": True},
        "tampered_payload": {"bundle": tampered_payload, "valid": False},
        "tampered_canonical": {"bundle": tampered_canonical, "valid": False},
        "wrong_batch_root": {"bundle": wrong_batch_root, "valid": False},
        "foreign_checkpoint": {"bundle": foreign_checkpoint, "valid": False},
        "swapped_receipt": {"bundle": swapped_receipt, "valid": False},
        "broken_link": {"bundle": broken_link, "valid": False, "links": False},
        "conflicting_checkpoints": {"bundle": conflicting_checkpoints, "valid": False},
    },
}

json.dump(vectors, open(out, "w"), indent=1)
print("wrote", out, "cases:", list(vectors["cases"]))
