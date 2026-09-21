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
starter_receipt = issuer.issue_receipt(decision_id="dec_s", agent_id="agent_abc", status="success",
                                       policy_version=0, policy_hash=policy_terms.starter_hash(starter_text), policy_source="starter")
budget_token, _, _ = issuer.issue_budget_token(agent_id="agent_abc", resource="https://merchant.example", cnf_jwk={"kty": "OKP"},
                                               budget={"amount": "10.00", "currency": "KZT"}, mandate_id=snapshot["mandate_id"], ttl_seconds=600)
wrong_key = other.issue_receipt(decision_id="dec_w", agent_id="agent_abc", status="success")
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
    "policy_reveal": policy_reveal,
    "starter_text": starter_text,
    "cases": {
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
json.dump(vectors, open(out, "w"), indent=1)
print("wrote", out, "cases:", list(vectors["cases"]))
