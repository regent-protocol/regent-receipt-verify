"""Counterparty confirmation vectors for both verifiers: `confirmation_vectors.json`.

Standalone (needs only `cryptography`). A receipt signed by a stand-in issuer embeds a
settlement confirmation signed by a stand-in counterparty; each case varies what the
confirmation says. Both verifiers must give the same verdict and print the same text.

    python make_confirmation_vectors.py      # rewrites confirmation_vectors.json beside this file
"""

from __future__ import annotations

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import serialization


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwk(key, kid):
    n = key.public_key().public_numbers()
    return {"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
            "n": b64u(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")), "e": b64u(n.e.to_bytes(3, "big"))}


def sign(key, header: dict, payload: bytes) -> str:
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(payload)
    return f"{h}.{p}." + b64u(key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256()))


NOW = 1795000000
regent = rsa.generate_private_key(public_exponent=65537, key_size=2048)
merchant = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RECEIPT = {"iss": "regent-control", "aud": "regent-receipt", "iat": 1792564722, "exp": 2107924722, "jti": "rcp_conf",
           "decision_id": "dec_cccccccccccc", "agent_id": "agent_demo", "status": "success", "amount": 12, "currency": "USD",
           "settlement_source": "counterparty", "confirmed_by": "merchant", "confirmation_kid": "cp-1"}
CONF = {"iss": "merchant", "decision_id": "dec_cccccccccccc", "status": "success", "amount": 12, "currency": "usd",
        "iat": 1792564700, "exp": 2107924722}

cases: dict[str, dict] = {}


def case(name, payload: bytes, *, match, error=None, prints=None, note=None, conf=None, cp_jwks=None, claims_over=None):
    conf = conf or sign(merchant, {"alg": "RS256", "kid": "cp-1", "typ": "settlement-confirmation+jwt"}, payload)
    claims = {**RECEIPT, "confirmation": conf, "confirmation_hash": hashlib.sha256(conf.encode()).hexdigest(), **(claims_over or {})}
    token = sign(regent, {"alg": "RS256", "kid": "rk-1", "typ": "receipt+jwt"}, json.dumps(claims, separators=(",", ":")).encode())
    cases[name] = {"token": token, "match": match, "error_contains": error, "prints": prints, "note": note}
    if cp_jwks is not None:
        cases[name]["counterparty_jwks"] = cp_jwks


def raw_jws(header: dict, payload: bytes, signature: bytes) -> tuple[str, bytes]:
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(payload)
    return f"{h}.{p}.{b64u(signature)}", f"{h}.{p}".encode()


def signed_with(alg: str, signer) -> str:
    """A confirmation whose signature `signer(bytes) -> bytes` makes, under header alg `alg`."""
    head = {"alg": alg, "kid": "cp-x", "typ": "settlement-confirmation+jwt"}
    _, to_sign = raw_jws(head, body(), b"")
    token, _ = raw_jws(head, body(), signer(to_sign))
    return token


SIGNED_BY_ANOTHER_KEY = "confirmation signature does not verify against the counterparty key(s)"


def body(**over) -> bytes:
    return json.dumps({**CONF, **over}, separators=(",", ":")).encode()


case("the_same_facts", body(), match=True, prints="    confirmed by merchant (kid cp-1): success 12 usd")
case("an_amount_as_decimal_text", body(amount="12.00"), match=True)
case("an_amount_within_a_cent", body(amount=12.004), match=True)
case("another_amount", body(amount=13), match=False, error="confirmation amount 13 differs from the receipt's 12")
case("an_amount_that_is_nan_as_text", body(amount="nan"), match=False, error="confirmation amount is not a number",
     note="Python's float() reads 'nan', and NaN compared with anything is not 'more than a cent off'")
case("an_amount_that_is_infinity_as_text", body(amount="Infinity"), match=False, error="confirmation amount is not a number")
case("an_amount_with_underscores", body(amount="1_2"), match=False, error="confirmation amount is not a number")
case("an_amount_in_hex", body(amount="0xc"), match=False, error="confirmation amount is not a number")
case("an_amount_in_a_list", body(amount=[12]), match=False, error="confirmation amount is not a number")
case("an_amount_that_is_true", body(amount=True), match=False, error="confirmation amount is not a number")
case("a_bare_nan_in_the_payload", body()[:-1] + b',"x":NaN}', match=False, error="cannot decode the confirmation")
case("a_payload_that_is_null", b"null", match=False, error="cannot decode the confirmation: payload is not a JSON object")
case("a_payload_that_is_a_number", b"5", match=False, error="cannot decode the confirmation: payload is not a JSON object")
case("a_currency_that_is_a_number", body(currency=840), match=False, error="confirmation currency differs")
case("another_currency", body(currency="eur"), match=False, error="confirmation currency differs")
case("an_issuer_with_a_quote", body(iss="mer'chant"), match=False,
     error="confirmation issuer 'mer'chant' differs from the receipt's confirmed_by")
case("a_status_that_is_a_list", body(status=["success"]), match=False,
     error="confirmation status '[\"success\"]' differs from the receipt's 'success'")
case("a_ref_that_is_an_empty_list", body(ref=[]), match=True, prints="    confirmed by merchant (kid cp-1): success 12 usd ref []")
case("a_ref_with_a_nested_float", body(ref={"a": 1.0, "2": 0, "1": 0}), match=True,
     prints='    confirmed by merchant (kid cp-1): success 12 usd ref {"1":0,"2":0,"a":1}')
case("an_expiry_that_is_true", body(exp=True), match=True, note="true is not a number of seconds: no expiry is read from it")

# ── keys: each algorithm takes one key type, read strictly, of a sound size (both languages) ──
k1 = ec.generate_private_key(ec.SECP256K1())
k1n = k1.public_key().public_numbers()
case("es256_with_a_secp256k1_key", b"", match=False, error=SIGNED_BY_ANOTHER_KEY,
     conf=signed_with("ES256", lambda m: b"".join(v.to_bytes(32, "big") for v in decode_dss_signature(k1.sign(m, ec.ECDSA(hashes.SHA256()))))),
     cp_jwks={"keys": [{"kty": "EC", "crv": "secp256k1", "kid": "cp-x", "x": b64u(k1n.x.to_bytes(32, "big")), "y": b64u(k1n.y.to_bytes(32, "big"))}]})
e448 = ed448.Ed448PrivateKey.generate()
case("eddsa_with_an_ed448_key", b"", match=False, error=SIGNED_BY_ANOTHER_KEY, conf=signed_with("EdDSA", e448.sign),
     cp_jwks={"keys": [{"kty": "OKP", "crv": "Ed448", "kid": "cp-x",
                        "x": b64u(e448.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))}]})
p256 = ec.generate_private_key(ec.SECP256R1())
pn = p256.public_key().public_numbers()
P256_JWK = {"kty": "EC", "crv": "P-256", "kid": "cp-x", "x": b64u(pn.x.to_bytes(32, "big")), "y": b64u(pn.y.to_bytes(32, "big"))}
case("rs256_named_over_an_ec_key", b"", match=False, error=SIGNED_BY_ANOTHER_KEY,
     conf=signed_with("RS256", lambda m: p256.sign(m, ec.ECDSA(hashes.SHA256()))), cp_jwks={"keys": [P256_JWK]},
     note="the algorithm the header names decides the key type, not the key the reader is handed")
case("ps256_named_over_an_ec_key", b"", match=False, error=SIGNED_BY_ANOTHER_KEY,
     conf=signed_with("PS256", lambda m: p256.sign(m, ec.ECDSA(hashes.SHA256()))), cp_jwks={"keys": [P256_JWK]})
case("eddsa_named_over_an_rsa_key", b"", match=False, error=SIGNED_BY_ANOTHER_KEY,
     conf=signed_with("EdDSA", lambda m: merchant.sign(m, padding.PKCS1v15(), hashes.SHA256())), cp_jwks={"keys": [{**jwk(merchant, "cp-x")}]})
mjwk = jwk(merchant, "cp-x")
case("an_rsa_modulus_with_a_space_in_it", b"", match=False, error=SIGNED_BY_ANOTHER_KEY,
     conf=signed_with("RS256", lambda m: merchant.sign(m, padding.PKCS1v15(), hashes.SHA256())),
     cp_jwks={"keys": [{**mjwk, "n": mjwk["n"][:40] + " " + mjwk["n"][40:]}]})
small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
case("an_rsa_key_of_1024_bits", b"", match=False, error=SIGNED_BY_ANOTHER_KEY,
     conf=signed_with("RS256", lambda m: small.sign(m, padding.PKCS1v15(), hashes.SHA256())), cp_jwks={"keys": [jwk(small, "cp-x")]})


def e1_forgery(m: bytes) -> bytes:
    """With e = 1 the 'signature' is the padded hash itself: no private key is needed."""
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(m).digest()
    return b"\x00\x01" + b"\xff" * (256 - 3 - len(digest_info)) + b"\x00" + digest_info


case("an_rsa_key_with_exponent_1_and_a_forged_signature", b"", match=False, error=SIGNED_BY_ANOTHER_KEY,
     conf=signed_with("RS256", e1_forgery),
     cp_jwks={"keys": [{"kty": "RSA", "kid": "cp-x", "n": b64u(b"\xff" * 255 + b"\xfb"), "e": b64u(b"\x01")}]},
     note="anyone can compute this signature; a reader that accepts e = 1 accepts a forged confirmation")
case("a_confirmation_hash_that_is_not_hex", body(), match=False, error="confirmation_hash in the receipt does not match",
     claims_over={"confirmation_hash": "é"})
case("an_amount_too_long_for_a_number", body(amount="1" + "0" * 320), match=False, error="confirmation amount is not a number")

# ── reveals: a value of a type the format does not define matches nothing, in both languages ──
sha = lambda t: hashlib.sha256(t.encode()).hexdigest()  # noqa: E731
POLICY_TEXT = "permit(principal, action, resource);"
POLICY_HASH = sha("|".join(["policy-v1", "org_id=org-1", "version=16", f"text_sha256={sha(POLICY_TEXT)}", "profile_sha256=none", "salt=ab12"]))
SNAP = {"mandate_id": "mnd_demo", "version": 3, "agent_id": "agent_demo", "owner_id": "owner-1", "currency": "USD",
        "settlement_chain": "stripe", "status": "active", "per_tx_limit": "100", "daily_limit": "250.5", "monthly_limit": None,
        "per_entity_limit": None, "entity_key": None, "relational_cap": False, "expires_at": None, "agent_may_read_limits": True,
        "allowed_resources": ["a", "b"]}
V2 = ["mandate_id", "version", "agent_id", "owner_id", "currency", "settlement_chain", "status", "per_tx_limit", "daily_limit",
      "monthly_limit", "per_entity_limit", "entity_key", "relational_cap", "expires_at", "agent_may_read_limits"]


def _cv(v):
    return "none" if v is None else "true" if v is True else "false" if v is False else ",".join(v) if isinstance(v, list) else str(v)


PROFILE_REVEAL = {"org_id": "org-1", "version": 16, "cedar_text": POLICY_TEXT, "salt": "ab12"}
PROFILE_HASH = sha("|".join(["policy-v1", "org_id=org-1", "version=16", f"text_sha256={sha(POLICY_TEXT)}",
                             f"profile_sha256={sha(json.dumps({'a': 'x', 'n': 40}, sort_keys=True, separators=(',', ':')))}", "salt=ab12"]))
MANDATE_HASH = sha("|".join(["terms-v3", *(f"{k}={_cv(SNAP.get(k))}" for k in [*V2, "allowed_resources"]), "salt=cd34"]))
PAYEE_HASH = sha("payee-v1|payee=acct-1|salt=ef56")
reveals = {
    "policy": {"claims": {"policy_hash": POLICY_HASH, "policy_version": 16, "policy_source": "org"}, "cases": [
        ["as_issued", {"org_id": "org-1", "version": 16, "cedar_text": POLICY_TEXT, "salt": "AB12"}, True],
        ["a_version_written_with_a_decimal_point", {"org_id": "org-1", "version": 16.0, "cedar_text": POLICY_TEXT, "salt": "ab12"}, True],
        ["a_version_in_hex_text", {"org_id": "org-1", "version": "0x10", "cedar_text": POLICY_TEXT, "salt": "ab12"}, False],
        ["a_version_with_a_fraction", {"org_id": "org-1", "version": 16.5, "cedar_text": POLICY_TEXT, "salt": "ab12"}, False],
        ["a_version_as_text", {"org_id": "org-1", "version": "16", "cedar_text": POLICY_TEXT, "salt": "ab12"}, False],
        ["an_org_id_that_is_a_number", {"org_id": 1, "version": 16, "cedar_text": POLICY_TEXT, "salt": "ab12"}, False],
        ["a_salt_in_a_list", {"org_id": "org-1", "version": 16, "cedar_text": POLICY_TEXT, "salt": ["ab12"]}, False],
        ["a_version_beyond_2_53", {"org_id": "org-1", "version": 9007199254740993, "cedar_text": POLICY_TEXT, "salt": "ab12"}, False],
        ["text_with_a_lone_surrogate", {"org_id": "org-1", "version": 16, "cedar_text": POLICY_TEXT + "\udc00", "salt": "ab12"}, False],
    ]},
    "mandate": {"claims": {"mandate_hash": MANDATE_HASH, "mandate_version": 3}, "cases": [
        ["as_issued", {"snapshot": SNAP, "salt": "cd34"}, True],
        ["a_limit_as_a_number", {"snapshot": {**SNAP, "per_tx_limit": 100}, "salt": "cd34"}, True],
        ["a_limit_as_a_number_with_a_decimal_point", {"snapshot": {**SNAP, "per_tx_limit": 100.0}, "salt": "cd34"}, True],
        ["a_version_as_text", {"snapshot": {**SNAP, "version": "abc"}, "salt": "cd34"}, False],
        ["a_version_with_a_fraction", {"snapshot": {**SNAP, "version": 3.5}, "salt": "cd34"}, False],
        ["a_scope_with_a_true_in_it", {"snapshot": {**SNAP, "allowed_resources": ["a", True]}, "salt": "cd34"}, False],
        ["a_scope_with_a_null_in_it", {"snapshot": {**SNAP, "allowed_resources": ["a", None]}, "salt": "cd34"}, False],
        ["a_limit_that_is_an_object", {"snapshot": {**SNAP, "per_tx_limit": {"v": "100"}}, "salt": "cd34"}, False],
        ["a_salt_that_is_a_number", {"snapshot": SNAP, "salt": 1234}, False],
        ["a_canon_named_like_a_builtin", {"snapshot": SNAP, "salt": "cd34", "canon": "toString"}, True],
        ["a_salt_with_a_lone_surrogate", {"snapshot": SNAP, "salt": "cd34\ud800"}, False],
        ["a_text_value_with_a_lone_surrogate", {"snapshot": {**SNAP, "agent_id": "a\ud800"}, "salt": "cd34"}, False],
        ["a_scope_item_with_a_lone_surrogate", {"snapshot": {**SNAP, "allowed_resources": ["a\udc00"]}, "salt": "cd34"}, False],
        ["a_version_beyond_2_53", {"snapshot": {**SNAP, "version": 9007199254740993}, "salt": "cd34"}, False],
    ]},
    "policy_starter": {"claims": {"policy_hash": sha(POLICY_TEXT), "policy_source": "starter"}, "cases": [
        ["as_issued", POLICY_TEXT, True],
        ["text_with_a_lone_surrogate", POLICY_TEXT + "\ud800", False],
    ]},
    "policy_profile": {"claims": {"policy_hash": PROFILE_HASH, "policy_version": 16, "policy_source": "org"}, "cases": [
        ["as_issued", {**PROFILE_REVEAL, "profile": {"a": "x", "n": 40}}, True],
        ["a_whole_number_with_a_decimal_point", {**PROFILE_REVEAL, "profile": {"a": "x", "n": 40.0}}, True],
        ["a_number_in_exponent_form", {**PROFILE_REVEAL, "profile": {"a": "x", "n": 1e-7}}, False],
        ["a_number_too_large_to_be_exact", {**PROFILE_REVEAL, "profile": {"a": "x", "n": 1e16}}, False],
        ["an_integer_beyond_2_53", {**PROFILE_REVEAL, "profile": {"a": "x", "n": 9007199254740993}}, False],
        ["a_key_above_the_basic_plane", {**PROFILE_REVEAL, "profile": {"a": "x", "n": 40, "\U0001F600": 1}}, False],
        ["a_value_with_a_lone_surrogate", {**PROFILE_REVEAL, "profile": {"a": "x\udc00", "n": 40}}, False],
        ["an_org_id_with_a_lone_surrogate", {**PROFILE_REVEAL, "org_id": "org-1\ud800", "profile": {"a": "x", "n": 40}}, False],
    ]},
    "payee": {"claims": {"payee_hash": PAYEE_HASH, "decision_id": "dec_cccccccccccc"}, "cases": [
        ["a_payee_with_a_lone_surrogate", {"payee": "acct-\udc00", "salt": "ef56"}, False],
        ["a_salt_with_a_lone_surrogate", {"payee": "acct-1", "salt": "ef56\ud800"}, False],
        ["as_issued", {"payee": "acct-1", "salt": "EF56"}, True],
        ["a_payee_in_a_list", {"payee": ["acct-1"], "salt": "ef56"}, False],
        ["a_salt_in_a_list", {"payee": "acct-1", "salt": ["ef56"]}, False],
        ["another_decision", {"payee": "acct-1", "salt": "ef56", "decision_id": "dec_dddddddddddd"}, False],
        ["the_decision_named_as_a_list", {"payee": "acct-1", "salt": "ef56", "decision_id": ["dec_cccccccccccc"]}, False],
    ]},
}

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "confirmation_vectors.json")
with open(out, "w") as f:
    json.dump({"now": NOW, "receipt_jwks": {"keys": [jwk(regent, "rk-1")]}, "counterparty_jwks": {"keys": [jwk(merchant, "cp-1")]},
               "cases": cases, "reveals": reveals}, f, indent=1, sort_keys=True)
    f.write("\n")
print("wrote", out, "cases:", len(cases))
