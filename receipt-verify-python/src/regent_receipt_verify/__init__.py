"""regent-receipt-verify — check a Regent Control receipt or allow token without Regent.

Everything needed is in the token and a JWKS you saved while the issuer was reachable
(GET https://control-api.regentprotocol.org/v1/control/.well-known/jwks.json). Nothing here
calls the network. Signature: RS256 via `cryptography`. Commitments: the same canonical
strings as the gate (terms-v2 for mandates, policy-v1 for policies) and the same request
hash (sha256 over canonical JSON of {tool, action, resource, args}).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .approval import ApprovalResult, SignedApproval, verify_approval  # approval.py imports nothing from here
from .strict import Malformed, _as_double, _same, compact_jws, confirmation_key, jwk_list, number_text, rs256_ok, show

__version__ = "0.9.2"
__all__ = [
    "VerificationResult", "ConfirmationCheck", "verify_token", "verify", "canonical_args_hash",
    "check_request_binding", "mandate_commitment", "check_mandate_reveal", "policy_commitment",
    "check_policy_reveal", "check_confirmation", "verify_bundle", "BundleResult",
    "verify_approval", "ApprovalResult", "SignedApproval",
]


# ── JWS ───────────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_uint(s: str) -> int:
    return int.from_bytes(_b64url_decode(s), "big")


def _keys(jwks: Any) -> list[dict[str, Any]]:
    """Accept a JWKS dict, a list of JWKS dicts (key rotation), or a list of JWKs."""
    return jwk_list(jwks)


@dataclass
class VerificationResult:
    signature_valid: bool
    kind: str                      # receipt | allow | budget | unknown
    header: dict[str, Any] = field(default_factory=dict)
    claims: dict[str, Any] = field(default_factory=dict)
    kid: str | None = None
    expired: bool | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # populated by verify() when the optional inputs are given
    args_hash_match: bool | None = None
    mandate_match: bool | None = None
    policy_match: bool | None = None
    payee_match: bool | None = None   # payee-v1 reveal opened the receipt's payee_hash
    # the counterparty's settlement confirmation embedded in the receipt, checked against
    # the counterparty's own JWKS (None when no counterparty JWKS was supplied)
    confirmation_match: bool | None = None
    confirmation_errors: list[str] = field(default_factory=list)
    confirmation: dict[str, Any] | None = None

    @property
    def valid(self) -> bool:
        """Authentic and, for a receipt, still inside its evidence period."""
        return self.signature_valid and not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid, "signature_valid": self.signature_valid, "kind": self.kind, "kid": self.kid,
            "expired": self.expired, "args_hash_match": self.args_hash_match, "mandate_match": self.mandate_match,
            "policy_match": self.policy_match, "payee_match": self.payee_match, "confirmation_match": self.confirmation_match,
            "confirmation_errors": self.confirmation_errors, "confirmation": self.confirmation,
            "errors": self.errors, "warnings": self.warnings, "header": self.header, "claims": self.claims,
        }


def _finite_number(value: Any) -> bool:
    """A JSON number that is finite as a double reads it: an integer of 400 digits is not."""
    return _is_number(value) and math.isfinite(_as_double(value))


def _wf(text: Any) -> bool:
    """Text that UTF-8 can carry: no lone surrogate (JSON can spell one, "\\ud800")."""
    if not isinstance(text, str):
        return False
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


_DECIMAL = re.compile(r"-?[0-9]+(\.[0-9]+)?")


def _amount(value: Any) -> float | None:
    """An amount: a finite JSON number, or a plain decimal string ("12.50"). Anything else,
    NaN and "nan" included, is not an amount."""
    if _finite_number(value):
        return float(value)
    if isinstance(value, str) and _DECIMAL.fullmatch(value):
        x = float(value)
        return x if x not in (float("inf"), float("-inf")) else None   # 309 digits and more: not an amount
    return None


_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
_SAFE = 2**53 - 1   # beyond it two integers read as one double in JavaScript


def _whole(value: Any) -> int | None:
    """A whole number as JSON carries it (12 or 12.0, within 2**53 - 1), else None."""
    if not _finite_number(value) or abs(value) > _SAFE:
        return None
    return int(value) if float(value).is_integer() else None


def _lower_ascii(text: str) -> str:
    return text.lower() if text.isascii() else text


def _amount_text(value: Any) -> str:
    return value if isinstance(value, str) else (number_text(value) or show(value))


def _given(value: Any) -> bool:
    """Present in the sense both languages agree on: not absent, null, empty text or false."""
    return value is not None and value is not False and value != ""


def _upper_ascii(value: Any) -> Any:
    if value is None:
        return ""
    if not isinstance(value, str):
        return object()            # not text: equal to nothing
    return value.upper() if value.isascii() else value


def _is_number(value: Any) -> bool:
    """A JSON number: in Python `True` is an int, in JSON it is not a number."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _kind(header: dict[str, Any], claims: dict[str, Any]) -> str:
    typ = header.get("typ") if isinstance(header.get("typ"), str) else ""
    if typ == "receipt+jwt" or claims.get("aud") == "regent-receipt":
        return "receipt"
    if typ == "aa-auth+jwt" or "budget" in claims:
        return "budget"
    if "scope" in claims and "decision_id" in claims:
        return "allow"
    return "unknown"


def verify_token(token: str, jwks: Any, *, now: float | None = None, issuer: str | None = "regent-control") -> VerificationResult:
    """Signature + structure. Returns a result even for invalid tokens (never raises on bad input)."""
    if now is not None and not _finite_number(now):
        return VerificationResult(False, "unknown", errors=["now is not a finite number of seconds"])
    now = time.time() if now is None else now
    try:
        header, claims, signature, signed = compact_jws(token)
    except Malformed as exc:
        text = str(exc)
        return VerificationResult(False, "unknown", errors=[text if text.startswith("not a compact JWS") else f"cannot decode token: {text}"])
    res = VerificationResult(False, _kind(header, claims), header=header, claims=claims, kid=header.get("kid"))
    if header.get("alg") != "RS256":
        res.errors.append(f"unsupported alg '{show(header.get('alg'))}' (Regent signs RS256)")
        return res
    candidates = [k for k in _keys(jwks) if k.get("kty") == "RSA" and (res.kid is None or k.get("kid") == res.kid)]
    if not candidates:
        res.errors.append(f"no RSA key with kid '{show(res.kid)}' in the JWKS you supplied")
        return res
    for k in candidates:
        if rs256_ok(k, signed, signature):
            res.signature_valid = True
            res.kid = k.get("kid") if isinstance(k.get("kid"), str) else None
            break
    if not res.signature_valid:
        res.errors.append("signature does not verify against the supplied key(s)")
        return res
    # structure
    if issuer and claims.get("iss") != issuer:
        res.errors.append(f"issuer is '{show(claims.get('iss'))}', expected '{issuer}'")
    if res.kind == "receipt" and claims.get("aud") != "regent-receipt":
        res.errors.append("receipt audience must be 'regent-receipt'")
    exp = claims.get("exp")
    if _is_number(exp):
        res.expired = exp < now
        if res.expired:
            if res.kind == "receipt":
                res.errors.append("receipt is past its evidence period (exp)")
            else:
                res.warnings.append("token expired (allow tokens live about a minute; signature and binding still verify)")
    iat = claims.get("iat")
    if _is_number(iat) and iat > now + 300:
        res.errors.append("issued in the future (iat)")
    return res


# ── request binding (args_hash) ───────────────────────────────────────────────

def canonical_args_hash(tool: str, action: str, resource: str | None, args: dict[str, Any] | None) -> str:
    """Byte-identical to the gate: sha256 over canonical JSON of {tool, action, resource, args}."""
    canonical = json.dumps({"tool": tool, "action": action, "resource": resource, "args": args or {}},
                           sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def check_request_binding(claims: dict[str, Any], *, tool: str, action: str, resource: str | None = None,
                          args: dict[str, Any] | None = None) -> bool:
    expected = claims.get("args_hash")
    return bool(expected) and hmac.compare_digest(canonical_args_hash(tool, action, resource, args), str(expected))


# ── mandate terms (terms-v2 / terms-v3) ───────────────────────────────────────
# terms-v3 (2026-10-13) appends allowed_resources: the mandate's scope (tool names or
# resource prefixes), comma-joined in stored order. A reveal says which canon it is; a
# snapshot that names allowed_resources is v3 when it does not.
MANDATE_FIELDS_V2 = ("mandate_id", "version", "agent_id", "owner_id", "currency", "settlement_chain", "status",
                     "per_tx_limit", "daily_limit", "monthly_limit", "per_entity_limit", "entity_key", "relational_cap",
                     "expires_at", "agent_may_read_limits")
MANDATE_FIELDS_V3 = (*MANDATE_FIELDS_V2, "allowed_resources")
# terms-v4 (2026-10-15) appends entity_limits: caps per counterparty as canonical strings
# "<match>=<per_tx|none>;<monthly|none>[;<daily>]", sorted, comma-joined like the scope;
# the third field appears only where the owner set a daily figure.
MANDATE_FIELDS_V4 = (*MANDATE_FIELDS_V3, "entity_limits")
MANDATE_FIELDS = MANDATE_FIELDS_V4
_MANDATE_CANONS = {"terms-v2": MANDATE_FIELDS_V2, "terms-v3": MANDATE_FIELDS_V3, "terms-v4": MANDATE_FIELDS_V4}


class _NotCanonical(ValueError):
    """A snapshot value of a type the canonical string does not define."""


def _cv(value: Any) -> str:
    """One snapshot value in the canonical string: none, true, false, text, a number as
    JavaScript prints it, or a list of texts joined by commas. Anything else is not part of
    the format, and a reveal that carries it matches nothing (in both languages alike)."""
    if value is None:
        return "none"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str) and _wf(value):
        return value
    if _finite_number(value):
        return number_text(value)
    if isinstance(value, list) and all(_wf(v) for v in value):
        return ",".join(value)
    raise _NotCanonical("snapshot value of another type")


def mandate_canon(snapshot: dict[str, Any], canon: str | None = None) -> str:
    if canon in _MANDATE_CANONS:
        return canon
    if "entity_limits" in snapshot:
        return "terms-v4"
    return "terms-v3" if "allowed_resources" in snapshot else "terms-v2"


def mandate_canonical_string(snapshot: dict[str, Any], salt: str, canon: str | None = None) -> str:
    c = mandate_canon(snapshot, canon)
    return "|".join([c, *(f"{n}={_cv(snapshot.get(n))}" for n in _MANDATE_CANONS[c]), f"salt={salt}"])


def mandate_commitment(snapshot: dict[str, Any], salt: str, canon: str | None = None) -> str:
    return hashlib.sha256(mandate_canonical_string(snapshot, salt, canon).encode("utf-8")).hexdigest()


def check_mandate_reveal(claims: dict[str, Any], reveal: dict[str, Any]) -> bool:
    """`reveal` = the owner's version object ({snapshot, salt, ...}) or {snapshot, salt}.
    Values of a type the format does not define match nothing; this never raises."""
    if not isinstance(claims, dict) or not isinstance(reveal, dict):
        return False
    expected, salt = claims.get("mandate_hash"), reveal.get("salt")
    snap = reveal.get("snapshot") if isinstance(reveal.get("snapshot"), dict) else reveal
    if not (isinstance(expected, str) and _HEX64.fullmatch(expected) and _wf(salt) and salt):
        return False
    if snap.get("version") is not None and claims.get("mandate_version") is not None:
        mine, theirs = _whole(snap.get("version")), _whole(claims.get("mandate_version"))
        if mine is None or theirs is None or mine != theirs:
            return False
    canon = reveal.get("canon") if isinstance(reveal.get("canon"), str) else None
    try:
        got = mandate_commitment(snap, _lower_ascii(salt), canon)
    except _NotCanonical:
        return False
    return hmac.compare_digest(got, expected.lower())


# ── payee (payee-v1) ──────────────────────────────────────────────────────────

def payee_canonical_string(payee: str, salt: str) -> str:
    return f"payee-v1|payee={payee}|salt={_lower_ascii(salt)}"


def payee_commitment(payee: str, salt: str) -> str:
    return hashlib.sha256(payee_canonical_string(payee, salt).encode("utf-8")).hexdigest()


def check_payee_reveal(claims: dict[str, Any], reveal: dict[str, Any]) -> bool:
    """`reveal` = the owner's {payee, salt} for this decision (GET …/decisions/{id}/payee-reveal).
    The receipt carries `payee_hash` (+ `payee_commit: payee-v1`); the clear `payee` may or
    may not be beside it. A reveal that names another decision is refused outright."""
    if not isinstance(claims, dict) or not isinstance(reveal, dict):
        return False
    expected, payee, salt = claims.get("payee_hash"), reveal.get("payee"), reveal.get("salt")
    if not (isinstance(expected, str) and _HEX64.fullmatch(expected) and _wf(payee) and payee and _wf(salt) and salt):
        return False
    if _given(reveal.get("decision_id")) and _given(claims.get("decision_id")) and not _same(reveal["decision_id"], claims["decision_id"]):
        return False
    return hmac.compare_digest(payee_commitment(payee, _lower_ascii(salt)), expected.lower())


# ── policy (policy-v1) ────────────────────────────────────────────────────────

class _NotPortable(ValueError):
    pass


def _portable(value: Any, depth: int = 0) -> Any:
    if depth > 64:
        raise _NotPortable("nested too deeply")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        if not _wf(value):
            raise _NotPortable("text that is not valid")
        return value
    if _is_number(value):
        w = _whole(value)
        if w is None:
            raise _NotPortable("a number other than a whole number within 2**53 - 1")
        return w   # 40.0 is 40, as JavaScript reads it
    if isinstance(value, list):
        return [_portable(v, depth + 1) for v in value]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if not (_wf(k) and all(ord(ch) <= 0xFFFF for ch in k)):
                raise _NotPortable("a key outside the basic plane")
            out[k] = _portable(v, depth + 1)
        return out
    raise _NotPortable("a value of another type")


def _profile(profile: dict[str, Any]) -> dict[str, Any] | None:
    """A policy profile both languages hash to the same bytes: text, booleans, null, whole
    numbers within 2**53 - 1, lists and objects of those, keys inside the basic plane. A
    profile with anything else (a fraction, 1e16, a key above U+FFFF) matches nothing."""
    try:
        return _portable(profile)
    except _NotPortable:
        return None


def _text_digest(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def policy_canonical_string(org_id: str, version: int, cedar_text: str, profile: dict[str, Any] | None, salt: str) -> str:
    prof = None if profile is None else hashlib.sha256(
        json.dumps(profile, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
    return "|".join(["policy-v1", f"org_id={org_id}", f"version={int(version)}", f"text_sha256={_text_digest(cedar_text)}",
                     f"profile_sha256={prof if prof is not None else 'none'}", f"salt={salt}"])


def policy_commitment(org_id: str, version: int, cedar_text: str, profile: dict[str, Any] | None, salt: str) -> str:
    return hashlib.sha256(policy_canonical_string(org_id, version, cedar_text, profile, salt).encode("utf-8")).hexdigest()


def check_policy_reveal(claims: dict[str, Any], reveal: dict[str, Any] | str) -> bool:
    """`reveal` = the org's version object ({org_id, version, cedar_text, profile, salt}); for a
    starter-pack or legacy decision the Cedar text alone (str or {cedar_text})."""
    if not isinstance(claims, dict):
        return False
    expected = claims.get("policy_hash")
    if not (isinstance(expected, str) and _HEX64.fullmatch(expected)):
        return False
    if isinstance(reveal, str):
        reveal = {"cedar_text": reveal}
    if not isinstance(reveal, dict):
        return False
    text = reveal.get("cedar_text") if isinstance(reveal.get("cedar_text"), str) else reveal.get("cedar")
    if not _wf(text):
        return False
    if claims.get("policy_source") in ("starter", "legacy"):
        return hmac.compare_digest(_text_digest(text), expected.lower())
    version = _whole(reveal["version"] if reveal.get("version") is not None else claims.get("policy_version"))
    org_id, salt = reveal.get("org_id"), reveal.get("salt")
    if version is None or not (org_id is None or _wf(org_id)) or not (salt is None or _wf(salt)):
        return False
    profile = reveal.get("profile") if isinstance(reveal.get("profile"), dict) else None
    if profile is not None:
        profile = _profile(profile)
        if profile is None:
            return False
    try:
        got = policy_commitment(org_id or "", version, text, profile, _lower_ascii(salt or ""))
    except (TypeError, ValueError, RecursionError):
        return False
    return hmac.compare_digest(got, expected.lower())


# ── where the money went: settlement_ref / settlement_network (0.7.0) ─────────
#
# A receipt whose settlement Regent read from the rail itself (`settlement_source:
# custodian` for a custodian's ledger, `counterparty` for a signed confirmation) may carry
# `settlement_ref`: the rail's own reference for the settled money — a chain transaction
# hash, a PSP charge id — and, when that reference lives on a chain, `settlement_network`.
# They are signed claims like any other: the verifier shows them, you look them up on the
# rail. A receipt for a failed or voided settlement never carries them.

# ── counterparty settlement confirmation ──────────────────────────────────────
#
# A receipt whose settlement was confirmed by the other side of the payment carries
# `settlement_source: counterparty`, `confirmed_by` (the counterparty's issuer URL),
# `confirmation_kid`, `confirmation_hash` (sha256 of the JWS) and `confirmation`: the
# counterparty's compact JWS itself (typ settlement-confirmation+jwt; ES256, EdDSA, RS256 or
# PS256). Regent verified it when the receipt was minted; with the counterparty's JWKS you can
# repeat that check yourself, offline, and so hold two signatures over the same facts.

CONFIRMATION_TYP = "settlement-confirmation+jwt"
CONFIRMATION_ALGS = ("ES256", "EdDSA", "RS256", "PS256")


@dataclass
class ConfirmationCheck:
    ok: bool
    errors: list[str] = field(default_factory=list)
    issuer: str | None = None
    kid: str | None = None
    claims: dict[str, Any] = field(default_factory=dict)


def _jws_signature_ok(alg: str, key: Any, signed: bytes, sig: bytes) -> bool:
    try:
        if alg == "ES256":
            if len(sig) != 64:
                return False
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            key.verify(der, signed, ec.ECDSA(hashes.SHA256()))
        elif alg == "EdDSA":
            key.verify(sig, signed)
        elif alg == "RS256":
            key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
        elif alg == "PS256":
            key.verify(sig, signed, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError, AttributeError):
        return False


def check_confirmation(claims: dict[str, Any], counterparty_jwks: Any, *, now: float | None = None) -> ConfirmationCheck:
    """Verify the counterparty confirmation embedded in a receipt against the counterparty's JWKS
    and check it says the same as the receipt. `claims` are the (already verified) receipt claims.
    Never raises on bad input."""
    out = ConfirmationCheck(False)
    try:
        _check_confirmation(out, claims, counterparty_jwks, now)
    except Exception as exc:  # noqa: BLE001 — a verifier answers "does not match", it does not crash
        out.errors.append(f"the confirmation could not be read ({type(exc).__name__})")
    out.ok = not out.errors
    return out


def _check_confirmation(out: ConfirmationCheck, claims: Any, counterparty_jwks: Any, now: Any) -> None:
    claims = claims if isinstance(claims, dict) else {}
    jws = claims.get("confirmation")
    if not isinstance(jws, str) or jws.count(".") != 2:
        out.errors.append("the receipt carries no counterparty confirmation (settlement is agent-reported)")
        return
    if now is not None and not _finite_number(now):
        out.errors.append("now is not a finite number of seconds")
        return
    try:
        header, payload, signature, signed = compact_jws(jws)   # the one strict reader: no NaN, no BOM, one spelling
    except Malformed as exc:
        out.errors.append(f"cannot decode the confirmation: {exc}")
        return
    out.claims, out.kid, out.issuer = payload, header.get("kid"), payload.get("iss")
    if header.get("typ") != CONFIRMATION_TYP:
        out.errors.append(f"confirmation typ is '{show(header.get('typ'))}', expected '{CONFIRMATION_TYP}'")
    alg = header.get("alg")
    if alg not in CONFIRMATION_ALGS:
        out.errors.append(f"unsupported confirmation alg '{show(alg)}'")
        return
    candidates = [k for k in _keys(counterparty_jwks) if out.kid is None or k.get("kid") == out.kid]
    if not candidates:
        out.errors.append(f"no key with kid '{show(out.kid)}' in the counterparty JWKS you supplied")
        return
    sig_ok = False
    for k in candidates:
        try:
            key = confirmation_key(k, alg)   # the one key type this algorithm uses, read strictly
        except Malformed:
            continue
        if _jws_signature_ok(alg, key, signed, signature):
            sig_ok, out.kid = True, k.get("kid")
            break
    if not sig_ok:
        out.errors.append("confirmation signature does not verify against the counterparty key(s)")
        return
    # the confirmation must be the one the receipt cites, about this decision, saying the same thing
    expected_hash = claims.get("confirmation_hash")
    if _given(expected_hash) and not (isinstance(expected_hash, str) and _HEX64.fullmatch(expected_hash) and hmac.compare_digest(
            hashlib.sha256(jws.encode("ascii")).hexdigest(), expected_hash.lower())):
        out.errors.append("confirmation_hash in the receipt does not match the embedded confirmation")
    if _given(claims.get("confirmed_by")) and not _same(payload.get("iss"), claims.get("confirmed_by")):
        out.errors.append(f"confirmation issuer '{show(payload.get('iss'))}' differs from the receipt's confirmed_by")
    if _given(claims.get("confirmation_kid")) and not _same(out.kid, claims.get("confirmation_kid")):
        out.errors.append("confirmation kid differs from the receipt's confirmation_kid")
    if not _same(payload.get("decision_id"), claims.get("decision_id")):
        out.errors.append("the confirmation is about another decision")
    if not _same(payload.get("status"), claims.get("status")):
        out.errors.append(f"confirmation status '{show(payload.get('status'))}' differs from the receipt's '{show(claims.get('status'))}'")
    p_amount, r_amount = payload.get("amount"), claims.get("amount")
    if p_amount is not None and r_amount is not None:
        p, r = _amount(p_amount), _amount(r_amount)
        if p is None or r is None:
            out.errors.append("confirmation amount is not a number")
        elif abs(p - r) > 0.01:
            out.errors.append(f"confirmation amount {_amount_text(p_amount)} differs from the receipt's {_amount_text(r_amount)}")
        cp, cr = _upper_ascii(payload.get("currency")), _upper_ascii(claims.get("currency"))
        if not (isinstance(cp, str) and isinstance(cr, str) and cp == cr):
            out.errors.append("confirmation currency differs from the receipt's")
    # time: the confirmation had to be live when Regent accepted it, i.e. at the receipt's iat
    iat_r = claims.get("iat")
    accepted_at = iat_r if _finite_number(iat_r) else (time.time() if now is None else now)
    exp, iat = payload.get("exp"), payload.get("iat")
    if _finite_number(exp) and exp < accepted_at:
        out.errors.append("the confirmation had already expired when the receipt was minted")
    if _finite_number(iat) and iat > accepted_at + 300:
        out.errors.append("the confirmation was issued after the receipt")


# ── one call for everything ───────────────────────────────────────────────────

def verify(token: str, jwks: Any, *, request: dict[str, Any] | None = None, mandate_reveal: dict[str, Any] | None = None,
           policy_reveal: dict[str, Any] | str | None = None, counterparty_jwks: Any = None, now: float | None = None,
           issuer: str | None = "regent-control", payee_reveal: dict[str, Any] | None = None) -> VerificationResult:
    res = verify_token(token, jwks, now=now, issuer=issuer)
    if not res.signature_valid:
        return res
    for name, given in (("request", request), ("mandate reveal", mandate_reveal), ("payee reveal", payee_reveal)):
        if given is not None and not isinstance(given, dict):
            res.errors.append(f"the {name} is not a JSON object")
    if policy_reveal is not None and not isinstance(policy_reveal, (dict, str)):
        res.errors.append("the policy reveal is not a JSON object or text")
    request = request if isinstance(request, dict) else None
    mandate_reveal = mandate_reveal if isinstance(mandate_reveal, dict) else None
    payee_reveal = payee_reveal if isinstance(payee_reveal, dict) else None
    policy_reveal = policy_reveal if isinstance(policy_reveal, (dict, str)) else None
    if request is not None:
        res.args_hash_match = check_request_binding(res.claims, tool=request.get("tool", ""), action=request.get("action", ""),
                                                    resource=request.get("resource"), args=request.get("args"))
    if mandate_reveal is not None:
        res.mandate_match = check_mandate_reveal(res.claims, mandate_reveal)
    if policy_reveal is not None:
        res.policy_match = check_policy_reveal(res.claims, policy_reveal)
    if payee_reveal is not None:
        res.payee_match = check_payee_reveal(res.claims, payee_reveal)
    if counterparty_jwks is not None:
        c = check_confirmation(res.claims, counterparty_jwks, now=now)
        res.confirmation_match, res.confirmation_errors = c.ok, c.errors
        res.confirmation = c.claims if c.ok else None
    return res


def verify_bundle(bundle, **kw):  # noqa: ANN001, ANN201 — thin re-export, see bundle.py
    """Verify an evidence bundle (regent-evidence-bundle/1). See `regent_receipt_verify.bundle`."""
    from .bundle import verify_bundle as _vb
    return _vb(bundle, **kw)


def BundleResult():  # noqa: N802 — re-export for `from regent_receipt_verify import BundleResult`
    from .bundle import BundleResult as _BR
    return _BR

