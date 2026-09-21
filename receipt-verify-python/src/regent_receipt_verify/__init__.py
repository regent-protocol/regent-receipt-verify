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
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

__version__ = "0.1.0"
__all__ = [
    "VerificationResult", "verify_token", "verify", "canonical_args_hash", "check_request_binding",
    "mandate_commitment", "check_mandate_reveal", "policy_commitment", "check_policy_reveal",
]


# ── JWS ───────────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_uint(s: str) -> int:
    return int.from_bytes(_b64url_decode(s), "big")


def _keys(jwks: Any) -> list[dict[str, Any]]:
    """Accept a JWKS dict, a list of JWKS dicts (key rotation), or a list of JWKs."""
    if isinstance(jwks, dict) and "keys" in jwks:
        return list(jwks["keys"])
    if isinstance(jwks, dict):
        return [jwks]
    out: list[dict[str, Any]] = []
    for item in jwks or []:
        out.extend(_keys(item))
    return out


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

    @property
    def valid(self) -> bool:
        """Authentic and, for a receipt, still inside its evidence period."""
        return self.signature_valid and not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid, "signature_valid": self.signature_valid, "kind": self.kind, "kid": self.kid,
            "expired": self.expired, "args_hash_match": self.args_hash_match, "mandate_match": self.mandate_match,
            "policy_match": self.policy_match, "errors": self.errors, "warnings": self.warnings,
            "header": self.header, "claims": self.claims,
        }


def _kind(header: dict[str, Any], claims: dict[str, Any]) -> str:
    typ = str(header.get("typ") or "")
    if typ == "receipt+jwt" or claims.get("aud") == "regent-receipt":
        return "receipt"
    if typ == "aa-auth+jwt" or "budget" in claims:
        return "budget"
    if "scope" in claims and "decision_id" in claims:
        return "allow"
    return "unknown"


def verify_token(token: str, jwks: Any, *, now: float | None = None, issuer: str | None = "regent-control") -> VerificationResult:
    """Signature + structure. Returns a result even for invalid tokens (never raises on bad input)."""
    now = time.time() if now is None else now
    parts = token.strip().split(".")
    if len(parts) != 3:
        return VerificationResult(False, "unknown", errors=["not a compact JWS (expected header.payload.signature)"])
    try:
        header = json.loads(_b64url_decode(parts[0]))
        claims = json.loads(_b64url_decode(parts[1]))
        signature = _b64url_decode(parts[2])
    except Exception as exc:  # noqa: BLE001
        return VerificationResult(False, "unknown", errors=[f"cannot decode token: {exc}"])
    res = VerificationResult(False, _kind(header, claims), header=header, claims=claims, kid=header.get("kid"))
    if header.get("alg") != "RS256":
        res.errors.append(f"unsupported alg {header.get('alg')!r} (Regent signs RS256)")
        return res
    candidates = [k for k in _keys(jwks) if k.get("kty") == "RSA" and (res.kid is None or k.get("kid") == res.kid)]
    if not candidates:
        res.errors.append(f"no RSA key with kid {res.kid!r} in the JWKS you supplied")
        return res
    signed = f"{parts[0]}.{parts[1]}".encode("ascii")
    for k in candidates:
        try:
            pub = rsa.RSAPublicNumbers(_b64url_uint(k["e"]), _b64url_uint(k["n"])).public_key()
            pub.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
            res.signature_valid = True
            res.kid = k.get("kid")
            break
        except (InvalidSignature, ValueError, KeyError):
            continue
    if not res.signature_valid:
        res.errors.append("signature does not verify against the supplied key(s)")
        return res
    # structure
    if issuer and claims.get("iss") != issuer:
        res.errors.append(f"issuer is {claims.get('iss')!r}, expected {issuer!r}")
    if res.kind == "receipt" and claims.get("aud") != "regent-receipt":
        res.errors.append("receipt audience must be 'regent-receipt'")
    exp = claims.get("exp")
    if isinstance(exp, (int, float)):
        res.expired = exp < now
        if res.expired:
            if res.kind == "receipt":
                res.errors.append("receipt is past its evidence period (exp)")
            else:
                res.warnings.append("token expired (allow tokens live about a minute; signature and binding still verify)")
    iat = claims.get("iat")
    if isinstance(iat, (int, float)) and iat > now + 300:
        res.errors.append("issued in the future (iat)")
    if res.kind == "allow" and "scope" in claims and claims.get("scope") != f"{claims.get('aud')}:{claims.get('scope','').split(':', 1)[-1]}":
        res.warnings.append("scope does not start with the audience tool")
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


# ── mandate terms (terms-v2) ──────────────────────────────────────────────────

MANDATE_FIELDS = ("mandate_id", "version", "agent_id", "owner_id", "currency", "settlement_chain", "status",
                  "per_tx_limit", "daily_limit", "monthly_limit", "per_entity_limit", "entity_key", "relational_cap",
                  "expires_at", "agent_may_read_limits")


def _cv(value: Any) -> str:
    if value is None:
        return "none"
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def mandate_canonical_string(snapshot: dict[str, Any], salt: str) -> str:
    return "|".join(["terms-v2", *(f"{n}={_cv(snapshot.get(n))}" for n in MANDATE_FIELDS), f"salt={salt}"])


def mandate_commitment(snapshot: dict[str, Any], salt: str) -> str:
    return hashlib.sha256(mandate_canonical_string(snapshot, salt).encode("utf-8")).hexdigest()


def check_mandate_reveal(claims: dict[str, Any], reveal: dict[str, Any]) -> bool:
    """`reveal` = the owner's version object ({snapshot, salt, ...}) or {snapshot, salt}."""
    expected = str(claims.get("mandate_hash") or "")
    snap = reveal.get("snapshot") if isinstance(reveal.get("snapshot"), dict) else reveal
    salt = str(reveal.get("salt") or "")
    if not expected or not salt:
        return False
    if "version" in snap and claims.get("mandate_version") is not None and int(snap["version"]) != int(claims["mandate_version"]):
        return False
    return hmac.compare_digest(mandate_commitment(snap, salt.lower()), expected.lower())


# ── policy (policy-v1) ────────────────────────────────────────────────────────

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
    expected = str(claims.get("policy_hash") or "")
    if not expected:
        return False
    if isinstance(reveal, str):
        reveal = {"cedar_text": reveal}
    text = reveal.get("cedar_text") if isinstance(reveal.get("cedar_text"), str) else reveal.get("cedar")
    if not isinstance(text, str):
        return False
    if claims.get("policy_source") in ("starter", "legacy"):
        return hmac.compare_digest(_text_digest(text), expected.lower())
    try:
        version = reveal["version"] if reveal.get("version") is not None else claims.get("policy_version")
        got = policy_commitment(str(reveal.get("org_id") or ""), int(version), text,
                                reveal.get("profile") if isinstance(reveal.get("profile"), dict) else None,
                                str(reveal.get("salt") or "").lower())
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(got, expected.lower())


# ── one call for everything ───────────────────────────────────────────────────

def verify(token: str, jwks: Any, *, request: dict[str, Any] | None = None, mandate_reveal: dict[str, Any] | None = None,
           policy_reveal: dict[str, Any] | str | None = None, now: float | None = None,
           issuer: str | None = "regent-control") -> VerificationResult:
    res = verify_token(token, jwks, now=now, issuer=issuer)
    if not res.signature_valid:
        return res
    if request is not None:
        res.args_hash_match = check_request_binding(res.claims, tool=request.get("tool", ""), action=request.get("action", ""),
                                                    resource=request.get("resource"), args=request.get("args"))
    if mandate_reveal is not None:
        res.mandate_match = check_mandate_reveal(res.claims, mandate_reveal)
    if policy_reveal is not None:
        res.policy_match = check_policy_reveal(res.claims, policy_reveal)
    return res
