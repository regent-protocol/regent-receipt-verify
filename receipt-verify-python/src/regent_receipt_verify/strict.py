"""Strict readers shared by every check in this package.

A verifier is handed files written by whoever wants a particular answer, and its output is
read by a person in a dispute. So input is read one way only: the base64url alphabet in its
canonical spelling, UTF-8, JSON without NaN or Infinity, numbers a double holds exactly,
bounded depth, a compact JWS with nothing around or inside it, RSA keys of the profile
Regent signs with (e = 65537, 2048 to 8192 bits). The Node verifier reads the same way, so
the two give the same answer for the same bytes. Malformed input raises `Malformed`, which
every caller turns into an INVALID result, never into an exception for the user.

This module imports nothing from the rest of the package.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any

_HEX64 = re.compile(r"[0-9a-f]{64}")
_B64U = re.compile(r"[A-Za-z0-9_-]*")
_SAFE_INT = 2**53 - 1
_MAX_DEPTH = 64


class Malformed(ValueError):
    """Input that is not what the format allows. Always becomes an INVALID result."""


# ── strict readers ───────────────────────────────────────────────────────────────────────


def _str(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise Malformed(f"{what} is not a string")
    return value


def _b64u(value: Any, what: str) -> bytes:
    """base64url in its one canonical spelling: the URL-safe alphabet, no padding, no
    stray bits in the last character. Two spellings of the same bytes would let two
    programs disagree about one file."""
    text = _str(value, what)
    if not _B64U.fullmatch(text) or len(text) % 4 == 1:
        raise Malformed(f"{what} is not base64url")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError as exc:
        raise Malformed(f"{what} is not base64url") from exc
    if _b64u_enc(data) != text:
        raise Malformed(f"{what} is not base64url")
    return data


def _b64u_enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


_BAD_NUMBER = "JSON carries a number a double does not hold exactly"


def _refuse_constant(name: str) -> Any:
    raise ValueError("NaN and Infinity are not JSON")


def _int(text: str) -> Any:
    # far beyond 2**53: read as the double another language reads it as (an infinity past
    # 1e308), so two long integers that differ still differ and one compared with itself is
    # itself; _check_values refuses it where exactness is required. This also keeps Python's
    # own limit on the digits of an integer out of the way.
    return int(text) if len(text) <= 20 else float(text)


def _check_values(value: Any, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        raise Malformed("JSON is nested too deeply")
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, (int, float)):
        if value != value or abs(value) > _SAFE_INT:
            raise Malformed(_BAD_NUMBER)
        return
    if isinstance(value, list):
        for item in value:
            _check_values(item, depth + 1)
        return
    if isinstance(value, dict):
        for item in value.values():
            _check_values(item, depth + 1)
        return
    raise Malformed("JSON carries an unknown value")


def _parse(text: Any, what: str) -> tuple[Any, bytes]:
    """(object, bytes) from a canonical string: strict UTF-8, JSON without NaN or Infinity,
    integers a double can hold, bounded depth."""
    text = _str(text, what)
    if not text:
        raise Malformed(f"{what} is empty")
    try:
        raw = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise Malformed(f"{what} is not valid text") from exc
    try:
        obj = json.loads(text, parse_constant=_refuse_constant, parse_int=_int)
    except Malformed:
        raise
    except RecursionError as exc:
        raise Malformed("JSON is nested too deeply") from exc
    except ValueError as exc:
        raise Malformed(f"{what} is not JSON") from exc
    _check_values(obj)
    return obj, raw


def _as_double(x: Any) -> float:
    """A number as the double another language reads it as (an integer too large for one
    is an infinity there)."""
    try:
        return float(x)
    except OverflowError:
        return float("inf") if x > 0 else float("-inf")


def _same(a: Any, b: Any, depth: int = 0) -> bool:
    """Equality as JSON means it: true is not 1, a number equals a number of the same
    value whatever its spelling (1200 and 1200.0), everything else exactly."""
    if depth > _MAX_DEPTH:
        return False
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return _as_double(a) == _as_double(b)
    if a is None or b is None or isinstance(a, str) or isinstance(b, str):
        return type(a) is type(b) and a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same(x, y, depth + 1) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_same(a[k], b[k], depth + 1) for k in a)
    return False


# ── a compact JWS and the RSA keys of a JWKS, read one way ───────────────────────────────

_JWS = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def json_object(raw: bytes, what: str) -> dict[str, Any]:
    """Bytes that are one JSON object in UTF-8: no byte order mark, no NaN, numbers a
    double holds exactly, bounded depth."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Malformed(f"{what} is not UTF-8") from exc
    if text.startswith("\ufeff"):
        raise Malformed(f"{what} starts with a byte order mark")
    obj, _ = _parse(text, what)
    if not isinstance(obj, dict):
        raise Malformed(f"{what} is not a JSON object")
    return obj


def compact_jws(token: Any) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """(header, claims, signature, signed bytes) of `header.payload.signature`. Only spaces,
    tabs and line ends around the token are ignored (a token saved to a file ends with
    one); inside it every character is base64url, canonical and unpadded."""
    text = _str(token, "token").strip(" \t\r\n")
    if not _JWS.fullmatch(text):
        raise Malformed("not a compact JWS (expected header.payload.signature)")
    h, p, sig = text.split(".")
    header = json_object(_b64u(h, "header"), "header")
    claims = json_object(_b64u(p, "payload"), "payload")
    kid = header.get("kid")
    if kid is not None and not isinstance(kid, str):
        raise Malformed("kid is not a string")
    return header, claims, _b64u(sig, "signature"), f"{h}.{p}".encode("ascii")


MAX_KEYS = 16      # keys read from one key set: a set of thousands is a way to spend time, not a key set


def jwk_list(jwks: Any) -> list[dict[str, Any]]:
    """The key objects of a JWKS, of one JWK, or of a list of those (key rotation): the
    first MAX_KEYS of them. What is not an object is skipped; nothing here raises or recurses."""
    out: list[dict[str, Any]] = []
    for item in (jwks if isinstance(jwks, list) else [jwks])[:MAX_KEYS]:
        if not isinstance(item, dict):
            continue
        if "keys" in item:
            if isinstance(item["keys"], list):
                out.extend(k for k in item["keys"][:MAX_KEYS] if isinstance(k, dict))
        else:
            out.append(item)
    return out[:MAX_KEYS]


def rs256_ok(jwk: dict[str, Any], signed: bytes, signature: bytes) -> bool:
    """RS256 with one RSA key of a JWKS. The key must be of the profile Regent signs with
    (e = 65537, 2048 to 8192 bits); any other key verifies nothing."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    try:
        n = int.from_bytes(_b64u(jwk.get("n"), "n"), "big")
        e = int.from_bytes(_b64u(jwk.get("e"), "e"), "big")
    except Malformed:
        return False
    if e != 65537 or not 2048 <= n.bit_length() <= 8192 or n % 2 == 0:
        return False
    try:
        rsa.RSAPublicNumbers(e, n).public_key().verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def show(value: Any) -> str:
    """A value inside a message, spelled the same in every language: a string as it is,
    anything else as compact JSON the way JSON.stringify writes it, cut at 120 characters."""
    if isinstance(value, str):
        return value
    try:
        return js_json(value)[:120]
    except (TypeError, ValueError, RecursionError):
        return "?"


def string_list(value: Any, what: str) -> list[str] | None:
    """An option that must be a list of strings (None = not given). A bare string would
    match by substring, which is not what anyone passing one means."""
    if value is None:
        return None
    if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) for v in value):
        raise Malformed(f"{what} must be a list of strings")
    return list(value)


def _plain(value: Any, limit: int = 120) -> str | None:
    """A short string of ordinary printable characters, or None. What the block merely
    says is returned for a reader to see; a value that carries a line break, an escape
    sequence or any other control character is dropped, so nothing it says can be dressed
    up as a line of this verifier's own output."""
    if not isinstance(value, str) or not value or len(value) > limit:
        return None
    return None if any(unprintable(ord(ch)) for ch in value) else value


def unprintable(code: int) -> bool:
    """A code point that must not reach a terminal or a page as it is: C0 and C1 controls,
    DEL, lone surrogates, line and paragraph separators, and the invisible characters that
    reorder or hide text (bidirectional controls, zero-width and other default-ignorable
    characters, the BOM)."""
    return (code < 0x20 or 0x7F <= code <= 0x9F or code == 0xAD or code == 0x034F or 0xD800 <= code <= 0xDFFF
            or code == 0x061C or 0x115F <= code <= 0x1160 or 0x17B4 <= code <= 0x17B5 or 0x180B <= code <= 0x180F
            or 0x200B <= code <= 0x200F or 0x2028 <= code <= 0x202E or 0x2060 <= code <= 0x206F or code == 0x3164
            or 0xFE00 <= code <= 0xFE0F or code == 0xFEFF or code == 0xFFA0 or 0xFFF0 <= code <= 0xFFFB
            or 0x1BCA0 <= code <= 0x1BCA3 or 0x1D173 <= code <= 0x1D17A or 0xE0000 <= code <= 0xE0FFF)


# ── numbers and JSON as JavaScript prints them ──────────────────────────────────────────
# The Node twin prints with String(x) and JSON.stringify. These two functions print the same
# text for the same value, so that one file gets one answer, word for word.

_SAFE_PRINT = 2**53


def number_text(value: Any) -> str:
    """A JSON number as JavaScript's Number::toString prints it: 9000.0 is 9000, 0.00001 is
    0.00001, 1e-7 is 1e-7, 1e21 is 1e+21, and an integer beyond 2**53 is the double it reads
    as there. Not a number: the empty string."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return ""
    if isinstance(value, int) and abs(value) <= _SAFE_PRINT:
        return str(value)
    try:
        x = float(value)
    except OverflowError:
        return "-Infinity" if value < 0 else "Infinity"
    if x != x:
        return "NaN"
    if x in (float("inf"), float("-inf")):
        return "Infinity" if x > 0 else "-Infinity"
    if x == 0:
        return "0"
    mantissa, _, exp = repr(abs(x)).partition("e")   # repr: the shortest digits that read back as x
    whole, _, frac = mantissa.partition(".")
    raw = whole + frac
    digits = raw.lstrip("0")
    n = len(whole) + int(exp or 0) - (len(raw) - len(digits))   # x = 0.digits × 10**n
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * -n + digits
    else:
        e = n - 1
        text = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return ("-" if x < 0 else "") + text


_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
_ARRAY_INDEX = re.compile(r"0|[1-9][0-9]*")


def _js_string(text: str) -> str:
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif code < 0x20 or 0xD800 <= code <= 0xDFFF:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _js_keys(obj: dict[Any, Any]) -> list[Any]:
    """Keys in the order JavaScript keeps them: array indexes ascending, then the rest as inserted."""
    index = [k for k in obj if isinstance(k, str) and _ARRAY_INDEX.fullmatch(k) and int(k) < 2**32 - 1]
    seen = set(index)
    return sorted(index, key=int) + [k for k in obj if k not in seen]


def js_json(value: Any, indent: int | None = None, _level: int = 0) -> str:
    """JSON text as JSON.stringify(value, null, indent) writes it."""
    if _level > 1024:
        raise ValueError("nested too deeply")
    pad = "" if indent is None else "\n" + " " * (indent * (_level + 1))
    end = "" if indent is None else "\n" + " " * (indent * _level)
    colon = ":" if indent is None else ": "
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        text = number_text(value)
        return "null" if text in ("NaN", "Infinity", "-Infinity", "") else text
    if isinstance(value, str):
        return _js_string(value)
    if isinstance(value, (list, tuple)):
        if not value:
            return "[]"
        return "[" + ",".join(pad + js_json(v, indent, _level + 1) for v in value) + end + "]"
    if isinstance(value, dict):
        if not value:
            return "{}"
        return "{" + ",".join(pad + _js_string(str(k)) + colon + js_json(value[k], indent, _level + 1)
                              for k in _js_keys(value)) + end + "}"
    return _js_string(str(value))


# ── a counterparty's key, read one way ──────────────────────────────────────────────────
# A confirmation names its algorithm; the key must be of the one type that algorithm uses,
# read from strict base64url, and of a sound size. Anything else verifies nothing: a key the
# Node twin would accept and this program would not (or the other way round) gives one
# receipt two answers, and an RSA key with e = 1 makes a "signature" anyone can compute.

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_ED25519_SMALL_ORDER = {bytes.fromhex(h) for h in (
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
)}


def confirmation_key(jwk: Any, alg: Any) -> Any:
    """The public key of one JWK for one algorithm: ES256 needs EC P-256 (x, y of 32 bytes,
    on the curve), EdDSA needs OKP Ed25519 (x of 32 bytes, not of small order), RS256 and
    PS256 need RSA with e = 65537 and a modulus of 2048 to 8192 bits. Raises Malformed."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    if not isinstance(jwk, dict):
        raise Malformed("key is not an object")
    kty = jwk.get("kty")
    if alg == "ES256":
        if kty != "EC" or jwk.get("crv") != "P-256":
            raise Malformed("ES256 needs an EC P-256 key")
        x, y = _b64u(jwk.get("x"), "x"), _b64u(jwk.get("y"), "y")
        if len(x) != 32 or len(y) != 32:
            raise Malformed("EC key without 32-byte coordinates")
        xi, yi = int.from_bytes(x, "big"), int.from_bytes(y, "big")
        if xi >= _P256_P or yi >= _P256_P:
            raise Malformed("EC point is not on the curve")
        try:
            return ec.EllipticCurvePublicNumbers(xi, yi, ec.SECP256R1()).public_key()
        except ValueError as exc:
            raise Malformed("EC point is not on the curve") from exc
    if alg == "EdDSA":
        if kty != "OKP" or jwk.get("crv") != "Ed25519":
            raise Malformed("EdDSA needs an OKP Ed25519 key")
        x = _b64u(jwk.get("x"), "x")
        if len(x) != 32:
            raise Malformed("Ed25519 key without a 32-byte point")
        if x[:31] + bytes([x[31] & 0x7F]) in _ED25519_SMALL_ORDER:
            raise Malformed("Ed25519 key is of small order")
        try:
            return ed25519.Ed25519PublicKey.from_public_bytes(x)
        except ValueError as exc:
            raise Malformed("Ed25519 key is not usable") from exc
    if alg in ("RS256", "PS256"):
        if kty != "RSA":
            raise Malformed(f"{alg} needs an RSA key")
        n = int.from_bytes(_b64u(jwk.get("n"), "n"), "big")
        e = int.from_bytes(_b64u(jwk.get("e"), "e"), "big")
        if e != 65537 or not 2048 <= n.bit_length() <= 8192 or n % 2 == 0:
            raise Malformed("RSA key must have e=65537 and 2048 to 8192 bits")
        try:
            return rsa.RSAPublicNumbers(e, n).public_key()
        except ValueError as exc:
            raise Malformed("RSA key is not usable") from exc
    raise Malformed("unsupported algorithm")


# ── certificates in PEM text, read one way ────────────────────────────────────────────────
# Each language has its own PEM reader, and they disagree (one line, CR line ends, headers).
# So a block is read here, by one grammar, before any parser sees it: BEGIN, lines of base64,
# END, nothing else; the body is canonical base64 and one DER certificate, with no byte after it.

_PEM_ANY = re.compile(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----")
_PEM_STRICT = re.compile(r"-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE-----")


def _der_whole(der: bytes) -> bool:
    """One DER SEQUENCE and nothing after it."""
    if len(der) < 2 or der[0] != 0x30:
        return False
    first = der[1]
    if first < 0x80:
        head, size = 2, first
    else:
        n = first & 0x7F
        if not 1 <= n <= 4 or len(der) < 2 + n:
            return False
        head, size = 2 + n, int.from_bytes(der[2:2 + n], "big")
    return head + size == len(der)


def pem_certificates(text: str) -> list[bytes]:
    """The DER of every certificate block in `text`. Raises Malformed when there is none,
    or when any block is not of the one form both languages read."""
    blocks = _PEM_ANY.findall(text)
    if not blocks:
        raise Malformed("no certificate")
    out = []
    for block in blocks:
        if not _PEM_STRICT.fullmatch(block):
            raise Malformed("a certificate block of another form")
        body = "".join(block.split("\n")[1:-1]).replace("\r", "")
        try:
            der = base64.b64decode(body, validate=True)
        except ValueError as exc:
            raise Malformed("a certificate block that is not base64") from exc
        if base64.b64encode(der).decode() != body or not _der_whole(der):
            raise Malformed("a certificate block that is not one certificate")
        out.append(der)
    return out
