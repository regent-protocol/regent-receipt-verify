"""regent-verify — command line for regent_receipt_verify.

  regent-verify TOKEN --jwks jwks.json [--jwks older.json] [--request req.json]
                      [--mandate reveal.json] [--policy reveal.json|text.cedar]
                      [--counterparty-jwks merchant-jwks.json] [--json] [--now EPOCH]

Exit 0 when the signature verifies and every supplied check matches; 1 otherwise."""
from __future__ import annotations

import json
import os
import re
import select
import sys

from . import __version__, verify
from .approval import VERIFIES_SIGNATURE
from .approval import lines as _approval_lines
from .strict import Malformed, _int, js_json, pem_certificates, unprintable
from .strict import number_text as _number

# Text output is for a person at a terminal, and a bundle is untrusted input. Two rules keep
# a bundle from writing what looks like this program's own verdict: every character that
# moves the cursor, hides or reorders text is printed as an escape; and no line is left to
# the terminal to wrap (a label padded to the terminal's width would otherwise start a row of
# its own). A long line is broken here, and its continuation carries a marker no line of
# this program starts with. Automation reads --json.
_WIDTH = 78
_CONT = "      | "


def _safe(text: object) -> str:
    out = []
    for ch in str(text):
        code = ord(ch)
        if unprintable(code):
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def _cols(text: str) -> int:
    """Columns a string takes, counted generously: anything outside ASCII as two (some
    terminals draw even "°" and "±" double-width)."""
    return sum(1 if ch < "\u0080" else 2 for ch in text)


def _wrap(line: str) -> list[str]:
    out, cur, width = [], "", 0
    for ch in line:
        w = 1 if ch < "\u0080" else 2
        if width + w > _WIDTH:
            cut = cur.rfind(" ")
            if cut > len(_CONT) and cut > len(cur) - 24:
                out.append(cur[:cut])
                cur = _CONT + cur[cut + 1:]
            else:
                out.append(cur)
                cur = _CONT
            width = _cols(cur)
        cur += ch
        width += w
    out.append(cur)
    return out


_reader_gone = False


class _CannotWrite(Exception):
    pass


def _quiet(fd: int) -> None:
    """Point a descriptor at the null device, so that nothing later (the interpreter's own
    flush at exit included) fails on it again."""
    try:
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, fd)
        os.close(null)
    except (OSError, ValueError):
        pass


def _write_fd(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
        except BlockingIOError:      # a non-blocking descriptor that is full for now: wait, then go on
            select.select([], [fd], [], 5.0)
            continue
        except InterruptedError:
            continue
        view = view[n:]


def _write(data: bytes) -> None:
    """Write to standard output. When nobody reads it (`| head`, a pager closed early,
    standard output closed) there is nothing more to say: writing stops, without a
    traceback, and the exit code still carries the verdict. Any other failure to write
    (a full disk, a file too large, a descriptor not open for writing) stops the program
    with exit code 2: an answer that was not written must not pass for one that was."""
    global _reader_gone
    if _reader_gone:
        return
    if sys.stdout is None:
        _reader_gone = True
        return
    try:
        sys.stdout.flush()
        try:
            fd = sys.stdout.fileno()
        except (AttributeError, ValueError, OSError):
            fd = None
        if fd is None:
            sys.stdout.buffer.write(data)
            sys.stdout.flush()
        else:
            _write_fd(fd, data)
    except BrokenPipeError:
        _reader_gone = True
        _quiet(1)
    except (OSError, ValueError) as exc:
        _reader_gone = True
        _quiet(1)
        raise _CannotWrite("cannot write the output") from exc


def _err(text: str) -> None:
    """One line on standard error, if there is anyone to read it."""
    try:
        sys.stderr.flush()
        _write_fd(sys.stderr.fileno(), ("regent-verify: " + _safe(text)).encode("utf-8", "backslashreplace") + b"\n")
    except Exception:  # noqa: BLE001 — a closed or broken stderr changes nothing about the answer
        _quiet(2)


def _out(*parts: object) -> None:
    line = " ".join(_safe(x) for x in parts)
    for piece in _wrap(line):
        _write(piece.encode("utf-8", "backslashreplace") + b"\n")


def _ascii(text: str) -> str:
    """Every character from DEL up as a \\u escape (a pair for one outside the BMP), so
    nothing in the JSON acts on a terminal: what the Node twin does to JSON.stringify's text."""
    out = []
    for ch in text:
        code = ord(ch)
        if code < 0x7F:
            out.append(ch)
        elif code <= 0xFFFF:
            out.append(f"\\u{code:04x}")
        else:
            code -= 0x10000
            out.append(f"\\u{0xD800 + (code >> 10):04x}\\u{0xDC00 + (code & 0x3FF):04x}")
    return "".join(out)


def _out_json(obj: object) -> None:
    """JSON as the Node twin writes it (JSON.stringify with two spaces), in ASCII only."""
    _write(_ascii(js_json(obj, 2)).encode("ascii") + b"\n")


class _Unreadable(Exception):
    pass


MAX_NESTING = 512


def _too_deep(text: str) -> bool:
    """Brackets outside strings nest deeper than MAX_NESTING. Each language's own parser
    gives up at a different depth; this one limit, checked first, is the same in both."""
    depth, in_string, escaped = 0, False, False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_NESTING:
                return True
        elif ch in "]}":
            depth -= 1
    return False


_SECONDS = re.compile(r"-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?")


def _finite(text: str) -> float:
    """Epoch seconds in one spelling, the same in both languages: ASCII digits, an optional
    fraction and exponent. Not 1_000, not 0x10, not digits of another script."""
    value = float(text) if isinstance(text, str) and _SECONDS.fullmatch(text) else float("nan")
    if value != value or value in (float("inf"), float("-inf")):
        raise _Unreadable("--now must be a finite number of seconds")
    return value


# Arguments are read by hand, the same way the Node twin reads them, so that one command line
# gets one answer whatever the Python version (argparse treats `--` and negative numbers
# differently from one release to the next): `--name value` or `--name=value`, options
# anywhere, `--` ends the options, one positional. A value is checked as soon as it is read;
# `--help` and `--version` act where they stand; an unknown option or a second positional is
# reported once everything has been read. Abbreviations are not accepted. A word that starts
# with "-" is an option unless it is "-" alone, starts like a negative number, or holds a space.
_NEGATIVE = re.compile(r"-\.?[0-9]")


def _is_option(a: str) -> bool:
    return len(a) > 1 and a[0] == "-" and not _NEGATIVE.match(a) and " " not in a


def _short_arg(a: str) -> str:
    return a[:60] + "…" if len(a) > 60 else a


def _parse_args(args: list[str], spec: dict[str, str], what: str, convert: dict | None = None) -> dict:
    convert = convert or {}
    opts: dict[str, object] = {}
    positional: list[str] = []
    unknown: list[str] = []
    over = False
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if over or not _is_option(a):
            positional.append(a)
            continue
        if a == "--":
            over = True
            continue
        eq = a.find("=")
        name = a[:eq] if eq > 0 else a
        kind = spec.get(name)
        if kind is None:
            unknown.append(a)
            continue
        if kind in ("flag", "help", "version"):
            if eq > 0:
                raise _Unreadable(f"{name} takes no value")
            if kind in ("help", "version"):
                return {kind: True}
            opts[name] = True
            continue
        if eq > 0:
            value: object = a[eq + 1:]
        else:
            if i >= len(args) or _is_option(args[i]):
                raise _Unreadable(f"{name} needs a value")
            value = args[i]
            i += 1
        if name in convert:
            value = convert[name](value)
        if kind == "list":
            opts.setdefault(name, []).append(value)  # type: ignore[union-attr]
        else:
            opts[name] = value
    if not positional:
        raise _Unreadable(f"no {what} given; see --help")
    if unknown or len(positional) > 1:
        raise _Unreadable(f"unrecognized argument {_short_arg(unknown[0] if unknown else positional[1])}; see --help")
    return {"opts": opts, "positional": positional[0]}


_BUNDLE_USAGE = ("usage: regent-verify bundle FILE [--jwks receipt-jwks.json] [--checkpoint-jwks ck-jwks.json] [--rpc URL] "
                 "[--now EPOCH] [--tsa-root root.pem]{pins} [--json]")
_TOKEN_USAGE = ("usage: regent-verify TOKEN --jwks jwks.json [--request req.json] [--mandate reveal.json] [--policy reveal.json] "
                "[--payee reveal.json] [--counterparty-jwks merchant-jwks.json] [--issuer ISS] [--now EPOCH] [--json] [--version]")


def _scalar(value: object) -> str:
    """A value from a token or a bundle as the Node twin prints it."""
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, str):
        return value
    try:
        return js_json(value)
    except (TypeError, ValueError, RecursionError):
        return "?"


def _not_json(name: str):
    raise ValueError("NaN and Infinity are not JSON")


def _load(path: str, *, text_ok: bool = False):
    """A JSON file, read as strictly as the Node twin reads it: UTF-8, no NaN. With
    `text_ok` a file that is not JSON is returned as text (the Cedar policy for --policy)."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as exc:
        raise _Unreadable(f"cannot read {path}: {exc.strerror or 'not readable'}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _Unreadable(f"cannot read {path}: it is not UTF-8") from exc
    if _too_deep(text):
        raise _Unreadable(f"cannot read {path}: it is nested too deeply")
    try:
        return json.loads(text, parse_constant=_not_json, parse_int=_int)
    except (ValueError, RecursionError) as exc:
        if text_ok:
            return text
        raise _Unreadable(f"cannot read {path}: it is not JSON") from exc


def _load_object(path: str, *, text_ok: bool = False):
    """A file that must hold one JSON object (or, with `text_ok`, text that is not JSON)."""
    value = _load(path, text_ok=text_ok)
    if isinstance(value, dict) or (text_ok and isinstance(value, str)):
        return value
    raise _Unreadable(f"cannot read {path}: it is not a JSON object")


def _bundle_main(argv: list[str]) -> int:
    from .bundle import verify_bundle
    parsed = _parse_args(argv, {"--jwks": "list", "--checkpoint-jwks": "list", "--rpc": "one", "--now": "one", "--tsa-root": "list",
                                "--approver-key": "list", "--origin": "list", "--rp-id": "list", "--json": "flag",
                                "--help": "help", "-h": "help"}, "bundle file", {"--now": _finite})
    if parsed.get("help"):
        _out(_BUNDLE_USAGE.format(pins=" [--approver-key KEY] [--origin URL] [--rp-id DOMAIN]" if VERIFIES_SIGNATURE else ""))
        return 0
    p = parsed["opts"]

    class _A:
        bundle = parsed["positional"]
        jwks = p.get("--jwks")
        checkpoint_jwks = p.get("--checkpoint-jwks")
        rpc = p.get("--rpc")
        now = p.get("--now")
        tsa_root = p.get("--tsa-root")
        approver_key = p.get("--approver-key")
        origin = p.get("--origin")
        rp_id = p.get("--rp-id")
        json = bool(p.get("--json"))
    a = _A
    if not VERIFIES_SIGNATURE and (a.approver_key or a.origin or a.rp_id):
        raise _Unreadable("--approver-key, --origin and --rp-id need a version that verifies the owner's signature; "
                          f"this one ({__version__}) does not")
    bundle = _load(a.bundle)
    res = verify_bundle(bundle, receipt_jwks=[_load(p) for p in a.jwks] if a.jwks else None,
                        checkpoint_jwks=[_load(p) for p in a.checkpoint_jwks] if a.checkpoint_jwks else None,
                        rpc=a.rpc, now=a.now, tsa_roots=_tsa_roots(a.tsa_root),
                        approver_keys=a.approver_key, origins=a.origin, rp_ids=a.rp_id)
    if a.json:
        _out_json(res.to_dict())
        return 0 if res.valid else 1
    _out(("VALID" if res.valid else "INVALID") + " — evidence bundle"
          + (f" for {res.decision_id}" if res.decision_id else "") + f", {len(res.events)} event(s)")
    if res.approval is not None:
        # a verdict of its own, beside the bundle's: the bundle can be VALID while the
        # owner's approval was not checked, and the first lines must say so
        _out(f"{res.approval.verdict} — the owner's approval: {res.approval.why}")
    for e in res.errors:
        _out(f"  error: {e}")
    for w in res.warnings:
        _out(f"  note: {w}")
    for ev in res.events:
        flag = "ok " if ev.ok else "BAD"
        _out(f"  [{flag}] {ev.event_id} ({_scalar(ev.event_type)}) seq={_scalar(ev.seq)} bytes={_yn(ev.canonical_ok)} "
              f"batch={_yn(ev.merkle_ok)} checkpoint={_yn(ev.checkpoint_ok)}"
              + (f" kid={ev.checkpoint_kid}" if ev.checkpoint_kid else "")
              + (f" epoch={_yn(ev.epoch_ok)}" if ev.epoch_ok is not None else "")
              + (f" rfc3161={_yn(ev.tsa_ok)}" + (f" {ev.tsa_time} by {ev.tsa_signer}" if ev.tsa_ok else "")
                 if ev.tsa_ok is not None else ""))
        for e in ev.errors:
            _out(f"        {e}")
    if res.links_ok is not None:
        _out(f"  checkpoint links: {'consistent' if res.links_ok else 'BROKEN'}")
    if res.receipt_valid is not None:
        _out(f"  receipt: {'VALID' if res.receipt_valid else 'INVALID'}"
              + (", anchored in the trail" if res.receipt_anchored else ", NOT anchored")
              + (f" — {res.receipt_claims['status']} {_number(res.receipt_claims.get('amount'))} "
                 f"{res.receipt_claims.get('currency') if isinstance(res.receipt_claims.get('currency'), str) else ''}"
                 if isinstance(res.receipt_claims.get("status"), str) else ""))
    if res.approval is not None:
        for line in _approval_lines(res.approval, anchored=res.approval_anchor is not None, pinned=bool(a.jwks)):
            _out(line)
    if res.rpc_ok is not None:
        _out(f"  on-chain: {'confirmed' if res.rpc_ok else 'NOT confirmed'}")
        for c in res.rpc_checks:
            _out(f"        {c.get('kind')} {c.get('tx')}: "
                  + ("ok" if c.get("ok") else c.get("error") or "root not found in a successful instruction"))
    return 0 if res.valid else 1


def _tsa_roots(paths: list[str] | None):  # noqa: ANN202
    """Roots from PEM files: a file that cannot be read, or holds no certificate, stops the
    program with exit code 2 instead of quietly trusting nothing."""
    if not paths:
        return None
    from cryptography import x509
    roots = []
    for p in paths:
        try:
            with open(p, "rb") as f:
                data = f.read()
        except OSError as exc:
            raise _Unreadable(f"cannot read {p}: {exc.strerror or 'not readable'}") from exc
        try:
            certs = [x509.load_der_x509_certificate(der) for der in pem_certificates(data.decode("utf-8"))]
        except (Malformed, ValueError):   # the one reader both languages use: see strict.pem_certificates
            certs = []
        if not certs:
            raise _Unreadable(f"cannot read {p}: it holds no PEM certificate")
        roots.extend(certs)
    return roots


def _yn(v: bool | None) -> str:
    return "?" if v is None else ("yes" if v else "NO")


def main(argv: list[str] | None = None) -> int:
    """Exit 0 = valid, 1 = not valid, 2 = the program could not do what was asked: a file
    could not be read, an option is wrong, the output could not be written, or anything else
    went wrong. Never a traceback, and never 1 for a failure of the program itself (1 means
    the input is not valid)."""
    global _reader_gone
    _reader_gone = False
    try:
        code = _main(argv)
    except (_Unreadable, _CannotWrite) as exc:
        _err(str(exc))
        code = 2
    except Exception:  # noqa: BLE001 — a failure of this program is not a verdict on the input
        _err("could not run")
        code = 2
    # what argparse printed is still buffered: flush it now, while a failure can still be told
    for stream, fd in ((sys.stdout, 1), (sys.stderr, 2)):
        if stream is None:
            continue
        try:
            stream.flush()
        except BrokenPipeError:
            _quiet(fd)
        except (OSError, ValueError):
            _quiet(fd)
            if fd == 1 and code != 2:
                _err("cannot write the output")
                code = 2
    return code


def _main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "bundle":
        return _bundle_main(args[1:])
    parsed = _parse_args(args, {"--jwks": "list", "--request": "one", "--mandate": "one", "--policy": "one", "--payee": "one",
                                "--counterparty-jwks": "list", "--now": "one", "--issuer": "one", "--json": "flag",
                                "--help": "help", "-h": "help", "--version": "version"}, "token", {"--now": _finite})
    if parsed.get("version"):
        _out(__version__)
        return 0
    if parsed.get("help"):
        _out(_TOKEN_USAGE)
        return 0
    q = parsed["opts"]
    if not q.get("--jwks"):
        raise _Unreadable("--jwks is required")

    class _A:
        token = parsed["positional"]
        jwks = q.get("--jwks")
        request = q.get("--request")
        mandate = q.get("--mandate")
        policy = q.get("--policy")
        payee = q.get("--payee")
        counterparty_jwks = q.get("--counterparty-jwks")
        issuer = q.get("--issuer", "regent-control")
        now = q.get("--now")
        json = bool(q.get("--json"))
    a = _A
    token = a.token
    if token.startswith("@"):
        try:
            with open(token[1:], "rb") as f:
                token = f.read().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise _Unreadable(f"cannot read {a.token[1:]}") from exc
    res = verify(token, [_load(p) for p in a.jwks],
                 request=_load_object(a.request) if a.request else None,
                 mandate_reveal=_load_object(a.mandate) if a.mandate else None,
                 policy_reveal=_load_object(a.policy, text_ok=True) if a.policy else None,
                 payee_reveal=_load_object(a.payee) if a.payee else None,
                 counterparty_jwks=[_load(p) for p in a.counterparty_jwks] if a.counterparty_jwks else None,
                 now=a.now, issuer=a.issuer or None)
    checks = [res.args_hash_match, res.mandate_match, res.policy_match, res.payee_match, res.confirmation_match]
    ok = res.valid and all(c is not False for c in checks)
    if a.json:
        _out_json(res.to_dict())
        return 0 if ok else 1
    c = res.claims
    _out(("VALID" if res.valid else "INVALID") + f" — {res.kind} signed by "
         f"{'?' if c.get('iss') is None else _scalar(c.get('iss'))} (kid {_scalar(res.kid)})")
    for e in res.errors:
        _out(f"  error: {e}")
    for w in res.warnings:
        _out(f"  note: {w}")
    if res.signature_valid:
        for k in ("decision_id", "status", "environment", "sub", "assertion_scheme", "assertion_kid", "key_custody",
                  "amount", "currency", "payee", "payee_hash", "mandate_id", "mandate_version",
                  "mandate_hash", "policy_source", "policy_version", "policy_hash", "risk_model", "tool", "action",
                  "scope", "args_hash", "settlement_mismatch", "settlement_source", "settlement_ref", "settlement_network",
                  "confirmed_by", "confirmation_kid",
                  "confirmation_ref", "confirmation_kind", "agent_report_mismatch", "jti", "iat", "exp"):
            if k in c:
                _out(f"  {k}: {_scalar(c[k])}")
        for label, val in (("request binding (args_hash)", res.args_hash_match), ("mandate reveal", res.mandate_match),
                           ("policy reveal", res.policy_match), ("payee reveal", res.payee_match),
                           ("counterparty confirmation", res.confirmation_match)):
            if val is not None:
                _out(f"  {label}: {'MATCH' if val else 'NO MATCH'}")
        if "payee_hash" in c and "payee" not in c and res.payee_match is None:
            _out("  payee: committed (hidden by the organization); pass --payee reveal.json to open it")
        for e in res.confirmation_errors:
            _out(f"    confirmation: {e}")
        if res.confirmation is not None:
            conf = res.confirmation
            _out(f"    confirmed by {_scalar(conf.get('iss'))} (kid {_scalar(c.get('confirmation_kid'))}): "
                  f"{_scalar(conf.get('status'))} {_scalar(conf.get('amount'))} {_scalar(conf.get('currency'))}"
                  + (f" ref {_scalar(conf.get('ref'))}" if conf.get("ref") not in (None, "") else ""))
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
