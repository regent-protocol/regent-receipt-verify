"""regent-verify — command line for regent_receipt_verify.

  regent-verify TOKEN --jwks jwks.json [--jwks older.json] [--request req.json]
                      [--mandate reveal.json] [--policy reveal.json|text.cedar]
                      [--counterparty-jwks merchant-jwks.json] [--json] [--now EPOCH]

Exit 0 when the signature verifies and every supplied check matches; 1 otherwise."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__, verify


def _load(path: str):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        return json.loads(text)
    except ValueError:
        return text  # a Cedar text file for --policy


def _bundle_main(argv: list[str]) -> int:
    from .bundle import verify_bundle
    ap = argparse.ArgumentParser(prog="regent-verify bundle",
                                 description="Verify a Regent evidence bundle offline (regent-evidence-bundle/1).")
    ap.add_argument("bundle", help="the bundle JSON file")
    ap.add_argument("--jwks", action="append", help="saved receipt JWKS (default: the one inside the bundle)")
    ap.add_argument("--checkpoint-jwks", action="append",
                    help="saved checkpoint JWKS (default: the one inside the bundle)")
    ap.add_argument("--rpc", help="Solana JSON-RPC URL: also check the append and anchor transactions on the network")
    ap.add_argument("--now", type=float, help="epoch seconds to evaluate the receipt's exp against")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args(argv)
    bundle = _load(a.bundle)
    res = verify_bundle(bundle, receipt_jwks=[_load(p) for p in a.jwks] if a.jwks else None,
                        checkpoint_jwks=[_load(p) for p in a.checkpoint_jwks] if a.checkpoint_jwks else None,
                        rpc=a.rpc, now=a.now)
    if a.json:
        print(json.dumps(res.to_dict(), indent=2, ensure_ascii=False))
        return 0 if res.valid else 1
    print(("VALID" if res.valid else "INVALID") + " — evidence bundle"
          + (f" for {res.decision_id}" if res.decision_id else "") + f", {len(res.events)} event(s)")
    for e in res.errors:
        print(f"  error: {e}")
    for w in res.warnings:
        print(f"  note: {w}")
    for ev in res.events:
        flag = "ok " if ev.ok else "BAD"
        print(f"  [{flag}] {ev.event_id} ({ev.event_type}) seq={ev.seq} bytes={_yn(ev.canonical_ok)} "
              f"batch={_yn(ev.merkle_ok)} checkpoint={_yn(ev.checkpoint_ok)}"
              + (f" kid={ev.checkpoint_kid}" if ev.checkpoint_kid else "")
              + (f" epoch={_yn(ev.epoch_ok)}" if ev.epoch_ok is not None else ""))
        for e in ev.errors:
            print(f"        {e}")
    if res.links_ok is not None:
        print(f"  checkpoint links: {'consistent' if res.links_ok else 'BROKEN'}")
    if res.receipt_valid is not None:
        print(f"  receipt: {'VALID' if res.receipt_valid else 'INVALID'}"
              + (", anchored in the trail" if res.receipt_anchored else ", NOT anchored")
              + (f" — {res.receipt_claims.get('status')} {res.receipt_claims.get('amount')} "
                 f"{res.receipt_claims.get('currency') or ''}" if res.receipt_claims else ""))
    if res.rpc_ok is not None:
        print(f"  on-chain: {'confirmed' if res.rpc_ok else 'NOT confirmed'}")
        for c in res.rpc_checks:
            print(f"        {c.get('kind')} {c.get('tx')}: "
                  + ("ok" if c.get("ok") else c.get("error") or "root not found in a successful instruction"))
    return 0 if res.valid else 1


def _yn(v: bool | None) -> str:
    return "?" if v is None else ("yes" if v else "NO")


def main(argv: list[str] | None = None) -> int:
    import sys as _sys
    args = list(_sys.argv[1:] if argv is None else argv)
    if args and args[0] == "bundle":
        return _bundle_main(args[1:])
    ap = argparse.ArgumentParser(prog="regent-verify",
                                 description="Verify a Regent receipt or allow token offline. "
                                             "`regent-verify bundle FILE` verifies an evidence bundle.")
    ap.add_argument("token", help="the JWT, or @file to read it from a file")
    ap.add_argument("--jwks", action="append", required=True, help="saved JWKS file (repeat for older keys)")
    ap.add_argument("--request", help='JSON {"tool","action","resource","args"} to check args_hash')
    ap.add_argument("--mandate", help="mandate version reveal JSON from the owner")
    ap.add_argument("--policy", help="policy version reveal JSON, or the Cedar text for starter-pack decisions")
    ap.add_argument("--counterparty-jwks", action="append",
                    help="the counterparty's JWKS, to re-verify the settlement confirmation embedded in the receipt (repeatable)")
    ap.add_argument("--issuer", default="regent-control")
    ap.add_argument("--now", type=float, help="epoch seconds to evaluate exp against (default: now)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--version", action="version", version=__version__)
    a = ap.parse_args(args)

    token = open(a.token[1:], encoding="utf-8").read().strip() if a.token.startswith("@") else a.token
    res = verify(token, [_load(p) for p in a.jwks],
                 request=_load(a.request) if a.request else None,
                 mandate_reveal=_load(a.mandate) if a.mandate else None,
                 policy_reveal=_load(a.policy) if a.policy else None,
                 counterparty_jwks=[_load(p) for p in a.counterparty_jwks] if a.counterparty_jwks else None,
                 now=a.now, issuer=a.issuer or None)
    checks = [res.args_hash_match, res.mandate_match, res.policy_match, res.confirmation_match]
    ok = res.valid and all(c is not False for c in checks)
    if a.json:
        print(json.dumps(res.to_dict(), indent=2, ensure_ascii=False))
        return 0 if ok else 1
    c = res.claims
    print(("VALID" if res.valid else "INVALID") + f" — {res.kind} signed by {c.get('iss', '?')} (kid {res.kid})")
    for e in res.errors:
        print(f"  error: {e}")
    for w in res.warnings:
        print(f"  note: {w}")
    if res.signature_valid:
        for k in ("decision_id", "status", "environment", "sub", "assertion_scheme", "assertion_kid", "key_custody",
                  "amount", "currency", "payee", "mandate_id", "mandate_version",
                  "mandate_hash", "policy_source", "policy_version", "policy_hash", "risk_model", "tool", "action",
                  "scope", "args_hash", "settlement_mismatch", "settlement_source", "confirmed_by", "confirmation_kid",
                  "confirmation_ref", "confirmation_kind", "agent_report_mismatch", "jti", "iat", "exp"):
            if k in c:
                print(f"  {k}: {c[k]}")
        for label, val in (("request binding (args_hash)", res.args_hash_match), ("mandate reveal", res.mandate_match),
                           ("policy reveal", res.policy_match), ("counterparty confirmation", res.confirmation_match)):
            if val is not None:
                print(f"  {label}: {'MATCH' if val else 'NO MATCH'}")
        for e in res.confirmation_errors:
            print(f"    confirmation: {e}")
        if res.confirmation:
            print(f"    confirmed by {res.confirmation.get('iss')} (kid {c.get('confirmation_kid')}): "
                  f"{res.confirmation.get('status')} {res.confirmation.get('amount')} {res.confirmation.get('currency') or ''}"
                  + (f" ref {res.confirmation.get('ref')}" if res.confirmation.get('ref') else ""))
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
