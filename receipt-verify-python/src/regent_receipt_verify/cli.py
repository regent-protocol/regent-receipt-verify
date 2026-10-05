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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="regent-verify", description="Verify a Regent receipt or allow token offline.")
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
    a = ap.parse_args(argv)

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
        for k in ("decision_id", "status", "sub", "amount", "currency", "payee", "mandate_id", "mandate_version",
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
