# regent-receipt-verify

Offline verifiers for **Regent Control** receipts and allow tokens: prove what a decision
authorised, under which mandate version and which policy version, without calling Regent.
Only the token and a JWKS you saved while the issuer was reachable are needed.

| package | install | runtime |
|---|---|---|
| [`regent-receipt-verify`](receipt-verify-python/) | `pip install regent-receipt-verify` | Python ≥ 3.10, one dependency (`cryptography`) |
| [`@regent-protocol/receipt-verify`](receipt-verify-node/) | `npm i @regent-protocol/receipt-verify` | Node ≥ 18, zero dependencies |

Both ship a `regent-verify` CLI and the same library surface, and both run the same test
vectors in [`receipt-verify-vectors/`](receipt-verify-vectors/), minted by the real issuer.

```
curl -s https://control-api.regentprotocol.org/v1/control/.well-known/jwks.json > jwks-2026-09.json
regent-verify @receipt.txt --jwks jwks-2026-09.json --request request.json \
  --mandate mandate-v2-reveal.json --policy policy-v3-reveal.json
```

What a verification proves:

| check | meaning |
|---|---|
| signature (RS256, `kid` from the JWKS) | Regent's issuer signed exactly these claims |
| kind | a receipt (`typ receipt+jwt`, `aud regent-receipt`) can never pass as an access token |
| `args_hash` | the token authorised this exact request (tool, action, resource, args) and nothing else |
| mandate reveal (`terms-v2`) | the owner's revealed mandate version (snapshot + salt) opens the receipt's `mandate_hash` |
| policy reveal (`policy-v1`) | the organisation's revealed policy version (text + profile + salt) opens `policy_hash`; starter-pack decisions need only the public text |

Ceilings never ride in a token: the receipt carries a version and a salted commitment, the
owner reveals the terms to whoever needs them (an insurer, an auditor), and this verifier checks
the two match. Save the JWKS with the receipts; keys rotate, and every JWKS you kept can be passed
with `--jwks`.

Licence: Apache-2.0. Issues and pull requests welcome.
