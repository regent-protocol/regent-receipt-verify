# regent-receipt-verify

Verify a Regent Control **receipt** or **allow token** without Regent: only the token and a JWKS
you saved while the issuer was reachable. Nothing calls the network. One dependency
(`cryptography`) for RS256.

```
pip install regent-receipt-verify
curl -s https://control-api.regentprotocol.org/v1/control/.well-known/jwks.json > jwks-2026-09.json   # save it now, keep it with the receipts
regent-verify @receipt.txt --jwks jwks-2026-09.json --request request.json --mandate mandate-v2-reveal.json --policy policy-v3-reveal.json
```

```python
from regent_receipt_verify import verify
res = verify(token, jwks, request={"tool": "stripe", "action": "charge.create", "resource": None, "args": {...}},
             mandate_reveal=reveal_from_owner, policy_reveal=policy_reveal_from_org)
res.valid, res.kind, res.claims, res.args_hash_match, res.mandate_match, res.policy_match
```

What it proves:

| check | meaning |
|---|---|
| signature (RS256, kid from the JWKS) | Regent's issuer signed exactly these claims |
| `kind` receipt / allow / budget | a receipt (`typ receipt+jwt`, `aud regent-receipt`) can never pass as an access token |
| `expired` | receipts carry a 10-year evidence period; an allow token lives about a minute, so for evidence its expiry is a note, not a failure |
| `args_hash_match` | the token authorised this exact request (tool, action, resource, args) and nothing else |
| `mandate_match` | the owner's revealed mandate version (snapshot + salt, `terms-v2`) opens the receipt's `mandate_hash` |
| `policy_match` | the organisation's revealed policy version (text + profile + salt, `policy-v1`) opens `policy_hash`; starter-pack decisions need only the public text |

Key rotation: pass `--jwks` several times (every JWKS you saved). Exit code 0 when the signature
verifies and every supplied check matches.

Test vectors are minted by the real issuer (`packages/receipt-verify-vectors`), and the same
file drives the Node package `@regent-protocol/receipt-verify`.
