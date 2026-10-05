# @regent-protocol/receipt-verify

Verify a Regent Control **receipt** or **allow token** without Regent: only the token and a JWKS
you saved while the issuer was reachable. Zero dependencies (Node ≥ 18, `node:crypto`).

```
npm i @regent-protocol/receipt-verify
curl -s https://control-api.regentprotocol.org/v1/control/.well-known/jwks.json > jwks-2026-09.json
npx regent-verify @receipt.txt --jwks jwks-2026-09.json --request request.json --mandate mandate-v2-reveal.json --policy policy-v3-reveal.json --counterparty-jwks get4agent-jwks.json
```

```js
import { verify } from "@regent-protocol/receipt-verify";
const res = verify(token, jwks, { request, mandateReveal, policyReveal });
res.valid; res.kind; res.claims; res.argsHashMatch; res.mandateMatch; res.policyMatch;
```

Checks: RS256 signature against the JWKS (`kid`), token kind (receipt / allow / budget), expiry
(a note for allow tokens, an error for receipts past their 10-year evidence period), request
binding (`args_hash` over canonical JSON of tool, action, resource, args), mandate reveal
(`terms-v2`), policy reveal (`policy-v1`; starter-pack decisions need only the public text) and, with
`--counterparty-jwks`, the counterparty's settlement confirmation embedded in the receipt (`checkConfirmation`:
ES256 / EdDSA / RS256 / PS256 against the counterparty's JWKS, then decision, status, amount and hash
compared with the receipt).
Pass several `--jwks` files for key rotation. Exit 0 when the signature verifies and every supplied
check matches.

Note on numbers: `args_hash` is computed over the request as the gate parsed it (Python JSON). A
JSON value written as `40.0` is `40.0` there and `40` in JavaScript; pass amounts as integers or
strings when you need to reproduce the hash from JavaScript.
