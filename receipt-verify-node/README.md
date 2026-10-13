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
(`terms-v2 / terms-v3 (with the scope `allowed_resources`)`), policy reveal (`policy-v1`; starter-pack decisions need only the public text) and, with
`--counterparty-jwks`, the counterparty's settlement confirmation embedded in the receipt (`checkConfirmation`:
ES256 / EdDSA / RS256 / PS256 against the counterparty's JWKS, then decision, status, amount and hash
compared with the receipt).
Pass several `--jwks` files for key rotation. Exit 0 when the signature verifies and every supplied
check matches.

Note on numbers: `args_hash` is computed over the request as the gate parsed it (Python JSON). A
JSON value written as `40.0` is `40.0` there and `40` in JavaScript; pass amounts as integers or
strings when you need to reproduce the hash from JavaScript.

## Evidence bundles (0.4.0)

A bundle is one JSON document from the console ("Evidence bundle" on a decision or an audit
event) or from `GET /v1/organizations/{org}/decisions/{id}/bundle`. It carries every audit
event of a decision with the exact bytes that were hashed, the Merkle proof to the batch root,
Regent's signed checkpoint over that root and its chain position, the epoch proof, the
OpenTimestamps proof, the retained receipt and the keys.

```
npx regent-verify bundle regent-evidence-dec_7f301d041e9f.json
npx regent-verify bundle regent-evidence-dec_7f301d041e9f.json --jwks jwks-2026-09.json --checkpoint-jwks audit-jwks.json
npx regent-verify bundle regent-evidence-dec_7f301d041e9f.json --rpc https://api.mainnet-beta.solana.com
```

```js
import { verifyBundle } from "@regent-protocol/receipt-verify";
const res = await verifyBundle(bundle, { receiptJwks: savedReceiptJwks, checkpointJwks: savedAuditJwks,
                                         rpc: "https://api.devnet.solana.com" });   // rpc is optional
res.valid, res.events, res.receipt_valid, res.receipt_anchored, res.links_ok, res.rpc_ok
```

| check | meaning |
|---|---|
| canonical bytes | `sha256(payload_canonical) == payload_hash`, and the bytes parse to the payload |
| batch proof | payload hash → Merkle proof → batch root |
| checkpoint | Regent's RS256 statement (`typ checkpoint+jwt`) names this batch: id, seq, root, head |
| epoch proof | batch root → epoch proof → epoch root |
| receipt | verifies, names the bundle's decision, and is byte-for-byte the one inside the anchored receipt event |
| links | consecutive checkpoints chain (`prev_head` of N == `head` of N-1); one seq, one checkpoint |
| on-chain (`--rpc`) | the append and anchor transactions succeeded and carry the root in an instruction to the audit program |

Keys default to the ones inside the bundle, which proves consistency; pass the JWKS you saved
(`--jwks`, `--checkpoint-jwks`) to prove provenance. The checkpoint JWKS is public at
`https://api.regentprotocol.org/v1/audit/.well-known/jwks.json`.
