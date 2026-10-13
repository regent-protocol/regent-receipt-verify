# regent-receipt-verify

Verify a Regent Control **receipt** or **allow token** without Regent: only the token and a JWKS
you saved while the issuer was reachable. Nothing calls the network. One dependency
(`cryptography`) for RS256.

```
pip install regent-receipt-verify
curl -s https://control-api.regentprotocol.org/v1/control/.well-known/jwks.json > jwks-2026-09.json   # save it now, keep it with the receipts
regent-verify @receipt.txt --jwks jwks-2026-09.json --request request.json --mandate mandate-v2-reveal.json --policy policy-v3-reveal.json --counterparty-jwks get4agent-jwks.json
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
| `mandate_match` | the owner's revealed mandate version (snapshot + salt; `terms-v2`, or `terms-v3` with the scope `allowed_resources`) opens the receipt's `mandate_hash` |
| `policy_match` | the organisation's revealed policy version (text + profile + salt, `policy-v1`) opens `policy_hash`; starter-pack decisions need only the public text |
| `confirmation_match` | the settlement confirmation the counterparty (merchant, PSP, custodian) signed over the same decision, embedded in the receipt, re-verified against the counterparty's own JWKS and compared with the receipt's figures: two signatures over the same facts, checked offline. `settlement_source: agent` receipts have none |

Key rotation: pass `--jwks` several times (every JWKS you saved). Exit code 0 when the signature
verifies and every supplied check matches.

Test vectors are minted by the real issuer (`packages/receipt-verify-vectors`), and the same
file drives the Node package `@regent-protocol/receipt-verify`.

## Evidence bundles (0.4.0)

A bundle is one JSON document from the console ("Evidence bundle" on a decision or an audit
event) or from `GET /v1/organizations/{org}/decisions/{id}/bundle`. It carries every audit
event of a decision with the exact bytes that were hashed, the Merkle proof to the batch root,
Regent's signed checkpoint over that root and its chain position, the epoch proof, the
OpenTimestamps proof, the retained receipt and the keys.

```
regent-verify bundle regent-evidence-dec_7f301d041e9f.json
regent-verify bundle regent-evidence-dec_7f301d041e9f.json --jwks jwks-2026-09.json --checkpoint-jwks audit-jwks.json
regent-verify bundle regent-evidence-dec_7f301d041e9f.json --rpc https://api.mainnet-beta.solana.com
```

```python
from regent_receipt_verify.bundle import verify_bundle
res = verify_bundle(bundle, receipt_jwks=saved_receipt_jwks, checkpoint_jwks=saved_audit_jwks,
                    rpc="https://api.devnet.solana.com")   # rpc is optional
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
