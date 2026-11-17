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
OpenTimestamps proof, the RFC 3161 time-stamp token (0.8.0), the retained receipt and the keys.

```
npx regent-verify bundle regent-evidence-dec_7f301d041e9f.json
npx regent-verify bundle regent-evidence-dec_7f301d041e9f.json --jwks jwks-2026-09.json --checkpoint-jwks audit-jwks.json
npx regent-verify bundle regent-evidence-dec_7f301d041e9f.json --rpc https://api.mainnet-beta.solana.com
npx regent-verify bundle regent-evidence-dec_7f301d041e9f.json --tsa-root my-tsa-root.pem
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
| rfc3161 | the epoch's RFC 3161 token (`tsa_token_b64`) is CMS SignedData whose TSTInfo names exactly this epoch root under SHA-256, whose signature verifies with the time-stamping certificate it carries, and whose certificate chains to a trusted root and was valid at the certified time; the line shows that time and the signer |
| receipt | verifies, names the bundle's decision, and is byte-for-byte the one inside the anchored receipt event |
| links | consecutive checkpoints chain (`prev_head` of N == `head` of N-1); one seq, one checkpoint |
| on-chain (`--rpc`) | the append and anchor transactions succeeded and carry the root in an instruction to the audit program |

The RFC 3161 token is the clock a bank's auditor already knows how to read: a public Time
Stamping Authority (DigiCert or Sectigo today) signed the epoch root at seal time, so "this root
existed no later than genTime" rests on the TSA's key, not on Regent or on any chain. The two
TSA roots ship with the package (`tsa_roots.pem`, from the Mozilla root store); `--tsa-root`
(`tsaRoots` in the library) replaces them with your own. A bundle without a token reports nothing for this
check; a token that fails any step makes the bundle INVALID.

**What VALID binds, and what it cannot.** Every event verifies on its own bytes, its batch proof
and Regent's signed checkpoint; every event names this decision and appears once; the current receipt
is the highest attempt. What offline verification cannot prove is completeness: that no event of the
decision was left out of the file. For that, the organization's own trail (or the API that served the
bundle) is the record; a bundle is evidence for the events it carries.

Keys default to the ones inside the bundle, which proves consistency; pass the JWKS you saved
(`--jwks`, `--checkpoint-jwks`) to prove provenance. The checkpoint JWKS is public at
`https://api.regentprotocol.org/v1/audit/.well-known/jwks.json`.

## The owner's approval (0.9.1: compared with the receipt, not verified)

A receipt names its approval by digest (`approval_digest`). A bundle downloaded with the
approval revealed (a signed-in admin of the organization only) carries an `approval` block
with the exact evidence string that was hashed. `regent-verify bundle` checks one thing
about that block, with no call to Regent: **the evidence bytes hash to the digest that a
verified receipt names.** Evidence that was edited, replaced by other evidence, or moved to
another decision makes the bundle `INVALID`.

**This version does not verify the owner's signature inside the evidence, and it does not
check that the terms shown beside the evidence are the terms that were approved.** It says
so itself, in the second line of its output:

```
VALID — evidence bundle for dec_7f301d041e9f, 3 event(s)
NOT CHECKED — the owner's approval: this version does not verify it
```

Two verdicts; read both. The first covers the trail and the receipt. The second is about
the approval, and in this version it is `NOT CHECKED` or `INVALID`, never anything better.
The program that verifies the owner's signature is given by Regent, on request, to the
parties to a dispute and to their auditors and advisers: evidence@regentprotocol.org.

Two rules:

- **The anchor is the receipt, and only the receipt.** The digest comes from a receipt
  whose signature verified. No event in the bundle can stand in for it: an event's id and
  type are labels beside its payload, not part of what is hashed into the trail. With no
  verified receipt nothing is compared. Pass your saved `--jwks`: a bundle that ships its
  own receipt key proves consistency, not provenance, and a note in the output says which
  key was used.
- **Nothing the block merely says is repeated as a finding.** The method and the scope are
  the receipt's. Dates, the approver's id and "applied" are printed as *stated by the
  organization, not verified*. No terms are returned.

A block that contradicts the receipt is an error, and the bundle is `INVALID`: another
method or scope than the receipt's, "no signature was taken" beside a receipt that names a
digest, "none recorded" beside a receipt that names an approval. A receipt that names an
approval the bundle does not carry is not an error: the second line then says
`the bundle does not carry it`. Changes to a mandate listed in the block are counted and
reported as `NOT CHECKED`.

### Reading the result

- **The exit code and `valid` are the bundle's.** They can be 0 and `true` while the
  approval is `NOT CHECKED`, and also when the bundle does not carry the approval evidence
  at all, or says it is not on file: the exit code does not show missing evidence. To know
  what was checked about the approval, read the second line, or `approval.verdict` in the
  result. Exit codes: 0 valid, 1 not valid, 2 the program could not do what was asked: a
  file could not be read (not UTF-8, not JSON, nested deeper than 512, a root file with no
  PEM certificate, a reveal that is not a JSON object), an option is unknown, abbreviated,
  missing its value or cannot be enforced, `--now` is not plain digits, the output could
  not be written, or the program itself failed. When nobody reads the output (`| head`),
  writing stops and the exit code still gives the verdict.
- **Arguments are read the same way in both languages**, by the same hand-written reader:
  `--name value` or `--name=value`, options anywhere, `--` ends the options, one file or
  token. `--now` takes ASCII digits with an optional fraction and exponent (`1795000000`,
  `-1e5`), nothing else. One exception outside this program's reach: when standard output
  is a directory, Python stops before the program starts (exit 1), Node exits 2.
- **`--approver-key`, `--origin` and `--rp-id` are refused by this version** (exit 2; in
  the library, an error in the result, whether or not the bundle carries an approval).
  They pin the owner's key and site where the owner's signature is verified. A
  requirement that cannot be enforced must not look as if it was.
- **A receipt checked with a key from the bundle anchors nothing you can rely on.** The
  evidence is still compared with it, and the output says so: the second line reads
  `the receipt key came from the bundle`, and a note says which keys were taken from the
  bundle. Pass `--jwks` (and `--checkpoint-jwks`) with copies you saved.
- **Automation reads `--json`** (or the library result), never the text. `--json` is plain
  ASCII. The text is written for a person, and a bundle is untrusted input, so two rules
  hold in it. Every control character, bidirectional control, zero-width and other
  default-ignorable character is printed as an escape. Letters of right-to-left scripts,
  combining marks and private-use characters are printed as they are: a terminal may draw
  them over or beside their neighbours, but none of them can start a line. And no row is left for the terminal to wrap: a row longer than 78 columns is
  continued on lines that start with `      | `, so that a label padded to the width of
  the screen does not start a row of its own. Only two rows start at the left edge: the
  bundle's verdict and the approval's. A label can still contain any words. This holds on
  a terminal at least 80 columns wide that draws characters at their usual widths (every
  character outside ASCII is counted as two columns to leave room). On a narrower
  terminal, or whenever the answer matters, read `--json`.
- **The format is strict on purpose.** Base64url in its one spelling (no padding, no stray
  bits), a receipt token that is exactly `header.payload.signature`, UTF-8 JSON whose
  numbers a double holds exactly, RSA keys with e=65537 and 2048 to 8192 bits, and every
  field of a bundle of one type: a number given as text is refused, not converted.
  Anything else is `malformed` and the bundle is invalid, in this package and in its
  Python twin alike. The two are tested against each other on the same hostile inputs and
  give one answer: the same exit code and the same text. `--json` of a bundle is the same in
  both; `--json` of a token names its fields in each language's style (`signature_valid`,
  `signatureValid`), as it did in 0.9.0. If they ever give two answers for the same file,
  treat the bundle as not verified and tell us.
  Reveals are read so that both languages hash the same bytes: text with a lone
  surrogate, a version beyond 2**53 - 1, and a policy profile holding anything but text,
  booleans, null and whole numbers within 2**53 - 1 (12.0 is read as 12), nested no
  deeper than 64, or a key above U+FFFF, matches nothing. Roots given as PEM text are read
  by one grammar in both languages (BEGIN, lines of base64, END): a one-line or CR-only
  certificate, or one with headers, is refused, not read one way here and another there. Two limits remain. Request arguments (`--request`) holding a number with a
  decimal point (40.0), in exponent form or beyond 2**53 hash differently in Node, which
  reads them as another double: give such values as integers or text. And a command-line
  argument that is not valid UTF-8 reaches Python as escaped bytes and Node as U+FFFD.
- **What 0.9.1 fixes in 0.9.0.** 0.9.0 said nothing about an approval block: a bundle whose
  approval evidence had been altered or replaced was `VALID`, and one whose block had been
  removed said nothing either (0.9.1 still calls that bundle `VALID`, and says in its
  second line that the bundle does not carry the evidence). A label with a line break
  could print a row that looked like this program's own, and escape sequences reached the
  terminal. A bundle with a field of the wrong type could end in a stack trace instead of
  an answer. Upgrade.
- **What changes when you upgrade from 0.9.0.** The text output is wrapped at 78 columns
  (continuation lines start with `      | `) and has a second line at the left edge; a
  script that reads the text should read `--json`, which only gained fields. A key set is
  read up to its 16th key, across all `--jwks` files together. RSA keys must have
  e=65537 and 2048 to 8192 bits. A bundle field of the wrong type (a number given as
  text, a label longer than 128 characters) makes the bundle `malformed` where 0.9.0
  converted it or let it through. A counterparty confirmation is read as strictly as a
  receipt; its amount must be a finite number or plain decimal text (0.9.0 in Python
  let `"nan"` match any amount), and its key must be the one type its algorithm uses:
  ES256 an EC P-256 key, EdDSA an Ed25519 key, RS256 and PS256 an RSA key with e=65537
  and 2048 to 8192 bits (0.9.0 in Node accepted any key for any algorithm, an RSA key
  with e=1 included, whose "signature" anyone can compute). A mandate, payee or policy
  reveal whose values are not of the types the format defines (a version that is not a
  whole number, a payee or salt that is not text, a scope that is not a list of texts)
  matches nothing, where 0.9.0 converted them differently in each language. An option name the library does not know (`approver_keys` for `approverKeys`) is an error in
  the result, and nothing is verified.

```js
import { verifyBundle } from "@regent-protocol/receipt-verify";

const res = await verifyBundle(bundle, { receiptJwks: savedJwks });   // a key you saved, not the bundle's
res.valid;                                                            // the trail and the receipt
if (res.approval) console.log(res.approval.verdict, res.approval.why); // "NOT CHECKED" or "INVALID" in this version
```
