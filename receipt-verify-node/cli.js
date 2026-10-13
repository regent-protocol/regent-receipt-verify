#!/usr/bin/env node
// regent-verify TOKEN|@file --jwks jwks.json [--jwks older.json] [--request req.json] [--mandate reveal.json]
//               [--policy reveal.json|text.cedar] [--counterparty-jwks merchant-jwks.json] [--now EPOCH] [--json]
import { readFileSync } from "node:fs";
import { verify, VERSION } from "./index.js";

const args = process.argv.slice(2);
if (args[0] === "bundle") {
  const { verifyBundle } = await import("./bundle.js");
  const o = { jwks: [], checkpointJwks: [] }; let file = null;
  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (a === "--jwks") o.jwks.push(args[++i]);
    else if (a === "--checkpoint-jwks") o.checkpointJwks.push(args[++i]);
    else if (a === "--rpc") o.rpc = args[++i];
    else if (a === "--now") o.now = Number(args[++i]);
    else if (a === "--json") o.json = true;
    else if (a === "--help" || a === "-h") { console.log("usage: regent-verify bundle FILE [--jwks receipt-jwks.json] [--checkpoint-jwks ck-jwks.json] [--rpc URL] [--now EPOCH] [--json]"); process.exit(0); }
    else file = a;
  }
  if (!file) { console.error("usage: regent-verify bundle FILE [--jwks ...] [--checkpoint-jwks ...] [--rpc URL] [--json]"); process.exit(2); }
  const loadJ = (p) => JSON.parse(readFileSync(p, "utf8"));
  const res = await verifyBundle(loadJ(file), {
    receiptJwks: o.jwks.length ? o.jwks.map(loadJ) : undefined,
    checkpointJwks: o.checkpointJwks.length ? o.checkpointJwks.map(loadJ) : undefined,
    rpc: o.rpc, now: o.now,
  });
  if (o.json) { console.log(JSON.stringify(res, null, 2)); process.exit(res.valid ? 0 : 1); }
  const yn = (v) => (v == null ? "?" : v ? "yes" : "NO");
  console.log(`${res.valid ? "VALID" : "INVALID"} — evidence bundle${res.decision_id ? ` for ${res.decision_id}` : ""}, ${res.events.length} event(s)`);
  for (const e of res.errors) console.log(`  error: ${e}`);
  for (const w of res.warnings) console.log(`  note: ${w}`);
  for (const ev of res.events) {
    console.log(`  [${ev.ok ? "ok " : "BAD"}] ${ev.event_id} (${ev.event_type}) seq=${ev.seq} bytes=${yn(ev.canonical_ok)} batch=${yn(ev.merkle_ok)} checkpoint=${yn(ev.checkpoint_ok)}${ev.checkpoint_kid ? ` kid=${ev.checkpoint_kid}` : ""}${ev.epoch_ok != null ? ` epoch=${yn(ev.epoch_ok)}` : ""}`);
    for (const e of ev.errors) console.log(`        ${e}`);
  }
  if (res.links_ok != null) console.log(`  checkpoint links: ${res.links_ok ? "consistent" : "BROKEN"}`);
  if (res.receipt_valid != null) console.log(`  receipt: ${res.receipt_valid ? "VALID" : "INVALID"}${res.receipt_anchored ? ", anchored in the trail" : ", NOT anchored"}${res.receipt_claims.status ? ` — ${res.receipt_claims.status} ${res.receipt_claims.amount ?? ""} ${res.receipt_claims.currency ?? ""}` : ""}`);
  if (res.rpc_ok != null) { console.log(`  on-chain: ${res.rpc_ok ? "confirmed" : "NOT confirmed"}`); for (const c of res.rpc_checks) console.log(`        ${c.kind} ${c.tx}: ${c.ok ? "ok" : c.error || "root not found in a successful instruction"}`); }
  process.exit(res.valid ? 0 : 1);
}
const opt = { jwks: [], counterpartyJwks: [] };
let token = null;
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--jwks") opt.jwks.push(args[++i]);
  else if (a === "--request") opt.request = args[++i];
  else if (a === "--mandate") opt.mandate = args[++i];
  else if (a === "--policy") opt.policy = args[++i];
  else if (a === "--counterparty-jwks") opt.counterpartyJwks.push(args[++i]);
  else if (a === "--now") opt.now = Number(args[++i]);
  else if (a === "--issuer") opt.issuer = args[++i];
  else if (a === "--json") opt.json = true;
  else if (a === "--version") { console.log(VERSION); process.exit(0); }
  else if (a === "--help" || a === "-h") { console.log("usage: regent-verify TOKEN --jwks jwks.json [--request req.json] [--mandate reveal.json] [--policy reveal.json] [--counterparty-jwks merchant-jwks.json] [--now EPOCH] [--json]"); process.exit(0); }
  else token = a;
}
if (!token || !opt.jwks.length) { console.error("usage: regent-verify TOKEN --jwks jwks.json [...]"); process.exit(2); }
const load = (p) => { const t = readFileSync(p, "utf8"); try { return JSON.parse(t); } catch { return t; } };
if (token.startsWith("@")) token = readFileSync(token.slice(1), "utf8").trim();

const res = verify(token, opt.jwks.map(load), {
  request: opt.request ? load(opt.request) : undefined,
  mandateReveal: opt.mandate ? load(opt.mandate) : undefined,
  policyReveal: opt.policy ? load(opt.policy) : undefined,
  counterpartyJwks: opt.counterpartyJwks.length ? opt.counterpartyJwks.map(load) : undefined,
  now: opt.now, issuer: opt.issuer === undefined ? "regent-control" : (opt.issuer || null),
});
const ok = res.valid && [res.argsHashMatch, res.mandateMatch, res.policyMatch, res.confirmationMatch].every((c) => c !== false);
if (opt.json) { console.log(JSON.stringify({ ...res, valid: res.valid }, null, 2)); process.exit(ok ? 0 : 1); }
const c = res.claims;
console.log(`${res.valid ? "VALID" : "INVALID"} — ${res.kind} signed by ${c.iss ?? "?"} (kid ${res.kid})`);
for (const e of res.errors) console.log(`  error: ${e}`);
for (const w of res.warnings) console.log(`  note: ${w}`);
if (res.signatureValid) {
  for (const k of ["decision_id", "status", "environment", "sub", "assertion_scheme", "assertion_kid", "key_custody",
    "amount", "currency", "payee", "mandate_id", "mandate_version", "mandate_hash",
                   "policy_source", "policy_version", "policy_hash", "risk_model", "tool", "action", "scope", "args_hash",
                   "settlement_mismatch", "settlement_source", "confirmed_by", "confirmation_kid", "confirmation_ref", "confirmation_kind",
                   "agent_report_mismatch", "jti", "iat", "exp"]) if (k in c) console.log(`  ${k}: ${c[k]}`);
  for (const [label, val] of [["request binding (args_hash)", res.argsHashMatch], ["mandate reveal", res.mandateMatch], ["policy reveal", res.policyMatch],
                              ["counterparty confirmation", res.confirmationMatch]])
    if (val !== null) console.log(`  ${label}: ${val ? "MATCH" : "NO MATCH"}`);
  for (const e of res.confirmationErrors) console.log(`    confirmation: ${e}`);
  if (res.confirmation) console.log(`    confirmed by ${res.confirmation.iss} (kid ${c.confirmation_kid}): ${res.confirmation.status} ${res.confirmation.amount ?? ""} ${res.confirmation.currency ?? ""}${res.confirmation.ref ? ` ref ${res.confirmation.ref}` : ""}`);
}
process.exit(ok ? 0 : 1);
