#!/usr/bin/env node
// regent-verify TOKEN|@file --jwks jwks.json [--jwks older.json] [--request req.json] [--mandate reveal.json]
//               [--policy reveal.json|text.cedar] [--counterparty-jwks merchant-jwks.json] [--now EPOCH] [--json]
import { readFileSync } from "node:fs";
import { verify, VERSION } from "./index.js";

const args = process.argv.slice(2);
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
  for (const k of ["decision_id", "status", "sub", "amount", "currency", "payee", "mandate_id", "mandate_version", "mandate_hash",
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
