import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { verify, verifyToken, canonicalArgsHash, checkConfirmation, checkMandateReveal, checkPolicyReveal, checkRequestBinding } from "../index.js";

const here = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(here, "..", "..", "receipt-verify-vectors", "vectors.json"), "utf8"));
const NOW = V.now;

test("args hash matches the gate", () => {
  const r = V.request;
  assert.equal(canonicalArgsHash(r.tool, r.action, r.resource, r.args), V.args_hash);
});

for (const name of ["receipt", "allow"]) {
  test(`full verification: ${name}`, () => {
    const res = verify(V.cases[name].token, V.jwks, { request: V.request, mandateReveal: V.mandate_reveal, policyReveal: V.policy_reveal, now: NOW });
    assert.equal(res.kind, V.cases[name].expect.kind);
    assert.equal(res.signatureValid, true); assert.equal(res.valid, true); assert.equal(res.expired, false);
    assert.equal(res.argsHashMatch, true); assert.equal(res.mandateMatch, true); assert.equal(res.policyMatch, true);
    assert.equal(res.kid, V.jwks.keys[0].kid);
    assert.equal(verify(V.cases[name].token, V.jwks, { request: V.wrong_request, now: NOW }).argsHashMatch, false);
    assert.equal(checkMandateReveal(res.claims, { ...V.mandate_reveal, salt: "00".repeat(32) }), false);
    assert.equal(checkMandateReveal(res.claims, { ...V.mandate_reveal, snapshot: { ...V.mandate_reveal.snapshot, daily_limit: "9999.000000" } }), false);
    assert.equal(checkPolicyReveal(res.claims, { ...V.policy_reveal, cedar_text: V.policy_reveal.cedar_text + " " }), false);
    assert.equal(checkPolicyReveal(res.claims, { ...V.policy_reveal, profile: null }), false);
  });
}

test("allow expiry is a note, receipt past evidence period is an error", () => {
  const a = verifyToken(V.cases.allow_expired.token, V.jwks, { now: V.cases.allow_expired.now });
  assert.equal(a.signatureValid, true); assert.equal(a.expired, true); assert.equal(a.valid, true); assert.ok(a.warnings.length);
  const r = verifyToken(V.cases.receipt.token, V.jwks, { now: NOW + 86400 * 4000 });
  assert.equal(r.signatureValid, true); assert.equal(r.expired, true); assert.equal(r.valid, false);
});

test("starter policy opens with the text only", () => {
  assert.equal(verify(V.cases.starter_receipt.token, V.jwks, { policyReveal: V.starter_text, now: NOW }).policyMatch, true);
  assert.equal(verify(V.cases.starter_receipt.token, V.jwks, { policyReveal: V.starter_text + "\n", now: NOW }).policyMatch, false);
});

test("budget token classified; wrong key and tampering fail; key rotation via several JWKS", () => {
  assert.equal(verifyToken(V.cases.budget.token, V.jwks, { now: NOW }).kind, "budget");
  assert.equal(verifyToken(V.cases.wrong_key.token, V.jwks, { now: NOW }).signatureValid, false);
  assert.equal(verifyToken(V.cases.tampered.token, V.jwks, { now: NOW }).signatureValid, false);
  assert.equal(verifyToken(V.cases.wrong_key.token, [V.jwks, V.other_jwks], { now: NOW }).signatureValid, true);
});

test("garbage never throws", () => {
  for (const bad of ["", "abc", "a.b", "a.b.c", "x".repeat(10), null, undefined]) {
    const res = verifyToken(bad, V.jwks, { now: NOW });
    assert.equal(res.signatureValid, false); assert.ok(res.errors.length);
  }
});

test("request binding helper", () => {
  const claims = verifyToken(V.cases.allow.token, V.jwks, { now: NOW }).claims;
  assert.equal(checkRequestBinding(claims, V.request), true);
  assert.equal(checkRequestBinding(claims, { ...V.request, action: "charge.refund" }), false);
});

test("cli", () => {
  const dir = mkdtempSync(join(tmpdir(), "rv-"));
  const f = (n, v) => { const p = join(dir, n); writeFileSync(p, JSON.stringify(v)); return p; };
  const out = execFileSync("node", [join(here, "..", "cli.js"), V.cases.receipt.token, "--jwks", f("jwks.json", V.jwks), "--request", f("req.json", V.request),
    "--mandate", f("m.json", V.mandate_reveal), "--policy", f("p.json", V.policy_reveal), "--now", String(NOW)], { encoding: "utf8" });
  assert.ok(out.startsWith("VALID")); assert.ok(out.includes("mandate reveal: MATCH")); assert.ok(out.includes("policy reveal: MATCH"));
  assert.throws(() => execFileSync("node", [join(here, "..", "cli.js"), V.cases.tampered.token, "--jwks", f("jwks.json", V.jwks), "--now", String(NOW)], { stdio: "pipe" }));
});

// ── counterparty settlement confirmation (receipts minted with P-1) ────────────

for (const name of ["receipt_confirmed", "receipt_confirmed_es256"]) {
  test(`counterparty confirmation verifies against its JWKS: ${name}`, () => {
    const res = verify(V.cases[name].token, V.jwks, { counterpartyJwks: V.counterparty_jwks, now: NOW });
    assert.equal(res.valid, true); assert.equal(res.claims.settlement_source, "counterparty");
    assert.equal(res.confirmationMatch, true); assert.deepEqual(res.confirmationErrors, []);
    assert.equal(res.confirmation.iss, res.claims.confirmed_by); assert.equal(res.confirmation.decision_id, res.claims.decision_id);
    assert.equal(res.confirmation.amount, res.claims.amount); assert.equal(res.confirmation.ref, "ord_1");
  });
}

test("counterparty confirmation fails with a stranger's key, an empty JWKS, or an agent-reported receipt", () => {
  const stranger = verify(V.cases.receipt_confirmed.token, V.jwks, { counterpartyJwks: V.stranger_jwks, now: NOW });
  assert.equal(stranger.valid, true); assert.equal(stranger.confirmationMatch, false); assert.equal(stranger.confirmation, null);
  assert.ok(stranger.confirmationErrors.some((e) => e.includes("does not verify")));
  const none = verify(V.cases.receipt_confirmed.token, V.jwks, { counterpartyJwks: { keys: [] }, now: NOW });
  assert.equal(none.confirmationMatch, false); assert.ok(none.confirmationErrors.some((e) => e.includes("no key with kid")));
  const agent = verify(V.cases.receipt.token, V.jwks, { counterpartyJwks: V.counterparty_jwks, now: NOW });
  assert.equal(agent.confirmationMatch, false); assert.ok(agent.confirmationErrors.some((e) => e.includes("agent-reported")));
});

test("a confirmation that disagrees with the receipt is caught", () => {
  const claims = verifyToken(V.cases.receipt_confirmed.token, V.jwks, { now: NOW }).claims;
  assert.equal(checkConfirmation(claims, V.counterparty_jwks).ok, true);
  for (const bad of [{ amount: 401 }, { decision_id: "dec_other" }, { status: "failed" }, { confirmation_hash: "00".repeat(32) }, { confirmed_by: "https://other.example" }])
    assert.equal(checkConfirmation({ ...claims, ...bad }, V.counterparty_jwks).ok, false, JSON.stringify(bad));
});

test("cli reports the counterparty", () => {
  const dir = mkdtempSync(join(tmpdir(), "rv-"));
  const f = (n, v) => { const p = join(dir, n); writeFileSync(p, JSON.stringify(v)); return p; };
  const out = execFileSync("node", [join(here, "..", "cli.js"), V.cases.receipt_confirmed.token, "--jwks", f("jwks.json", V.jwks),
    "--counterparty-jwks", f("cp.json", V.counterparty_jwks), "--now", String(NOW)], { encoding: "utf8" });
  assert.ok(out.startsWith("VALID")); assert.ok(out.includes("counterparty confirmation: MATCH")); assert.ok(out.includes("confirmed by https://merchant.example"));
  assert.throws(() => execFileSync("node", [join(here, "..", "cli.js"), V.cases.receipt_confirmed.token, "--jwks", f("jwks.json", V.jwks),
    "--counterparty-jwks", f("stranger.json", V.stranger_jwks), "--now", String(NOW)], { stdio: "pipe" }));
});
