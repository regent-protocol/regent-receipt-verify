// payee-v1: the receipt commits to the counterparty; the owner's reveal opens it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { checkPayeeReveal, payeeCommitment, verify } from "../index.js";

const here = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(here, "..", "..", "receipt-verify-vectors", "vectors.json"), "utf8"));

test("the reveal opens the commitment and nothing else", () => {
  const salt = "ab".repeat(16);
  const claims = { decision_id: "dec_1", payee_hash: payeeCommitment("ACME Ltd", salt), payee_commit: "payee-v1" };
  assert.equal(payeeCommitment("ACME Ltd", salt), createHash("sha256").update(`payee-v1|payee=ACME Ltd|salt=${salt}`).digest("hex"));
  assert.equal(checkPayeeReveal(claims, { payee: "ACME Ltd", salt }), true);
  assert.equal(checkPayeeReveal(claims, { payee: "ACME Ltd", salt: salt.toUpperCase(), decision_id: "dec_1" }), true);
  assert.equal(checkPayeeReveal(claims, { payee: "ACME Ltd", salt, decision_id: "dec_2" }), false);
  assert.equal(checkPayeeReveal(claims, { payee: "Someone", salt }), false);
  assert.equal(checkPayeeReveal({ payee: "ACME Ltd" }, { payee: "ACME Ltd", salt }), false);
});

test("verify reports payeeMatch only when a reveal is given", () => {
  const rec = V.cases.receipt;
  const res = verify(rec.token, V.jwks, { now: V.now, payeeReveal: { payee: "x", salt: "y" } });
  assert.equal(res.signatureValid, true); assert.equal(res.payeeMatch, false);
  assert.equal(verify(rec.token, V.jwks, { now: V.now }).payeeMatch, null);
});
