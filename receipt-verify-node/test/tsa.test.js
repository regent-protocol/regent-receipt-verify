// RFC 3161 tokens: the real public TSAs (fixtures), then tokens from a TSA of our own making
// (made by the Python test helper, kept as files) for the failure cases a bank's checklist
// names: expired certificate, altered content, wrong purpose, untrusted root.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { defaultRoots, loadRoots, verifyToken } from "../tsa.js";
import { normHex, verifyBundle } from "../bundle.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (n) => readFileSync(join(here, "fixtures", n));
const D = createHash("sha256").update("regent epoch test").digest();

// a TimeStampResp is SEQUENCE { status, token }: skip the outer header and the status element
function tokenOfResponse(buf) {
  const len = (b, i) => { let l = b[i], n = 1; if (l & 0x80) { const k = l & 0x7f; l = 0; for (let j = 0; j < k; j++) l = (l << 8) | b[i + 1 + j]; n += k; } return [l, n]; };
  const [, h] = len(buf, 1); let p = 1 + h;             // inside the outer SEQUENCE
  const [sl, sh] = len(buf, p + 1); p += 1 + sh + sl;     // past the status element
  return buf.subarray(p);
}

for (const [file, signer, root] of [
  ["digicert-regent-epoch-test.tsr", "DigiCert", "DigiCert Trusted Root G4"],
  ["sectigo-regent-epoch-test.tsr", "Sectigo", "USERTrust RSA Certification Authority"],
]) {
  test(`real ${signer} token verifies against the shipped roots`, () => {
    const r = verifyToken(tokenOfResponse(fx(file)), D);
    assert.equal(r.ok, true, r.errors.join("; "));
    assert.ok(r.digest_ok && r.signature_ok && r.chain_ok && r.valid_at_gen_time);
    assert.ok(r.signer.includes(signer) && r.root === root && r.gen_time.startsWith("2026-"));
  });
}

test("the wrong digest or a flipped signature byte fails", () => {
  const tok = tokenOfResponse(fx("digicert-regent-epoch-test.tsr"));
  const wrong = verifyToken(tok, createHash("sha256").update("some other root").digest());
  assert.equal(wrong.ok, false); assert.equal(wrong.digest_ok, false);
  const bad = Buffer.from(tok); bad[bad.length - 1] ^= 0x01;  // the signature is the last field
  const r = verifyToken(bad, D);
  assert.equal(r.ok, false); assert.equal(r.signature_ok, false);
  assert.ok(r.errors.some((e) => e.includes("does not verify")));
});

test("no roots means chain not checked and not ok", () => {
  const r = verifyToken(tokenOfResponse(fx("sectigo-regent-epoch-test.tsr")), D, []);
  assert.equal(r.ok, false); assert.equal(r.signature_ok, true); assert.equal(r.chain_ok, null);
  assert.equal(defaultRoots().length, 2);
});

test("our own TSA verifies only against its own root", () => {
  const roots = loadRoots(fx("own-root.pem"));
  const good = verifyToken(fx("own-valid.tst"), D, roots);
  assert.equal(good.ok, true, good.errors.join("; "));
  assert.equal(good.root, "Test TSA Root"); assert.equal(good.signer, "Test TSA Signer"); assert.equal(good.gen_time, "2026-11-04T12:00:00Z");
  const untrusted = verifyToken(fx("own-valid.tst"), D);
  assert.equal(untrusted.ok, false); assert.equal(untrusted.chain_ok, false);
});

test("expired at the certified time, altered content, wrong purpose all fail", () => {
  const expired = verifyToken(fx("own-expired.tst"), D, loadRoots(fx("expired-root.pem")));
  assert.equal(expired.ok, false); assert.equal(expired.signature_ok, true); assert.equal(expired.chain_ok, true); assert.equal(expired.valid_at_gen_time, false);
  const tampered = verifyToken(fx("own-tampered.tst"), D, loadRoots(fx("own-root.pem")));
  assert.equal(tampered.ok, false); assert.ok(tampered.errors.some((e) => e.includes("content altered")));
  const noeku = verifyToken(fx("own-noeku.tst"), D, loadRoots(fx("noeku-root.pem")));
  assert.equal(noeku.ok, false); assert.ok(noeku.errors.some((e) => e.includes("timeStamping EKU")));
});

test("inside a bundle: reported when present, fatal when wrong, silent when absent", async () => {
  const V = JSON.parse(readFileSync(join(here, "..", "..", "receipt-verify-vectors", "vectors.json"), "utf8"));
  const name = Object.keys(V.bundle.cases).find((n) => V.bundle.cases[n].valid && V.bundle.cases[n].bundle.events.some((e) => e.epoch));
  const b = structuredClone(V.bundle.cases[name].bundle);
  const ep = b.events.find((e) => e.epoch).epoch;
  // the own-valid token names sha256("regent epoch test"), not this epoch's root: a token for something else
  ep.tsa_token_b64 = fx("own-valid.tst").toString("base64"); ep.tsa_status = "complete";
  let res = await verifyBundle(b, { tsaRoots: loadRoots(fx("own-root.pem")) });
  assert.equal(res.valid, false); assert.ok(res.errors.some((e) => e.includes("rfc3161")));
  const ev = res.events.find((e) => e.tsa_ok != null);
  assert.equal(ev.tsa_ok, false);
  delete ep.tsa_token_b64; delete ep.tsa_status;
  res = await verifyBundle(b);
  assert.equal(res.valid, true); assert.ok(res.events.every((e) => e.tsa_ok == null));
  assert.ok(normHex("0xAB") === "ab");
  // and a token the Python helper made over this very epoch root: the two verifiers agree
  const withTsa = JSON.parse(readFileSync(join(here, "fixtures", "bundle-with-tsa.json"), "utf8"));
  res = await verifyBundle(withTsa, { tsaRoots: loadRoots(fx("bundle-tsa-root.pem")) });
  assert.equal(res.valid, true, res.errors.join("; "));
  const ok = res.events.find((e) => e.tsa_ok != null);
  assert.equal(ok.tsa_ok, true); assert.equal(ok.tsa_time, "2026-11-04T12:00:00Z"); assert.equal(ok.tsa_signer, "Test TSA Signer");
});
