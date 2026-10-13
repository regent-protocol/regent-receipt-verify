import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { b58decode, merkleRootFrom, verifyBundle } from "../bundle.js";

const here = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(here, "..", "..", "receipt-verify-vectors", "vectors.json"), "utf8"));
const B = V.bundle;

for (const [name, c] of Object.entries(B.cases)) {
  test(`bundle case: ${name}`, async () => {
    const res = await verifyBundle(c.bundle);
    assert.equal(res.valid, c.valid, `${name}: ${res.errors.join("; ")}`);
    if ("receipt_valid" in c) { assert.equal(res.receipt_valid, c.receipt_valid); assert.equal(res.receipt_anchored, c.receipt_anchored); }
    if ("links" in c) assert.equal(res.links_ok, c.links);
    assert.equal(res.decision_id, B.decision_id);
  });
}

test("saved keys override the bundle's own", async () => {
  const good = B.cases.good.bundle;
  assert.ok((await verifyBundle(good, { checkpointJwks: B.checkpoint_jwks, receiptJwks: V.jwks })).valid);
  const bad = await verifyBundle(good, { checkpointJwks: B.other_checkpoint_jwks });
  assert.ok(!bad.valid && bad.errors.some((e) => e.includes("checkpoint")));
});

test("receipt must name the bundle's decision", async () => {
  const good = JSON.parse(JSON.stringify(B.cases.good.bundle));
  good.decision_id = "dec_somethingelse";
  const res = await verifyBundle(good);
  assert.ok(!res.valid && res.errors.includes("receipt names a different decision than the bundle"));
});

test("merkle helper and base58 match the vectors", async () => {
  const ev = B.cases.good.bundle.events[0];
  assert.equal(merkleRootFrom(ev.payload_hash, ev.batch.merkle_proof, ev.batch.merkle_index), ev.batch.root);
  assert.equal(b58decode("111").toString("hex"), "000000");
  assert.equal(b58decode("2NEpo7TZRRrLZSi2U").toString("utf8"), "Hello World!");
  JSON.stringify(await verifyBundle(B.cases.good.bundle));
});
