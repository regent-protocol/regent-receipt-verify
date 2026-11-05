// What a bundle's VALID binds (05.11.2026): the events are about this decision and appear once.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyBundle } from "../bundle.js";

const here = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(here, "..", "..", "receipt-verify-vectors", "vectors.json"), "utf8"));
const good = () => { const n = Object.keys(V.bundle.cases).find((k) => V.bundle.cases[k].valid); return structuredClone(V.bundle.cases[n].bundle); };

test("an event of another decision or a duplicate makes the bundle invalid", async () => {
  assert.equal((await verifyBundle(good())).valid, true);
  const other = good();
  const ev = other.events.find((e) => (e.payload || {}).decision_id);
  ev.payload.decision_id = "dec_ffffffffffff";
  ev.payload_canonical = JSON.stringify(ev.payload, Object.keys(ev.payload).sort());
  let res = await verifyBundle(other);
  assert.equal(res.valid, false); assert.ok(res.errors.some((e) => e.includes("names decision dec_ffffffffffff")));
  const dup = good(); dup.events.push(structuredClone(dup.events[0]));
  res = await verifyBundle(dup);
  assert.equal(res.valid, false); assert.ok(res.errors.some((e) => e.includes("more than once")));
});

test("an unanchored epoch is said so", async () => {
  const b = good();
  for (const e of b.events) if (e.epoch) { e.epoch.tx = null; delete e.epoch.tsa_token_b64; }
  const res = await verifyBundle(b);
  assert.ok(res.warnings.some((w) => w.includes("not anchored in this bundle")));
});
