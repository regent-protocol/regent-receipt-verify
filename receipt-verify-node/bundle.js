// Evidence bundle verification (regent-evidence-bundle/1) — same checks as the Python package:
// canonical bytes → batch proof → signed checkpoint → epoch proof → receipt; checkpoint links;
// optional on-chain check of the append / anchor transactions through a Solana RPC endpoint.
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { verify } from "./index.js";

export const BUNDLE_VERSION = "regent-evidence-bundle/1";
export const CHECKPOINT_TYP = "checkpoint+jwt";

const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const b64url = (s) => Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");
export const normHex = (h) => { const x = String(h || "").toLowerCase(); return x.startsWith("0x") ? x.slice(2) : x; };

function keysOf(jwks) {
  if (!jwks) return [];
  if (Array.isArray(jwks)) return jwks.flatMap(keysOf);
  if (jwks.keys) return [...jwks.keys];
  return [jwks];
}

export function merkleRootFrom(leaf, proof, index) {
  let cur = leaf, i = index;
  for (const sib of proof) { cur = i % 2 === 0 ? sha256hex(cur + sib) : sha256hex(sib + cur); i = Math.floor(i / 2); }
  return cur;
}

function verifyJws(token, jwks, typ) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return { ok: false, error: "not a compact JWS" };
  let header, claims, sig;
  try { header = JSON.parse(b64url(parts[0]).toString("utf8")); claims = JSON.parse(b64url(parts[1]).toString("utf8")); sig = b64url(parts[2]); }
  catch (e) { return { ok: false, error: `cannot decode: ${e.message}` }; }
  if (header.typ !== typ) return { ok: false, header, claims, kid: header.kid, error: `typ is '${header.typ}', expected '${typ}'` };
  if (header.alg !== "RS256") return { ok: false, header, claims, kid: header.kid, error: `alg is '${header.alg}', expected RS256` };
  const signed = Buffer.from(`${parts[0]}.${parts[1]}`, "ascii");
  for (const k of keysOf(jwks)) {
    if (k.kty !== "RSA" || (header.kid && k.kid !== header.kid)) continue;
    try {
      const key = createPublicKey({ key: { kty: "RSA", n: k.n, e: k.e }, format: "jwk" });
      if (cryptoVerify("sha256", signed, key, sig)) return { ok: true, header, claims, kid: k.kid ?? null };
    } catch { /* next key */ }
  }
  return { ok: false, header, claims, kid: header.kid ?? null, error: "signature does not verify against the checkpoint key(s)" };
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null) return false;
  if (Array.isArray(a)) return Array.isArray(b) && a.length === b.length && a.every((v, i) => deepEqual(v, b[i]));
  if (typeof a === "object") {
    const ka = Object.keys(a).sort(), kb = Object.keys(b).sort();
    return ka.length === kb.length && ka.every((k, i) => k === kb[i] && deepEqual(a[k], b[k]));
  }
  return false;
}

function checkEvent(e, checkpointJwks) {
  const r = { event_id: String(e.event_id), event_type: e.event_type ?? null, canonical_ok: null, merkle_ok: null,
              checkpoint_ok: null, checkpoint_kid: null, epoch_ok: null, seq: null, chain_tx: null, errors: [],
              get ok() { return this.errors.length === 0; } };
  const ph = String(e.payload_hash || "");
  if (typeof e.payload_canonical !== "string" || !ph) { r.canonical_ok = false; r.errors.push("payload_canonical or payload_hash missing"); }
  else {
    const hashOk = normHex(ph) === sha256hex(e.payload_canonical);
    let parseOk = false;
    try { parseOk = deepEqual(JSON.parse(e.payload_canonical), e.payload); } catch { parseOk = false; }
    r.canonical_ok = hashOk && parseOk;
    if (!hashOk) r.errors.push("sha256(payload_canonical) != payload_hash");
    if (!parseOk) r.errors.push("payload_canonical does not parse to payload");
  }
  const batch = e.batch;
  if (!batch) { r.errors.push("event is not in a sealed batch yet"); return r; }
  r.seq = batch.seq ?? null; r.chain_tx = batch.chain_tx ?? null;
  try { r.merkle_ok = normHex(merkleRootFrom(ph, batch.merkle_proof || [], Number(batch.merkle_index || 0))) === normHex(batch.root); }
  catch (ex) { r.merkle_ok = false; r.errors.push(`merkle proof unreadable: ${ex.message}`); }
  if (r.merkle_ok === false && r.errors.length === 0) r.errors.push("merkle proof does not reach the batch root");
  if (!batch.checkpoint) { r.errors.push("batch has no signed checkpoint yet"); }
  else {
    const v = verifyJws(batch.checkpoint, checkpointJwks, CHECKPOINT_TYP);
    r.checkpoint_kid = v.kid ?? null;
    if (!v.ok) { r.checkpoint_ok = false; r.errors.push(`checkpoint: ${v.error}`); }
    else {
      const c = v.claims, mism = [];
      if (String(c.batch_id) !== String(batch.batch_id)) mism.push("batch_id");
      if (c.seq !== batch.seq) mism.push("seq");
      if (normHex(c.root) !== normHex(batch.root)) mism.push("root");
      if (c.head && batch.chain_head && normHex(c.head) !== normHex(batch.chain_head)) mism.push("head");
      if (c.chain_tx && batch.chain_tx && c.chain_tx !== batch.chain_tx) mism.push("chain_tx");
      r.checkpoint_ok = mism.length === 0;
      if (mism.length) r.errors.push(`checkpoint does not describe this batch: ${mism.join(", ")}`);
    }
  }
  if (e.epoch) {
    try { r.epoch_ok = normHex(merkleRootFrom(normHex(batch.root), e.epoch.proof || [], Number(e.epoch.leaf_index || 0))) === normHex(e.epoch.root); }
    catch (ex) { r.epoch_ok = false; r.errors.push(`epoch proof unreadable: ${ex.message}`); }
    if (r.epoch_ok === false && !r.errors.includes("epoch proof does not reach the epoch root")) r.errors.push("epoch proof does not reach the epoch root");
  }
  return r;
}

function checkLinks(events, checkpointJwks) {
  const bySeq = new Map(), tokens = new Map(), errors = [];
  for (const e of events) {
    const b = e.batch || {};
    if (b.checkpoint && b.seq != null) {
      const seq = Number(b.seq);
      if (tokens.has(seq) && tokens.get(seq) !== b.checkpoint) { const msg = `conflicting checkpoints for seq ${seq} inside the bundle`; if (!errors.includes(msg)) errors.push(msg); continue; }
      tokens.set(seq, b.checkpoint);
      const v = verifyJws(b.checkpoint, checkpointJwks, CHECKPOINT_TYP); if (v.ok) bySeq.set(seq, v.claims);
    }
  }
  const seqs = [...bySeq.keys()].sort((a, b) => a - b);
  let checked = false;
  for (let i = 1; i < seqs.length; i++) {
    const a = seqs[i - 1], b = seqs[i];
    if (b === a + 1) { checked = true; if (normHex(bySeq.get(b).prev_head) !== normHex(bySeq.get(a).head)) errors.push(`checkpoint ${b} prev_head does not equal checkpoint ${a} head`); }
  }
  return { linksOk: checked ? errors.length === 0 : null, errors };
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function b58decode(s) {
  let n = 0n;
  for (const ch of s) { const d = B58.indexOf(ch); if (d < 0) throw new Error("bad base58"); n = n * 58n + BigInt(d); }
  const bytes = []; while (n > 0n) { bytes.unshift(Number(n % 256n)); n /= 256n; }
  let pad = 0; for (const ch of s) { if (ch === "1") pad++; else break; }
  return Buffer.concat([Buffer.alloc(pad), Buffer.from(bytes)]);
}

async function rpc(url, method, params) {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  return (await r.json()).result;
}

export async function checkTxCarriesRoot(rpcUrl, signature, programId, rootHex) {
  const out = { tx: signature, found: false, succeeded: null, root_in_instruction: false };
  let res;
  try { res = await rpc(rpcUrl, "getTransaction", [signature, { encoding: "json", maxSupportedTransactionVersion: 0 }]); }
  catch (e) { out.error = `rpc: ${e.message}`; return out; }
  if (!res) { out.error = "transaction not found"; return out; }
  out.found = true; out.succeeded = (res.meta || {}).err == null;
  const msg = (res.transaction || {}).message || {}; const keys = msg.accountKeys || [];
  const want = Buffer.from(normHex(rootHex), "hex");
  for (const ix of msg.instructions || []) {
    try { if (keys[ix.programIdIndex] !== programId) continue; if (b58decode(ix.data || "").includes(want)) { out.root_in_instruction = true; break; } }
    catch { /* skip */ }
  }
  out.ok = Boolean(out.succeeded && out.root_in_instruction);
  return out;
}

/** Verify a bundle. `rpc` makes it async-network; without it the function never touches the network. */
export async function verifyBundle(bundle, { receiptJwks, checkpointJwks, rpc: rpcUrl, now } = {}) {
  const res = { valid: false, decision_id: bundle.decision_id ?? null, events: [], receipt_valid: null, receipt_anchored: null,
                receipt_claims: {}, links_ok: null, rpc_ok: null, rpc_checks: [], errors: [], warnings: [] };
  if (bundle.bundle_version !== BUNDLE_VERSION) { res.errors.push(`unknown bundle_version '${bundle.bundle_version}'`); return res; }
  const keys = bundle.keys || {};
  const ck = checkpointJwks !== undefined ? checkpointJwks : keys.checkpoint_jwks;
  const rk = receiptJwks !== undefined ? receiptJwks : keys.receipt_jwks;
  if (checkpointJwks === undefined) res.warnings.push("checkpoint key taken from the bundle itself; pass --checkpoint-jwks to use a saved one");
  const events = bundle.events || [];
  if (!events.length) { res.errors.push("bundle has no events"); return res; }
  for (const e of events) { const er = checkEvent(e, ck); res.events.push(er); res.errors.push(...er.errors.map((x) => `${er.event_id}: ${x}`)); }
  const links = checkLinks(events, ck); res.links_ok = links.linksOk; res.errors.push(...links.errors);
  const rec = bundle.receipt;
  if (rec && rec.token) {
    if (rk == null) { res.warnings.push("receipt present but no receipt JWKS (bundle or --jwks); receipt not verified"); }
    else {
      if (receiptJwks === undefined) res.warnings.push("receipt key taken from the bundle itself; pass --jwks to use a saved one");
      const vr = verify(rec.token, rk, { now });
      res.receipt_valid = vr.valid; res.receipt_claims = vr.signatureValid ? vr.claims : {};
      res.errors.push(...vr.errors.map((x) => `receipt: ${x}`));
      if (vr.signatureValid && res.decision_id && vr.claims.decision_id !== res.decision_id) res.errors.push("receipt names a different decision than the bundle");
    }
    const anchoredIn = events.find((e) => e.event_id === rec.event_id);
    if (anchoredIn) {
      const evOk = res.events.find((x) => x.event_id === anchoredIn.event_id)?.ok ?? false;
      const inside = (anchoredIn.payload || {}).receipt;
      res.receipt_anchored = Boolean(inside === rec.token && evOk);
      if (inside !== rec.token) res.errors.push("receipt token is not the one inside the anchored receipt event");
      else if (!evOk) res.errors.push("receipt event did not verify, so the receipt is not proven anchored");
    } else { res.receipt_anchored = false; res.warnings.push("receipt event not in bundle; receipt anchoring not checked"); }
  }
  if (rpcUrl) {
    const programId = (bundle.programs || {}).audit_anchor || ""; const seen = new Set();
    for (const e of events) {
      const b = e.batch || {};
      for (const [sig, root, kind] of [[b.chain_tx, b.root, "chain_append"], [b.legacy_anchor_tx, b.root, "legacy_anchor"]]) {
        if (sig && !seen.has(sig)) { seen.add(sig); res.rpc_checks.push({ kind, seq: b.seq ?? null, ...(await checkTxCarriesRoot(rpcUrl, sig, programId, root)) }); }
      }
      const ep = e.epoch || {};
      if (ep.tx && !seen.has(ep.tx)) { seen.add(ep.tx); res.rpc_checks.push({ kind: "epoch_anchor", epoch_index: ep.epoch_index ?? null, ...(await checkTxCarriesRoot(rpcUrl, ep.tx, programId, ep.root || "")) }); }
    }
    res.rpc_ok = res.rpc_checks.length > 0 && res.rpc_checks.every((c) => c.ok);
    if (res.rpc_checks.length && !res.rpc_ok) res.errors.push("on-chain check failed for at least one transaction");
  }
  res.valid = res.errors.length === 0 && res.events.every((x) => x.ok);
  return res;
}
