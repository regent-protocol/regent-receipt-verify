// Evidence bundle verification (regent-evidence-bundle/1) — same checks as the Python package:
// canonical bytes → batch proof → signed checkpoint → epoch proof → receipt; checkpoint links;
// optional on-chain check of the append / anchor transactions through a Solana RPC endpoint.
import { X509Certificate, createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { verify } from "./index.js";
import { verifyToken } from "./tsa.js";
import { PINS_REFUSED, VERIFIES_SIGNATURE, summary, verifyApproval } from "./approval.js";
import { Malformed, compactJws, jwkList, pemCertificates, rs256Ok, same, show } from "./strict.js";

export const BUNDLE_VERSION = "regent-evidence-bundle/1";
export const CHECKPOINT_TYP = "checkpoint+jwt";

const sha256hex = (s) => createHash("sha256").update(s, "utf8").digest("hex");
export const normHex = (h) => { const x = typeof h === "string" ? h.toLowerCase() : ""; return x.startsWith("0x") ? x.slice(2) : x; };
const keysOf = jwkList;
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const get = (o, k) => (has(o, k) ? o[k] : undefined);
/** A non-empty string, or null: what "is it there" means for an optional text field. */
const text = (v) => (typeof v === "string" && v ? v : null);
/** An integer a double holds exactly, or null. */
const whole = (v) => (typeof v === "number" && Number.isSafeInteger(v) ? v : null);
const wellFormed = (t) => (typeof t.isWellFormed === "function" ? t.isWellFormed() : !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(t));

// ── the shape of a bundle: every field this program reads has one type ──────────────────
// s = string, i = integer, o = object, ls = list of strings; "?" = may be null or absent.
const TOP = { bundle_version: "s?", decision_id: "s?", keys: "o?", programs: "o?" };
const EVENT = { event_id: "s", event_type: "s?", payload: "o?", payload_canonical: "s?", payload_hash: "s?", batch: "o?", epoch: "o?" };
const BATCH = { batch_id: "s?", seq: "i?", root: "s?", merkle_index: "i?", merkle_proof: "ls?", chain_tx: "s?", chain_head: "s?", legacy_anchor_tx: "s?", checkpoint: "s?" };
const EPOCH = { epoch_index: "i?", proof: "ls?", leaf_index: "i?", root: "s?", tx: "s?", tsa_token_b64: "s?" };
const KINDS = { s: "a string", i: "an integer", o: "an object", ls: "a list of strings" };
const MAX_EVENTS = 10000;
const MAX_LABEL = 128;
// identifiers are short: a long one is not an identifier, it is room to write in (counted in code points)
function label(v, where) { if (typeof v === "string" && [...v.slice(0, MAX_LABEL * 2 + 2)].length > MAX_LABEL) throw new Malformed(`${where} is longer than ${MAX_LABEL} characters`); }

function isKind(kind, v) {
  if (kind === "s") return typeof v === "string";
  if (kind === "i") return whole(v) !== null;
  if (kind === "o") return isObject(v);
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

function fields(obj, spec, where) {
  for (const [name, kind] of Object.entries(spec)) {
    const v = get(obj, name);
    const base = kind.replace("?", "");
    if (v === undefined || v === null) { if (kind.endsWith("?")) continue; throw new Malformed(`${where}${name} is missing`); }
    if (!isKind(base, v)) throw new Malformed(`${where}${name} must be ${KINDS[base]}`);
    // a lone surrogate is not text: it cannot be hashed or compared
    for (const t of (typeof v === "string" ? [v] : Array.isArray(v) ? v : [])) if (!wellFormed(t)) throw new Malformed(`${where}${name} is not valid text`);
  }
}

/** Throw Malformed unless the bundle is of the shape the format defines. Two programs that coerce a
 *  wrong type differently would give two answers for one file; neither coerces, both refuse. */
function shape(bundle) {
  if (!isObject(bundle)) throw new Malformed("it is not an object");
  fields(bundle, TOP, "");
  label(get(bundle, "decision_id"), "decision_id");
  if (isObject(get(bundle, "programs"))) fields(bundle.programs, { audit_anchor: "s?" }, "programs.");
  const events = get(bundle, "events");
  if (events === undefined || events === null) return;
  if (!Array.isArray(events)) throw new Malformed("events must be a list");
  if (events.length > MAX_EVENTS) throw new Malformed(`more than ${MAX_EVENTS} events`);
  events.forEach((e, i) => {
    if (!isObject(e)) throw new Malformed(`events[${i}] must be an object`);
    fields(e, EVENT, `events[${i}].`);
    label(e.event_id, `events[${i}].event_id`); label(get(e, "event_type"), `events[${i}].event_type`);
    if (isObject(get(e, "batch"))) fields(e.batch, BATCH, `events[${i}].batch.`);
    if (isObject(get(e, "epoch"))) fields(e.epoch, EPOCH, `events[${i}].epoch.`);
  });
}

/** The canonical string says what the payload shown beside it says (JSON equality, numbers by
 *  their value as a double, nesting up to 64). */
function parsesTo(canonical, payload) {
  let parsed;
  try { parsed = JSON.parse(canonical); } catch { return false; }
  return same(parsed, payload === undefined ? null : payload);
}

const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const HEX64 = /^[0-9a-f]{64}$/;

export function merkleRootFrom(leaf, proof, index) {
  let cur = leaf, i = index;
  for (const sib of proof) { cur = i % 2 === 0 ? sha256hex(cur + sib) : sha256hex(sib + cur); i = Math.floor(i / 2); }
  return cur;
}

function verifyJws(token, jwks, typ) {
  let header, claims, signature, signed;
  try { ({ header, claims, signature, signed } = compactJws(token)); }
  catch (e) {
    const t = e instanceof Malformed ? e.message : "it could not be read";
    return { ok: false, error: t.startsWith("not a compact JWS") ? "not a compact JWS" : `cannot decode: ${t}` };
  }
  const kid = header.kid ?? null;
  if (header.typ !== typ) return { ok: false, header, claims, kid, error: `typ is '${show(header.typ)}', expected '${typ}'` };
  if (header.alg !== "RS256") return { ok: false, header, claims, kid, error: `alg is '${show(header.alg)}', expected RS256` };
  for (const k of keysOf(jwks)) {
    if (k.kty !== "RSA" || (kid && k.kid !== kid)) continue;
    if (rs256Ok(k, signed, signature)) return { ok: true, header, claims, kid: typeof k.kid === "string" ? k.kid : null };
  }
  return { ok: false, header, claims, kid, error: "signature does not verify against the checkpoint key(s)" };
}

function checkEvent(e, checkpointJwks, tsaRoots) {
  const r = { event_id: e.event_id, event_type: e.event_type ?? null, canonical_ok: null, merkle_ok: null,
              checkpoint_ok: null, checkpoint_kid: null, epoch_ok: null, tsa_ok: null, tsa_time: null, tsa_signer: null,
              seq: null, chain_tx: null, errors: [],
              get ok() { return this.errors.length === 0; } };
  const ph = e.payload_hash || "";
  if (typeof e.payload_canonical !== "string" || !ph) { r.canonical_ok = false; r.errors.push("payload_canonical or payload_hash missing"); }
  else {
    const hashOk = normHex(ph) === sha256hex(e.payload_canonical);
    const parseOk = parsesTo(e.payload_canonical, e.payload);
    r.canonical_ok = hashOk && parseOk;
    if (!hashOk) r.errors.push("sha256(payload_canonical) != payload_hash");
    if (!parseOk) r.errors.push("payload_canonical does not parse to payload");
  }
  const batch = e.batch;
  if (!batch || !Object.keys(batch).length) { r.errors.push("event is not in a sealed batch yet"); return r; }
  r.seq = whole(batch.seq); r.chain_tx = batch.chain_tx ?? null;
  r.merkle_ok = normHex(merkleRootFrom(ph, batch.merkle_proof || [], whole(batch.merkle_index) || 0)) === normHex(batch.root);
  if (r.merkle_ok === false && r.errors.length === 0) r.errors.push("merkle proof does not reach the batch root");
  if (!batch.checkpoint) { r.errors.push("batch has no signed checkpoint yet"); }
  else {
    const v = verifyJws(batch.checkpoint, checkpointJwks, CHECKPOINT_TYP);
    r.checkpoint_kid = v.kid ?? null;
    if (!v.ok) { r.checkpoint_ok = false; r.errors.push(`checkpoint: ${v.error}`); }
    else {
      const c = v.claims, mism = [];
      const jn = (x) => (x === undefined ? null : x);
      if (!same(jn(get(c, "batch_id")), jn(batch.batch_id))) mism.push("batch_id");
      if (!same(jn(get(c, "seq")), jn(batch.seq))) mism.push("seq");
      if (normHex(get(c, "root")) !== normHex(batch.root)) mism.push("root");
      if (text(get(c, "head")) && text(batch.chain_head) && normHex(c.head) !== normHex(batch.chain_head)) mism.push("head");
      if (text(get(c, "chain_tx")) && text(batch.chain_tx) && c.chain_tx !== batch.chain_tx) mism.push("chain_tx");
      r.checkpoint_ok = mism.length === 0;
      if (mism.length) r.errors.push(`checkpoint does not describe this batch: ${mism.join(", ")}`);
    }
  }
  const ep = e.epoch;
  if (ep && Object.keys(ep).length) {
    r.epoch_ok = normHex(merkleRootFrom(normHex(batch.root), ep.proof || [], whole(ep.leaf_index) || 0)) === normHex(ep.root);
    if (r.epoch_ok === false && !r.errors.includes("epoch proof does not reach the epoch root")) r.errors.push("epoch proof does not reach the epoch root");
    // 4b. RFC 3161: a public TSA's clock over the same root, checked offline
    if (ep.tsa_token_b64) {
      try {
        if (!B64.test(ep.tsa_token_b64) || !HEX64.test(normHex(ep.root))) throw new Error("not base64, or the epoch root is not 32 bytes of hex");
        const tr = verifyToken(Buffer.from(ep.tsa_token_b64, "base64"), Buffer.from(normHex(ep.root), "hex"), tsaRoots);
        r.tsa_ok = tr.ok; r.tsa_signer = tr.signer; r.tsa_time = tr.gen_time;
        r.errors.push(...tr.errors.map((x) => `rfc3161: ${x}`));
      } catch { r.tsa_ok = false; r.errors.push("rfc3161: token unreadable"); }
    }
  }
  return r;
}

function checkLinks(events, checkpointJwks) {
  const bySeq = new Map(), tokens = new Map(), errors = [], conflicting = new Set();
  for (const e of events) {
    const b = e.batch || {};
    const seq = whole(b.seq);
    if (b.checkpoint && seq !== null) {
      if (tokens.has(seq) && tokens.get(seq) !== b.checkpoint) {
        if (!conflicting.has(seq)) { conflicting.add(seq); errors.push(`conflicting checkpoints for seq ${seq} inside the bundle`); }
        continue;
      }
      tokens.set(seq, b.checkpoint);
      if (bySeq.has(seq)) continue;  // the same checkpoint again: already read
      const v = verifyJws(b.checkpoint, checkpointJwks, CHECKPOINT_TYP); if (v.ok) bySeq.set(seq, v.claims);
    }
  }
  const seqs = [...bySeq.keys()].sort((a, b) => a - b);
  let checked = false;
  for (let i = 1; i < seqs.length; i++) {
    const a = seqs[i - 1], b = seqs[i];
    if (b === a + 1) { checked = true; if (normHex(get(bySeq.get(b), "prev_head")) !== normHex(get(bySeq.get(a), "head"))) errors.push(`checkpoint ${b} prev_head does not equal checkpoint ${a} head`); }
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
const blank = (decisionId = null) => ({ valid: false, decision_id: decisionId, events: [], receipt_valid: null, receipt_anchored: null,
  receipt_claims: {}, links_ok: null, rpc_ok: null, rpc_checks: [], approval: null, approval_anchor: null, errors: [], warnings: [] });

/** Never throws: whatever is handed in, the answer is a result, and a file that is not a bundle is an INVALID one. */
class BadRoots extends Error {}
/** Roots to trust for RFC 3161 tokens, read the same way as the Python twin: undefined or null for
 *  the packaged roots; else PEM text (string, Buffer, Uint8Array), a certificate, or a list of those.
 *  Every certificate block of every item must read, and every item must hold one. */
function readRoots(tsaRoots) {
  if (tsaRoots === undefined || tsaRoots === null) return undefined;
  const items = Array.isArray(tsaRoots) ? tsaRoots : [tsaRoots];
  const out = [];
  items.forEach((item, i) => {
    if (item instanceof X509Certificate) { out.push(item); return; }
    let text = item;
    if (Buffer.isBuffer(item) || item instanceof Uint8Array) {
      try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(item); }
      catch { throw new BadRoots(`tsa roots: item ${i} holds no usable certificate`); }
    }
    if (typeof text !== "string") throw new BadRoots(`tsa roots: item ${i} is neither PEM text nor a certificate`);
    let ders;
    try { ders = pemCertificates(text); } catch { throw new BadRoots(`tsa roots: item ${i} holds no usable certificate`); }
    for (const der of ders) {
      try { out.push(new X509Certificate(der)); } catch { throw new BadRoots(`tsa roots: item ${i} holds no usable certificate`); }
    }
  });
  return out;
}

const BUNDLE_OPTIONS = ["receiptJwks", "checkpointJwks", "rpc", "now", "tsaRoots", "approverKeys", "origins", "rpIds"];

export async function verifyBundle(bundle, options = {}) {
  const o = isObject(options) ? options : {};
  // an option name the function does not know (approver_keys for approverKeys) would drop a
  // requirement without a word: nothing is verified, and the result says why
  const unknown = Object.keys(o).filter((k) => !BUNDLE_OPTIONS.includes(k));
  if (unknown.length) {
    const res = blank(isObject(bundle) && typeof bundle.decision_id === "string" ? bundle.decision_id : null);
    res.errors.push(`unknown option ${show(unknown[0])}; the options are ${BUNDLE_OPTIONS.join(", ")}`);
    return res;
  }
  let roots;
  try { roots = readRoots(o.tsaRoots); }
  catch (e) {
    if (!(e instanceof BadRoots)) throw e;
    const res = blank(isObject(bundle) && typeof bundle.decision_id === "string" ? bundle.decision_id : null);
    res.errors.push(e.message);
    return res;
  }
  const res = await verifyAny(bundle, { ...o, tsaRoots: roots });
  // a requirement this version cannot enforce is refused on every path, a malformed bundle's included
  if (!VERIFIES_SIGNATURE && [o.approverKeys, o.origins, o.rpIds].some((x) => x !== undefined && x !== null) && !res.errors.includes(PINS_REFUSED)) {
    res.errors.push(PINS_REFUSED); res.valid = false;
  }
  if (res.approval && !res.valid) [res.approval.verdict, res.approval.why] = summary(res.approval, { anchored: res.approval_anchor !== null, pinned: o.receiptJwks != null, bundleValid: false });
  return res;
}

async function verifyAny(bundle, options) {
  try { shape(bundle); }
  catch (e) {
    const res = blank();
    res.errors.push(e instanceof Malformed ? `bundle is malformed: ${e.message}` : `bundle could not be read (${e?.name || "Error"})`);
    return res;
  }
  try { return await verifyShaped(bundle, options); }
  catch (e) { const res = blank(bundle.decision_id ?? null); res.errors.push(`bundle could not be read (${e?.name || "Error"})`); return res; }
}

async function verifyShaped(bundle, { receiptJwks, checkpointJwks, rpc: rpcUrl, now, tsaRoots, approverKeys, origins, rpIds }) {
  const res = blank(bundle.decision_id ?? null);
  // roots may be given as PEM text, as documented, or as certificates already read
  if (bundle.bundle_version !== BUNDLE_VERSION) { res.errors.push(`unknown bundle_version '${show(bundle.bundle_version)}'`); return res; }
  const keys = bundle.keys || {};
  const ck = checkpointJwks != null ? checkpointJwks : keys.checkpoint_jwks;
  const rk = receiptJwks != null ? receiptJwks : keys.receipt_jwks;
  if (checkpointJwks == null) res.warnings.push("checkpoint key taken from the bundle itself; pass --checkpoint-jwks to use a saved one");
  const events = bundle.events || [];
  if (!events.length) { res.errors.push("bundle has no events"); return res; }
  for (const e of events) { const er = checkEvent(e, ck, tsaRoots); res.events.push(er); res.errors.push(...er.errors.map((x) => `${er.event_id}: ${x}`)); }
  const links = checkLinks(events, ck); res.links_ok = links.linksOk; res.errors.push(...links.errors);
  // what offline verification binds (05.11.2026): every event is about THIS decision and appears once;
  // completeness (that none is missing) is not provable offline — the organization's trail is the record
  if (res.decision_id) {
    for (const e of events) {
      const named = get(e.payload || {}, "decision_id") ?? null;
      if (named !== null && named !== "" && named !== res.decision_id) res.errors.push(`${e.event_id}: names decision ${typeof named === "string" ? named : "(not a string)"}, this bundle is for ${res.decision_id}`);
    }
  }
  const seenIds = new Set();
  for (const e of events) {
    const id = e.event_id;
    if (seenIds.has(id)) res.errors.push(`${id}: appears more than once in the bundle`);
    seenIds.add(id);
  }
  const unanchored = events.find((e) => e.epoch && Object.keys(e.epoch).length && !e.epoch.tx && !e.epoch.tsa_token_b64);
  if (unanchored) res.warnings.push(`${unanchored.event_id}: the epoch root is not anchored in this bundle (no transaction, no RFC 3161 token); its proof only ties the batch to a root — pass --rpc or ask for a bundle with the anchor`);
  // a decision completed more than once carries a receipt per attempt; the highest attempt is its state
  const receipts = events.filter((e) => e.event_type === "control.decision.receipt");
  if (receipts.length > 1) {
    const att = (e) => whole(get(e.payload || {}, "attempt")) || 1;
    const latest = receipts.reduce((a, b) => (att(b) > att(a) ? b : a));
    res.warnings.push(`${receipts.length} receipts in the trail (attempts ${receipts.map(att).join(", ")}); the current one is ${latest.event_id} — earlier receipts are history, not the decision's state`);
  }
  let rec = bundle.receipt ?? null;
  if (rec !== null && (typeof rec !== "object" || Array.isArray(rec))) { res.errors.push("receipt: it is not an object"); rec = null; }
  let anchor = null;   // the only thing an approval may be checked against
  if (rec && typeof rec.token === "string" && rec.token) {
    if (rk == null) { res.warnings.push("receipt present but no receipt JWKS (bundle or --jwks); receipt not verified"); }
    else {
      if (receiptJwks == null) res.warnings.push("receipt key taken from the bundle itself; pass --jwks to use a saved one");
      let vr = null;
      try { vr = verify(rec.token, rk, { now }); }
      catch (e) { res.receipt_valid = false; res.errors.push(`receipt: could not be read (${e?.name || "Error"})`); }
      if (vr) {
        res.receipt_valid = vr.valid; res.receipt_claims = vr.signatureValid ? vr.claims : {};
        res.errors.push(...vr.errors.map((x) => `receipt: ${x}`));
        const named = get(vr.claims, "decision_id");
        const namesThis = Boolean(res.decision_id) && typeof named === "string" && named === res.decision_id;
        if (vr.signatureValid && res.decision_id && !namesThis) res.errors.push("receipt names a different decision than the bundle");
        // An approval is anchored by a RECEIPT that is valid in full and names THIS decision:
        // not by an allow token, an expired or foreign-issuer token, or another decision's
        // receipt, each of which the receipt key may have signed.
        if (vr.valid && vr.kind === "receipt" && namesThis) { anchor = vr.claims; res.approval_anchor = "receipt"; }
      }
    }
    const anchoredIn = typeof rec.event_id === "string" ? events.find((e) => e.event_id === rec.event_id) : undefined;
    if (anchoredIn) {
      const evOk = res.events.find((x) => x.event_id === anchoredIn.event_id)?.ok ?? false;
      const inside = get(anchoredIn.payload || {}, "receipt");
      res.receipt_anchored = Boolean(inside === rec.token && evOk);
      if (inside !== rec.token) res.errors.push("receipt token is not the one inside the anchored receipt event");
      else if (!evOk) res.errors.push("receipt event did not verify, so the receipt is not proven anchored");
    } else { res.receipt_anchored = false; res.warnings.push("receipt event not in bundle; receipt anchoring not checked"); }
  }
  // 6. the owner's approval the receipt names (approval.js). The anchor is the claims of a
  // valid receipt for this decision (`anchor` above), and nothing else: an event's id and
  // type are labels beside its payload, not part of what is hashed into the trail, so no
  // event in the bundle may stand in for the receipt (a tenant can have any payload anchored).
  if ((bundle.approval !== undefined && bundle.approval !== null) || (anchor && (get(anchor, "approval_digest") ?? null) !== null)) {
    res.approval = verifyApproval(bundle.approval ?? null, anchor, { approverKeys, origins, rpIds });
    if (receiptJwks == null) {
      // The receipt's key came from the bundle itself: whoever wrote the bundle could have
      // written the key, the receipt and the approval together. Terms are a finding only under
      // a receipt you can trust, so none are returned, whatever the verdict.
      res.approval.terms = null;
      if (res.approval.signed) res.approval.signed.terms = null;
      for (const part of res.approval.changes) part.terms = null;
    }
    if (res.approval.valid === true && receiptJwks == null) {
      // Every check passed against that receipt. That shows the bundle agrees with itself, not
      // that Regent issued any of it.
      res.approval.valid = null; res.approval.consistent = true;
      res.approval.warnings.push("the approval is consistent with the receipt, but the receipt's key came from the bundle itself, so nothing here is verified: pass your saved receipt JWKS");
    }
    for (const e of res.approval.errors) res.errors.push(e);     // a loop, not a spread: a long list must not overflow the stack
    for (const w of res.approval.warnings) res.warnings.push(w);
  } else if (!VERIFIES_SIGNATURE && [approverKeys, origins, rpIds].some((x) => x !== undefined && x !== null)) {
    // a requirement this version cannot enforce is refused, approval or none
    res.errors.push(PINS_REFUSED);
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
  // last, so that the one line a person reads first agrees with everything above it
  if (res.approval) [res.approval.verdict, res.approval.why] = summary(res.approval, { anchored: anchor !== null, pinned: receiptJwks != null, bundleValid: res.valid });
  return res;
}
