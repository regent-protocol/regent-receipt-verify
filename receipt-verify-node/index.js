// @regent-protocol/receipt-verify — verify a Regent Control receipt or allow token without Regent.
// Node ≥ 18, no dependencies: RS256 via node:crypto, commitments via the same canonical strings
// the gate and the browser verifier use (terms-v2 for mandates, policy-v1 for policies), and
// the same request hash (sha256 over canonical JSON of {tool, action, resource, args}).
import { constants, createHash, createPublicKey, timingSafeEqual, verify as cryptoVerify } from "node:crypto";
import { Malformed, compactJws, confirmationKey, jwkList, rs256Ok, same, show } from "./strict.js";

export const VERSION = "0.9.1";

const b64url = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");

const keysOf = jwkList;

function kindOf(header, claims) {
  const typ = typeof header.typ === "string" ? header.typ : "";
  if (typ === "receipt+jwt" || claims.aud === "regent-receipt") return "receipt";
  if (typ === "aa-auth+jwt" || "budget" in claims) return "budget";
  if ("scope" in claims && "decision_id" in claims) return "allow";
  return "unknown";
}

const finiteNumber = (v) => typeof v === "number" && Number.isFinite(v);
/** An option the function does not know is refused, not ignored: `approver_keys` for
 *  `approverKeys` would otherwise drop a requirement without a word. */
function unknownOptions(options, allowed) {
  if (options === undefined || options === null || typeof options !== "object") return null;
  const bad = Object.keys(options).filter((k) => !allowed.includes(k));
  return bad.length ? `unknown option ${show(bad[0])}; the options are ${allowed.join(", ")}` : null;
}
export { unknownOptions };
const DECIMAL = /^-?[0-9]+(\.[0-9]+)?$/;
/** An amount: a finite JSON number, or a plain decimal string ("12.50"). NaN and "nan" are not. */
const amountOf = (v) => {
  if (finiteNumber(v)) return v;
  if (typeof v !== "string" || !DECIMAL.test(v)) return null;
  const x = Number(v);
  return Number.isFinite(x) ? x : null;   // 309 digits and more: not an amount
};
const HEX64 = /^[0-9a-fA-F]{64}$/;
const SAFE = Number.MAX_SAFE_INTEGER;   // 2**53 - 1: beyond it two integers read as one double
/** A whole number as JSON carries it (12 or 12.0, within 2**53 - 1), else null. */
const whole = (v) => (finiteNumber(v) && Math.abs(v) <= SAFE && Number.isInteger(v) ? v : null);
const lowerAscii = (t) => (ASCII.test(t) ? t.toLowerCase() : t);
const plainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const LONE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
/** Text that UTF-8 can carry: no lone surrogate (JSON can spell one, "\\ud800"). */
const wellFormed = (t) => typeof t === "string" && (typeof t.isWellFormed === "function" ? t.isWellFormed() : !LONE.test(t));
class NotPortable extends Error {}
const SURROGATE = /[\uD800-\uDFFF]/;
function portable(v, depth = 0) {
  if (depth > 64) throw new NotPortable("nested too deeply");
  if (v === null || typeof v === "boolean") return v;
  if (typeof v === "string") { if (!wellFormed(v)) throw new NotPortable("text that is not valid"); return v; }
  if (typeof v === "number") { const w = whole(v); if (w === null) throw new NotPortable("a number other than a whole number within 2**53 - 1"); return w; }
  if (Array.isArray(v)) return v.map((x) => portable(x, depth + 1));
  if (plainObject(v)) {
    const out = {};
    for (const k of Object.keys(v)) {
      if (!wellFormed(k) || SURROGATE.test(k)) throw new NotPortable("a key outside the basic plane");
      Object.defineProperty(out, k, { value: portable(v[k], depth + 1), enumerable: true, writable: true, configurable: true });
    }
    return out;
  }
  throw new NotPortable("a value of another type");
}
/** A policy profile both languages hash to the same bytes (see the Python twin's `_profile`), or null. */
const portableProfile = (p) => { try { return portable(p); } catch (e) { if (e instanceof NotPortable) return null; throw e; } };
const ownGet = (o, k) => (Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined);
const amountText = (v) => (typeof v === "string" ? v : typeof v === "number" ? String(v) : show(v));
/** Present in the sense both languages agree on: not absent, null, empty text or false. */
const given = (v) => v !== undefined && v !== null && v !== false && v !== "";
const ASCII = /^[\x00-\x7f]*$/;
const upperAscii = (v) => (v === undefined || v === null ? "" : typeof v !== "string" ? null : ASCII.test(v) ? v.toUpperCase() : v);

const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
};

/** Signature + structure. Never throws on bad input. */
export function verifyToken(token, jwks, options = {}) {
  const { now: given, issuer = "regent-control" } = options ?? {};
  let now = given;
  const res = { signatureValid: false, kind: "unknown", header: {}, claims: {}, kid: null, expired: null, errors: [], warnings: [],
                argsHashMatch: null, mandateMatch: null, policyMatch: null, payeeMatch: null,
                confirmationMatch: null, confirmationErrors: [], confirmation: null,
                get valid() { return this.signatureValid && this.errors.length === 0; } };
  const unknown = unknownOptions(options, ["now", "issuer"]);
  if (unknown) { res.errors.push(unknown); return res; }
  if (now !== undefined && now !== null && !finiteNumber(now)) { res.errors.push("now is not a finite number of seconds"); return res; }
  if (now === undefined || now === null) now = Date.now() / 1000;
  let header, claims, signature, signed;
  try { ({ header, claims, signature, signed } = compactJws(token)); }
  catch (e) {
    const text = e instanceof Malformed ? e.message : "it could not be read";
    res.errors.push(text.startsWith("not a compact JWS") ? text : `cannot decode token: ${text}`); return res;
  }
  Object.assign(res, { header, claims, kid: header.kid ?? null, kind: kindOf(header, claims) });
  if (header.alg !== "RS256") { res.errors.push(`unsupported alg '${show(header.alg)}' (Regent signs RS256)`); return res; }
  const candidates = keysOf(jwks).filter((k) => k.kty === "RSA" && (res.kid == null || k.kid === res.kid));
  if (!candidates.length) { res.errors.push(`no RSA key with kid '${show(res.kid)}' in the JWKS you supplied`); return res; }
  for (const k of candidates) {
    if (rs256Ok(k, signed, signature)) { res.signatureValid = true; res.kid = typeof k.kid === "string" ? k.kid : null; break; }
  }
  if (!res.signatureValid) { res.errors.push("signature does not verify against the supplied key(s)"); return res; }
  if (issuer && claims.iss !== issuer) res.errors.push(`issuer is '${show(claims.iss)}', expected '${issuer}'`);
  if (res.kind === "receipt" && claims.aud !== "regent-receipt") res.errors.push("receipt audience must be 'regent-receipt'");
  if (typeof claims.exp === "number") {
    res.expired = claims.exp < now;
    if (res.expired) {
      if (res.kind === "receipt") res.errors.push("receipt is past its evidence period (exp)");
      else res.warnings.push("token expired (allow tokens live about a minute; signature and binding still verify)");
    }
  }
  if (typeof claims.iat === "number" && claims.iat > now + 300) res.errors.push("issued in the future (iat)");
  return res;
}

// ── canonical JSON as Python's json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False) ──
function canonicalJson(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k])).join(",") + "}";
}
const sha256 = (s) => createHash("sha256").update(s, "utf8").digest("hex");

/** Byte-identical to the gate's request hash. Note: numbers are hashed as the gate parsed them; a
 *  JSON value like 40.0 is "40.0" in Python but "40" here — pass amounts as integers or strings. */
export function canonicalArgsHash(tool, action, resource, args) {
  return sha256(canonicalJson({ tool, action, resource: resource ?? null, args: args ?? {} }));
}

export function checkRequestBinding(claims, { tool, action, resource = null, args = {} }) {
  return Boolean(claims.args_hash) && safeEq(canonicalArgsHash(tool, action, resource, args), claims.args_hash);
}

// ── mandate terms (terms-v2 / terms-v3 / terms-v4) ──
// terms-v3 (2026-10-13) appends allowed_resources: the mandate's scope, comma-joined in stored order.
// terms-v4 (2026-10-15) appends entity_limits: caps per counterparty as canonical strings
// "<match>=<per_tx|none>;<monthly|none>[;<daily>]", sorted, comma-joined — the same list
// form as the scope. The third field appears only where the owner set a daily figure.
export const MANDATE_FIELDS_V2 = ["mandate_id", "version", "agent_id", "owner_id", "currency", "settlement_chain", "status",
  "per_tx_limit", "daily_limit", "monthly_limit", "per_entity_limit", "entity_key", "relational_cap", "expires_at", "agent_may_read_limits"];
export const MANDATE_FIELDS_V3 = [...MANDATE_FIELDS_V2, "allowed_resources"];
export const MANDATE_FIELDS_V4 = [...MANDATE_FIELDS_V3, "entity_limits"];
export const MANDATE_FIELDS = MANDATE_FIELDS_V4;
const MANDATE_CANONS = { "terms-v2": MANDATE_FIELDS_V2, "terms-v3": MANDATE_FIELDS_V3, "terms-v4": MANDATE_FIELDS_V4 };
class NotCanonical extends Error {}
/** One snapshot value in the canonical string: none, true, false, text, a number, or a list of
 *  texts joined by commas. Anything else is not part of the format and matches nothing. */
const cv = (v) => {
  if (v === null || v === undefined) return "none";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "string" && wellFormed(v)) return v;
  if (finiteNumber(v)) return String(v);
  if (Array.isArray(v) && v.every((x) => wellFormed(x))) return v.join(",");
  throw new NotCanonical("snapshot value of another type");
};
export const mandateCanon = (snapshot, canon) => (typeof canon === "string" && Object.prototype.hasOwnProperty.call(MANDATE_CANONS, canon)) ? canon
  : ("entity_limits" in (snapshot || {}) ? "terms-v4" : "allowed_resources" in (snapshot || {}) ? "terms-v3" : "terms-v2");
export const mandateCanonicalString = (snapshot, salt, canon) => { const c = mandateCanon(snapshot, canon); return [c, ...MANDATE_CANONS[c].map((k) => `${k}=${cv(Object.prototype.hasOwnProperty.call(snapshot, k) ? snapshot[k] : undefined)}`), `salt=${salt}`].join("|"); };
export const mandateCommitment = (snapshot, salt, canon) => sha256(mandateCanonicalString(snapshot, salt, canon));

/** Values of a type the format does not define match nothing; this never throws. */
export function checkMandateReveal(claims, reveal) {
  if (!plainObject(claims) || !plainObject(reveal)) return false;
  const expected = ownGet(claims, "mandate_hash"); const salt = ownGet(reveal, "salt");
  const snap = plainObject(ownGet(reveal, "snapshot")) ? reveal.snapshot : reveal;
  if (!(typeof expected === "string" && HEX64.test(expected) && wellFormed(salt) && salt)) return false;
  const sv = ownGet(snap, "version"); const cv_ = ownGet(claims, "mandate_version");
  if (sv !== undefined && sv !== null && cv_ !== undefined && cv_ !== null) {
    const mine = whole(sv); const theirs = whole(cv_);
    if (mine === null || theirs === null || mine !== theirs) return false;
  }
  const canon = typeof ownGet(reveal, "canon") === "string" ? reveal.canon : undefined;
  let got;
  try { got = mandateCommitment(snap, lowerAscii(salt), canon); } catch (e) { if (e instanceof NotCanonical) return false; throw e; }
  return safeEq(got, expected.toLowerCase());
}

// ── payee (payee-v1) ──
export const payeeCanonicalString = (payee, salt) => `payee-v1|payee=${payee}|salt=${lowerAscii(String(salt))}`;
export const payeeCommitment = (payee, salt) => sha256(payeeCanonicalString(payee, salt));
/** reveal = the owner's {payee, salt} for this decision; opens the receipt's payee_hash. */
export function checkPayeeReveal(claims, reveal) {
  if (!plainObject(claims) || !plainObject(reveal)) return false;
  const expected = ownGet(claims, "payee_hash"); const payee = ownGet(reveal, "payee"); const salt = ownGet(reveal, "salt");
  if (!(typeof expected === "string" && HEX64.test(expected) && wellFormed(payee) && payee && wellFormed(salt) && salt)) return false;
  if (given(ownGet(reveal, "decision_id")) && given(ownGet(claims, "decision_id")) && !same(reveal.decision_id, claims.decision_id)) return false;
  return safeEq(payeeCommitment(payee, salt), expected.toLowerCase());
}

// ── policy (policy-v1) ──
export function policyCanonicalString(orgId, version, cedarText, profile, salt) {
  const prof = profile == null ? "none" : sha256(canonicalJson(profile));
  return ["policy-v1", `org_id=${orgId}`, `version=${Number(version)}`, `text_sha256=${sha256(cedarText || "")}`, `profile_sha256=${prof}`, `salt=${salt}`].join("|");
}
export const policyCommitment = (orgId, version, cedarText, profile, salt) => sha256(policyCanonicalString(orgId, version, cedarText, profile, salt));

export function checkPolicyReveal(claims, reveal) {
  if (!plainObject(claims)) return false;
  const expected = ownGet(claims, "policy_hash");
  if (!(typeof expected === "string" && HEX64.test(expected))) return false;
  if (typeof reveal === "string") reveal = { cedar_text: reveal };
  if (!plainObject(reveal)) return false;
  const ct = ownGet(reveal, "cedar_text"); const cd = ownGet(reveal, "cedar");
  const text = typeof ct === "string" ? ct : (typeof cd === "string" ? cd : null);
  if (text === null || !wellFormed(text)) return false;
  const source = ownGet(claims, "policy_source");
  if (source === "starter" || source === "legacy") return safeEq(sha256(text), expected.toLowerCase());
  const rv = ownGet(reveal, "version");
  const version = whole(rv !== undefined && rv !== null ? rv : ownGet(claims, "policy_version"));
  const orgId = ownGet(reveal, "org_id"); const salt = ownGet(reveal, "salt");
  if (version === null || !(orgId === undefined || orgId === null || wellFormed(orgId)) || !(salt === undefined || salt === null || wellFormed(salt))) return false;
  let profile = plainObject(ownGet(reveal, "profile")) ? reveal.profile : null;
  if (profile !== null) { profile = portableProfile(profile); if (profile === null) return false; }
  return safeEq(policyCommitment(orgId || "", version, text, profile, lowerAscii(salt || "")), expected.toLowerCase());
}

// ── where the money went: settlement_ref / settlement_network (0.7.0) ─────────
// A receipt whose settlement Regent read from the rail itself (`settlement_source:
// custodian` for a custodian's ledger, `counterparty` for a signed confirmation) may carry
// `settlement_ref`: the rail's own reference for the settled money — a chain transaction
// hash, a PSP charge id — and, when that reference lives on a chain, `settlement_network`.
// Signed claims like any other: shown here, looked up on the rail by the reader. A receipt
// for a failed or voided settlement never carries them.

// ── counterparty settlement confirmation ──────────────────────────────────────
// A receipt whose settlement the other side of the payment confirmed carries
// `settlement_source: counterparty`, `confirmed_by`, `confirmation_kid`, `confirmation_hash` and
// `confirmation`: the counterparty's own compact JWS (typ settlement-confirmation+jwt; ES256,
// EdDSA, RS256 or PS256). Regent verified it at minting time; with the counterparty's JWKS you
// repeat that check offline and hold two signatures over the same facts.

export const CONFIRMATION_TYP = "settlement-confirmation+jwt";
export const CONFIRMATION_ALGS = ["ES256", "EdDSA", "RS256", "PS256"];

function jwsSignatureOk(alg, jwk, signed, signature) {
  try {
    const key = confirmationKey(jwk, alg);   // the one key type this algorithm uses, read strictly
    if (alg === "ES256") return signature.length === 64 && cryptoVerify("sha256", signed, { key, dsaEncoding: "ieee-p1363" }, signature);
    if (alg === "EdDSA") return cryptoVerify(null, signed, key, signature);
    if (alg === "RS256") return cryptoVerify("sha256", signed, key, signature);
    if (alg === "PS256") return cryptoVerify("sha256", signed, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);
  } catch { /* unsupported or malformed key */ }
  return false;
}

/** Verify the counterparty confirmation embedded in (already verified) receipt claims against the
 *  counterparty's JWKS and check it says the same as the receipt. Never throws. */
export function checkConfirmation(claims, counterpartyJwks, options = {}) {
  const out = { ok: false, errors: [], issuer: null, kid: null, claims: {} };
  const unknown = unknownOptions(options, ["now"]);
  if (unknown) { out.errors.push(unknown); return out; }
  const now = options !== null && typeof options === "object" ? options.now : undefined;
  try { checkConfirmationInto(out, claims, counterpartyJwks, now); }
  catch (e) { out.errors.push(`the confirmation could not be read (${e?.name || "Error"})`); }
  out.ok = out.errors.length === 0;
  return out;
}

function checkConfirmationInto(out, claimsIn, counterpartyJwks, now) {
  const claims = claimsIn !== null && typeof claimsIn === "object" && !Array.isArray(claimsIn) ? claimsIn : {};
  const own = (o, k) => (Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined);
  const jws = own(claims, "confirmation");
  if (typeof jws !== "string" || jws.split(".").length !== 3) {
    out.errors.push("the receipt carries no counterparty confirmation (settlement is agent-reported)"); return;
  }
  if (now !== undefined && now !== null && !finiteNumber(now)) { out.errors.push("now is not a finite number of seconds"); return; }
  let header, payload, signature, signed;
  // the one strict reader: no NaN, no byte order mark, one spelling of base64url
  try { ({ header, claims: payload, signature, signed } = compactJws(jws)); }
  catch (e) { out.errors.push(`cannot decode the confirmation: ${e instanceof Malformed ? e.message : "it could not be read"}`); return; }
  const p = (k) => own(payload, k); const c = (k) => own(claims, k);
  Object.assign(out, { claims: payload, kid: own(header, "kid") ?? null, issuer: p("iss") ?? null });
  if (own(header, "typ") !== CONFIRMATION_TYP) out.errors.push(`confirmation typ is '${show(own(header, "typ"))}', expected '${CONFIRMATION_TYP}'`);
  const alg = own(header, "alg");
  if (!CONFIRMATION_ALGS.includes(alg)) { out.errors.push(`unsupported confirmation alg '${show(alg)}'`); return; }
  const candidates = keysOf(counterpartyJwks).filter((k) => out.kid == null || k.kid === out.kid);
  if (!candidates.length) { out.errors.push(`no key with kid '${show(out.kid)}' in the counterparty JWKS you supplied`); return; }
  const hit = candidates.find((k) => jwsSignatureOk(alg, k, signed, signature));
  if (!hit) { out.errors.push("confirmation signature does not verify against the counterparty key(s)"); return; }
  out.kid = hit.kid ?? null;
  // the confirmation must be the one the receipt cites, about this decision, saying the same thing
  const expected = c("confirmation_hash");
  if (given(expected) && !(typeof expected === "string" && HEX64.test(expected) && safeEq(sha256(jws), expected.toLowerCase())))
    out.errors.push("confirmation_hash in the receipt does not match the embedded confirmation");
  if (given(c("confirmed_by")) && !same(p("iss") ?? null, c("confirmed_by")))
    out.errors.push(`confirmation issuer '${show(p("iss"))}' differs from the receipt's confirmed_by`);
  if (given(c("confirmation_kid")) && !same(out.kid, c("confirmation_kid"))) out.errors.push("confirmation kid differs from the receipt's confirmation_kid");
  if (!same(p("decision_id") ?? null, c("decision_id") ?? null)) out.errors.push("the confirmation is about another decision");
  if (!same(p("status") ?? null, c("status") ?? null)) out.errors.push(`confirmation status '${show(p("status"))}' differs from the receipt's '${show(c("status"))}'`);
  const pAmount = p("amount"); const rAmount = c("amount");
  if (pAmount !== undefined && pAmount !== null && rAmount !== undefined && rAmount !== null) {
    const pa = amountOf(pAmount); const ra = amountOf(rAmount);
    if (pa === null || ra === null) out.errors.push("confirmation amount is not a number");
    else if (Math.abs(pa - ra) > 0.01) out.errors.push(`confirmation amount ${amountText(pAmount)} differs from the receipt's ${amountText(rAmount)}`);
    const cp = upperAscii(p("currency")); const cr = upperAscii(c("currency"));
    if (!(typeof cp === "string" && typeof cr === "string" && cp === cr)) out.errors.push("confirmation currency differs from the receipt's");
  }
  // time: the confirmation had to be live when Regent accepted it, i.e. at the receipt's iat
  const acceptedAt = finiteNumber(c("iat")) ? c("iat") : (now ?? Date.now() / 1000);
  if (finiteNumber(p("exp")) && p("exp") < acceptedAt) out.errors.push("the confirmation had already expired when the receipt was minted");
  if (finiteNumber(p("iat")) && p("iat") > acceptedAt + 300) out.errors.push("the confirmation was issued after the receipt");
}

/** One call: signature, structure, and each optional check. */
export function verify(token, jwks, options = {}) {
  const o = options !== null && typeof options === "object" ? options : {};
  let { request, mandateReveal, policyReveal, payeeReveal } = o;
  const { counterpartyJwks, now, issuer } = o;
  const res = verifyToken(token, jwks, { now, issuer });
  const unknown = unknownOptions(o, ["request", "mandateReveal", "policyReveal", "payeeReveal", "counterpartyJwks", "now", "issuer"]);
  if (unknown) res.errors.push(unknown);
  if (!res.signatureValid) return res;
  const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  for (const [name, value] of [["request", request], ["mandate reveal", mandateReveal], ["payee reveal", payeeReveal]]) {
    if (value !== undefined && value !== null && !isObj(value)) res.errors.push(`the ${name} is not a JSON object`);
  }
  if (policyReveal !== undefined && policyReveal !== null && !isObj(policyReveal) && typeof policyReveal !== "string") res.errors.push("the policy reveal is not a JSON object or text");
  request = isObj(request) ? request : null; mandateReveal = isObj(mandateReveal) ? mandateReveal : null; payeeReveal = isObj(payeeReveal) ? payeeReveal : null;
  policyReveal = isObj(policyReveal) || typeof policyReveal === "string" ? policyReveal : null;
  if (request !== null) res.argsHashMatch = checkRequestBinding(res.claims, request);
  if (mandateReveal !== null) res.mandateMatch = checkMandateReveal(res.claims, mandateReveal);
  if (policyReveal !== null) res.policyMatch = checkPolicyReveal(res.claims, policyReveal);
  if (payeeReveal !== null) res.payeeMatch = checkPayeeReveal(res.claims, payeeReveal);
  if (counterpartyJwks !== undefined && counterpartyJwks !== null) {
    const c = checkConfirmation(res.claims, counterpartyJwks, { now });
    res.confirmationMatch = c.ok; res.confirmationErrors = c.errors; res.confirmation = c.ok ? c.claims : null;
  }
  return res;
}

export { verifyBundle, checkTxCarriesRoot, merkleRootFrom, BUNDLE_VERSION } from "./bundle.js";
export { verifyApproval } from "./approval.js";
