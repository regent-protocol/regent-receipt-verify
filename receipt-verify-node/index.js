// @regent-protocol/receipt-verify — verify a Regent Control receipt or allow token without Regent.
// Node ≥ 18, no dependencies: RS256 via node:crypto, commitments via the same canonical strings
// the gate and the browser verifier use (terms-v2 for mandates, policy-v1 for policies), and
// the same request hash (sha256 over canonical JSON of {tool, action, resource, args}).
import { constants, createHash, createPublicKey, timingSafeEqual, verify as cryptoVerify } from "node:crypto";

export const VERSION = "0.2.0";

const b64url = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");

function keysOf(jwks) {
  if (!jwks) return [];
  if (Array.isArray(jwks)) return jwks.flatMap(keysOf);
  if (jwks.keys) return [...jwks.keys];
  return [jwks];
}

function kindOf(header, claims) {
  const typ = String(header.typ || "");
  if (typ === "receipt+jwt" || claims.aud === "regent-receipt") return "receipt";
  if (typ === "aa-auth+jwt" || "budget" in claims) return "budget";
  if ("scope" in claims && "decision_id" in claims) return "allow";
  return "unknown";
}

const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
};

/** Signature + structure. Never throws on bad input. */
export function verifyToken(token, jwks, { now = Date.now() / 1000, issuer = "regent-control" } = {}) {
  const res = { signatureValid: false, kind: "unknown", header: {}, claims: {}, kid: null, expired: null, errors: [], warnings: [],
                argsHashMatch: null, mandateMatch: null, policyMatch: null,
                confirmationMatch: null, confirmationErrors: [], confirmation: null,
                get valid() { return this.signatureValid && this.errors.length === 0; } };
  const parts = String(token || "").trim().split(".");
  if (parts.length !== 3) { res.errors.push("not a compact JWS (expected header.payload.signature)"); return res; }
  let header, claims, signature;
  try { header = JSON.parse(b64url(parts[0]).toString("utf8")); claims = JSON.parse(b64url(parts[1]).toString("utf8")); signature = b64url(parts[2]); }
  catch (e) { res.errors.push(`cannot decode token: ${e.message}`); return res; }
  Object.assign(res, { header, claims, kid: header.kid ?? null, kind: kindOf(header, claims) });
  if (header.alg !== "RS256") { res.errors.push(`unsupported alg '${header.alg}' (Regent signs RS256)`); return res; }
  const candidates = keysOf(jwks).filter((k) => k.kty === "RSA" && (res.kid == null || k.kid === res.kid));
  if (!candidates.length) { res.errors.push(`no RSA key with kid '${res.kid}' in the JWKS you supplied`); return res; }
  const signed = Buffer.from(`${parts[0]}.${parts[1]}`, "ascii");
  for (const k of candidates) {
    try {
      const key = createPublicKey({ key: { kty: "RSA", n: k.n, e: k.e }, format: "jwk" });
      if (cryptoVerify("sha256", signed, key, signature)) { res.signatureValid = true; res.kid = k.kid ?? null; break; }
    } catch { /* try the next key */ }
  }
  if (!res.signatureValid) { res.errors.push("signature does not verify against the supplied key(s)"); return res; }
  if (issuer && claims.iss !== issuer) res.errors.push(`issuer is '${claims.iss}', expected '${issuer}'`);
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

// ── mandate terms (terms-v2) ──
export const MANDATE_FIELDS = ["mandate_id", "version", "agent_id", "owner_id", "currency", "settlement_chain", "status",
  "per_tx_limit", "daily_limit", "monthly_limit", "per_entity_limit", "entity_key", "relational_cap", "expires_at", "agent_may_read_limits"];
const cv = (v) => (v === null || v === undefined) ? "none" : v === true ? "true" : v === false ? "false" : String(v);
export const mandateCanonicalString = (snapshot, salt) => ["terms-v2", ...MANDATE_FIELDS.map((k) => `${k}=${cv(snapshot[k])}`), `salt=${salt}`].join("|");
export const mandateCommitment = (snapshot, salt) => sha256(mandateCanonicalString(snapshot, salt));

export function checkMandateReveal(claims, reveal) {
  const expected = String(claims.mandate_hash || "");
  const snap = reveal && typeof reveal.snapshot === "object" && reveal.snapshot ? reveal.snapshot : reveal;
  const salt = String((reveal && reveal.salt) || "");
  if (!expected || !salt || !snap) return false;
  if (snap.version !== undefined && claims.mandate_version != null && Number(snap.version) !== Number(claims.mandate_version)) return false;
  return safeEq(mandateCommitment(snap, salt.toLowerCase()), expected.toLowerCase());
}

// ── policy (policy-v1) ──
export function policyCanonicalString(orgId, version, cedarText, profile, salt) {
  const prof = profile == null ? "none" : sha256(canonicalJson(profile));
  return ["policy-v1", `org_id=${orgId}`, `version=${Number(version)}`, `text_sha256=${sha256(cedarText || "")}`, `profile_sha256=${prof}`, `salt=${salt}`].join("|");
}
export const policyCommitment = (orgId, version, cedarText, profile, salt) => sha256(policyCanonicalString(orgId, version, cedarText, profile, salt));

export function checkPolicyReveal(claims, reveal) {
  const expected = String(claims.policy_hash || "");
  if (!expected) return false;
  if (typeof reveal === "string") reveal = { cedar_text: reveal };
  const text = typeof reveal?.cedar_text === "string" ? reveal.cedar_text : (typeof reveal?.cedar === "string" ? reveal.cedar : null);
  if (text === null) return false;
  if (claims.policy_source === "starter" || claims.policy_source === "legacy") return safeEq(sha256(text), expected.toLowerCase());
  const version = reveal.version ?? claims.policy_version;
  if (version === undefined || version === null || Number.isNaN(Number(version))) return false;
  const profile = reveal.profile && typeof reveal.profile === "object" ? reveal.profile : null;
  return safeEq(policyCommitment(String(reveal.org_id || ""), version, text, profile, String(reveal.salt || "").toLowerCase()), expected.toLowerCase());
}

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
    const key = createPublicKey({ key: jwk, format: "jwk" });
    if (alg === "ES256") return signature.length === 64 && cryptoVerify("sha256", signed, { key, dsaEncoding: "ieee-p1363" }, signature);
    if (alg === "EdDSA") return cryptoVerify(null, signed, key, signature);
    if (alg === "RS256") return cryptoVerify("sha256", signed, key, signature);
    if (alg === "PS256") return cryptoVerify("sha256", signed, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);
  } catch { /* unsupported or malformed key */ }
  return false;
}

/** Verify the counterparty confirmation embedded in (already verified) receipt claims against the
 *  counterparty's JWKS and check it says the same as the receipt. Never throws. */
export function checkConfirmation(claims, counterpartyJwks, { now } = {}) {
  const out = { ok: false, errors: [], issuer: null, kid: null, claims: {} };
  const jws = claims?.confirmation;
  if (typeof jws !== "string" || jws.split(".").length !== 3) {
    out.errors.push("the receipt carries no counterparty confirmation (settlement is agent-reported)"); return out;
  }
  const parts = jws.split(".");
  let header, payload, signature;
  try { header = JSON.parse(b64url(parts[0]).toString("utf8")); payload = JSON.parse(b64url(parts[1]).toString("utf8")); signature = b64url(parts[2]); }
  catch (e) { out.errors.push(`cannot decode the confirmation: ${e.message}`); return out; }
  Object.assign(out, { claims: payload, kid: header.kid ?? null, issuer: payload.iss ?? null });
  if (header.typ !== CONFIRMATION_TYP) out.errors.push(`confirmation typ is '${header.typ}', expected '${CONFIRMATION_TYP}'`);
  if (!CONFIRMATION_ALGS.includes(header.alg)) { out.errors.push(`unsupported confirmation alg '${header.alg}'`); return out; }
  const candidates = keysOf(counterpartyJwks).filter((k) => out.kid == null || k.kid === out.kid);
  if (!candidates.length) { out.errors.push(`no key with kid '${out.kid}' in the counterparty JWKS you supplied`); return out; }
  const signed = Buffer.from(`${parts[0]}.${parts[1]}`, "ascii");
  const hit = candidates.find((k) => jwsSignatureOk(header.alg, k, signed, signature));
  if (!hit) { out.errors.push("confirmation signature does not verify against the counterparty key(s)"); return out; }
  out.kid = hit.kid ?? null;
  // the confirmation must be the one the receipt cites, about this decision, saying the same thing
  if (claims.confirmation_hash && !safeEq(sha256(jws), String(claims.confirmation_hash).toLowerCase()))
    out.errors.push("confirmation_hash in the receipt does not match the embedded confirmation");
  if (claims.confirmed_by && payload.iss !== claims.confirmed_by)
    out.errors.push(`confirmation issuer '${payload.iss}' differs from the receipt's confirmed_by`);
  if (claims.confirmation_kid && out.kid !== claims.confirmation_kid) out.errors.push("confirmation kid differs from the receipt's confirmation_kid");
  if (payload.decision_id !== claims.decision_id) out.errors.push("the confirmation is about another decision");
  if (payload.status !== claims.status) out.errors.push(`confirmation status '${payload.status}' differs from the receipt's '${claims.status}'`);
  if (payload.amount != null && claims.amount != null) {
    if (!(Math.abs(Number(payload.amount) - Number(claims.amount)) <= 0.01)) out.errors.push(`confirmation amount ${payload.amount} differs from the receipt's ${claims.amount}`);
    if (String(payload.currency ?? "").toUpperCase() !== String(claims.currency ?? "").toUpperCase()) out.errors.push("confirmation currency differs from the receipt's");
  }
  // time: the confirmation had to be live when Regent accepted it, i.e. at the receipt's iat
  const acceptedAt = typeof claims.iat === "number" ? claims.iat : (now ?? Date.now() / 1000);
  if (typeof payload.exp === "number" && payload.exp < acceptedAt) out.errors.push("the confirmation had already expired when the receipt was minted");
  if (typeof payload.iat === "number" && payload.iat > acceptedAt + 300) out.errors.push("the confirmation was issued after the receipt");
  out.ok = out.errors.length === 0;
  return out;
}

/** One call: signature, structure, and each optional check. */
export function verify(token, jwks, { request, mandateReveal, policyReveal, counterpartyJwks, now, issuer } = {}) {
  const res = verifyToken(token, jwks, { now, issuer });
  if (!res.signatureValid) return res;
  if (request) res.argsHashMatch = checkRequestBinding(res.claims, request);
  if (mandateReveal) res.mandateMatch = checkMandateReveal(res.claims, mandateReveal);
  if (policyReveal !== undefined && policyReveal !== null) res.policyMatch = checkPolicyReveal(res.claims, policyReveal);
  if (counterpartyJwks !== undefined && counterpartyJwks !== null) {
    const c = checkConfirmation(res.claims, counterpartyJwks, { now });
    res.confirmationMatch = c.ok; res.confirmationErrors = c.errors; res.confirmation = c.ok ? c.claims : null;
  }
  return res;
}
