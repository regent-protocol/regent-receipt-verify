// @regent-protocol/receipt-verify — verify a Regent Control receipt or allow token without Regent.
// Node ≥ 18, no dependencies: RS256 via node:crypto, commitments via the same canonical strings
// the gate and the browser verifier use (terms-v2 for mandates, policy-v1 for policies), and
// the same request hash (sha256 over canonical JSON of {tool, action, resource, args}).
import { createHash, createPublicKey, timingSafeEqual, verify as cryptoVerify } from "node:crypto";

export const VERSION = "0.1.0";

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
                argsHashMatch: null, mandateMatch: null, policyMatch: null, get valid() { return this.signatureValid && this.errors.length === 0; } };
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

/** One call: signature, structure, and each optional check. */
export function verify(token, jwks, { request, mandateReveal, policyReveal, now, issuer } = {}) {
  const res = verifyToken(token, jwks, { now, issuer });
  if (!res.signatureValid) return res;
  if (request) res.argsHashMatch = checkRequestBinding(res.claims, request);
  if (mandateReveal) res.mandateMatch = checkMandateReveal(res.claims, mandateReveal);
  if (policyReveal !== undefined && policyReveal !== null) res.policyMatch = checkPolicyReveal(res.claims, policyReveal);
  return res;
}
