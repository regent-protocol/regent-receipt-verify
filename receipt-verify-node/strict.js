// Strict readers shared by every check in this package; the same rules as strict.py.
//
// A verifier is handed files written by whoever wants a particular answer, and its output is
// read by a person in a dispute. So input is read one way only: the base64url alphabet in its
// canonical spelling, UTF-8, JSON, numbers a double holds exactly, bounded depth, a compact
// JWS with nothing around or inside it, RSA keys of the profile Regent signs with (e = 65537,
// 2048 to 8192 bits). Malformed input throws `Malformed`, which every caller turns into an
// INVALID result, never into an exception for the user.
//
// This module imports nothing from the rest of the package.
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

export const HEX64 = /^[0-9a-f]{64}$/;
const B64U = /^[A-Za-z0-9_-]*$/;
const MAX_DEPTH = 64;
const BAD_NUMBER = "JSON carries a number a double does not hold exactly";

export class Malformed extends Error {}

// ── strict readers ──────────────────────────────────────────────────────────────────────
export function str(value, what) { if (typeof value !== "string") throw new Malformed(`${what} is not a string`); return value; }
export const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
export const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
export const get = (o, k) => (has(o, k) ? o[k] : undefined);

/** base64url in its one canonical spelling: the URL-safe alphabet, no padding, no stray bits in
 *  the last character. Two spellings of the same bytes would let two programs disagree about one file. */
export function b64u(value, what) {
  const text = str(value, what);
  if (!B64U.test(text) || text.length % 4 === 1) throw new Malformed(`${what} is not base64url`);
  const data = Buffer.from(text, "base64url");
  if (data.toString("base64url") !== text) throw new Malformed(`${what} is not base64url`);
  return data;
}
export const b64uEnc = (buf) => Buffer.from(buf).toString("base64url");
export const sha256 = (data) => createHash("sha256").update(data).digest();
// trailing '=' removed with a loop: /=+$/ is quadratic on a long run of '=' that does not end the string
export const stripPad = (s) => { const t = String(s); let end = t.length; while (end > 0 && t[end - 1] === "=") end--; return t.slice(0, end); };

export function utf8(text, what) {
  // a lone surrogate cannot be encoded: refuse it instead of writing U+FFFD
  if (typeof text.isWellFormed === "function" ? !text.isWellFormed() : /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(text)) throw new Malformed(`${what} is not valid text`);
  return Buffer.from(text, "utf8");
}

function checkValues(value, depth = 0) {
  if (depth > MAX_DEPTH) throw new Malformed("JSON is nested too deeply");
  if (value === null || typeof value === "boolean" || typeof value === "string") return;
  if (typeof value === "number") {
    if (!(Math.abs(value) <= Number.MAX_SAFE_INTEGER)) throw new Malformed(BAD_NUMBER);  // also NaN and Infinity
    return;
  }
  if (Array.isArray(value)) { for (const item of value) checkValues(item, depth + 1); return; }
  if (typeof value === "object") { for (const k of Object.keys(value)) checkValues(value[k], depth + 1); return; }
  throw new Malformed("JSON carries an unknown value");
}

/** [object, bytes] from a canonical string: strict UTF-8, JSON, integers a double can hold, bounded depth. */
export function parse(text, what) {
  str(text, what);
  if (!text) throw new Malformed(`${what} is empty`);
  const raw = utf8(text, what);
  let obj;
  try { obj = JSON.parse(text); } catch (e) {
    if (e instanceof RangeError) throw new Malformed(`${what} is nested too deeply`);
    throw new Malformed(`${what} is not JSON`);
  }
  // an integer literal too large for a double parses to a value beyond the safe range, so the
  // one rule on values (checkValues) catches it: no scan of the text is needed
  checkValues(obj);
  return [obj, raw];
}

/** Equality as JSON means it: true is not 1, numbers by value, everything else exactly. */
export function same(a, b, depth = 0) {
  if (depth > MAX_DEPTH) return false;
  if (a === null || b === null) return a === b;
  if (typeof a !== typeof b) return false;
  if (typeof a !== "object") return a === b;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => same(x, b[i], depth + 1));
  const ka = Object.keys(a); const kb = Object.keys(b);
  return ka.length === kb.length && ka.every((k) => has(b, k) && same(a[k], b[k], depth + 1));
}

// ── a compact JWS and the RSA keys of a JWKS, read one way ─────────────────────────────
const JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/** Bytes that are one JSON object in UTF-8: no byte order mark, no NaN, numbers a double holds exactly, bounded depth. */
export function jsonObject(raw, what) {
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw); }
  catch { throw new Malformed(`${what} is not UTF-8`); }
  if (text.startsWith("\ufeff")) throw new Malformed(`${what} starts with a byte order mark`);
  const [obj] = parse(text, what);
  if (!isObject(obj)) throw new Malformed(`${what} is not a JSON object`);
  return obj;
}

const trimAscii = (t) => { let a = 0; let b = t.length; const ws = (c) => c === " " || c === "\t" || c === "\r" || c === "\n"; while (a < b && ws(t[a])) a++; while (b > a && ws(t[b - 1])) b--; return t.slice(a, b); };

/** { header, claims, signature, signed } of `header.payload.signature`. Only spaces, tabs and line
 *  ends around the token are ignored; inside it every character is base64url, canonical and unpadded. */
export function compactJws(token) {
  const text = trimAscii(str(token, "token"));
  if (!JWS.test(text)) throw new Malformed("not a compact JWS (expected header.payload.signature)");
  const [h, p, sig] = text.split(".");
  const header = jsonObject(b64u(h, "header"), "header");
  const claims = jsonObject(b64u(p, "payload"), "payload");
  const kid = get(header, "kid") ?? null;
  if (kid !== null && typeof kid !== "string") throw new Malformed("kid is not a string");
  return { header, claims, signature: b64u(sig, "signature"), signed: Buffer.from(`${h}.${p}`, "ascii") };
}

/** The key objects of a JWKS, of one JWK, or of a list of those (key rotation). What is not an
 *  object is skipped; nothing here throws or recurses. */
export const MAX_KEYS = 16;      // keys read from one key set: a set of thousands is a way to spend time, not a key set
export function jwkList(jwks) {
  const out = [];
  for (const item of (Array.isArray(jwks) ? jwks : [jwks]).slice(0, MAX_KEYS)) {
    if (!isObject(item)) continue;
    if (has(item, "keys")) { if (Array.isArray(item.keys)) for (const k of item.keys.slice(0, MAX_KEYS)) if (isObject(k)) out.push(k); }
    else out.push(item);
  }
  return out.slice(0, MAX_KEYS);
}

/** RS256 with one RSA key of a JWKS. The key must be of the profile Regent signs with
 *  (e = 65537, 2048 to 8192 bits); any other key verifies nothing. */
export function rs256Ok(jwk, signed, signature) {
  let n; let e;
  try { n = b64u(get(jwk, "n"), "n"); e = b64u(get(jwk, "e"), "e"); } catch { return false; }
  const bits = bitLength(n);
  if (!isE65537(e) || bits < 2048 || bits > 8192 || (n[n.length - 1] & 1) === 0) return false;
  try {
    const key = createPublicKey({ key: { kty: "RSA", n: b64uEnc(n), e: b64uEnc(e) }, format: "jwk" });
    return cryptoVerify("sha256", signed, key, signature);
  } catch { return false; }
}

/** A value inside a message, spelled the same in every language: a string as it is, anything else as compact JSON. */
export function show(value) {
  if (typeof value === "string") return value;
  // cut by code point, as the Python twin does
  try { const t = JSON.stringify(value === undefined ? null : value); return typeof t === "string" ? [...t].slice(0, 120).join("") : "?"; } catch { return "?"; }
}

/** An option that must be a list of strings (null = not given). A bare string would match by substring. */
export function stringList(value, what) {
  if (value === undefined || value === null) return null;
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) throw new Malformed(`${what} must be a list of strings`);
  return [...value];
}

/** A code point that must not reach a terminal or a page as it is: C0 and C1 controls, DEL, lone
 *  surrogates, line and paragraph separators, and the invisible characters that reorder or hide text. */
export const unprintable = (code) => code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0xad || code === 0x034f || (code >= 0xd800 && code <= 0xdfff)
  || code === 0x061c || (code >= 0x115f && code <= 0x1160) || (code >= 0x17b4 && code <= 0x17b5) || (code >= 0x180b && code <= 0x180f)
  || (code >= 0x200b && code <= 0x200f) || (code >= 0x2028 && code <= 0x202e) || (code >= 0x2060 && code <= 0x206f) || code === 0x3164
  || (code >= 0xfe00 && code <= 0xfe0f) || code === 0xfeff || code === 0xffa0 || (code >= 0xfff0 && code <= 0xfffb)
  || (code >= 0x1bca0 && code <= 0x1bca3) || (code >= 0x1d173 && code <= 0x1d17a) || (code >= 0xe0000 && code <= 0xe0fff);

export const bitLength = (buf) => { let i = 0; while (i < buf.length && buf[i] === 0) i++; return i === buf.length ? 0 : (buf.length - i - 1) * 8 + (32 - Math.clz32(buf[i])); };
export const isE65537 = (buf) => { let i = 0; while (i < buf.length - 1 && buf[i] === 0) i++; const t = buf.subarray(i); return t.length === 3 && t[0] === 1 && t[1] === 0 && t[2] === 1; };

/** A short string of ordinary printable characters, or null: a value with a line break, an
 *  escape sequence or any other control character is dropped, so nothing the block says can
 *  be dressed up as a line of this verifier's own output. */
export function plain(value, limit = 120) {
  if (typeof value !== "string" || !value || value.length > limit * 2) return null;
  const points = [...value];  // by code point: an astral character is one, a lone surrogate stays a surrogate
  if (points.length > limit) return null;
  for (const ch of points) if (unprintable(ch.codePointAt(0))) return null;
  return value;
}

// ── a counterparty's key, read one way (the same rules as strict.py) ───────────────────
// A confirmation names its algorithm; the key must be of the one type that algorithm uses,
// read from strict base64url, and of a sound size. The key handed to node:crypto is built
// from the checked parts, never from the JWK as given.
const P256_FIELD = Buffer.from("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", "hex");
const ED25519_SMALL_ORDER = new Set([
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]);

/** The KeyObject of one JWK for one algorithm, or a thrown Malformed. */
export function confirmationKey(jwk, alg) {
  if (!isObject(jwk)) throw new Malformed("key is not an object");
  const kty = get(jwk, "kty");
  if (alg === "ES256") {
    if (kty !== "EC" || get(jwk, "crv") !== "P-256") throw new Malformed("ES256 needs an EC P-256 key");
    const x = b64u(get(jwk, "x"), "x"); const y = b64u(get(jwk, "y"), "y");
    if (x.length !== 32 || y.length !== 32) throw new Malformed("EC key without 32-byte coordinates");
    if (Buffer.compare(x, P256_FIELD) >= 0 || Buffer.compare(y, P256_FIELD) >= 0) throw new Malformed("EC point is not on the curve");
    let key; try { key = createPublicKey({ key: { kty: "EC", crv: "P-256", x: b64uEnc(x), y: b64uEnc(y) }, format: "jwk" }); }
    catch { throw new Malformed("EC point is not on the curve"); }
    if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new Malformed("ES256 needs an EC P-256 key");
    return key;
  }
  if (alg === "EdDSA") {
    if (kty !== "OKP" || get(jwk, "crv") !== "Ed25519") throw new Malformed("EdDSA needs an OKP Ed25519 key");
    const x = b64u(get(jwk, "x"), "x");
    if (x.length !== 32) throw new Malformed("Ed25519 key without a 32-byte point");
    const masked = Buffer.from(x); masked[31] &= 0x7f;
    if (ED25519_SMALL_ORDER.has(masked.toString("hex"))) throw new Malformed("Ed25519 key is of small order");
    let key; try { key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: b64uEnc(x) }, format: "jwk" }); }
    catch { throw new Malformed("Ed25519 key is not usable"); }
    if (key.asymmetricKeyType !== "ed25519") throw new Malformed("EdDSA needs an OKP Ed25519 key");
    return key;
  }
  if (alg === "RS256" || alg === "PS256") {
    if (kty !== "RSA") throw new Malformed(`${alg} needs an RSA key`);
    const n = b64u(get(jwk, "n"), "n"); const e = b64u(get(jwk, "e"), "e");
    const bits = bitLength(n);
    if (!isE65537(e) || bits < 2048 || bits > 8192 || (n[n.length - 1] & 1) === 0) throw new Malformed("RSA key must have e=65537 and 2048 to 8192 bits");
    let key; try { key = createPublicKey({ key: { kty: "RSA", n: b64uEnc(n), e: b64uEnc(e) }, format: "jwk" }); }
    catch { throw new Malformed("RSA key is not usable"); }
    if (key.asymmetricKeyType !== "rsa") throw new Malformed(`${alg} needs an RSA key`);
    return key;
  }
  throw new Malformed("unsupported algorithm");
}

// ── certificates in PEM text, read one way (the same rules as strict.py) ─────────────────
const PEM_ANY = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const PEM_STRICT = /^-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE-----$/;
/** One DER SEQUENCE and nothing after it. */
function derWhole(der) {
  if (der.length < 2 || der[0] !== 0x30) return false;
  const first = der[1]; let head; let size;
  if (first < 0x80) { head = 2; size = first; }
  else {
    const n = first & 0x7f;
    if (n < 1 || n > 4 || der.length < 2 + n) return false;
    head = 2 + n; size = 0; for (let i = 0; i < n; i++) size = size * 256 + der[2 + i];
  }
  return head + size === der.length;
}
/** The DER of every certificate block in `text`; throws Malformed when there is none, or when any
 *  block is not of the one form both languages read. */
export function pemCertificates(text) {
  const blocks = String(text).match(PEM_ANY) || [];
  if (!blocks.length) throw new Malformed("no certificate");
  return blocks.map((block) => {
    if (!PEM_STRICT.test(block)) throw new Malformed("a certificate block of another form");
    const body = block.split("\n").slice(1, -1).join("").replace(/\r/g, "");
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(body) || body.length % 4 !== 0) throw new Malformed("a certificate block that is not base64");
    const der = Buffer.from(body, "base64");
    if (der.toString("base64") !== body || !derWhole(der)) throw new Malformed("a certificate block that is not one certificate");
    return der;
  });
}
