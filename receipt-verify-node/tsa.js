// RFC 3161 time-stamp tokens on epochs, verified offline — same checks as the Python package:
//   1. the token is CMS SignedData over a TSTInfo;
//   2. TSTInfo.messageImprint is SHA-256 of exactly the epoch root we were given;
//   3. the signed attributes name that TSTInfo (message-digest) and the signature over them
//      verifies with the certificate the token carries;
//   4. that certificate is a time-stamping certificate, valid at genTime, and chains to a root
//      the caller trusts (default: the DigiCert and Sectigo roots in tsa_roots.pem).
// Zero dependencies: a small DER reader here, X509Certificate and verify() from node:crypto.
import { createHash, verify as cryptoVerify, X509Certificate, constants } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const OID = {
  signedData: "1.2.840.113549.1.7.2",
  tstInfo: "1.2.840.113549.1.9.16.1.4",
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  sha256: "2.16.840.1.101.3.4.2.1", sha384: "2.16.840.1.101.3.4.2.2", sha512: "2.16.840.1.101.3.4.2.3",
  rsaEncryption: "1.2.840.113549.1.1.1", sha256Rsa: "1.2.840.113549.1.1.11", sha384Rsa: "1.2.840.113549.1.1.12", sha512Rsa: "1.2.840.113549.1.1.13",
  ecdsa256: "1.2.840.10045.4.3.2", ecdsa384: "1.2.840.10045.4.3.3", ecdsa512: "1.2.840.10045.4.3.4",
  timeStamping: "1.3.6.1.5.5.7.3.8",
};
const HASH = { [OID.sha256]: "sha256", [OID.sha384]: "sha384", [OID.sha512]: "sha512" };

// ── DER ──────────────────────────────────────────────────────────────────────
function der(buf, off = 0) {
  if (off + 2 > buf.length) throw new Error("truncated DER");
  const first = buf[off];
  const cls = first >> 6, constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f, i = off + 1;
  if (tag === 0x1f) { tag = 0; do { tag = (tag << 7) | (buf[i] & 0x7f); } while (buf[i++] & 0x80); }
  let len = buf[i++];
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let k = 0; k < n; k++) len = (len << 8) | buf[i++]; }
  const start = i, end = i + len;
  if (end > buf.length) throw new Error("truncated DER");
  const node = { cls, constructed, tag, start, end, headerStart: off, bytes: () => buf.subarray(off, end), value: () => buf.subarray(start, end) };
  if (constructed) {
    node.children = []; let p = start;
    while (p < end) { const c = der(buf, p); node.children.push(c); p = c.end; }
  }
  return node;
}
const isSeq = (n) => n.cls === 0 && n.tag === 16;
const isCtx = (n, t) => n.cls === 2 && n.tag === t;
function oid(n) {
  const v = n.value(); const out = [Math.floor(v[0] / 40), v[0] % 40]; let acc = 0;
  for (let i = 1; i < v.length; i++) { acc = acc * 128 + (v[i] & 0x7f); if (!(v[i] & 0x80)) { out.push(acc); acc = 0; } }
  if (out[0] === 2 && v[0] >= 80) { out[0] = 2; out[1] = v[0] - 80; }
  return out.join(".");
}
function genTime(n) {
  const s = n.value().toString("latin1"); // YYYYMMDDHHMMSS[.fff]Z
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(s);
  if (!m) throw new Error(`unexpected GeneralizedTime ${s}`);
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], m[7] ? Math.round(Number(`0.${m[7]}`) * 1000) : 0));
}
const bigint = (n) => BigInt("0x" + (n.value().toString("hex") || "0"));

// ── roots ────────────────────────────────────────────────────────────────────
export function loadRoots(pem) {
  const out = []; const re = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g; let m;
  while ((m = re.exec(String(pem)))) out.push(new X509Certificate(m[0]));
  return out;
}
export function defaultRoots() {
  return loadRoots(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "tsa_roots.pem"), "utf8"));
}
const cn = (name) => { const m = /(?:^|\n)CN=([^\n]+)/.exec(name); return m ? m[1] : name; };
const issuedBy = (cert, issuer) => { try { return cert.checkIssued(issuer) && cert.verify(issuer.publicKey); } catch { return false; } };
const notBefore = (c) => new Date(c.validFrom), notAfter = (c) => new Date(c.validTo);

// ── the check ────────────────────────────────────────────────────────────────
/** token: Buffer (DER TimeStampToken); expectedDigest: Buffer (32 raw bytes of the epoch root);
 *  roots: X509Certificate[] (undefined = the packaged TSA roots; [] = do not check the chain). */
export function verifyToken(token, expectedDigest, roots) {
  const res = { ok: false, digest_ok: null, signature_ok: null, chain_ok: null, valid_at_gen_time: null,
                gen_time: null, signer: null, root: null, policy: null, errors: [] };
  let sd, content, info, imprint;
  try {
    const ci = der(Buffer.from(token));
    if (!isSeq(ci) || oid(ci.children[0]) !== OID.signedData) { res.errors.push("token is not CMS SignedData"); return res; }
    sd = ci.children[1].children[0];
    const eci = sd.children[2];
    if (oid(eci.children[0]) !== OID.tstInfo) { res.errors.push("SignedData does not carry a TSTInfo"); return res; }
    const octets = eci.children[1].children[0];
    content = octets.value();
    info = der(content);
    res.policy = oid(info.children[1]);
    imprint = info.children[2];
    res.gen_time = genTime(info.children[4]).toISOString().replace(/\.000Z$/, "Z");
  } catch (ex) { res.errors.push(`unreadable token: ${ex.message}`); return res; }

  // 2. the digest
  res.digest_ok = oid(imprint.children[0].children[0]) === OID.sha256 && Buffer.from(expectedDigest).equals(imprint.children[1].value());
  if (!res.digest_ok) res.errors.push("token does not name this epoch root (messageImprint differs)");

  // 3. the signature
  let leaf, certs = [];
  try {
    const certsNode = sd.children.find((c) => isCtx(c, 0));
    certs = (certsNode?.children || []).filter(isSeq).map((c) => new X509Certificate(c.bytes()));
    const signerInfos = sd.children.find((c) => c.cls === 0 && c.tag === 17 && sd.children.indexOf(c) > 2);
    const si = signerInfos.children[0];
    const sid = si.children[1];
    const hashName = HASH[oid(si.children[2].children[0])];
    if (!hashName) throw new Error("unsupported digest algorithm");
    const attrs = si.children.find((c) => isCtx(c, 0));
    if (!attrs) throw new Error("no signed attributes");
    const byType = {};
    for (const a of attrs.children) byType[oid(a.children[0])] = a.children[1].children[0];
    if (!byType[OID.contentType] || oid(byType[OID.contentType]) !== OID.tstInfo) throw new Error("signed content-type is not TSTInfo");
    const md = byType[OID.messageDigest]?.value();
    if (!md || !md.equals(createHash(hashName).update(content).digest())) throw new Error("signed message-digest does not match the TSTInfo (content altered)");
    const idx = si.children.indexOf(attrs);
    const sigAlg = oid(si.children[idx + 1].children[0]);
    const signature = si.children[idx + 2].value();
    if (isSeq(sid)) {
      const serial = bigint(sid.children[1]);
      leaf = certs.find((c) => BigInt("0x" + c.serialNumber) === serial);
    } else {
      const ski = sid.value().toString("hex");
      leaf = certs.find((c) => (c.subjectKeyIdentifier || "").replace(/:/g, "").toLowerCase() === ski);
    }
    if (!leaf) throw new Error("signer certificate not in the token");
    res.signer = cn(leaf.subject);
    const signed = Buffer.concat([Buffer.from([0x31]), attrs.bytes().subarray(1)]); // [0] IMPLICIT is signed as a SET
    const key = leaf.publicKey;
    let ok = false;
    if ([OID.rsaEncryption, OID.sha256Rsa, OID.sha384Rsa, OID.sha512Rsa].includes(sigAlg) && key.asymmetricKeyType === "rsa") {
      ok = cryptoVerify(hashName, signed, { key, padding: constants.RSA_PKCS1_PADDING }, signature);
    } else if ([OID.ecdsa256, OID.ecdsa384, OID.ecdsa512].includes(sigAlg) && key.asymmetricKeyType === "ec") {
      ok = cryptoVerify(hashName, signed, { key, dsaEncoding: "der" }, signature);
    }
    if (!ok) throw new Error("signature does not verify with the signer certificate");
    res.signature_ok = true;
  } catch (ex) { res.signature_ok = false; res.errors.push(`signature: ${ex.message}`); return res; }

  // 4. the certificate: purpose, validity at genTime, chain to a trusted root
  const hasTsa = (leaf.keyUsage || []).includes(OID.timeStamping);
  if (!hasTsa) res.errors.push("signer certificate is not a time-stamping certificate (no timeStamping EKU)");
  const trusted = roots === undefined ? defaultRoots() : roots;
  const chain = [leaf]; let current = leaf;
  res.chain_ok = trusted.length ? false : null;
  for (let i = 0; i < 6; i++) {
    const anchor = trusted.find((r) => issuedBy(current, r));
    if (anchor) { res.chain_ok = true; res.root = cn(anchor.subject); break; }
    const parent = certs.find((c) => c !== current && c.subject !== current.subject && issuedBy(current, c));
    if (!parent) break;
    chain.push(parent); current = parent;
  }
  if (res.chain_ok === false) res.errors.push("no path from the signer certificate to a trusted root");
  else if (res.chain_ok === null) res.errors.push("certificate chain not checked (no trusted roots given)");
  const gt = new Date(res.gen_time);
  res.valid_at_gen_time = chain.every((c) => notBefore(c) <= gt && gt <= notAfter(c));
  if (!res.valid_at_gen_time) res.errors.push("a certificate in the chain was not valid at the time the token certifies");
  res.ok = Boolean(res.digest_ok && res.signature_ok && res.chain_ok && res.valid_at_gen_time && hasTsa);
  return res;
}
