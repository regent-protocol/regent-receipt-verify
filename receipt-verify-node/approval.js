// What this version says about the owner's approval behind a receipt. The same checks, in
// the same order, with the same messages as receipt-verify-python/…/approval.py.
//
// A receipt names its approval by digest: `approval_digest` is the SHA-256 of the approval
// evidence. When an admin of the organization asks for it, an evidence bundle carries an
// `approval` block with the exact string that was hashed. This version checks ONE thing about
// that block, with no call to Regent:
//
//     sha256(evidence_canonical) == the approval_digest of a VERIFIED receipt
//
// so the evidence in a bundle cannot be edited, swapped for other evidence or attached to
// another decision without the bundle turning INVALID.
//
// It does NOT verify the owner's signature inside the evidence, and it does not check that
// the terms shown beside the evidence are the terms that were approved. Its verdict on an
// approval is therefore never better than NOT CHECKED, it never returns terms, and it never
// prints the words a later version uses for a verified signature. A bundle can be VALID while
// its approval is NOT CHECKED: the two verdicts are separate, and both are printed.
//
// Two rules it shares with the versions that do verify the signature:
//
// * THE ANCHOR IS THE RECEIPT, AND ONLY THE RECEIPT. The digest comes from the claims of a
//   receipt whose signature verified. An event's id and type are labels beside its payload,
//   not part of what is hashed into the trail, so no event may stand in for the receipt.
//   Without a verified receipt nothing is compared.
// * NOTHING THE BLOCK MERELY SAYS IS REPEATED AS A FINDING. Method and scope are the
//   receipt's; dates, the approver's id and "applied" are returned under `stated`.
//
// Malformed input is an INVALID result, never an exception.
import { HEX64, Malformed, get, has, isObject, parse, plain, same, sha256, stringList } from "./strict.js";

export { Malformed };
export const VERIFIES_SIGNATURE = false;   // this version compares the evidence with the receipt's digest and nothing more
export const PINS_REFUSED = "an approver key, an origin or a relying party id was required, and this version cannot require them: it does not verify the owner's signature";
const ON_FILE = "on_file";
const RECORDS = ["on_file", "no_signature", "not_retained", "not_recorded", "unavailable"];
const MAX_CHANGES = 1000;  // listed changes to one mandate

/** The approval evidence a bundle carries, as far as this version looks at it. */
function checkEvidence(part, digest) {
  // signature_ok and terms are always null: this version does not verify the owner's signature and returns no terms
  const s = { label: "approval", anchored: false, evidence_ok: null, signature_ok: null, terms: null, errors: [], ok: true };
  try {
    const [evidence, evidenceRaw] = parse(get(part, "evidence_canonical"), "evidence_canonical");
    s.evidence_ok = sha256(evidenceRaw).toString("hex") === digest;
    if (!s.evidence_ok) s.errors.push("evidence: the bytes do not hash to the digest that names them");
    if (has(part, "evidence") && !same(part.evidence, evidence)) s.errors.push("evidence: the object shown is not what the hashed bytes say");
  } catch (e) {
    if (e instanceof Malformed) s.errors.push(`malformed: ${e.message}`);
    else throw e;
  }
  s.ok = s.errors.length === 0;
  return s;
}

const passkeyNamed = (method) => typeof method === "string" && method.split("+").includes("passkey");

/**
 * Compare a bundle's `approval` block with the claims of a VERIFIED receipt.
 * `receiptClaims`: the claims of a receipt whose signature verified, or null when there is no
 * such receipt (nothing is then compared). `valid` is false when the block contradicts the
 * receipt and null otherwise; it is never true in this version: read `verdict`. The options
 * `approverKeys`, `origins`, `rpIds` pin the owner's key and site in versions that verify the
 * owner's signature. This one does not, so passing any of them is an error: a requirement
 * that cannot be enforced must not look as if it was.
 */
export function verifyApproval(approval, receiptClaims = null, options = {}) {
  // `verdict` and `why`: the answer in one word and one reason, in this program's own words (see
  // `summary`). A bundle can be VALID while its approval is NOT CHECKED: read these, not the bundle's verdict.
  // `consistent` and `terms` are always null and `changes` always empty in this version.
  const res = { verdict: "NOT CHECKED", why: "", valid: null, consistent: null, record: null, method: null, scope: null, names: null,
    terms: null, stated: {}, signed: null, changes: [], changes_listed: 0, errors: [], warnings: [] };
  try {
    const o = isObject(options) ? options : {};
    const unknown = Object.keys(o).filter((k) => !["approverKeys", "origins", "rpIds"].includes(k));
    if (unknown.length) throw new Malformed(`unknown option ${unknown[0]}; the options are approverKeys, origins, rpIds`);
    verifyInto(res, approval, receiptClaims, { approverKeys: o.approverKeys ?? null, origins: o.origins ?? null, rpIds: o.rpIds ?? null });
  } catch (e) {
    if (e instanceof Malformed) res.errors.push(`approval block is malformed: ${e.message}`);
    else res.errors.push(`approval block could not be read (${e?.name || "Error"})`);
  }
  if (res.errors.length) res.valid = false;
  [res.verdict, res.why] = summary(res, { anchored: isObject(receiptClaims) });
  return res;
}

const NOTHING = new Map([
  ["on_file", "this version does not verify it"],
  ["no_signature", "no signature was taken"],
  ["not_retained", "its evidence is not on file"],
  ["not_recorded", "none was recorded"],
  ["unavailable", "it could not be looked up"],
]);

/**
 * [verdict, why]: the approval in one word and one short reason, in this program's own words.
 * `anchored`: a receipt valid in full names this decision. Nothing a bundle says is repeated in
 * either string, and both fit one line of output.
 */
export function summary(res, { anchored, pinned = true }) {
  if (res.valid === false) return ["INVALID", "a check failed, see the errors"];
  if (res.record === null) return ["NOT CHECKED", "the bundle does not carry it"];
  if (!anchored) return ["NOT CHECKED", "no verified receipt for this decision"];
  if (!pinned) return ["NOT CHECKED", "the receipt key came from the bundle"];
  return ["NOT CHECKED", NOTHING.get(res.record) ?? "nothing to verify"];
}

const yn = (v) => (v == null ? "?" : v ? "yes" : "NO");

/** The approval as indented lines of text for a person. The caller escapes and wraps them: values a bundle supplied are inside. */
export function lines(res, { anchored, pinned = true }) {
  if (res.record === null) return [];
  const said = !anchored ? "no verified receipt for this decision"
    : (res.method || res.names) ? (res.method || "an approval, method not named") : "no approval";
  const out = [`  approval: ${res.valid === false ? "INVALID" : "NOT CHECKED"} (record ${res.record}; the receipt says: ${said}${res.names ? `, covering ${res.names}` : ""})`];
  if (res.signed) {
    out.push(`        evidence: ${res.signed.anchored ? "named by the receipt" : "NOT named by the receipt"}, bytes match its digest: ${yn(res.signed.evidence_ok)}`);
    if (res.signed.anchored && !pinned) out.push("        that receipt was checked with the key inside the bundle");
    out.push("        owner's signature: NOT CHECKED; terms: NOT CHECKED");
  }
  if (res.changes_listed) out.push(`        listed changes to the mandate: ${res.changes_listed}, NOT CHECKED`);
  const stated = Object.keys(res.stated).sort().map((k) => `${k}=${res.stated[k]}`);
  if (stated.length) out.push(`        stated by the organization, not verified: ${stated.join(", ")}`);
  return out;
}

function verifyInto(res, approval, receiptClaims, opts) {
  opts.approverKeys = stringList(opts.approverKeys, "approver_keys");
  opts.origins = stringList(opts.origins, "origins");
  opts.rpIds = stringList(opts.rpIds, "rp_ids");
  if (opts.approverKeys !== null || opts.origins !== null || opts.rpIds !== null) res.errors.push(PINS_REFUSED);
  const verified = isObject(receiptClaims);
  const claims = verified ? receiptClaims : {};
  const named = get(claims, "approval_digest") ?? null;
  if (named !== null && !(typeof named === "string" && HEX64.test(named))) throw new Malformed("the receipt's approval_digest is not 64 lowercase hex characters");
  res.method = plain(get(claims, "approval_method"), 40);
  res.scope = plain(get(claims, "approval_scope"), 40);
  // a receipt that names no scope names a mandate approval: one approval then stands behind
  // every purchase made under that mandate
  if (named || res.method) res.names = res.scope === "purchase" ? "this purchase" : "the creation of the mandate";

  if (approval === null || approval === undefined) {
    if (named) res.warnings.push("the receipt names an approval by digest, but the bundle does not carry it; ask the organization for a bundle with the approval revealed");
    return;
  }
  if (!isObject(approval)) throw new Malformed("it is not an object");
  const record = get(approval, "record");
  res.record = RECORDS.includes(record) ? record : "unknown";
  for (const k of ["approved_at", "applied_at", "approver", "kind", "subject_ref"]) { const v = plain(get(approval, k)); if (v !== null) res.stated[k] = v; }

  if (!verified) {
    res.warnings.push("there is no verified receipt, so the approval in the bundle cannot be tied to this decision and was not checked");
    return;
  }

  const statedDigest = get(approval, "evidence_digest");
  const blockScope = get(approval, "scope");
  const receiptScope = res.scope === "purchase" ? "purchase" : "mandate";
  if ((named || res.method) && typeof blockScope === "string" && blockScope !== receiptScope) res.errors.push(`the receipt says the approval covers the ${receiptScope}, the bundle says otherwise`);
  const blockMethod = get(approval, "method");
  if (res.method && typeof blockMethod === "string" && blockMethod !== res.method) res.errors.push(`the receipt says the approval was by ${res.method}, the bundle says otherwise`);

  if (record === ON_FILE) {
    if (!named) { res.errors.push("nothing anchored names this approval: the receipt carries no approval digest"); return; }
    if (statedDigest !== named) res.errors.push("the approval in the bundle is not the one the receipt names (digests differ)");
    res.signed = checkEvidence(approval, named);
    res.signed.anchored = res.signed.evidence_ok === true;  // named by the receipt only if its bytes hash to the digest
    for (const e of res.signed.errors) res.errors.push(`approval: ${e}`);
    if (res.signed.errors.length === 0) res.warnings.push("the approval evidence in the bundle is the one the receipt names; this version does not verify the owner's signature inside it, and the terms shown beside it are covered by nothing it checks");
  } else if (record === "no_signature") {
    if (named) res.errors.push("the receipt names an approval by digest; the bundle says no signature was taken");
    else if (!res.method) res.warnings.push("the bundle states an approval the receipt does not name; it is not repeated here");
    else if (passkeyNamed(res.method)) res.warnings.push("the receipt says a passkey approved this and names no digest of it (approvals recorded before digests were kept): there is nothing to verify");
    else res.warnings.push(`approved without a passkey (${res.method}): there is no signature to verify`);
  } else if (record === "not_retained") {
    if (!named) res.errors.push("the bundle says the evidence was not kept, but the receipt names no approval digest");
    else if (statedDigest !== named) res.errors.push("the approval in the bundle is not the one the receipt names (digests differ)");
    else res.warnings.push("the receipt names an approval whose evidence is not on file; it cannot be verified");
  } else if (record === "not_recorded") {
    if (named || res.method) res.errors.push("the receipt names an approval; the bundle says none was recorded");
    else res.warnings.push("the receipt names no approval, and the bundle says none was recorded");
  } else if (record === "unavailable") res.warnings.push("the approval could not be looked up when the bundle was built; ask for the bundle again");
  else res.errors.push("unknown approval record state");

  let changes = get(approval, "changes");
  if (changes === undefined || changes === null) changes = [];
  if (!Array.isArray(changes)) throw new Malformed("changes is not a list");
  if (changes.length > MAX_CHANGES) throw new Malformed(`more than ${MAX_CHANGES} changes`);
  res.changes_listed = changes.length;
  if (changes.length) res.warnings.push(`the bundle lists ${changes.length} change(s) to the mandate; this version does not check them, and the list itself (complete or not, applied or not) is the organization's statement`);
}
