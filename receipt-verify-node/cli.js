#!/usr/bin/env node
// regent-verify TOKEN|@file --jwks jwks.json [--jwks older.json] [--request req.json] [--mandate reveal.json]
//               [--policy reveal.json|text.cedar] [--counterparty-jwks merchant-jwks.json] [--now EPOCH] [--json]
import { fstatSync, readFileSync, writeSync } from "node:fs";
import { verify, VERSION } from "./index.js";
import { VERIFIES_SIGNATURE, lines as approvalLines } from "./approval.js";
import { pemCertificates, unprintable } from "./strict.js";

// Text output is for a person at a terminal, and a bundle is untrusted input. Two rules keep a
// bundle from writing what looks like this program's own verdict: every character that moves the
// cursor, hides or reorders text is printed as an escape; and no line is left to the terminal to
// wrap (a label padded to the terminal's width would otherwise start a row of its own). A long
// line is broken here, and its continuation carries a marker no line of this program starts
// with. Automation reads --json.
const WIDTH = 78;
const CONT = "      | ";
const safe = (text) => {
  let o = "";
  for (const ch of String(text)) {
    const code = ch.codePointAt(0);
    o += unprintable(code) ? (code < 0x100 ? `\\x${code.toString(16).padStart(2, "0")}` : `\\u${code.toString(16).padStart(4, "0")}`) : ch;
  }
  return o;
};
const colsOf = (ch) => (ch < "\u0080" ? 1 : 2);  // counted generously: anything outside ASCII as two (some terminals draw even "°" double-width)
const cols = (t) => { let n = 0; for (const ch of t) n += colsOf(ch); return n; };
function wrap(line) {
  // by code point, as the Python twin counts: a character outside the BMP is one, not two
  const lines = []; let cur = []; let width = 0;
  for (const ch of line) {
    const w = colsOf(ch);
    if (width + w > WIDTH) {
      const cut = cur.lastIndexOf(" ");
      if (cut > CONT.length && cut > cur.length - 24) { lines.push(cur.slice(0, cut).join("")); cur = [...CONT, ...cur.slice(cut + 1)]; }
      else { lines.push(cur.join("")); cur = [...CONT]; }
      width = cols(cur.join(""));
    }
    cur.push(ch); width += w;
  }
  lines.push(cur.join(""));
  return lines;
}
// When nobody reads the output (`| head`, a pager closed early) there is nothing more to say:
// writing stops, without a stack trace, and the exit code still carries the verdict. Any other
// failure to write (a full disk, a file too large, a descriptor not open for writing) stops the
// program with exit code 2: an answer that was not written must not pass for one that was.
let readerGone = false; let writeFailed = false;
const cannotWrite = () => {
  readerGone = true;
  if (writeFailed) return;
  writeFailed = true; process.exitCode = 2;
  try { process.stderr.write("regent-verify: cannot write the output\n"); } catch { /* nobody to tell */ }
};
try { if (fstatSync(1).isDirectory()) cannotWrite(); } catch { /* no descriptor: nothing to check */ }
process.stdout.on("error", (err) => { if (err && err.code === "EPIPE") readerGone = true; else cannotWrite(); });
process.stderr.on("error", () => { /* a closed or broken stderr changes nothing about the answer */ });
// A regular file is written here, byte by byte accounted for: Node's own stream for a file
// does not report a short write (a file size limit), and a truncated answer must not pass.
let stdoutIsFile = false;
try { stdoutIsFile = fstatSync(1).isFile(); } catch { /* no descriptor */ }
const writeFile = (text) => {
  const buf = Buffer.from(text, "utf8"); let at = 0;
  while (at < buf.length) {
    const n = writeSync(1, buf, at, buf.length - at);
    if (n <= 0) throw Object.assign(new Error("short write"), { code: "EIO" });
    at += n;
  }
};
const write = (text) => {
  if (readerGone) return;
  try { if (stdoutIsFile) writeFile(text); else process.stdout.write(text); }
  catch (err) { if (err && err.code === "EPIPE") readerGone = true; else cannotWrite(); }
};
const out = (...parts) => { for (const piece of wrap(parts.map(safe).join(" "))) write(`${piece}\n`); };
// JSON in ASCII only: every other character, DEL included, as a \u escape, so nothing in it acts on a terminal
const outJson = (obj) => write(`${JSON.stringify(obj, null, 2).replace(/[\u007f-\uffff]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`)}\n`);

class Unreadable extends Error {}
/** A JSON file, read as strictly as the Python twin reads it: UTF-8, JSON. With `textOk` a file
 *  that is not JSON is returned as text (the Cedar policy for --policy). */
function load(path, textOk = false) {
  let raw;
  try { raw = readFileSync(path); } catch { throw new Unreadable(`cannot read ${path}: not readable`); }
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw); }
  catch { throw new Unreadable(`cannot read ${path}: it is not UTF-8`); }
  if (tooDeep(text)) throw new Unreadable(`cannot read ${path}: it is nested too deeply`);
  try { return JSON.parse(text); }
  catch { if (textOk) return text; throw new Unreadable(`cannot read ${path}: it is not JSON`); }
}

/** A file that must hold one JSON object (or, with `textOk`, text). */
function loadObject(path, textOk = false) {
  const v = load(path, textOk);
  if ((v !== null && typeof v === "object" && !Array.isArray(v)) || (textOk && typeof v === "string")) return v;
  throw new Unreadable(`cannot read ${path}: it is not a JSON object`);
}

const MAX_NESTING = 512;
/** Brackets outside strings nest deeper than MAX_NESTING. Each language's own parser gives up at a
 *  different depth; this one limit, checked first, is the same in both. */
function tooDeep(text) {
  let depth = 0; let inString = false; let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inString) { if (escaped) escaped = false; else if (ch === "\\") escaped = true; else if (ch === '"') inString = false; }
    else if (ch === '"') inString = true;
    else if (ch === "[" || ch === "{") { depth += 1; if (depth > MAX_NESTING) return true; }
    else if (ch === "]" || ch === "}") depth -= 1;
  }
  return false;
}
/**
 * Arguments read the way the Python twin's argparse reads them, so that one command line gets one
 * answer: `--name value` or `--name=value`, options anywhere, `--` ends the options, one
 * positional. A value is checked as soon as it is read (a bad `--now` stops the run before a later
 * `--help`); `--help` and `--version` act where they stand; an unknown option or a second positional
 * is reported once everything has been read. Abbreviations are not accepted. A word that starts
 * with "-" is an option unless it is "-" alone, starts like a negative number, or holds a space.
 */
const NEGATIVE = /^-\.?[0-9]/;
const isOption = (a) => a.length > 1 && a[0] === "-" && !NEGATIVE.test(a) && !a.includes(" ");
const shortArg = (a) => (a.length > 60 ? `${a.slice(0, 60)}…` : a);
function parseArgs(args, spec, what, convert = {}) {
  const opts = {}; const positional = []; const unknown = []; let optionsOver = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (optionsOver || !isOption(a)) { positional.push(a); continue; }
    if (a === "--") { optionsOver = true; continue; }
    const eq = a.indexOf("=");
    const name = eq > 0 ? a.slice(0, eq) : a;
    const kind = Object.prototype.hasOwnProperty.call(spec, name) ? spec[name] : undefined;
    if (kind === undefined) { unknown.push(a); continue; }
    if (kind === "flag" || kind === "help" || kind === "version") {
      if (eq > 0) throw new Unreadable(`${name} takes no value`);
      if (kind === "help") return { help: true };
      if (kind === "version") return { version: true };
      opts[name] = true; continue;
    }
    let value;
    if (eq > 0) value = a.slice(eq + 1);
    else {
      value = args[i + 1];
      if (value === undefined || isOption(value)) throw new Unreadable(`${name} needs a value`);
      i += 1;
    }
    if (Object.prototype.hasOwnProperty.call(convert, name)) value = convert[name](value);
    if (kind === "list") (opts[name] ||= []).push(value); else opts[name] = value;
  }
  if (!positional.length) throw new Unreadable(`no ${what} given; see --help`);
  if (unknown.length || positional.length > 1) throw new Unreadable(`unrecognized argument ${shortArg(unknown.length ? unknown[0] : positional[1])}; see --help`);
  return { opts, positional: positional[0] };
}
const SECONDS = /^-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$/;
/** Epoch seconds in one spelling, the same in both languages: ASCII digits, an optional fraction
 *  and exponent. Not 1_000, not 0x10, not digits of another script. */
const finite = (text) => { const v = typeof text === "string" && SECONDS.test(text) ? Number(text) : NaN; if (!Number.isFinite(v)) throw new Unreadable("--now must be a finite number of seconds"); return v; };
/** A value from a token or a bundle as the Python twin prints it. */
const scalar = (v) => {
  if (v === null || v === undefined) return "-";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try { const t = JSON.stringify(v); return typeof t === "string" ? t : "?"; } catch { return "?"; }
};
/** A JSON number as both languages print it. */
const number = (v) => (typeof v === "number" ? String(v) : "");

/** Roots from PEM files: a file that cannot be read, or holds no certificate, stops the program
 *  with exit code 2 instead of quietly trusting nothing. */
async function rootsFrom(paths) {
  const { X509Certificate } = await import("node:crypto");
  const roots = [];
  for (const p of paths) {
    let raw; try { raw = readFileSync(p); } catch { throw new Unreadable(`cannot read ${p}: not readable`); }
    // the one reader both languages use: see pemCertificates in strict.js
    let certs; try { certs = pemCertificates(new TextDecoder("utf-8", { fatal: true }).decode(raw)).map((der) => new X509Certificate(der)); } catch { certs = []; }
    if (!certs.length) throw new Unreadable(`cannot read ${p}: it holds no PEM certificate`);
    roots.push(...certs);
  }
  return roots;
}

async function main(args) {
if (args[0] === "bundle") {
  const { verifyBundle } = await import("./bundle.js");
  const parsed = parseArgs(args.slice(1), { "--jwks": "list", "--checkpoint-jwks": "list", "--rpc": "one", "--now": "one", "--tsa-root": "list",
    "--approver-key": "list", "--origin": "list", "--rp-id": "list", "--json": "flag", "--help": "help", "-h": "help" }, "bundle file", { "--now": finite });
  if (parsed.help) { out(`usage: regent-verify bundle FILE [--jwks receipt-jwks.json] [--checkpoint-jwks ck-jwks.json] [--rpc URL] [--now EPOCH] [--tsa-root root.pem]${VERIFIES_SIGNATURE ? " [--approver-key KEY] [--origin URL] [--rp-id DOMAIN]" : ""} [--json]`); return 0; }
  const p = parsed.opts; const file = parsed.positional;
  const o = { jwks: p["--jwks"] || [], checkpointJwks: p["--checkpoint-jwks"] || [], rpc: p["--rpc"], now: p["--now"],
    tsaRoot: p["--tsa-root"] || [], approverKey: p["--approver-key"] || [], origin: p["--origin"] || [], rpId: p["--rp-id"] || [], json: Boolean(p["--json"]) };
  if (!VERIFIES_SIGNATURE && (o.approverKey.length || o.origin.length || o.rpId.length)) throw new Unreadable(`--approver-key, --origin and --rp-id need a version that verifies the owner's signature; this one (${VERSION}) does not`);
  const loadJ = (p) => load(p);
  const res = await verifyBundle(loadJ(file), {
    receiptJwks: o.jwks.length ? o.jwks.map(loadJ) : undefined,
    checkpointJwks: o.checkpointJwks.length ? o.checkpointJwks.map(loadJ) : undefined,
    rpc: o.rpc, now: o.now,
    approverKeys: o.approverKey.length ? o.approverKey : undefined,
    origins: o.origin.length ? o.origin : undefined,
    rpIds: o.rpId.length ? o.rpId : undefined,
    tsaRoots: o.tsaRoot.length ? await rootsFrom(o.tsaRoot) : undefined,
  });
  if (o.json) { outJson(res); return res.valid ? 0 : 1; }
  const yn = (v) => (v == null ? "?" : v ? "yes" : "NO");
  out(`${res.valid ? "VALID" : "INVALID"} — evidence bundle${res.decision_id ? ` for ${res.decision_id}` : ""}, ${res.events.length} event(s)`);
  // a verdict of its own, beside the bundle's: the bundle can be VALID while the owner's approval
  // was not checked, and the first lines must say so
  if (res.approval) out(`${res.approval.verdict} — the owner's approval: ${res.approval.why}`);
  for (const e of res.errors) out(`  error: ${e}`);
  for (const w of res.warnings) out(`  note: ${w}`);
  for (const ev of res.events) {
    out(`  [${ev.ok ? "ok " : "BAD"}] ${ev.event_id} (${scalar(ev.event_type)}) seq=${scalar(ev.seq)} bytes=${yn(ev.canonical_ok)} batch=${yn(ev.merkle_ok)} checkpoint=${yn(ev.checkpoint_ok)}${ev.checkpoint_kid ? ` kid=${ev.checkpoint_kid}` : ""}${ev.epoch_ok != null ? ` epoch=${yn(ev.epoch_ok)}` : ""}${ev.tsa_ok != null ? ` rfc3161=${yn(ev.tsa_ok)}${ev.tsa_ok ? ` ${ev.tsa_time} by ${ev.tsa_signer}` : ""}` : ""}`);
    for (const e of ev.errors) out(`        ${e}`);
  }
  if (res.links_ok != null) out(`  checkpoint links: ${res.links_ok ? "consistent" : "BROKEN"}`);
  if (res.receipt_valid != null) out(`  receipt: ${res.receipt_valid ? "VALID" : "INVALID"}${res.receipt_anchored ? ", anchored in the trail" : ", NOT anchored"}${typeof res.receipt_claims.status === "string" ? ` — ${res.receipt_claims.status} ${number(res.receipt_claims.amount)} ${typeof res.receipt_claims.currency === "string" ? res.receipt_claims.currency : ""}` : ""}`);
  if (res.approval) for (const line of approvalLines(res.approval, { anchored: res.approval_anchor !== null, pinned: o.jwks.length > 0 })) out(line);
  if (res.rpc_ok != null) { out(`  on-chain: ${res.rpc_ok ? "confirmed" : "NOT confirmed"}`); for (const c of res.rpc_checks) out(`        ${c.kind} ${c.tx}: ${c.ok ? "ok" : c.error || "root not found in a successful instruction"}`); }
  return res.valid ? 0 : 1;
}
const parsed = parseArgs(args, { "--jwks": "list", "--request": "one", "--mandate": "one", "--policy": "one", "--payee": "one",
  "--counterparty-jwks": "list", "--now": "one", "--issuer": "one", "--json": "flag", "--help": "help", "-h": "help", "--version": "version" }, "token", { "--now": finite });
if (parsed.version) { out(VERSION); return 0; }
if (parsed.help) { out("usage: regent-verify TOKEN --jwks jwks.json [--request req.json] [--mandate reveal.json] [--policy reveal.json] [--payee reveal.json] [--counterparty-jwks merchant-jwks.json] [--issuer ISS] [--now EPOCH] [--json] [--version]"); return 0; }
const q = parsed.opts;
const opt = { jwks: q["--jwks"] || [], counterpartyJwks: q["--counterparty-jwks"] || [], request: q["--request"], mandate: q["--mandate"], policy: q["--policy"],
  payee: q["--payee"], now: q["--now"], issuer: q["--issuer"], json: Boolean(q["--json"]) };
let token = parsed.positional;
if (!opt.jwks.length) throw new Unreadable("--jwks is required");
if (token.startsWith("@")) {
  try { token = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(readFileSync(token.slice(1))); }
  catch { throw new Unreadable(`cannot read ${token.slice(1)}`); }
}

const res = verify(token, opt.jwks.map(load), {
  request: opt.request ? loadObject(opt.request) : undefined,
  mandateReveal: opt.mandate ? loadObject(opt.mandate) : undefined,
  policyReveal: opt.policy ? loadObject(opt.policy, true) : undefined,
  payeeReveal: opt.payee ? loadObject(opt.payee) : undefined,
  counterpartyJwks: opt.counterpartyJwks.length ? opt.counterpartyJwks.map(load) : undefined,
  now: opt.now, issuer: opt.issuer === undefined ? "regent-control" : (opt.issuer || null),
});
const ok = res.valid && [res.argsHashMatch, res.mandateMatch, res.policyMatch, res.payeeMatch, res.confirmationMatch].every((c) => c !== false);
if (opt.json) { outJson({ ...res, valid: res.valid }); return ok ? 0 : 1; }
const c = res.claims;
out(`${res.valid ? "VALID" : "INVALID"} — ${res.kind} signed by ${c.iss === undefined || c.iss === null ? "?" : scalar(c.iss)} (kid ${scalar(res.kid)})`);
for (const e of res.errors) out(`  error: ${e}`);
for (const w of res.warnings) out(`  note: ${w}`);
if (res.signatureValid) {
  for (const k of ["decision_id", "status", "environment", "sub", "assertion_scheme", "assertion_kid", "key_custody",
    "amount", "currency", "payee", "payee_hash", "mandate_id", "mandate_version", "mandate_hash",
                   "policy_source", "policy_version", "policy_hash", "risk_model", "tool", "action", "scope", "args_hash",
                   "settlement_mismatch", "settlement_source", "settlement_ref", "settlement_network", "confirmed_by", "confirmation_kid", "confirmation_ref", "confirmation_kind",
                   "agent_report_mismatch", "jti", "iat", "exp"]) if (k in c) out(`  ${k}: ${scalar(c[k])}`);
  for (const [label, val] of [["request binding (args_hash)", res.argsHashMatch], ["mandate reveal", res.mandateMatch], ["policy reveal", res.policyMatch], ["payee reveal", res.payeeMatch],
                              ["counterparty confirmation", res.confirmationMatch]])
    if (val !== null) out(`  ${label}: ${val ? "MATCH" : "NO MATCH"}`);
  if ("payee_hash" in c && !("payee" in c) && res.payeeMatch === null) out("  payee: committed (hidden by the organization); pass --payee reveal.json to open it");
  for (const e of res.confirmationErrors) out(`    confirmation: ${e}`);
  if (res.confirmation) { const f = res.confirmation; out(`    confirmed by ${scalar(f.iss)} (kid ${scalar(c.confirmation_kid)}): ${scalar(f.status)} ${scalar(f.amount)} ${scalar(f.currency)}${f.ref !== undefined && f.ref !== null && f.ref !== "" ? ` ref ${scalar(f.ref)}` : ""}`); }
}
return ok ? 0 : 1;
}

// Exit 0 = valid, 1 = not valid, 2 = a file could not be read, an option is wrong, or the output could not be written. The code is set, not forced: a
// forced exit cuts off output still on its way down a pipe.
try { const code = await main(process.argv.slice(2)); process.exitCode = writeFailed ? 2 : code; }
catch (e) {
  try { process.stderr.write(`regent-verify: ${safe(e instanceof Unreadable ? e.message : "could not run")}\n`); } catch { /* nobody to tell */ }
  process.exitCode = 2;
}
