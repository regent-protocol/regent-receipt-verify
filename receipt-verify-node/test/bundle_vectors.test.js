// Whole bundles, the approval beside a receipt, and what the strict reader refuses
// (bundle_vectors.json): the same cases the Python verifier runs, with the same answers.
//
// Many of the cases are forgeries and malformed input that security reviews found an earlier
// version accepting, printing as its own verdict, or crashing on. The rest pin down what this
// version says about the owner's approval: it compares the evidence with the digest in the
// receipt, and its verdict is never better than NOT CHECKED.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { VERIFIES_SIGNATURE, verifyApproval } from "../approval.js";
import * as pkg from "../index.js";
import { verify } from "../index.js";
import { verifyBundle } from "../bundle.js";

const here = dirname(fileURLToPath(import.meta.url));
const B = JSON.parse(readFileSync(join(here, "..", "..", "receipt-verify-vectors", "bundle_vectors.json"), "utf8"));
const V = JSON.parse(readFileSync(join(here, "..", "..", "receipt-verify-vectors", "vectors.json"), "utf8"));
const clone = (x) => JSON.parse(JSON.stringify(x));
const RECORDS = [null, "unknown", "on_file", "no_signature", "not_retained", "not_recorded", "unavailable"];

test("this version does not claim to verify the owner's signature", () => {
  assert.equal(VERIFIES_SIGNATURE, false);
});

function neverMoreThanNotChecked(approval, name) {
  assert.ok(["INVALID", "NOT CHECKED"].includes(approval.verdict), name);
  assert.notEqual(approval.valid, true, name); assert.equal(approval.consistent, null, name);
  assert.equal(approval.terms, null, "this version returns no terms"); assert.deepEqual(approval.changes, [], "and checks no changes");
  if (approval.signed) { assert.equal(approval.signed.signature_ok, null, name); assert.equal(approval.signed.terms, null, name); }
}

for (const [name, c] of Object.entries(B.approvals).sort()) {
  test(`approval: ${name}`, () => {
    const res = verifyApproval(c.approval, c.anchored, { approverKeys: c.approver_keys ?? undefined, origins: c.origins ?? undefined });
    assert.deepEqual([res.verdict, res.why], [c.verdict, c.why], `${name}: ${JSON.stringify(res.errors)} ${JSON.stringify(res.warnings)}`);
    assert.equal(res.valid, c.valid, name);
    // right in everything but one thing: the whole list of errors is that one thing
    assert.deepEqual([...res.errors].sort(), [...c.errors_exact].sort(), name);
    if (c.warning_contains) assert.ok(res.warnings.some((w) => w.includes(c.warning_contains)), `${name}: ${JSON.stringify(res.warnings)}`);
    if ("evidence_ok" in c) assert.equal(res.signed.evidence_ok, c.evidence_ok, name);
    if ("anchored_returned" in c) assert.equal(res.signed.anchored, c.anchored_returned, name);
    if ("record_returned" in c) assert.equal(res.record, c.record_returned, name);
    if ("stated_keys" in c) assert.deepEqual(Object.keys(res.stated).sort(), [...c.stated_keys].sort(), name);
    if ("changes_listed" in c) assert.equal(res.changes_listed, c.changes_listed, name);
    assert.ok(RECORDS.includes(res.record), name);
    for (const value of Object.values(res.stated)) assert.ok(!/[\u0000-\u001f\u007f-\u009f]/.test(value), name);
    neverMoreThanNotChecked(res, name);
    JSON.stringify(res);
  });
}

test("junk is an invalid result, never an exception", () => {
  for (const junk of [5, true, "x", [1], { record: 5 }, { record: "on_file", evidence_canonical: 7 }, { record: "on_file", changes: 3 }]) {
    const res = verifyApproval(junk, { approval_method: "passkey", approval_digest: "ab".repeat(32) });
    assert.equal(res.valid, false, JSON.stringify(junk)); assert.ok(res.errors.length); assert.equal(res.verdict, "INVALID");
  }
});

test("an option of the wrong type is an invalid result", () => {
  const c = B.approvals.the_evidence_the_receipt_names;
  for (const options of [{ approverKeys: "k1" }, { origins: 5 }, { rpIds: [1] }]) {
    const res = verifyApproval(c.approval, c.anchored, options);
    assert.equal(res.verdict, "INVALID", JSON.stringify(options)); assert.ok(res.errors.length);
  }
});

// ── inside a whole bundle: real anchoring, keys pinned, the forgeries reviews found ──────
const run = (c, more = {}) => verifyBundle(c.bundle, { receiptJwks: c.pin_receipt ? B.receipt_jwks : undefined, checkpointJwks: B.checkpoint_jwks, now: B.now, ...more });

for (const [name, c] of Object.entries(B.bundles).sort()) {
  test(`bundle: ${name}`, async () => {
    const res = await run(c);
    if (c.valid !== null) assert.equal(res.valid, c.valid, `${name}: ${JSON.stringify(res.errors)}`);
    const approval = res.approval;
    assert.equal(approval ? approval.verdict : null, c.approval_verdict, `${name}: ${JSON.stringify(res.errors)} ${JSON.stringify(res.warnings)}`);
    assert.equal(res.approval_anchor, c.approval_anchor, name);
    if (approval) {
      neverMoreThanNotChecked(approval, name);
      assert.equal(approval.verdict === "INVALID", approval.valid === false, name);
      if (approval.verdict === "INVALID") assert.equal(res.valid, false, "an approval that contradicts the receipt makes the bundle invalid");
      if (c.why) assert.equal(approval.why, c.why, name);
      if ("evidence_ok" in c) assert.equal(approval.signed.evidence_ok, c.evidence_ok, name);
    }
    if (c.error) assert.ok(res.errors.some((e) => e.includes(c.error)), `${name}: ${JSON.stringify(res.errors)}`);
    if (c.warning) assert.ok(res.warnings.some((w) => w.includes(c.warning)), `${name}: ${JSON.stringify(res.warnings)}`);
    JSON.stringify(res);
  });
}

test("an approval can only be compared under a verified receipt for this decision", async () => {
  // evidence is reported as named by the receipt in the honest bundles and nowhere else
  const named = [];
  for (const [name, c] of Object.entries(B.bundles)) { const r = await run(c); if (r.approval && r.approval.signed && r.approval.signed.anchored) named.push(name); }
  assert.deepEqual(named.sort(), ["a_label_padded_to_draw_a_row_of_its_own", "a_label_with_a_line_break_and_a_verdict",
    "a_label_with_del_and_non_ascii", "a_self_signed_receipt_with_its_key_in_the_bundle",
    "an_index_written_with_a_decimal_point_is_the_same_number", "honest_but_the_receipt_key_comes_from_the_bundle",
    "honest_with_the_receipt_key_pinned", "the_terms_beside_the_evidence_rewritten"]);
  // the two of them whose receipt key the bundle brought carry the note that says so
  for (const name of ["a_self_signed_receipt_with_its_key_in_the_bundle", "honest_but_the_receipt_key_comes_from_the_bundle"]) {
    assert.ok((await run(B.bundles[name])).warnings.some((w) => w.includes("receipt key taken from the bundle itself")), name);
  }
});

test("requiring a key or a site through the bundle check is refused", async () => {
  const c = B.bundles.honest_with_the_receipt_key_pinned;
  for (const more of [{ approverKeys: ["k1"] }, { origins: ["https://app.regentprotocol.org"] }, { rpIds: ["app.regentprotocol.org"] }]) {
    const res = await run(c, more);
    assert.equal(res.valid, false, JSON.stringify(more)); assert.equal(res.approval.verdict, "INVALID");
    assert.ok(res.errors.some((e) => e.includes("this version cannot require them")), JSON.stringify(more));
  }
});

const dir = mkdtempSync(join(tmpdir(), "regent-verify-"));
writeFileSync(join(dir, "rk.json"), JSON.stringify(B.receipt_jwks));
writeFileSync(join(dir, "ck.json"), JSON.stringify(B.checkpoint_jwks));
const CLI = join(here, "..", "cli.js");
function cli(name, ...extra) {
  const c = B.bundles[name];
  const file = join(dir, `${name}.json`); writeFileSync(file, JSON.stringify(c.bundle));
  const args = [CLI, "bundle", file, "--checkpoint-jwks", join(dir, "ck.json"), "--now", String(B.now), ...extra];
  if (c.pin_receipt) args.push("--jwks", join(dir, "rk.json"));
  return spawnSync(process.execPath, args, { encoding: "utf8" });
}
const columns = (line) => { let n = 0; for (const ch of line) n += ch < "\u0080" ? 1 : 2; return n; };

for (const [name, c] of Object.entries(B.bundles).sort()) {
  test(`command line: ${name} gives two verdicts, and a bundle cannot write either`, () => {
    // The text output is what a person reads in a dispute. A bundle is untrusted input: its
    // strings must not add a line, clear the screen, or print this program's verdict.
    const p = cli(name);
    const out = p.stdout;
    assert.equal(p.stderr, "", name); assert.ok(p.status === 0 || p.status === 1, name);
    assert.ok(![...out].some((ch) => ch < " " && ch !== "\n"), "no control character reaches the terminal");
    const lines = out.split("\n");
    assert.ok(lines.every((ln) => columns(ln) <= 78), "no line is left for the terminal to wrap");
    // Two lines start at the left edge and no other: the bundle's verdict, and the approval's own
    // when there is anything to say about one. Nothing a bundle carries can add a third.
    const tops = lines.filter((ln) => ln !== "" && !ln.startsWith(" "));
    assert.ok(tops[0].startsWith("VALID — evidence bundle") || tops[0].startsWith("INVALID — evidence bundle"), `${name}: ${tops}`);
    assert.equal(tops.length, c.approval_verdict ? 2 : 1, `${name}: ${JSON.stringify(tops)}`);
    if (c.approval_verdict) {
      assert.ok(tops[1].startsWith(`${c.approval_verdict} — the owner's approval: `), `${name}: ${tops}`);
      assert.ok(!lines[lines.indexOf(tops[1]) + 1].startsWith("      | "), "the verdict on the approval is one line");
    }
    const detail = lines.filter((ln) => ln.startsWith("  approval: "));
    assert.ok(detail.length <= 1, `${name}: ${JSON.stringify(detail)}`);
    if (detail.length) assert.ok(detail[0].startsWith(`  approval: ${c.approval_verdict} (record `), `${name}: ${detail}`);
    // the words of a verified signature belong to a later version: here they can only be a label
    // a bundle supplied, and never at the start of a row of this program's
    for (const ln of lines) if (ln.includes("SIGNATURE VALID")) assert.ok(ln.startsWith("      | ") || ln.startsWith("  ["), `${name}: ${ln}`);
    if (c.cli_must_not_print) assert.ok(!out.includes(c.cli_must_not_print), name);
    if (c.valid !== null) assert.equal(p.status, c.valid ? 0 : 1, name);
    const js = cli(name, "--json").stdout;
    assert.ok(/^[\x00-\x7e]*$/.test(js), "JSON output is plain ASCII");
    const parsed = JSON.parse(js);
    assert.equal(parsed.approval ? parsed.approval.verdict : null, c.approval_verdict, name);
    if (parsed.approval) { assert.notEqual(parsed.approval.valid, true, name); assert.ok(parsed.approval.why, name); }
  });
}

test("a valid bundle says in its second line that the approval was not checked", () => {
  const out = cli("honest_with_the_receipt_key_pinned").stdout.split("\n");
  assert.equal(out[0], "VALID — evidence bundle for dec_aaaaaaaaaaaa, 2 event(s)");
  assert.equal(out[1], "NOT CHECKED — the owner's approval: this version does not verify it");
  assert.ok(out.includes("        evidence: named by the receipt, bytes match its digest: yes"));
  assert.ok(out.includes("        owner's signature: NOT CHECKED; terms: NOT CHECKED"));
});

test("an option this version cannot enforce stops the run", () => {
  const help = spawnSync(process.execPath, [CLI, "bundle", "--help"], { encoding: "utf8" }).stdout;
  for (const option of [["--approver-key", "k1"], ["--origin", "https://app.regentprotocol.org"], ["--rp-id", "app.regentprotocol.org"]]) {
    const p = cli("honest_with_the_receipt_key_pinned", ...option);
    assert.equal(p.status, 2, option[0]); assert.equal(p.stdout, "");
    assert.ok(p.stderr.includes("need a version that verifies the owner's signature"), p.stderr);
    assert.ok(!help.includes(option[0]), "an option that does nothing here is not offered");
  }
});

test("output is escaped and wrapped by this program", () => {
  // a label with an escape sequence, a direction override and enough padding to reach the margin
  const b = clone(B.bundles.honest_with_the_receipt_key_pinned.bundle);
  b.events[0].event_type = `a\u001b[2Jb‮\u0085${" ".repeat(70)}approval: SIGNATURE VALID (forged)`;
  const file = join(dir, "escaped.json"); writeFileSync(file, JSON.stringify(b));
  const p = spawnSync(process.execPath, [CLI, "bundle", file, "--jwks", join(dir, "rk.json"), "--checkpoint-jwks", join(dir, "ck.json"), "--now", String(B.now)], { encoding: "utf8" });
  assert.ok(p.stdout.includes("a\\x1b[2Jb\\u202e\\x85"), p.stdout);
  const lines = p.stdout.split("\n");
  assert.ok(lines.every((ln) => columns(ln) <= 78));
  assert.ok(!lines.some((ln) => ln.startsWith("  approval: SIGNATURE VALID")), "a padded label cannot draw a row of its own");
  assert.ok(lines.filter((ln) => ln.includes("SIGNATURE VALID")).every((ln) => ln.startsWith("      | ") || ln.startsWith("  [")));
});

test("a file that is not a bundle gets one plain line", () => {
  // no stack trace and nothing of the file echoed: a file can carry escape sequences too
  const cases = [[Buffer.from([0xff, 0xfe, 0x20]), 2], [Buffer.from("{not json"), 2], [Buffer.from(""), 2], [Buffer.from("﻿{}"), 2],
    [Buffer.from('{"a": NaN}'), 2], [Buffer.from("null"), 1], [Buffer.from("[]"), 1], [Buffer.from('"x"'), 1], [Buffer.from("{}"), 1]];
  for (const [content, code] of cases) {
    const file = join(dir, "notabundle.json");
    writeFileSync(file, code === 2 ? Buffer.concat([content, Buffer.from("\u001b[2J")]) : content);
    const p = spawnSync(process.execPath, [CLI, "bundle", file], { encoding: "utf8" });
    assert.equal(p.status, code, `${content.toString("latin1")}: ${p.stderr}`);
    assert.ok(!(p.stderr + p.stdout).includes("\u001b") && !p.stderr.includes("    at "), p.stderr);
    if (code === 2) { assert.equal(p.stdout, ""); assert.ok(p.stderr.startsWith("regent-verify: cannot read "), p.stderr); }
  }
});

for (const [name, c] of Object.entries(B.tokens).sort()) {
  test(`token: ${name}`, () => {
    // the strict reader and the key profile
    const res = verify(c.token, c.jwks, { now: B.now });
    assert.equal(res.valid, c.valid, `${name}: ${JSON.stringify(res.errors)}`);
    if (c.error_contains) assert.ok(res.errors.some((e) => e.includes(c.error_contains)), `${name}: ${JSON.stringify(res.errors)}`);
    if (name === "an_expiry_that_is_true_is_not_a_time") assert.equal(res.expired, null);
  });
}

test("what must not reach a terminal", async () => {
  const { unprintable } = await import("../strict.js");
  for (const code of [0x00, 0x09, 0x0a, 0x1b, 0x7f, 0x80, 0x85, 0x9f, 0x061c, 0x200b, 0x200e, 0x200f, 0x2028, 0x2029, 0x202a, 0x202e, 0x2060, 0x2066, 0x2069, 0xfeff, 0xd800, 0xdfff]) assert.ok(unprintable(code), code.toString(16));
  for (const code of [0x20, 0x7e, 0xa0, 0xb0, 0xe9, 0x0416, 0x2014, 0x2026, 0x4e2d, 0x1f600]) assert.ok(!unprintable(code), code.toString(16));
});

test("limits that keep a file from spending the reader's time", async () => {
  const honest = B.bundles.honest_with_the_receipt_key_pinned.bundle;
  const opts = { receiptJwks: B.receipt_jwks, checkpointJwks: B.checkpoint_jwks, now: B.now };
  const many = clone(honest); many.events = Array(10001).fill(many.events[0]);
  let res = await verifyBundle(many, opts);
  assert.equal(res.valid, false); assert.deepEqual(res.errors, ["bundle is malformed: more than 10000 events"]);
  const odd = clone(honest); odd.events[0].payload_hash = "\ud800";
  res = await verifyBundle(odd, opts);
  assert.deepEqual(res.errors, ["bundle is malformed: events[0].payload_hash is not valid text"]);
  const crowded = clone(honest); crowded.approval.changes = Array(1001).fill({});
  res = await verifyBundle(crowded, opts);
  assert.equal(res.valid, false); assert.ok(res.errors.includes("approval block is malformed: more than 1000 changes"));
  const far = clone(honest); far.approval.changes = Array(130000).fill({});   // far past any argument limit: still an answer
  res = await verifyBundle(far, opts);
  assert.equal(res.valid, false);
});

test("a time that is not a time is refused", () => {
  const file = join(dir, "time.json"); writeFileSync(file, JSON.stringify(B.bundles.honest_with_the_receipt_key_pinned.bundle));
  for (const value of ["abc", "inf", "nan", "Infinity", ""]) {
    const p = spawnSync(process.execPath, [CLI, "bundle", file, "--now", value], { encoding: "utf8" });
    assert.equal(p.status, 2, value); assert.ok(!p.stdout.includes("VALID"), value);
  }
});

test("a file nested too deeply is refused the same way everywhere", () => {
  const file = join(dir, "deep.json");
  writeFileSync(file, `{"bundle_version":"regent-evidence-bundle/1","x":${"[".repeat(600)}${"]".repeat(600)}}`);
  let p = spawnSync(process.execPath, [CLI, "bundle", file], { encoding: "utf8" });
  assert.equal(p.status, 2); assert.ok(p.stderr.includes("nested too deeply"));
  writeFileSync(file, `{"x":"${"[".repeat(600)}","y":${"[".repeat(500)}${"]".repeat(500)}}`);   // brackets inside a string do not count
  p = spawnSync(process.execPath, [CLI, "bundle", file], { encoding: "utf8" });
  assert.equal(p.status, 1);
});

test("a token has one spelling", () => {
  const token = B.bundles.honest_with_the_receipt_key_pinned.bundle.receipt.token;
  assert.ok(verify(token, B.receipt_jwks, { now: B.now }).valid);
  assert.ok(verify(`${token}\n`, B.receipt_jwks, { now: B.now }).valid, "a token saved to a file ends with a line end");
  const [h, pl, sig] = token.split(".");
  for (const other of [`${token}!`, `${token}=`, `\u001f${token}`, `${token} `, `${token}﻿`, `${h}.${pl}.${sig}=`,
    `${h}=.${pl}.${sig}`, token.replace(".", "\n."), `${h}.${pl}.${sig}.x`, `${sig.slice(0, -1)}Ł`]) {
    const res = verify(other, B.receipt_jwks, { now: B.now });
    assert.equal(res.valid, false, other.slice(-12)); assert.equal(res.signatureValid, false, other.slice(-12));
  }
  for (const jwks of [{ keys: "x" }, "x", null]) assert.equal(verify(token, jwks).valid, false);
});

test("verifyBundle answers for any shape and never throws", async () => {
  // every node of an honest bundle, the approval block included, replaced by every kind of junk
  const honest = B.bundles.honest_with_the_receipt_key_pinned.bundle;
  const junk = [null, 0, 1.5, true, "x", [], {}, [1], { a: 1 }, "\ud800"];
  const paths = [];
  (function walk(node, here) {
    paths.push(here);
    if (Array.isArray(node)) { if (node.length) walk(node[0], [...here, 0]); }
    else if (node && typeof node === "object") for (const k of Object.keys(node)) walk(node[k], [...here, k]);
  })(honest, []);
  let count = 0;
  for (const path of paths) {
    for (const value of junk) {
      let b = clone(honest);
      if (path.length) { let node = b; for (const step of path.slice(0, -1)) node = node[step]; node[path[path.length - 1]] = value; }
      else b = value;
      for (const jwks of [B.receipt_jwks, undefined, value]) {
        const res = await verifyBundle(b, { receiptJwks: jwks, checkpointJwks: jwks === value ? value : B.checkpoint_jwks, now: B.now });
        assert.ok(res.valid === true || res.valid === false); assert.ok(Array.isArray(res.errors));
        if (res.approval) neverMoreThanNotChecked(res.approval, JSON.stringify(path));
        JSON.stringify(res);
        count += 1;
      }
    }
  }
  assert.ok(count > 1500, String(count));
});

test("a bundle without an approval is as valid as before", async () => {
  const res = await verifyBundle(clone(V.bundle.cases.good.bundle), { now: V.now });
  assert.equal(res.valid, true); assert.equal(res.approval, null);
});

test("the package exports work as documented", () => {
  const c = B.approvals.the_evidence_the_receipt_names;
  const res = pkg.verifyApproval(c.approval, c.anchored);
  assert.equal(res.verdict, "NOT CHECKED"); assert.equal(res.valid, null); assert.equal(res.signed.evidence_ok, true);
  assert.equal(pkg.VERSION, "0.9.2");
});

test("a reader that goes away gets no stack trace, and the exit code still says the verdict", async () => {
  // `regent-verify bundle x.json | head -2`: the pipe closes before the output ends
  const { spawn } = await import("node:child_process");
  for (const mode of [[], ["--json"]]) {
    for (const [name, code] of [["honest_with_the_receipt_key_pinned", 0], ["the_approval_evidence_altered", 1]]) {
      const file = join(dir, `${name}.json`); writeFileSync(file, JSON.stringify(B.bundles[name].bundle));
      const child = spawn(process.execPath, [CLI, "bundle", file, "--jwks", join(dir, "rk.json"), "--checkpoint-jwks", join(dir, "ck.json"), "--now", String(B.now), ...mode], { stdio: ["ignore", "pipe", "pipe"] });
      child.stdout.destroy();   // nobody reads: the first write meets a closed pipe
      let err = ""; child.stderr.on("data", (d) => { err += d; });
      const status = await new Promise((resolve) => child.on("close", resolve));
      assert.equal(err, "", `${name} ${mode}`); assert.equal(status, code, `${name} ${mode}`);
    }
  }
});

// ── fifth review (17.11.2026): argument forms, unwritable output, numbers, invisible characters ──
const honestFile = () => { const f = join(dir, "honest5.json"); writeFileSync(f, JSON.stringify(B.bundles.honest_with_the_receipt_key_pinned.bundle)); return f; };
const runCli = (args, extra = {}) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", ...extra });

test("an option in any spelling is refused, never taken for a file", () => {
  const f = honestFile(); const tail = ["--checkpoint-jwks", join(dir, "ck.json"), "--now", String(B.now)];
  for (const args of [["--origin=https://evil.example", f], ["--approver-key=", f], ["--rp-id=evil.example", f], ["--orig", "x", f],
    ["--approver", "x", f], ["--rp", "x", f], [f, f], ["--bogus", f], [f, "--jwks"]]) {
    const p = runCli(["bundle", ...args, ...tail]);
    assert.equal(p.status, 2, JSON.stringify(args)); assert.equal(p.stdout, "", JSON.stringify(args));
  }
});

test("keys given with an equals sign are the keys used", () => {
  const f = join(dir, "ownkey5.json"); writeFileSync(f, JSON.stringify(B.bundles.a_self_signed_receipt_with_its_key_in_the_bundle.bundle));
  const p = runCli(["bundle", `--jwks=${join(dir, "rk.json")}`, `--checkpoint-jwks=${join(dir, "ck.json")}`, `--now=${B.now}`, f]);
  assert.equal(p.status, 1); assert.ok(p.stdout.includes("signature does not verify"), p.stdout);
});

test("a root file that cannot be used stops the run", () => {
  const f = honestFile(); const bad = join(dir, "notaroot.pem"); writeFileSync(bad, "not a certificate");
  for (const root of [join(dir, "missing-root.pem"), bad]) {
    const p = runCli(["bundle", f, "--jwks", join(dir, "rk.json"), "--checkpoint-jwks", join(dir, "ck.json"), "--tsa-root", root]);
    assert.equal(p.status, 2, root); assert.equal(p.stdout, ""); assert.ok(p.stderr.startsWith("regent-verify: cannot read"), p.stderr);
  }
});

test("output that cannot be written is exit 2, not success", async () => {
  const { openSync, closeSync } = await import("node:fs");
  const fd = openSync("/dev/null", "r");   // stdout open, but not for writing
  try {
    const p = spawnSync(process.execPath, [CLI, "bundle", honestFile(), "--jwks", join(dir, "rk.json"), "--checkpoint-jwks", join(dir, "ck.json"), "--now", String(B.now)], { stdio: ["ignore", fd, "pipe"], encoding: "utf8" });
    assert.equal(p.status, 2); assert.ok(p.stderr.includes("cannot write the output"), p.stderr);
  } finally { closeSync(fd); }
});

test("invisible characters are escaped too", async () => {
  const { unprintable } = await import("../strict.js");
  for (const code of [0xad, 0x034f, 0x115f, 0x17b4, 0x180e, 0x206a, 0x3164, 0xfe0f, 0xffa0, 0xfff9, 0x1bca0, 0x1d173, 0xe0041]) assert.ok(unprintable(code), code.toString(16));
});

test("options this version cannot enforce are refused even without an approval", async () => {
  for (const options of [{ origins: ["https://x"] }, { approverKeys: ["k"] }, { rpIds: [] }, { origins: "x" }]) {
    const res = await verifyBundle(B.bundles.no_approval_anywhere.bundle, { receiptJwks: B.receipt_jwks, checkpointJwks: B.checkpoint_jwks, now: B.now, ...options });
    assert.equal(res.valid, false, JSON.stringify(options)); assert.equal(res.approval, null);
    assert.ok(res.errors.some((e) => e.includes("this version cannot require them")), JSON.stringify(options));
  }
});

test("a receipt checked with the bundle's own key is said so in the verdict", () => {
  const f = join(dir, "ownkey6.json"); writeFileSync(f, JSON.stringify(B.bundles.a_self_signed_receipt_with_its_key_in_the_bundle.bundle));
  const out = runCli(["bundle", f, "--checkpoint-jwks", join(dir, "ck.json"), "--now", String(B.now)]).stdout.split("\n");
  assert.equal(out[1], "NOT CHECKED — the owner's approval: the receipt key came from the bundle");
  assert.ok(out.includes("        that receipt was checked with the key inside the bundle"));
});

test("PEM text is accepted as roots, as documented", async () => {
  const pem = readFileSync(join(here, "..", "tsa_roots.pem"), "utf8");
  for (const tsaRoots of [pem, [pem]]) {
    const res = await verifyBundle(B.bundles.honest_with_the_receipt_key_pinned.bundle, { receiptJwks: B.receipt_jwks, checkpointJwks: B.checkpoint_jwks, now: B.now, tsaRoots });
    assert.equal(res.valid, true);
  }
});

test("a clock of null means now, as in Python", () => {
  const token = B.bundles.honest_with_the_receipt_key_pinned.bundle.receipt.token;
  assert.ok(verify(token, B.receipt_jwks, { now: null }).valid);
});

test("Python and Node print one text for one file, emoji included", () => {
  const b = clone(B.bundles.honest_with_the_receipt_key_pinned.bundle);
  b.events[0].event_type = `aaaaaaaaaaaaaaaaaaaaaa ${"\u{1F600}".repeat(9)}bbbbb`;
  const f = join(dir, "emoji5.json"); writeFileSync(f, JSON.stringify(b));
  const args = ["bundle", f, "--jwks", join(dir, "rk.json"), "--checkpoint-jwks", join(dir, "ck.json"), "--now", String(B.now)];
  const node = runCli(args);
  const py = spawnSync(process.env.REGENT_PYTHON || "python3", ["-m", "regent_receipt_verify.cli", ...args], { encoding: "utf8", env: { ...process.env, PYTHONPATH: join(here, "..", "..", "receipt-verify-python", "src") } });
  if (py.error || py.status === null || /No module named/.test(py.stderr)) return;   // no Python with the dependencies here: nothing to compare
  assert.equal(node.stdout, py.stdout); assert.equal(node.status, py.status);
});

test("an option name the library does not know is refused, not ignored", async () => {
  for (const bad of [{ approver_keys: ["k"] }, { origin: ["https://x"] }, { rp_ids: ["x"] }]) {
    for (const name of ["honest_with_the_receipt_key_pinned", "no_approval_anywhere"]) {
      const res = await verifyBundle(B.bundles[name].bundle, { receiptJwks: B.receipt_jwks, checkpointJwks: B.checkpoint_jwks, now: B.now, ...bad });
      assert.equal(res.valid, false, `${name} ${JSON.stringify(bad)}`);
    }
    const c = B.approvals.the_evidence_the_receipt_names;
    assert.equal(verifyApproval(c.approval, c.anchored, bad).verdict, "INVALID");
  }
});
