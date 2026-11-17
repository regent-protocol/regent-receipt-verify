// Counterparty confirmations embedded in a receipt (confirmation_vectors.json): the Python
// verifier runs the same file and must give the same verdict and print the same text.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verify, verifyToken } from "../index.js";

const here = dirname(fileURLToPath(import.meta.url));
const C = JSON.parse(readFileSync(join(here, "..", "..", "receipt-verify-vectors", "confirmation_vectors.json"), "utf8"));
const CLI = join(here, "..", "cli.js");
const dir = mkdtempSync(join(tmpdir(), "regent-conf-"));
writeFileSync(join(dir, "rk.json"), JSON.stringify(C.receipt_jwks));
writeFileSync(join(dir, "cp.json"), JSON.stringify(C.counterparty_jwks));

for (const [name, c] of Object.entries(C.cases).sort()) {
  test(`confirmation: ${name}`, () => {
    const cp = c.counterparty_jwks ?? C.counterparty_jwks;
    const res = verify(c.token, C.receipt_jwks, { counterpartyJwks: cp, now: C.now });
    assert.ok(res.signatureValid, name); assert.equal(res.confirmationMatch, c.match, `${name}: ${JSON.stringify(res.confirmationErrors)}`);
    if (c.error_contains) assert.ok(res.confirmationErrors.some((e) => e.includes(c.error_contains)), `${name}: ${JSON.stringify(res.confirmationErrors)}`);
    else assert.deepEqual(res.confirmationErrors, [], name);
    // the command line prints what the Python twin prints, word for word
    const f = join(dir, `${name}.jwt`); writeFileSync(f, c.token);
    const cpf = join(dir, `${name}.cp.json`); writeFileSync(cpf, JSON.stringify(cp));
    const args = [`@${f}`, "--jwks", join(dir, "rk.json"), "--counterparty-jwks", cpf, "--now", String(C.now)];
    const node = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
    if (c.prints) assert.ok(node.stdout.split("\n").includes(c.prints), node.stdout);
    const py = spawnSync(process.env.REGENT_PYTHON || "python3", ["-m", "regent_receipt_verify.cli", ...args], { encoding: "utf8", env: { ...process.env, PYTHONPATH: join(here, "..", "..", "receipt-verify-python", "src") } });
    if (py.error || py.status === null || /No module named/.test(py.stderr)) return;
    assert.equal(node.stdout, py.stdout, name); assert.equal(node.status, py.status, name);
  });
}

test("a clock that is not a time is refused", () => {
  const c = C.cases.the_same_facts;
  for (const now of [NaN, Infinity, true, "1795000000"]) {
    const res = verifyToken(c.token, C.receipt_jwks, { now });
    assert.equal(res.valid, false); assert.deepEqual(res.errors, ["now is not a finite number of seconds"]);
  }
});

test("an option name the function does not know is refused, not ignored", () => {
  const c = C.cases.the_same_facts;
  const res = verify(c.token, C.receipt_jwks, { counterparty_jwks: C.counterparty_jwks, now: C.now });
  assert.equal(res.valid, false); assert.ok(res.errors.some((e) => e.startsWith("unknown option counterparty_jwks")), JSON.stringify(res.errors));
});

test("a reveal that is not an object stops the run", () => {
  const c = C.cases.the_same_facts; const f = join(dir, "t.jwt"); writeFileSync(f, c.token);
  for (const content of ["0", '""', "false", '"x"', "[]", "true"]) {
    for (const option of ["--request", "--mandate", "--payee"]) {
      const rv = join(dir, "rv.json"); writeFileSync(rv, content);
      const p = spawnSync(process.execPath, [CLI, `@${f}`, "--jwks", join(dir, "rk.json"), option, rv, "--now", String(C.now)], { encoding: "utf8" });
      assert.equal(p.status, 2, `${option} ${content}`); assert.equal(p.stdout, ""); assert.ok(p.stderr.includes("it is not a JSON object"), p.stderr);
    }
  }
});

const ARGV = [ // [arguments after the token file and --jwks, exit code] — the Python suite holds the same table
  [["--now", "-1e5"], 1], [["--now", "0x10"], 2], [["--now", "1_795_000_000"], 2], [["--now", "١٧"], 2],
  [["--now", String(C.now), "--"], 0], [["--now", "x", "--help"], 2], [["--bogus", "--help"], 0], [["--issuer", "-x"], 2],
  [[`--now=${C.now}`, "--json"], 0], [["--json=1"], 2], [["--js"], 2], [["--now"], 2],
];

test("arguments are read the same way in both languages", () => {
  const f = join(dir, "argv.jwt"); writeFileSync(f, C.cases.the_same_facts.token);
  for (const [extra, code] of ARGV) {
    const p = spawnSync(process.execPath, [CLI, `@${f}`, "--jwks", join(dir, "rk.json"), ...extra], { encoding: "utf8" });
    assert.equal(p.status, code, `${JSON.stringify(extra)}: ${p.stdout} ${p.stderr}`);
  }
  for (const [argv, code] of [[["--version"], 0], [["x", "--jwks", "--version"], 2], [["-5", "--jwks", "/dev/null"], 2], [[], 2]]) {
    const p = spawnSync(process.execPath, [CLI, ...argv], { encoding: "utf8" });
    assert.equal(p.status, code, `${JSON.stringify(argv)}: ${p.stdout} ${p.stderr}`);
  }
});

test("checkConfirmation never throws and refuses option names it does not know", async () => {
  const { checkConfirmation } = await import("../index.js");
  const claims = verify(C.cases.the_same_facts.token, C.receipt_jwks, { now: C.now }).claims;
  for (const options of [null, 5, "x", {}, { now: C.now }]) assert.equal(checkConfirmation(claims, C.counterparty_jwks, options).ok, true, JSON.stringify(options));
  const bad = checkConfirmation(claims, C.counterparty_jwks, { now: C.now, nwo: 1 });
  assert.equal(bad.ok, false); assert.ok(bad.errors[0].startsWith("unknown option"));
});

test("a reveal of the wrong type matches nothing and never throws", async () => {
  const { checkMandateReveal, checkPayeeReveal, checkPolicyReveal } = await import("../index.js");
  const fns = { policy: checkPolicyReveal, mandate: checkMandateReveal, payee: checkPayeeReveal };
  for (const [kind, group] of Object.entries(C.reveals)) {
    for (const [name, reveal, want] of group.cases) assert.equal(fns[kind.split("_")[0]](group.claims, reveal), want, `${kind} ${name}`);
  }
});

test("roots are read item by item, and refused when unusable", async () => {
  const { verifyBundle } = await import("../index.js");
  const V = JSON.parse(readFileSync(join(here, "..", "..", "receipt-verify-vectors", "vectors.json"), "utf8"));
  const good = V.bundle.cases.good.bundle;
  const ROOTS = readFileSync(join(here, "..", "tsa_roots.pem"), "utf8");
  for (const [roots, error] of [
    [null, null], [ROOTS, null], [[ROOTS], null], [Buffer.from(ROOTS), null],
    [["not a certificate", ROOTS], "tsa roots: item 0 holds no usable certificate"],
    [[ROOTS, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"], "tsa roots: item 1 holds no usable certificate"],
    [[5, ROOTS], "tsa roots: item 0 is neither PEM text nor a certificate"],
    [{}, "tsa roots: item 0 is neither PEM text nor a certificate"],
  ]) {
    const res = await verifyBundle(good, { now: V.now, tsaRoots: roots });
    if (error === null) assert.equal(res.valid, true, JSON.stringify(res.errors));
    else { assert.equal(res.valid, false); assert.deepEqual(res.errors, [error]); }
  }
});

test("a PEM form only one language's own reader takes is refused by both", async () => {
  const { verifyBundle } = await import("../index.js");
  const V = JSON.parse(readFileSync(join(here, "..", "..", "receipt-verify-vectors", "vectors.json"), "utf8"));
  const good = V.bundle.cases.good.bundle; writeFileSync(join(dir, "good.json"), JSON.stringify(good));
  const ROOTS = readFileSync(join(here, "..", "tsa_roots.pem"), "utf8");
  const first = `${ROOTS.split("-----END CERTIFICATE-----")[0]}-----END CERTIFICATE-----\n`;
  const forms = [first.replaceAll("\n", ""), first.replaceAll("\n", "\r"),
    first.replace("-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\nComment: x\n\n"),
    first.replace("-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n"),
    first.replace("-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\n\u00a0"),
    first.replaceAll("\n", "\u2028"), first.replace("\n-----END", "-----END"),
    first.replace("BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE").replace("END CERTIFICATE", "END X509 CERTIFICATE")];
  for (const [n, form] of forms.entries()) {
    const res = await verifyBundle(good, { now: V.now, tsaRoots: form });
    assert.equal(res.valid, false, String(n)); assert.deepEqual(res.errors, ["tsa roots: item 0 holds no usable certificate"], String(n));
    const f = join(dir, `root${n}.pem`); writeFileSync(f, form);
    const p = spawnSync(process.execPath, [CLI, "bundle", join(dir, "good.json"), "--tsa-root", f], { encoding: "utf8" });
    assert.equal(p.status, 2, String(n)); assert.ok(p.stderr.includes("it holds no PEM certificate"), p.stderr);
  }
});
