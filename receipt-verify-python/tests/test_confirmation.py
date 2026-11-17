"""Counterparty confirmations embedded in a receipt (confirmation_vectors.json): the Node
verifier runs the same file and must give the same verdict and print the same text."""
import json
import os
import subprocess
import sys

import pytest

from regent_receipt_verify import verify

HERE = os.path.dirname(__file__)
C = json.load(open(os.path.join(HERE, "..", "..", "receipt-verify-vectors", "confirmation_vectors.json")))


@pytest.mark.parametrize("name", sorted(C["cases"]))
def test_confirmation_cases(name):
    c = C["cases"][name]
    res = verify(c["token"], C["receipt_jwks"], counterparty_jwks=c.get("counterparty_jwks", C["counterparty_jwks"]), now=C["now"])
    assert res.signature_valid and res.confirmation_match is c["match"], (name, res.confirmation_errors)
    if c["error_contains"]:
        assert any(c["error_contains"] in e for e in res.confirmation_errors), (name, res.confirmation_errors)
    else:
        assert res.confirmation_errors == [], (name, res.confirmation_errors)


@pytest.mark.parametrize("name", sorted(n for n, c in C["cases"].items() if c["prints"]))
def test_confirmation_lines_as_printed(tmp_path, name):
    c = C["cases"][name]
    (tmp_path / "t.jwt").write_text(c["token"])
    (tmp_path / "rk.json").write_text(json.dumps(C["receipt_jwks"]))
    (tmp_path / "cp.json").write_text(json.dumps(C["counterparty_jwks"]))
    p = subprocess.run([sys.executable, "-m", "regent_receipt_verify.cli", f"@{tmp_path / 't.jwt'}", "--jwks", str(tmp_path / "rk.json"),
                        "--counterparty-jwks", str(tmp_path / "cp.json"), "--now", str(C["now"])], capture_output=True, text=True)
    assert c["prints"] in p.stdout.splitlines(), p.stdout


@pytest.mark.parametrize("now", [float("nan"), float("inf"), True])
def test_a_clock_that_is_not_a_time_is_refused(now):
    c = C["cases"]["the_same_facts"]
    res = verify(c["token"], C["receipt_jwks"], now=now)
    assert res.valid is False and res.errors == ["now is not a finite number of seconds"]


@pytest.mark.parametrize("content", [b"0", b'""', b"false", b'"x"', b"[]", b"true"])
@pytest.mark.parametrize("option", ["--request", "--mandate", "--payee"])
def test_a_reveal_that_is_not_an_object_stops_the_run(tmp_path, content, option):
    c = C["cases"]["the_same_facts"]
    (tmp_path / "t.jwt").write_text(c["token"])
    (tmp_path / "rk.json").write_text(json.dumps(C["receipt_jwks"]))
    (tmp_path / "rv.json").write_bytes(content)
    p = subprocess.run([sys.executable, "-m", "regent_receipt_verify.cli", f"@{tmp_path / 't.jwt'}", "--jwks", str(tmp_path / "rk.json"),
                        option, str(tmp_path / "rv.json"), "--now", str(C["now"])], capture_output=True, text=True)
    assert p.returncode == 2 and p.stdout == "" and "it is not a JSON object" in p.stderr and "Traceback" not in p.stderr


def test_a_failure_of_the_program_is_exit_2_not_a_verdict(monkeypatch):
    import regent_receipt_verify.cli as cli

    def boom(*a, **kw):
        raise RuntimeError("no")

    monkeypatch.setattr(cli, "verify", boom)
    c = C["cases"]["the_same_facts"]
    assert cli.main([c["token"], "--jwks", os.devnull]) == 2


ARGV = [  # (arguments after the token file and --jwks, exit code) — the Node suite holds the same table
    (["--now", "-1e5"], 1), (["--now", "0x10"], 2), (["--now", "1_795_000_000"], 2), (["--now", "١٧"], 2),
    (["--now", str(C["now"]), "--"], 0), (["--now", "x", "--help"], 2), (["--bogus", "--help"], 0), (["--issuer", "-x"], 2),
    (["--now=" + str(C["now"]), "--json"], 0), (["--json=1"], 2), (["--js"], 2), (["--now"], 2),
]


@pytest.mark.parametrize("extra,code", ARGV)
def test_arguments_are_read_the_same_way_in_both_languages(tmp_path, extra, code):
    c = C["cases"]["the_same_facts"]
    (tmp_path / "t.jwt").write_text(c["token"])
    (tmp_path / "rk.json").write_text(json.dumps(C["receipt_jwks"]))
    p = subprocess.run([sys.executable, "-m", "regent_receipt_verify.cli", f"@{tmp_path / 't.jwt'}", "--jwks", str(tmp_path / "rk.json"), *extra],
                       capture_output=True, text=True)
    assert p.returncode == code, (extra, p.stdout, p.stderr)
    assert "Traceback" not in p.stderr


@pytest.mark.parametrize("argv,code", [(["--version"], 0), (["x", "--jwks", "--version"], 2), (["-5", "--jwks", os.devnull], 2), ([], 2)])
def test_version_and_odd_positionals(argv, code):
    p = subprocess.run([sys.executable, "-m", "regent_receipt_verify.cli", *argv], capture_output=True, text=True)
    assert p.returncode == code, (argv, p.stdout, p.stderr)



@pytest.mark.parametrize("kind,name", [(k, c[0]) for k, v in sorted(C["reveals"].items()) for c in v["cases"]])
def test_a_reveal_of_the_wrong_type_matches_nothing_and_never_raises(kind, name):
    from regent_receipt_verify import check_mandate_reveal, check_payee_reveal, check_policy_reveal

    group = C["reveals"][kind]
    reveal, want = next((c[1], c[2]) for c in group["cases"] if c[0] == name)
    fn = {"policy": check_policy_reveal, "mandate": check_mandate_reveal, "payee": check_payee_reveal}[kind.split("_")[0]]
    assert fn(group["claims"], reveal) is want, (kind, name)



def test_integers_beyond_the_range_of_a_double_are_not_finite_numbers():
    from regent_receipt_verify import check_confirmation

    c = C["cases"]["the_same_facts"]
    claims = verify(c["token"], C["receipt_jwks"], now=C["now"]).claims
    assert check_confirmation({**claims, "iat": 10**401}, C["counterparty_jwks"]).ok is True   # ignored, as Node reads Infinity
    bad = check_confirmation({**claims, "amount": 10**400}, C["counterparty_jwks"])
    assert bad.ok is False and "confirmation amount is not a number" in bad.errors


V = json.load(open(os.path.join(HERE, "..", "..", "receipt-verify-vectors", "vectors.json")))
GOOD = V["bundle"]["cases"]["good"]["bundle"]
ROOTS = open(os.path.join(HERE, "..", "src", "regent_receipt_verify", "tsa_roots.pem")).read()


@pytest.mark.parametrize("roots,error", [
    (None, None), (ROOTS, None), ([ROOTS], None), (ROOTS.encode(), None),
    (["not a certificate", ROOTS], "tsa roots: item 0 holds no usable certificate"),
    ([ROOTS, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"], "tsa roots: item 1 holds no usable certificate"),
    ([5, ROOTS], "tsa roots: item 0 is neither PEM text nor a certificate"),
    ({}, "tsa roots: item 0 is neither PEM text nor a certificate"),
])
def test_roots_are_read_item_by_item_and_refused_when_unusable(roots, error):
    from regent_receipt_verify.bundle import verify_bundle

    res = verify_bundle(GOOD, now=V["now"], tsa_roots=roots)
    if error is None:
        assert res.valid is True, res.errors
    else:
        assert res.valid is False and res.errors == [error]



def _variants(pem: str) -> list[str]:
    """PEM forms one language's own reader takes and the other's does not: all refused now."""
    first = pem.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
    return [first.replace("\n", ""), first.replace("\n", "\r"),
            first.replace("-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\nComment: x\n\n"),
            first.replace("-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n"),
            first.replace("-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----\n\u00a0"),
            first.replace("\n", "\u2028"), first.replace("\n-----END", "-----END"),
            first.replace("BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE").replace("END CERTIFICATE", "END X509 CERTIFICATE")]


@pytest.mark.parametrize("n", range(8))
def test_a_pem_form_only_one_reader_takes_is_refused_by_both(tmp_path, n):
    from regent_receipt_verify.bundle import verify_bundle

    form = _variants(ROOTS)[n]
    res = verify_bundle(GOOD, now=V["now"], tsa_roots=form)
    assert res.valid is False and res.errors == ["tsa roots: item 0 holds no usable certificate"], (n, res.errors)
    f = tmp_path / "root.pem"
    f.write_text(form, encoding="utf-8", newline="")
    (tmp_path / "b.json").write_text(json.dumps(GOOD))
    p = subprocess.run([sys.executable, "-m", "regent_receipt_verify.cli", "bundle", str(tmp_path / "b.json"), "--tsa-root", str(f)],
                       capture_output=True, text=True)
    assert p.returncode == 2 and "it holds no PEM certificate" in p.stderr, (n, p.stderr)


def test_the_strict_form_of_the_packaged_roots_reads():
    from regent_receipt_verify.strict import pem_certificates

    assert len(pem_certificates(ROOTS)) >= 2 and len(pem_certificates(ROOTS.replace("\n", "\r\n"))) >= 2
