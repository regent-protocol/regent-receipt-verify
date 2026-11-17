"""Whole bundles, the approval beside a receipt, and what the strict reader refuses
(bundle_vectors.json). The Node verifier runs the same file and must agree.

Many of the cases are forgeries and malformed input that security reviews found an earlier
version accepting, printing as its own verdict, or crashing on. The rest pin down what this
version says about the owner's approval: it compares the evidence with the digest in the
receipt, and its verdict is never better than NOT CHECKED."""
import copy
import json
import os
import subprocess
import sys

import pytest

from regent_receipt_verify import verify
from regent_receipt_verify.approval import VERIFIES_SIGNATURE, verify_approval
from regent_receipt_verify.bundle import verify_bundle

HERE = os.path.dirname(__file__)
B = json.load(open(os.path.join(HERE, "..", "..", "receipt-verify-vectors", "bundle_vectors.json")))
V = json.load(open(os.path.join(HERE, "..", "..", "receipt-verify-vectors", "vectors.json")))
VERDICTS = ("INVALID", "NOT CHECKED")   # every verdict this version can give on an approval


def test_this_version_does_not_claim_to_verify_the_owners_signature():
    assert VERIFIES_SIGNATURE is False


@pytest.mark.parametrize("name", sorted(B["approvals"]))
def test_approval_cases(name):
    c = B["approvals"][name]
    res = verify_approval(c["approval"], c["anchored"], approver_keys=c.get("approver_keys"), origins=c.get("origins"))
    assert (res.verdict, res.why) == (c["verdict"], c["why"]), (name, res.errors, res.warnings)
    assert res.valid is c["valid"] and res.valid is not True, name
    # right in everything but one thing: the whole list of errors is that one thing
    assert sorted(res.errors) == sorted(c["errors_exact"]), (name, res.errors)
    if c.get("warning_contains"):
        assert any(c["warning_contains"] in w for w in res.warnings), (name, res.warnings)
    if "evidence_ok" in c:
        assert res.signed.evidence_ok is c["evidence_ok"], name
    if "anchored_returned" in c:
        assert res.signed.anchored is c["anchored_returned"], name
    if "record_returned" in c:
        assert res.record == c["record_returned"], name
    if "stated_keys" in c:
        assert sorted(res.stated) == sorted(c["stated_keys"]), (name, res.stated)
    if "changes_listed" in c:
        assert res.changes_listed == c["changes_listed"], name
    assert res.record in (None, "unknown", "on_file", "no_signature", "not_retained", "not_recorded", "unavailable")
    for value in res.stated.values():  # nothing the block says can carry a line break or an escape
        assert value.isprintable(), (name, value)
    _never_more_than_not_checked(res)
    json.dumps(res.to_dict())  # serialisable


def _never_more_than_not_checked(approval) -> None:
    assert approval.verdict in VERDICTS and approval.valid is not True and approval.consistent is None
    assert approval.terms is None and approval.changes == [], "this version returns no terms and checks no changes"
    if approval.signed is not None:
        assert approval.signed.signature_ok is None and approval.signed.terms is None


@pytest.mark.parametrize("junk", [5, True, "x", [1], {"record": 5}, {"record": "on_file", "evidence_canonical": 7},
                                  {"record": "on_file", "changes": 3}])
def test_junk_is_an_invalid_result_never_an_exception(junk):
    res = verify_approval(junk, {"approval_method": "passkey", "approval_digest": "ab" * 32})
    assert res.valid is False and res.errors and res.verdict == "INVALID"


@pytest.mark.parametrize("options", [{"approver_keys": "k1"}, {"origins": 5}, {"rp_ids": [1]}])
def test_an_option_of_the_wrong_type_is_an_invalid_result(options):
    c = B["approvals"]["the_evidence_the_receipt_names"]
    res = verify_approval(c["approval"], c["anchored"], **options)
    assert res.verdict == "INVALID" and res.errors


# ── inside a whole bundle: real anchoring, keys pinned, the forgeries reviews found ──────


def _run(c, **more):
    return verify_bundle(c["bundle"], receipt_jwks=B["receipt_jwks"] if c["pin_receipt"] else None,
                         checkpoint_jwks=B["checkpoint_jwks"], now=B["now"], **more)


@pytest.mark.parametrize("name", sorted(B["bundles"]))
def test_bundle_cases(name):
    c = B["bundles"][name]
    res = _run(c)
    if c["valid"] is not None:
        assert res.valid is c["valid"], (name, res.errors)
    approval = res.approval
    assert (approval.verdict if approval else None) == c["approval_verdict"], (name, res.errors, res.warnings)
    assert res.approval_anchor == c["approval_anchor"], name
    if approval is not None:
        _never_more_than_not_checked(approval)
        assert (approval.verdict == "INVALID") is (approval.valid is False), name
        if approval.verdict == "INVALID":
            assert res.valid is False, "an approval that contradicts the receipt makes the bundle invalid"
        if c.get("why"):
            assert approval.why == c["why"], name
        if "evidence_ok" in c:
            assert approval.signed.evidence_ok is c["evidence_ok"], name
    if c.get("error"):
        assert any(c["error"] in e for e in res.errors), (name, res.errors)
    if c.get("warning"):
        assert any(c["warning"] in w for w in res.warnings), (name, res.warnings)
    json.dumps(res.to_dict())


def test_an_approval_can_only_be_compared_under_a_verified_receipt_for_this_decision():
    """Evidence is reported as named by the receipt in the honest bundles and nowhere else."""
    named = sorted(n for n, c in B["bundles"].items()
                   if (r := _run(c)).approval is not None and r.approval.signed is not None and r.approval.signed.anchored)
    assert named == ["a_label_padded_to_draw_a_row_of_its_own", "a_label_with_a_line_break_and_a_verdict",
                     "a_label_with_del_and_non_ascii", "a_self_signed_receipt_with_its_key_in_the_bundle",
                     "an_index_written_with_a_decimal_point_is_the_same_number",
                     "honest_but_the_receipt_key_comes_from_the_bundle", "honest_with_the_receipt_key_pinned",
                     "the_terms_beside_the_evidence_rewritten"]
    # the two of them whose receipt key the bundle brought carry the note that says so
    for name in ("a_self_signed_receipt_with_its_key_in_the_bundle", "honest_but_the_receipt_key_comes_from_the_bundle"):
        assert any("receipt key taken from the bundle itself" in w for w in _run(B["bundles"][name]).warnings), name


def test_requiring_a_key_or_a_site_through_the_bundle_check_is_refused():
    c = B["bundles"]["honest_with_the_receipt_key_pinned"]
    for more in ({"approver_keys": ["k1"]}, {"origins": ["https://app.regentprotocol.org"]}, {"rp_ids": ["app.regentprotocol.org"]}):
        res = _run(c, **more)
        assert res.valid is False and res.approval.verdict == "INVALID", more
        assert any("this version cannot require them" in e for e in res.errors), more


def _cli(tmp_path, name, *extra):
    c = B["bundles"][name]
    f = tmp_path / "bundle.json"
    f.write_text(json.dumps(c["bundle"]))
    rk, ck = tmp_path / "rk.json", tmp_path / "ck.json"
    rk.write_text(json.dumps(B["receipt_jwks"]))
    ck.write_text(json.dumps(B["checkpoint_jwks"]))
    args = [sys.executable, "-m", "regent_receipt_verify.cli", "bundle", str(f), "--checkpoint-jwks", str(ck),
            "--now", str(B["now"]), *extra]
    if c["pin_receipt"]:
        args += ["--jwks", str(rk)]
    return subprocess.run(args, capture_output=True, text=True)


def _columns(line: str) -> int:
    return sum(1 if ch < "\u0080" else 2 for ch in line)


@pytest.mark.parametrize("name", sorted(B["bundles"]))
def test_the_command_line_gives_two_verdicts_and_a_bundle_cannot_write_either(tmp_path, name):
    """The text output is what a person reads in a dispute. A bundle is untrusted input: its
    strings must not be able to add a line, clear the screen, or print this program's verdict."""
    c = B["bundles"][name]
    p = _cli(tmp_path, name)
    out = p.stdout
    assert p.stderr == "" and p.returncode in (0, 1), (name, p.stderr)
    assert not any(ord(ch) < 0x20 and ch != "\n" for ch in out), "no control character reaches the terminal"
    lines = out.splitlines()
    assert all(_columns(ln) <= 78 for ln in lines), "no line is left for the terminal to wrap"
    # Two lines start at the left edge and no other: the bundle's verdict, and the approval's
    # own when there is anything to say about one. Nothing a bundle carries can add a third.
    tops = [ln for ln in lines if not ln.startswith(" ")]
    assert tops[0].startswith(("VALID — evidence bundle", "INVALID — evidence bundle")), (name, tops)
    assert len(tops) == (2 if c["approval_verdict"] else 1), (name, tops)
    if c["approval_verdict"]:
        assert tops[1].startswith(c["approval_verdict"] + " — the owner's approval: "), (name, tops)
        assert not lines[lines.index(tops[1]) + 1].startswith("      | "), "the verdict on the approval is one line"
    detail = [ln for ln in lines if ln.startswith("  approval: ")]
    assert len(detail) <= 1, (name, detail)
    if detail:
        assert detail[0].startswith("  approval: " + c["approval_verdict"] + " (record "), (name, detail)
    # the words of a verified signature belong to a later version: here they can only be a
    # label a bundle supplied, and never at the start of a row of this program's
    for ln in lines:
        if "SIGNATURE VALID" in ln:
            assert ln.startswith("      | ") or ln.startswith("  ["), (name, ln)
    if c.get("cli_must_not_print"):
        assert c["cli_must_not_print"] not in out, name
    if c["valid"] is not None:
        assert p.returncode == (0 if c["valid"] else 1), name
    js = _cli(tmp_path, name, "--json")
    assert js.stdout.isascii() and "\x7f" not in js.stdout, "JSON output is plain ASCII"
    parsed = json.loads(js.stdout)
    assert (parsed["approval"] or {}).get("verdict") == c["approval_verdict"], name
    if parsed["approval"] is not None:
        assert parsed["approval"]["valid"] is not True and parsed["approval"]["why"], name


def test_a_valid_bundle_says_in_its_second_line_that_the_approval_was_not_checked(tmp_path):
    out = _cli(tmp_path, "honest_with_the_receipt_key_pinned").stdout.splitlines()
    assert out[0] == "VALID — evidence bundle for dec_aaaaaaaaaaaa, 2 event(s)"
    assert out[1] == "NOT CHECKED — the owner's approval: this version does not verify it"
    assert "        evidence: named by the receipt, bytes match its digest: yes" in out
    assert "        owner's signature: NOT CHECKED; terms: NOT CHECKED" in out


@pytest.mark.parametrize("option", [["--approver-key", "k1"], ["--origin", "https://app.regentprotocol.org"],
                                    ["--rp-id", "app.regentprotocol.org"]])
def test_an_option_this_version_cannot_enforce_stops_the_run(tmp_path, option):
    p = _cli(tmp_path, "honest_with_the_receipt_key_pinned", *option)
    assert p.returncode == 2 and p.stdout == "" and "need a version that verifies the owner's signature" in p.stderr
    helped = subprocess.run([sys.executable, "-m", "regent_receipt_verify.cli", "bundle", "--help"], capture_output=True, text=True)
    assert option[0] not in helped.stdout, "an option that does nothing here is not offered"


def test_output_is_escaped_and_wrapped_by_this_program():
    from regent_receipt_verify.cli import _CONT, _safe, _wrap

    assert _safe("a\x1b[2Jb\nc\x7f\x85 ‮​﻿d") == "a\\x1b[2Jb\\x0ac\\x7f\\x85\\u2028\\u202e\\u200b\\ufeffd"
    assert _safe("Абай 😀 — ok") == "Абай 😀 — ok", "ordinary text in any script is left alone"
    forged = "  [ok ] evt (x" + " " * 70 + "approval: SIGNATURE VALID (forged)"
    pieces = _wrap(forged)
    assert len(pieces) > 1 and all(_columns(x) <= 78 for x in pieces)
    assert all(x.startswith(_CONT) for x in pieces[1:]) and not any(x.startswith("  approval:") for x in pieces)
    assert _wrap("short") == ["short"]
    assert all(_columns(x) <= 78 for x in _wrap("щ" * 200)), "wide and non-Latin text is counted generously"
    pieces = _wrap("°" * 200)
    assert len(pieces[0]) == 39 and all(_columns(x) <= 78 for x in pieces), "a character some terminals draw double-width counts as two"


@pytest.mark.parametrize("content,code", [(b"\xff\xfe not text", 2), (b"{not json", 2), (b"", 2), (b"\xef\xbb\xbf{}", 2),
                                          (b'{"a": NaN}', 2), (b"null", 1), (b"[]", 1), (b'"x"', 1), (b"{}", 1)])
def test_a_file_that_is_not_a_bundle_gets_one_plain_line(tmp_path, content, code):
    """No traceback and nothing of the file echoed: a file can carry escape sequences too."""
    f = tmp_path / "b.json"
    f.write_bytes(content + b"\x1b[2J")
    if code == 1:
        f.write_bytes(content)
    p = subprocess.run([sys.executable, "-m", "regent_receipt_verify.cli", "bundle", str(f)], capture_output=True)
    assert p.returncode == code, (content, p.returncode, p.stderr)
    assert b"Traceback" not in p.stderr and b"\x1b" not in p.stderr + p.stdout
    if code == 2:
        assert p.stdout == b"" and p.stderr.startswith(b"regent-verify: cannot read ")


@pytest.mark.parametrize("name", sorted(B["tokens"]))
def test_token_cases(name):
    """The strict reader and the key profile: a good signature under a key that is too
    small, a header or payload that is not what the format allows, a key set of the wrong shape."""
    c = B["tokens"][name]
    res = verify(c["token"], c["jwks"], now=B["now"])
    assert res.valid is c["valid"], (name, res.errors)
    if c["error_contains"]:
        assert any(c["error_contains"] in e for e in res.errors), (name, res.errors)
    if name == "an_expiry_that_is_true_is_not_a_time":
        assert res.expired is None


def test_what_must_not_reach_a_terminal():
    from regent_receipt_verify.strict import unprintable

    for code in (0x00, 0x09, 0x0A, 0x1B, 0x7F, 0x80, 0x85, 0x9F, 0x061C, 0x200B, 0x200E, 0x200F, 0x2028, 0x2029, 0x202A,
                 0x202E, 0x2060, 0x2066, 0x2069, 0xFEFF, 0xD800, 0xDFFF):
        assert unprintable(code), hex(code)
    for code in (0x20, 0x7E, 0xA0, 0xB0, 0xE9, 0x0416, 0x2014, 0x2026, 0x4E2D, 0x1F600):
        assert not unprintable(code), hex(code)


def test_limits_that_keep_a_file_from_spending_the_readers_time():
    honest = B["bundles"]["honest_with_the_receipt_key_pinned"]["bundle"]
    many = copy.deepcopy(honest)
    many["events"] = [many["events"][0]] * 10001
    res = verify_bundle(many, receipt_jwks=B["receipt_jwks"], checkpoint_jwks=B["checkpoint_jwks"], now=B["now"])
    assert res.valid is False and res.errors == ["bundle is malformed: more than 10000 events"]
    odd = copy.deepcopy(honest)
    odd["events"][0]["payload_hash"] = "\ud800"
    res = verify_bundle(odd, receipt_jwks=B["receipt_jwks"], checkpoint_jwks=B["checkpoint_jwks"], now=B["now"])
    assert res.errors == ["bundle is malformed: events[0].payload_hash is not valid text"]
    crowded = copy.deepcopy(honest)
    crowded["approval"]["changes"] = [{}] * 1001
    res = verify_bundle(crowded, receipt_jwks=B["receipt_jwks"], checkpoint_jwks=B["checkpoint_jwks"], now=B["now"])
    assert res.valid is False and "approval block is malformed: more than 1000 changes" in res.errors
    # a number too long for a double is still itself, and still not another number
    big = copy.deepcopy(honest)
    big["events"][0]["payload"]["wei"] = 10**21
    big["events"][0]["payload_canonical"] = json.dumps(big["events"][0]["payload"], sort_keys=True, ensure_ascii=False)
    e = verify_bundle(big, checkpoint_jwks=B["checkpoint_jwks"], now=B["now"]).events[0]
    assert "payload_canonical does not parse to payload" not in e.errors
    big["events"][0]["payload"]["wei"] = 2 * 10**21
    e = verify_bundle(big, checkpoint_jwks=B["checkpoint_jwks"], now=B["now"]).events[0]
    assert "payload_canonical does not parse to payload" in e.errors


@pytest.mark.parametrize("args,code", [(["--now", "abc"], 2), (["--now", "inf"], 2), (["--now", "nan"], 2)])
def test_a_time_that_is_not_a_time_is_refused(tmp_path, args, code):
    f = tmp_path / "b.json"
    f.write_text(json.dumps(B["bundles"]["honest_with_the_receipt_key_pinned"]["bundle"]))
    p = subprocess.run([sys.executable, "-m", "regent_receipt_verify.cli", "bundle", str(f), *args], capture_output=True)
    assert p.returncode == code and b"VALID" not in p.stdout


def test_a_file_nested_too_deeply_is_refused_the_same_way_everywhere(tmp_path):
    f = tmp_path / "deep.json"
    f.write_text('{"bundle_version":"regent-evidence-bundle/1","x":' + "[" * 600 + "]" * 600 + "}")
    p = subprocess.run([sys.executable, "-m", "regent_receipt_verify.cli", "bundle", str(f)], capture_output=True)
    assert p.returncode == 2 and b"nested too deeply" in p.stderr
    f.write_text('{"x":"' + "[" * 600 + '","y":' + "[" * 500 + "]" * 500 + "}")   # brackets inside a string do not count
    p = subprocess.run([sys.executable, "-m", "regent_receipt_verify.cli", "bundle", str(f)], capture_output=True)
    assert p.returncode == 1


def test_a_token_has_one_spelling():
    token = B["bundles"]["honest_with_the_receipt_key_pinned"]["bundle"]["receipt"]["token"]
    ok = verify(token, B["receipt_jwks"], now=B["now"])
    assert ok.valid and verify(token + "\n", B["receipt_jwks"], now=B["now"]).valid, "a token saved to a file ends with a line end"
    h, pl, sig = token.split(".")
    for other in (token + "!", token + "=", "\x1f" + token, token + " ", token + "﻿", f"{h}.{pl}.{sig}=",
                  f"{h}=.{pl}.{sig}", token.replace(".", "\n.", 1), f"{h}.{pl}.{sig}.x", sig[:-1] + "Ł"):
        res = verify(other, B["receipt_jwks"], now=B["now"])
        assert res.valid is False and res.signature_valid is False, other[-12:]
    assert verify(token, {"keys": "x"}).valid is False and verify(token, "x").valid is False and verify(token, None).valid is False


def test_verify_bundle_answers_for_any_shape_and_never_raises():
    """Every node of an honest bundle, the approval block included, replaced by every kind of junk."""
    honest = B["bundles"]["honest_with_the_receipt_key_pinned"]["bundle"]
    junk = [None, 0, 1.5, True, "x", [], {}, [1], {"a": 1}, "\ud800"]

    def paths(node, here=()):
        yield here
        if isinstance(node, dict):
            for k, v in node.items():
                yield from paths(v, (*here, k))
        elif isinstance(node, list) and node:
            yield from paths(node[0], (*here, 0))

    count = 0
    for path in paths(honest):
        for value in junk:
            b = copy.deepcopy(honest)
            node = b
            for step in path[:-1]:
                node = node[step]
            if path:
                node[path[-1]] = value
            else:
                b = value
            for jwks in (B["receipt_jwks"], None, value):
                res = verify_bundle(b, receipt_jwks=jwks, checkpoint_jwks=B["checkpoint_jwks"] if jwks is not value else value, now=B["now"])
                assert res.valid in (True, False) and isinstance(res.errors, list)
                if res.approval is not None:
                    _never_more_than_not_checked(res.approval)
                json.dumps(res.to_dict())
                count += 1
    assert count > 1500


def test_a_bundle_without_an_approval_is_as_valid_as_before():
    b = copy.deepcopy(V["bundle"]["cases"]["good"]["bundle"])
    res = verify_bundle(b, now=V["now"])
    assert res.valid is True and res.approval is None and res.to_dict()["approval"] is None


def test_the_package_exports_work_as_documented():
    import regent_receipt_verify as pkg

    c = B["approvals"]["the_evidence_the_receipt_names"]
    res = pkg.verify_approval(c["approval"], receipt_claims=c["anchored"])
    assert isinstance(res, pkg.ApprovalResult) and res.verdict == "NOT CHECKED" and res.valid is None
    assert isinstance(res.signed, pkg.SignedApproval) and res.signed.evidence_ok is True
    assert pkg.__version__ == "0.9.1"


@pytest.mark.parametrize("mode", [[], ["--json"]])
def test_a_reader_that_goes_away_gets_no_traceback_and_the_exit_code_still_says_the_verdict(tmp_path, mode):
    """`regent-verify bundle x.json | head -2`: the pipe closes before the output ends."""
    for name, code in (("honest_with_the_receipt_key_pinned", 0), ("the_approval_evidence_altered", 1)):
        f, rk, ck = tmp_path / "bundle.json", tmp_path / "rk.json", tmp_path / "ck.json"
        f.write_text(json.dumps(B["bundles"][name]["bundle"]))
        rk.write_text(json.dumps(B["receipt_jwks"]))
        ck.write_text(json.dumps(B["checkpoint_jwks"]))
        p = subprocess.Popen([sys.executable, "-m", "regent_receipt_verify.cli", "bundle", str(f), "--jwks", str(rk),
                              "--checkpoint-jwks", str(ck), "--now", str(B["now"]), *mode],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.stdout.close()   # nobody reads: the first write meets a closed pipe
        err = p.stderr.read()
        p.stderr.close()
        assert p.wait() == code and err == b"", (name, err)


# ── fifth review (17.11.2026): argument forms, unwritable output, numbers, invisible characters ──


def _run_cli(args, **kw):
    kw.setdefault("stdout", subprocess.PIPE)
    kw.setdefault("stderr", subprocess.PIPE)
    return subprocess.run([sys.executable, "-m", "regent_receipt_verify.cli", *args], **kw)


def _files(tmp_path, name="honest_with_the_receipt_key_pinned"):
    f, rk, ck = tmp_path / "b.json", tmp_path / "rk.json", tmp_path / "ck.json"
    f.write_text(json.dumps(B["bundles"][name]["bundle"]))
    rk.write_text(json.dumps(B["receipt_jwks"]))
    ck.write_text(json.dumps(B["checkpoint_jwks"]))
    return str(f), str(rk), str(ck)


@pytest.mark.parametrize("args", [
    ["--origin=https://evil.example", "{f}"], ["--approver-key=", "{f}"], ["--rp-id=evil.example", "{f}"],
    ["--orig", "x", "{f}"], ["--approver", "x", "{f}"], ["--rp", "x", "{f}"], ["{f}", "{f}"], ["--bogus", "{f}"],
    ["{f}", "--jwks"],
])
def test_an_option_in_any_spelling_is_refused_never_taken_for_a_file(tmp_path, args):
    f, rk, ck = _files(tmp_path)
    p = _run_cli(["bundle", *[a.replace("{f}", f) for a in args], "--checkpoint-jwks", ck, "--now", str(B["now"])], text=True)
    assert p.returncode == 2 and p.stdout == "", (args, p.stdout, p.stderr)


def test_keys_given_with_an_equals_sign_are_the_keys_used(tmp_path):
    f, rk, ck = _files(tmp_path, "a_self_signed_receipt_with_its_key_in_the_bundle")
    p = _run_cli(["bundle", f"--jwks={rk}", f"--checkpoint-jwks={ck}", f"--now={B['now']}", f], text=True)
    assert p.returncode == 1 and "signature does not verify" in p.stdout


@pytest.mark.parametrize("content", [None, b"not a certificate"])
def test_a_root_file_that_cannot_be_used_stops_the_run(tmp_path, content):
    f, rk, ck = _files(tmp_path)
    root = tmp_path / "root.pem"
    if content is not None:
        root.write_bytes(content)
    p = _run_cli(["bundle", f, "--jwks", rk, "--checkpoint-jwks", ck, "--tsa-root", str(root)])
    assert p.returncode == 2 and p.stdout == b"" and b"Traceback" not in p.stderr and p.stderr.startswith(b"regent-verify: cannot read")


def test_closed_streams_change_nothing_but_the_output(tmp_path):
    f, rk, ck = _files(tmp_path)
    p = _run_cli(["bundle", f, "--jwks", rk, "--checkpoint-jwks", ck, "--now", str(B["now"])], stdout=None,
                 preexec_fn=lambda: os.close(1))
    assert p.returncode == 0 and b"Traceback" not in p.stderr, p.stderr
    p = _run_cli(["bundle", str(tmp_path / "missing.json")], stderr=None, preexec_fn=lambda: os.close(2))
    assert p.returncode == 2


def test_output_that_cannot_be_written_is_exit_2_not_success(tmp_path):
    f, rk, ck = _files(tmp_path)
    fd = os.open(os.devnull, os.O_RDONLY)   # stdout open, but not for writing
    try:
        p = _run_cli(["bundle", f, "--jwks", rk, "--checkpoint-jwks", ck, "--now", str(B["now"])], stdout=fd)
    finally:
        os.close(fd)
    assert p.returncode == 2 and b"cannot write the output" in p.stderr and b"Traceback" not in p.stderr


def test_numbers_are_printed_as_javascript_prints_them():
    from regent_receipt_verify.cli import _number

    for value, text in ((0.00001, "0.00001"), (5e-06, "0.000005"), (1e-07, "1e-7"), (1e15, "1000000000000000"),
                        (1e21, "1e+21"), (12.5, "12.5"), (9000.0, "9000"), (-0.5, "-0.5"), (0.0, "0"),
                        (0.30000000000000004, "0.30000000000000004"), (True, "")):
        assert _number(value) == text, (value, _number(value))


def test_invisible_characters_are_escaped_too():
    from regent_receipt_verify.cli import _safe

    for code in (0xAD, 0x034F, 0x115F, 0x17B4, 0x180E, 0x206A, 0x3164, 0xFE0F, 0xFFA0, 0xFFF9, 0x1BCA0, 0x1D173, 0xE0041):
        assert _safe("a" + chr(code) + "b") != "a" + chr(code) + "b", hex(code)


@pytest.mark.parametrize("options", [{"origins": ["https://x"]}, {"approver_keys": ["k"]}, {"rp_ids": []}, {"origins": "x"}])
def test_options_this_version_cannot_enforce_are_refused_even_without_an_approval(options):
    res = verify_bundle(B["bundles"]["no_approval_anywhere"]["bundle"], receipt_jwks=B["receipt_jwks"],
                        checkpoint_jwks=B["checkpoint_jwks"], now=B["now"], **options)
    assert res.valid is False and res.approval is None and any("this version cannot require them" in e for e in res.errors)


def test_a_receipt_checked_with_the_bundles_own_key_is_said_so_in_the_verdict(tmp_path):
    f, rk, ck = _files(tmp_path, "a_self_signed_receipt_with_its_key_in_the_bundle")
    out = _run_cli(["bundle", f, "--checkpoint-jwks", ck, "--now", str(B["now"])], text=True).stdout.splitlines()
    assert out[1] == "NOT CHECKED — the owner's approval: the receipt key came from the bundle"
    assert "        that receipt was checked with the key inside the bundle" in out
