"""Both verifier packages run the same vectors, minted by the real issuer (make_vectors.py)."""
import json
import os

import pytest

from regent_receipt_verify import (
    canonical_args_hash, check_confirmation, check_mandate_reveal, check_policy_reveal, check_request_binding, verify,
    verify_token,
)
from regent_receipt_verify.cli import main

V = json.load(open(os.path.join(os.path.dirname(__file__), "..", "..", "receipt-verify-vectors", "vectors.json")))
NOW = V["now"]


def test_args_hash_matches_the_gate():
    r = V["request"]
    assert canonical_args_hash(r["tool"], r["action"], r["resource"], r["args"]) == V["args_hash"]


@pytest.mark.parametrize("name", ["receipt", "allow"])
def test_full_verification(name):
    case = V["cases"][name]
    res = verify(case["token"], V["jwks"], request=V["request"], mandate_reveal=V["mandate_reveal"],
                 policy_reveal=V["policy_reveal"], now=NOW)
    e = case["expect"]
    assert res.kind == e["kind"] and res.signature_valid is True and res.valid is True
    assert res.expired is False and res.args_hash_match is True
    assert res.mandate_match is True and res.policy_match is True
    assert res.kid == V["jwks"]["keys"][0]["kid"]
    # every tampering of a reveal or the request must fail to open the commitment
    assert verify(case["token"], V["jwks"], request=V["wrong_request"], now=NOW).args_hash_match is False
    bad_m = {**V["mandate_reveal"], "salt": "00" * 32}
    assert check_mandate_reveal(res.claims, bad_m) is False
    bad_snap = {**V["mandate_reveal"], "snapshot": {**V["mandate_reveal"]["snapshot"], "daily_limit": "9999.000000"}}
    assert check_mandate_reveal(res.claims, bad_snap) is False
    assert check_policy_reveal(res.claims, {**V["policy_reveal"], "cedar_text": V["policy_reveal"]["cedar_text"] + " "}) is False
    assert check_policy_reveal(res.claims, {**V["policy_reveal"], "profile": None}) is False


def test_allow_token_expiry_is_a_note_not_an_error():
    case = V["cases"]["allow_expired"]
    res = verify_token(case["token"], V["jwks"], now=case["now"])
    assert res.signature_valid and res.expired is True and res.valid is True and res.warnings


def test_receipt_past_evidence_period_is_invalid():
    res = verify_token(V["cases"]["receipt"]["token"], V["jwks"], now=NOW + 86400 * 4000)
    assert res.signature_valid and res.expired is True and res.valid is False


def test_starter_policy_opens_with_text_only():
    res = verify(V["cases"]["starter_receipt"]["token"], V["jwks"], policy_reveal=V["starter_text"], now=NOW)
    assert res.policy_match is True
    assert verify(V["cases"]["starter_receipt"]["token"], V["jwks"], policy_reveal=V["starter_text"] + "\n", now=NOW).policy_match is False


def test_budget_token_is_classified_and_verifies():
    res = verify_token(V["cases"]["budget"]["token"], V["jwks"], now=NOW)
    assert res.kind == "budget" and res.signature_valid


def test_wrong_key_and_tampering_fail():
    assert verify_token(V["cases"]["wrong_key"]["token"], V["jwks"], now=NOW).signature_valid is False
    assert verify_token(V["cases"]["tampered"]["token"], V["jwks"], now=NOW).signature_valid is False
    # the wrong key's own JWKS verifies it — key rotation: pass several JWKS
    assert verify_token(V["cases"]["wrong_key"]["token"], [V["jwks"], V["other_jwks"]], now=NOW).signature_valid is True


def test_garbage_never_raises():
    for bad in ("", "abc", "a.b", "a.b.c", "x" * 10):
        res = verify_token(bad, V["jwks"], now=NOW)
        assert res.signature_valid is False and res.errors


def test_request_binding_helper():
    claims = verify_token(V["cases"]["allow"]["token"], V["jwks"], now=NOW).claims
    r = V["request"]
    assert check_request_binding(claims, tool=r["tool"], action=r["action"], resource=r["resource"], args=r["args"])
    assert not check_request_binding(claims, tool=r["tool"], action="charge.refund", resource=r["resource"], args=r["args"])


def test_cli(tmp_path, capsys):
    jw = tmp_path / "jwks.json"; jw.write_text(json.dumps(V["jwks"]))
    req = tmp_path / "req.json"; req.write_text(json.dumps(V["request"]))
    man = tmp_path / "m.json"; man.write_text(json.dumps(V["mandate_reveal"]))
    pol = tmp_path / "p.json"; pol.write_text(json.dumps(V["policy_reveal"]))
    rc = main([V["cases"]["receipt"]["token"], "--jwks", str(jw), "--request", str(req), "--mandate", str(man),
               "--policy", str(pol), "--now", str(NOW)])
    out = capsys.readouterr().out
    assert rc == 0 and out.startswith("VALID") and "mandate reveal: MATCH" in out and "policy reveal: MATCH" in out
    rc = main([V["cases"]["tampered"]["token"], "--jwks", str(jw), "--json", "--now", str(NOW)])
    assert rc == 1 and json.loads(capsys.readouterr().out)["signature_valid"] is False
    bad = tmp_path / "bad.json"; bad.write_text(json.dumps(V["wrong_request"]))
    assert main([V["cases"]["allow"]["token"], "--jwks", str(jw), "--request", str(bad), "--now", str(NOW)]) == 1


# ── counterparty settlement confirmation (receipts minted with P-1) ────────────

@pytest.mark.parametrize("name", ["receipt_confirmed", "receipt_confirmed_es256"])
def test_counterparty_confirmation_verifies_against_its_jwks(name):
    case = V["cases"][name]
    res = verify(case["token"], V["jwks"], counterparty_jwks=V["counterparty_jwks"], now=NOW)
    assert res.valid and res.claims["settlement_source"] == "counterparty"
    assert res.confirmation_match is True and res.confirmation_errors == []
    assert res.confirmation["iss"] == res.claims["confirmed_by"] == "https://merchant.example"
    assert res.confirmation["decision_id"] == res.claims["decision_id"]
    assert res.confirmation["amount"] == res.claims["amount"] and res.confirmation["ref"] == "ord_1"
    # the embedded JWS really is the one the receipt cites
    import hashlib
    assert hashlib.sha256(res.claims["confirmation"].encode()).hexdigest() == res.claims["confirmation_hash"]


def test_counterparty_confirmation_fails_with_a_strangers_key():
    case = V["cases"]["receipt_confirmed"]
    res = verify(case["token"], V["jwks"], counterparty_jwks=V["stranger_jwks"], now=NOW)
    assert res.valid  # Regent's signature is fine; only the counterparty check fails
    assert res.confirmation_match is False and res.confirmation is None
    assert any("does not verify" in e for e in res.confirmation_errors)
    # an unknown kid is reported, not guessed
    res2 = verify(case["token"], V["jwks"], counterparty_jwks={"keys": []}, now=NOW)
    assert res2.confirmation_match is False and any("no key with kid" in e for e in res2.confirmation_errors)


def test_agent_reported_receipt_has_no_confirmation_to_check():
    res = verify(V["cases"]["receipt"]["token"], V["jwks"], counterparty_jwks=V["counterparty_jwks"], now=NOW)
    assert res.valid and res.confirmation_match is False
    assert any("agent-reported" in e for e in res.confirmation_errors)


def test_a_confirmation_that_disagrees_with_the_receipt_is_caught():
    """Same signed confirmation, but receipt claims that say something else: the check must notice.
    (Such a receipt would fail Regent's signature anyway, so the claims are compared directly.)"""
    case = V["cases"]["receipt_confirmed"]
    claims = dict(verify_token(case["token"], V["jwks"], now=NOW).claims)
    assert check_confirmation(claims, V["counterparty_jwks"]).ok
    assert not check_confirmation({**claims, "amount": 401.0}, V["counterparty_jwks"]).ok
    assert not check_confirmation({**claims, "decision_id": "dec_other"}, V["counterparty_jwks"]).ok
    assert not check_confirmation({**claims, "status": "failed"}, V["counterparty_jwks"]).ok
    assert not check_confirmation({**claims, "confirmation_hash": "00" * 32}, V["counterparty_jwks"]).ok
    assert not check_confirmation({**claims, "confirmed_by": "https://other.example"}, V["counterparty_jwks"]).ok


def test_cli_reports_the_counterparty(tmp_path, capsys):
    case = V["cases"]["receipt_confirmed"]
    jwks = tmp_path / "jwks.json"; jwks.write_text(json.dumps(V["jwks"]))
    cp = tmp_path / "cp.json"; cp.write_text(json.dumps(V["counterparty_jwks"]))
    assert main([case["token"], "--jwks", str(jwks), "--counterparty-jwks", str(cp), "--now", str(NOW)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("VALID") and "counterparty confirmation: MATCH" in out and "confirmed by https://merchant.example" in out
    stranger = tmp_path / "stranger.json"; stranger.write_text(json.dumps(V["stranger_jwks"]))
    assert main([case["token"], "--jwks", str(jwks), "--counterparty-jwks", str(stranger), "--now", str(NOW)]) == 1
    assert "counterparty confirmation: NO MATCH" in capsys.readouterr().out
