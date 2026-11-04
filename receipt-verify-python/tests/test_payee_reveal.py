"""payee-v1: the receipt commits to the counterparty; the owner's reveal opens it."""

import hashlib
import json
import os

from regent_receipt_verify import check_payee_reveal, payee_commitment, verify

V = json.load(open(os.path.join(os.path.dirname(__file__), "..", "..", "receipt-verify-vectors", "vectors.json")))


def test_reveal_opens_the_commitment_and_nothing_else():
    salt = "ab" * 16
    claims = {"decision_id": "dec_1", "payee_hash": payee_commitment("ACME Ltd", salt), "payee_commit": "payee-v1"}
    assert payee_commitment("ACME Ltd", salt) == hashlib.sha256(f"payee-v1|payee=ACME Ltd|salt={salt}".encode()).hexdigest()
    assert check_payee_reveal(claims, {"payee": "ACME Ltd", "salt": salt})
    assert check_payee_reveal(claims, {"payee": "ACME Ltd", "salt": salt.upper(), "decision_id": "dec_1"})
    assert not check_payee_reveal(claims, {"payee": "ACME Ltd", "salt": salt, "decision_id": "dec_2"})
    assert not check_payee_reveal(claims, {"payee": "Someone", "salt": salt})
    assert not check_payee_reveal(claims, {"payee": "ACME Ltd", "salt": "cd" * 16})
    assert not check_payee_reveal({"payee": "ACME Ltd"}, {"payee": "ACME Ltd", "salt": salt})  # pre-payee-v1 receipt


def test_verify_reports_payee_match_only_when_a_reveal_is_given():
    rec = V["cases"]["receipt"]
    res = verify(rec["token"], V["jwks"], now=V["now"], payee_reveal={"payee": "x", "salt": "y"})
    assert res.signature_valid and res.payee_match is False  # the vector predates payee-v1: no hash to open
    assert res.to_dict()["payee_match"] is False
    assert verify(rec["token"], V["jwks"], now=V["now"]).payee_match is None
