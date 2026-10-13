"""Evidence bundles minted by the real checkpoint signer and receipt issuer (vectors.json)."""
import json
import os

import pytest

from regent_receipt_verify.bundle import b58decode, merkle_root_from, verify_bundle

V = json.load(open(os.path.join(os.path.dirname(__file__), "..", "..", "receipt-verify-vectors", "vectors.json")))
B = V["bundle"]


@pytest.mark.parametrize("name", list(B["cases"]))
def test_bundle_cases(name):
    case = B["cases"][name]
    res = verify_bundle(case["bundle"])
    assert res.valid is case["valid"], (name, res.errors)
    if "receipt_valid" in case:
        assert res.receipt_valid is case["receipt_valid"] and res.receipt_anchored is case["receipt_anchored"]
    if "links" in case:
        assert res.links_ok is case["links"]
    assert res.decision_id == B["decision_id"]


def test_saved_keys_override_the_bundles_own():
    good = B["cases"]["good"]["bundle"]
    assert verify_bundle(good, checkpoint_jwks=B["checkpoint_jwks"], receipt_jwks=V["jwks"]).valid
    bad = verify_bundle(good, checkpoint_jwks=B["other_checkpoint_jwks"])
    assert not bad.valid and any("checkpoint" in e for e in bad.errors)
    assert not any("taken from the bundle" in w for w in bad.warnings if "checkpoint" in w)


def test_receipt_names_the_bundles_decision():
    good = json.loads(json.dumps(B["cases"]["good"]["bundle"]))
    good["decision_id"] = "dec_somethingelse"
    res = verify_bundle(good)
    assert not res.valid and "receipt names a different decision than the bundle" in res.errors


def test_result_is_json_serialisable_and_merkle_helper_matches_vectors():
    res = verify_bundle(B["cases"]["good"]["bundle"])
    json.dumps(res.to_dict())
    ev = B["cases"]["good"]["bundle"]["events"][0]
    assert merkle_root_from(ev["payload_hash"], ev["batch"]["merkle_proof"], ev["batch"]["merkle_index"]) == ev["batch"]["root"]


def test_base58_decodes_known_values():
    assert b58decode("111") == b"\x00\x00\x00"
    assert b58decode("2NEpo7TZRRrLZSi2U") == b"Hello World!"
