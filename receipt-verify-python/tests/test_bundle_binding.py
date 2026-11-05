"""What a bundle's VALID binds (05.11.2026): the events are about this decision and appear once."""

import copy
import json
import os

from regent_receipt_verify.bundle import verify_bundle

V = json.load(open(os.path.join(os.path.dirname(__file__), "..", "..", "receipt-verify-vectors", "vectors.json")))


def _good():
    cases = V["bundle"]["cases"]
    name = next(n for n, c in cases.items() if c["valid"])
    return copy.deepcopy(cases[name]["bundle"])


def test_an_event_of_another_decision_or_a_duplicate_makes_the_bundle_invalid():
    b = _good()
    assert verify_bundle(b).valid
    other = copy.deepcopy(b)
    ev = next(e for e in other["events"] if (e.get("payload") or {}).get("decision_id"))
    ev["payload"]["decision_id"] = "dec_ffffffffffff"
    ev["payload_canonical"] = json.dumps(ev["payload"], separators=(",", ":"), sort_keys=True)
    res = verify_bundle(other)
    assert not res.valid and any("names decision dec_ffffffffffff" in e for e in res.errors)
    dup = _good()
    dup["events"].append(copy.deepcopy(dup["events"][0]))
    res = verify_bundle(dup)
    assert not res.valid and any("more than once" in e for e in res.errors)


def test_an_unanchored_epoch_is_said_so():
    b = _good()
    for e in b["events"]:
        if e.get("epoch"):
            e["epoch"]["tx"] = None
            e["epoch"].pop("tsa_token_b64", None)
    res = verify_bundle(b)
    assert any("not anchored in this bundle" in w for w in res.warnings)
