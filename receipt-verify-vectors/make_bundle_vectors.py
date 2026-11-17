"""Bundle vectors for both verifiers: `bundle_vectors.json`.

Standalone (needs only `cryptography`). A stand-in issuer with the trail's own rules (RS256
checkpoints and receipts, the Merkle leaf is the payload hash and nothing else) builds
bundles whose keys a verifier PINS: the honest service anchoring whatever it is given,
including a tenant's own events. Three groups:

  bundles    whole evidence bundles: honest ones, forgeries, wrong shapes, and labels that
             try to print this program's verdict
  approvals  an `approval` block beside the claims of the verified receipt that names it
  tokens     receipts and key sets the strict reader must refuse

The approval evidence here is opaque on purpose: this version of the verifiers compares
its bytes with the digest in the receipt and reads nothing inside it. Every expected
verdict on an approval is therefore NOT CHECKED or INVALID, never better.

    python make_bundle_vectors.py        # rewrites bundle_vectors.json beside this file
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def digest(obj) -> str:
    return hashlib.sha256(canonical(obj).encode()).hexdigest()


# ── the approval block, with evidence nothing here reads ─────────────────────────────────
EVIDENCE = {"kind": "approve", "opaque": "test evidence: this version compares its bytes with the receipt and reads none of it",
            "serial": 1, "amount": 1200.0, "note": "продлить подписку"}
OTHER_EVIDENCE = {**EVIDENCE, "serial": 2}
TERMS = {"kind": "mandate_create", "agent_id": "agent_demo", "currency": "USD",
         "limits": {"per_tx_limit": "50", "daily_limit": "200", "monthly_limit": "1000"}}


def block(evidence=EVIDENCE, *, method="passkey", scope="mandate", record="on_file", **extra) -> dict:
    out = {"method": method, "scope": scope, "evidence_digest": digest(evidence) if evidence is not None else None,
           "names": "this purchase" if scope == "purchase" else "the creation of the mandate", "record": record}
    if record == "on_file":
        out.update({"kind": "mandate_create", "subject_ref": "mnd_demo", "approver": "0b9f6e0c-2a11-4c55-9d3e-6f1f6f1f6f1f",
                    "approved_at": "2026-11-15T18:20:00Z", "applied_at": "2026-11-15T18:20:01Z",
                    "terms": TERMS, "evidence": evidence, "evidence_canonical": canonical(evidence)})
    out.update(extra)
    return out


def facts(b: dict) -> dict:
    return {"approval_method": b["method"], "approval_digest": b["evidence_digest"], "approval_scope": b["scope"]}


good = block()

# ── approvals: a block beside the claims of the verified receipt ─────────────────────────
approvals: dict[str, dict] = {}


def approval_case(name, approval, anchored, *, verdict, why, valid, errors=(), warning=None, note=None, **opts) -> None:
    approvals[name] = {"approval": approval, "anchored": anchored, "verdict": verdict, "why": why, "valid": valid,
                       "errors_exact": list(errors), "warning_contains": warning, "note": note, **opts}


E_BYTES = "approval: evidence: the bytes do not hash to the digest that names them"
E_OTHER = "the approval in the bundle is not the one the receipt names (digests differ)"
E_SHOWN = "approval: evidence: the object shown is not what the hashed bytes say"
E_PINS = ("an approver key, an origin or a relying party id was required, and this version cannot require them: "
          "it does not verify the owner's signature")

approval_case("the_evidence_the_receipt_names", copy.deepcopy(good), facts(good), verdict="NOT CHECKED",
              why="this version does not verify it", valid=None, warning="does not verify the owner's signature",
              evidence_ok=True, anchored_returned=True,
              note="the most this version says: the bytes are the ones the receipt names; never more than NOT CHECKED")
edited = copy.deepcopy(good)
edited["evidence_canonical"] = canonical(OTHER_EVIDENCE)
edited["evidence"] = OTHER_EVIDENCE
approval_case("the_evidence_was_edited", edited, facts(good), verdict="INVALID", why="a check failed, see the errors",
              valid=False, errors=[E_BYTES], evidence_ok=False, anchored_returned=False,
              note="one byte of the evidence changed and the stated digest left as it was")
swapped = block(OTHER_EVIDENCE)
approval_case("other_evidence_in_its_place", swapped, facts(good), verdict="INVALID", why="a check failed, see the errors",
              valid=False, errors=[E_OTHER, E_BYTES], note="evidence that is consistent with itself, and not what the receipt names")
shown = copy.deepcopy(good)
shown["evidence"] = OTHER_EVIDENCE
approval_case("the_object_shown_is_not_the_bytes", shown, facts(good), verdict="INVALID", why="a check failed, see the errors",
              valid=False, errors=[E_SHOWN], evidence_ok=True,
              note="the hashed string is right; the object a person reads beside it says something else")
approval_case("the_terms_beside_it_can_say_anything", {**copy.deepcopy(good), "terms": {"limits": {"per_tx_limit": "5000000"}}},
              facts(good), verdict="NOT CHECKED", why="this version does not verify it", valid=None,
              warning="covered by nothing it checks",
              note="this version does not tie the terms to the evidence: it must say NOT CHECKED, and it does")
approval_case("the_receipt_names_one_and_the_bundle_carries_none", None, facts(good), verdict="NOT CHECKED",
              why="the bundle does not carry it", valid=None, warning="does not carry it", record_returned=None)
approval_case("no_verified_receipt", copy.deepcopy(good), None, verdict="NOT CHECKED",
              why="no verified receipt for this decision", valid=None, warning="no verified receipt")
approval_case("the_receipt_names_no_approval", copy.deepcopy(good), {"decision_id": "dec_aaaaaaaaaaaa"}, verdict="INVALID",
              why="a check failed, see the errors", valid=False,
              errors=["nothing anchored names this approval: the receipt carries no approval digest"])
approval_case("another_scope_than_the_receipts", {**copy.deepcopy(good), "scope": "purchase"}, facts(good), verdict="INVALID",
              why="a check failed, see the errors", valid=False,
              errors=["the receipt says the approval covers the mandate, the bundle says otherwise"])
approval_case("another_method_than_the_receipts", {**copy.deepcopy(good), "method": "session"}, facts(good), verdict="INVALID",
              why="a check failed, see the errors", valid=False,
              errors=["the receipt says the approval was by passkey, the bundle says otherwise"])
approval_case("said_to_be_unsigned_while_the_receipt_names_a_digest", block(None, record="no_signature"), facts(good),
              verdict="INVALID", why="a check failed, see the errors", valid=False,
              errors=["the receipt names an approval by digest; the bundle says no signature was taken"])
approval_case("approved_in_a_session", block(None, method="session", record="no_signature"),
              {"approval_method": "session", "approval_scope": "mandate"}, verdict="NOT CHECKED", why="no signature was taken",
              valid=None, warning="approved without a passkey (session)")
not_kept = block(None, record="not_retained")
not_kept["evidence_digest"] = good["evidence_digest"]
approval_case("evidence_not_kept", not_kept, facts(good), verdict="NOT CHECKED", why="its evidence is not on file", valid=None,
              warning="not on file")
approval_case("none_recorded_and_the_receipt_names_none", block(None, record="not_recorded"), {"decision_id": "dec_aaaaaaaaaaaa"},
              verdict="NOT CHECKED", why="none was recorded", valid=None)
approval_case("none_recorded_while_the_receipt_names_one", block(None, record="not_recorded"), facts(good), verdict="INVALID",
              why="a check failed, see the errors", valid=False,
              errors=["the receipt names an approval; the bundle says none was recorded"])
approval_case("an_unknown_record_state", {**copy.deepcopy(good), "record": "verified"}, facts(good), verdict="INVALID",
              why="a check failed, see the errors", valid=False, errors=["unknown approval record state"], record_returned="unknown")
approval_case("listed_changes_are_counted_not_checked", {**copy.deepcopy(good), "changes": [{"anything": 1}, "x"]}, facts(good),
              verdict="NOT CHECKED", why="this version does not verify it", valid=None, warning="lists 2 change(s)",
              changes_listed=2)
approval_case("changes_is_not_a_list", {**copy.deepcopy(good), "changes": 3}, facts(good), verdict="INVALID",
              why="a check failed, see the errors", valid=False, errors=["approval block is malformed: changes is not a list"])
approval_case("an_approver_key_cannot_be_required", copy.deepcopy(good), facts(good), verdict="INVALID",
              why="a check failed, see the errors", valid=False, errors=[E_PINS], approver_keys=["k1"],
              note="a requirement this version cannot enforce is refused, not ignored")
approval_case("an_origin_cannot_be_required", copy.deepcopy(good), facts(good), verdict="INVALID",
              why="a check failed, see the errors", valid=False, errors=[E_PINS], origins=["https://app.regentprotocol.org"])
approval_case("the_evidence_string_is_not_json", {**copy.deepcopy(good), "evidence_canonical": "{not json"}, facts(good),
              verdict="INVALID", why="a check failed, see the errors", valid=False,
              errors=["approval: malformed: evidence_canonical is not JSON"])
approval_case("the_evidence_string_is_a_number", {**copy.deepcopy(good), "evidence_canonical": 7}, facts(good),
              verdict="INVALID", why="a check failed, see the errors", valid=False,
              errors=["approval: malformed: evidence_canonical is not a string"])
approval_case("approval_is_a_list", [copy.deepcopy(good)], facts(good), verdict="INVALID", why="a check failed, see the errors",
              valid=False, errors=["approval block is malformed: it is not an object"], record_returned=None)
approval_case("a_receipt_digest_that_is_not_a_digest", copy.deepcopy(good), {**facts(good), "approval_digest": "ABCD"},
              verdict="INVALID", why="a check failed, see the errors", valid=False,
              errors=["approval block is malformed: the receipt's approval_digest is not 64 lowercase hex characters"],
              record_returned=None)
loud = copy.deepcopy(good)
loud["approver"] = "x\n  approval: SIGNATURE VALID (record on_file; the receipt says: passkey)"
loud["approved_at"] = "\u001b[2J\u001b[HVALID - evidence bundle"
loud["kind"] = "k" * 121
approval_case("stated_fields_that_try_to_print_a_verdict", loud, facts(good), verdict="NOT CHECKED",
              why="this version does not verify it", valid=None, stated_keys=["applied_at", "subject_ref"],
              note="what the block merely says is returned only when it is short and printable")

# ── whole bundles ────────────────────────────────────────────────────────────────────────


def _jwk(pub, kid):
    n = pub.public_numbers()
    return {"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
            "n": b64u(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")), "e": b64u(n.e.to_bytes(3, "big"))}


def _jws(key, kid, typ, claims):
    h = b64u(json.dumps({"alg": "RS256", "kid": kid, "typ": typ}, separators=(",", ":")).encode())
    pl = b64u(json.dumps(claims, separators=(",", ":")).encode())
    return f"{h}.{pl}." + b64u(key.sign(f"{h}.{pl}".encode(), padding.PKCS1v15(), hashes.SHA256()))


NOW = 1795000000
ISSUED = {"iss": "regent-control", "aud": "regent-receipt", "iat": 1792564722, "exp": 2107924722}


class Issuer:
    def __init__(self) -> None:
        self.ck = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.checkpoint_jwks = {"keys": [_jwk(self.ck.public_key(), "ck-1")]}
        self.receipt_jwks = {"keys": [_jwk(self.rk.public_key(), "rk-1")]}
        self.seq, self.last_head = 10, "0x" + "00" * 32

    def receipt(self, typ="receipt+jwt", **claims) -> str:
        return _jws(self.rk, "rk-1", typ, {**ISSUED, "jti": "rcp_" + uuid.uuid4().hex[:12], **claims})

    def seal(self, items):
        """Anchor one or two (event_id, event_type, payload): the bundle's event entries."""
        self.seq += 1
        canon = [json.dumps(pl, sort_keys=True, ensure_ascii=False) for _, _, pl in items]
        hs = ["0x" + hashlib.sha256(c.encode()).hexdigest() for c in canon]
        root, proofs = (hs[0], [[]]) if len(items) == 1 else (hashlib.sha256((hs[0] + hs[1]).encode()).hexdigest(), [[hs[1]], [hs[0]]])
        batch_id = str(uuid.uuid4())
        head = "0x" + hashlib.sha256((root + str(self.seq)).encode()).hexdigest()
        ck = _jws(self.ck, "ck-1", "checkpoint+jwt", {"iss": "https://api.regentprotocol.org/v1/audit", "batch_id": batch_id,
                                                     "seq": self.seq, "root": root, "head": head,
                                                     "prev_head": self.last_head, "chain_tx": None})
        self.last_head = head
        return [{"event_id": eid, "agent_id": "agent_demo", "event_type": etype, "received_at": "2026-11-15T18:21:00Z",
                 "status": "anchored", "payload": pl, "payload_canonical": canon[i], "payload_hash": hs[i],
                 "payload_hash_recomputed": True, "prev_hash": None,
                 "batch": {"batch_id": batch_id, "seq": self.seq, "root": root, "event_count": len(items), "merkle_index": i,
                           "merkle_proof": proofs[i], "chain_tx": None, "chain_head": head, "checkpoint": ck,
                           "checkpoint_kid": "ck-1"},
                 "epoch": None} for i, (eid, etype, pl) in enumerate(items)]

    def bundle(self, decision_id, events, token=None, receipt_event_id=None, approval=None, receipt_jwks=None):
        b = {"bundle_version": "regent-evidence-bundle/1", "generated_at": "2026-11-16T00:00:00Z", "decision_id": decision_id,
             "issuer": {"audit": "https://api.regentprotocol.org/v1/audit", "control": "regent-control"},
             "programs": {"audit_anchor": "8N1PpbJZKmvJjG86XWpP82XrWzp8HY5FHZuzyQTgjJas"}, "cluster": "devnet",
             "keys": {"checkpoint_jwks": self.checkpoint_jwks, "receipt_jwks": receipt_jwks or self.receipt_jwks},
             "events": events,
             "receipt": {"token": token, "kid": "rk-1", "jti": "x", "event_id": receipt_event_id} if token else None}
        if approval is not None:
            b["approval"] = approval
        return b


regent = Issuer()
DEC = "dec_aaaaaaaaaaaa"
bundles: dict[str, dict] = {}


def bundle_case(name, bundle, *, pin_receipt=True, valid, verdict, anchor, note=None, **opts):
    """`verdict`: the verdict on the approval, or None when the result carries no approval at all."""
    bundles[name] = {"bundle": bundle, "pin_receipt": pin_receipt, "valid": valid, "approval_verdict": verdict,
                     "approval_anchor": anchor, "note": note, **opts}


def decision_with(receipt_claims, approval, *, decision_id=DEC, typ="receipt+jwt", receipt_names=None):
    """A decision event and its receipt, anchored by the issuer; the approval beside them."""
    token = regent.receipt(typ=typ, decision_id=receipt_names or decision_id, agent_id="agent_demo", status="success",
                           amount=12.0, currency="USD", **receipt_claims)
    events = regent.seal([(f"ctrl-{decision_id}", "control.decision", {"decision_id": decision_id, "decision": "allow"}),
                          (f"ctrl-{decision_id}-receipt", "control.decision.receipt",
                           {"decision_id": decision_id, "receipt": token})])
    return regent.bundle(decision_id, events, token, f"ctrl-{decision_id}-receipt", approval)


honest = decision_with(facts(good), copy.deepcopy(good))
bundle_case("honest_with_the_receipt_key_pinned", honest, valid=True, verdict="NOT CHECKED", anchor="receipt",
            why="this version does not verify it", evidence_ok=True,
            note="the bundle is VALID and the approval is NOT CHECKED: two verdicts, both printed")
bundle_case("honest_but_the_receipt_key_comes_from_the_bundle", copy.deepcopy(honest), pin_receipt=False, valid=True,
            verdict="NOT CHECKED", anchor="receipt", warning="receipt key taken from the bundle itself")
plain_bundle = decision_with({}, None)
bundle_case("no_approval_anywhere", plain_bundle, valid=True, verdict=None, anchor="receipt",
            note="the receipt names no approval and the bundle carries none: nothing is said about one")
bundle_case("the_approval_block_removed", decision_with(facts(good), None), valid=True, verdict="NOT CHECKED", anchor="receipt",
            why="the bundle does not carry it", warning="does not carry it",
            note="removing the block does not make it pass: the receipt still names an approval, and the output says so")
altered = copy.deepcopy(honest)
altered["approval"]["evidence_canonical"] = canonical(OTHER_EVIDENCE)
altered["approval"]["evidence"] = OTHER_EVIDENCE
bundle_case("the_approval_evidence_altered", altered, valid=False, verdict="INVALID", anchor="receipt",
            error="evidence: the bytes do not hash to the digest that names them",
            note="the published 0.9.0 called this bundle VALID and said nothing about the approval")
replaced = copy.deepcopy(honest)
replaced["approval"] = block(OTHER_EVIDENCE)
bundle_case("the_approval_replaced_by_another", replaced, valid=False, verdict="INVALID", anchor="receipt", error="digests differ")
retold = copy.deepcopy(honest)
retold["approval"]["terms"] = {"limits": {"per_tx_limit": "5000000"}}
bundle_case("the_terms_beside_the_evidence_rewritten", retold, valid=True, verdict="NOT CHECKED", anchor="receipt",
            warning="covered by nothing it checks",
            note="this version cannot tell: the bundle stays VALID, and the approval line says terms NOT CHECKED")

# a tenant has an ordinary event anchored whose payload names the digest of the tenant's OWN
# evidence, and relabels it as the decision: labels are not hashed into the trail
forged = block(OTHER_EVIDENCE, scope="purchase")
tenant_payload = {"decision_id": DEC, "decision": "allow", "approval_method": "passkey",
                  "approval_digest": forged["evidence_digest"], "approval_scope": "purchase"}
plain_token = regent.receipt(decision_id=DEC, agent_id="agent_demo", status="success", amount=12.0, currency="USD")
relabelled = regent.seal([("evt-tenant-1", "custom.note", tenant_payload),
                          (f"ctrl-{DEC}-receipt", "control.decision.receipt", {"decision_id": DEC, "receipt": plain_token})])
relabelled[0]["event_id"], relabelled[0]["event_type"] = f"ctrl-{DEC}", "control.decision"
bundle_case("a_tenant_event_relabelled_as_the_decision", regent.bundle(DEC, relabelled, plain_token, f"ctrl-{DEC}-receipt", forged),
            valid=False, verdict="INVALID", anchor="receipt", error="nothing anchored names",
            note="the receipt for this decision names no approval; no event may stand in for it")
alone = regent.seal([("evt-tenant-2", "custom.note", tenant_payload)])
alone[0]["event_id"], alone[0]["event_type"] = f"ctrl-{DEC}", "control.decision"
bundle_case("the_receipt_removed_and_an_event_relabelled", regent.bundle(DEC, alone, None, None, copy.deepcopy(forged)),
            valid=True, verdict="NOT CHECKED", anchor=None, why="no verified receipt for this decision", warning="no verified receipt",
            note="the trail part still verifies (the tenant's event IS anchored); the approval is tied to nothing")

# the same trick moved onto the receipt: the attacker's own receipt key shipped inside the bundle
attacker = Issuer()
self_signed = attacker.receipt(decision_id=DEC, agent_id="agent_demo", status="success", amount=12.0, currency="USD",
                               **facts(forged))
smuggled = regent.seal([(f"ctrl-{DEC}", "control.decision", {"decision_id": DEC, "decision": "allow"}),
                        ("evt-tenant-3", "custom.note", {"decision_id": DEC, "receipt": self_signed})])
smuggled[1]["event_id"], smuggled[1]["event_type"] = f"ctrl-{DEC}-receipt", "control.decision.receipt"
own_key = regent.bundle(DEC, smuggled, self_signed, f"ctrl-{DEC}-receipt", copy.deepcopy(forged),
                        receipt_jwks=attacker.receipt_jwks)
bundle_case("a_self_signed_receipt_with_its_key_in_the_bundle", own_key, pin_receipt=False, valid=True, verdict="NOT CHECKED",
            anchor="receipt", warning="receipt key taken from the bundle itself",
            note="only the checkpoint key is pinned; the note says whose key the receipt was checked with")
bundle_case("a_self_signed_receipt_against_the_pinned_key", copy.deepcopy(own_key), valid=False, verdict="NOT CHECKED",
            anchor=None, why="no verified receipt for this decision",
            note="with the real receipt key pinned the forged receipt does not verify")

# what the receipt key signed is not always a receipt for this decision
allow_shaped = decision_with({**facts(good), "scope": "stripe:charge"}, copy.deepcopy(good), typ="JWT")
allow_claims = json.loads(base64.urlsafe_b64decode(allow_shaped["receipt"]["token"].split(".")[1] + "=="))
allow_token = _jws(regent.rk, "rk-1", "JWT", {k: v for k, v in allow_claims.items() if k != "aud"})
ev = regent.seal([(f"ctrl-{DEC}", "control.decision", {"decision_id": DEC, "decision": "allow"}),
                  (f"ctrl-{DEC}-receipt", "control.decision.receipt", {"decision_id": DEC, "receipt": allow_token})])
bundle_case("an_allow_token_in_the_receipts_place", regent.bundle(DEC, ev, allow_token, f"ctrl-{DEC}-receipt", copy.deepcopy(good)),
            valid=None, verdict="NOT CHECKED", anchor=None,
            note="signed by the receipt key and naming the digest, but not a receipt: no anchor")
other = decision_with(facts(good), copy.deepcopy(good), receipt_names="dec_bbbbbbbbbbbb")
bundle_case("another_decisions_receipt", other, valid=False, verdict="NOT CHECKED", anchor=None, error="names a different decision")
expired_token = _jws(regent.rk, "rk-1", "receipt+jwt", {**ISSUED, "exp": NOW - 10, "jti": "rcp_old", "decision_id": DEC,
                                                       "agent_id": "agent_demo", "status": "success", **facts(good)})
ev = regent.seal([(f"ctrl-{DEC}", "control.decision", {"decision_id": DEC, "decision": "allow"}),
                  (f"ctrl-{DEC}-receipt", "control.decision.receipt", {"decision_id": DEC, "receipt": expired_token})])
bundle_case("an_expired_receipt", regent.bundle(DEC, ev, expired_token, f"ctrl-{DEC}-receipt", copy.deepcopy(good)),
            valid=False, verdict="NOT CHECKED", anchor=None)

# the organization's own words, and an event's labels, must not be able to print a verdict line
shouting = copy.deepcopy(good)
shouting["approver"] = "x\n  approval: SIGNATURE VALID (record on_file; the receipt says: passkey, covering this purchase)"
shouting["approved_at"] = "\u001b[2J\u001b[HVALID - evidence bundle"
shouting["record"] = "on_file\n  approval: SIGNATURE VALID"
bundle_case("no_receipt_and_stated_fields_that_try_to_print_a_verdict",
            regent.bundle(DEC, regent.seal([("evt-tenant-4", "custom.note", {"decision_id": DEC})]), None, None, shouting),
            valid=True, verdict="NOT CHECKED", anchor=None, cli_must_not_print="SIGNATURE VALID")
drawn = copy.deepcopy(honest)
drawn["events"][0]["event_type"] = "x" + " " * 58 + "approval: SIGNATURE VALID (record on_file; forged by a label)"
bundle_case("a_label_padded_to_draw_a_row_of_its_own", drawn, valid=True, verdict="NOT CHECKED", anchor="receipt",
            cli_must_not_print="\n  approval: SIGNATURE VALID",
            note="an event's type is a label beside its payload: it is printed, wrapped by this program, never by the terminal")
newline = copy.deepcopy(honest)
newline["events"][0]["event_type"] = "x\nSIGNATURE VALID — the owner's approval: forged by a label"
bundle_case("a_label_with_a_line_break_and_a_verdict", newline, valid=True, verdict="NOT CHECKED", anchor="receipt",
            cli_must_not_print="\nSIGNATURE VALID",
            note="the published 0.9.0 printed the second line of this label as a row of its own")
loud_label = copy.deepcopy(honest)
loud_label["events"][0]["event_type"] = "café \u007f °°"
bundle_case("a_label_with_del_and_non_ascii", loud_label, valid=True, verdict="NOT CHECKED", anchor="receipt")
bad_receipt = copy.deepcopy(honest)
bad_receipt["receipt"] = "not an object"
bundle_case("the_receipt_is_a_string", bad_receipt, valid=False, verdict="NOT CHECKED", anchor=None, error="receipt: it is not an object")

# the receipt token has one spelling
respelt = copy.deepcopy(honest)
respelt["receipt"]["token"] += "!"
bundle_case("the_receipt_token_with_a_character_added", respelt, valid=False, verdict="NOT CHECKED", anchor=None,
            error="not a compact JWS", note="one program used to skip the character and call it valid, the other refused")
lead = copy.deepcopy(honest)
lead["receipt"]["token"] = "\u001f" + lead["receipt"]["token"]
bundle_case("the_receipt_token_after_a_control_character", lead, valid=False, verdict="NOT CHECKED", anchor=None,
            error="not a compact JWS")
bundle_case("the_whole_bundle_is_a_list", [honest], valid=False, verdict=None, anchor=None,
            error="bundle is malformed: it is not an object")
whole_number = copy.deepcopy(honest)
whole_number["events"][0]["batch"]["merkle_index"] = float(whole_number["events"][0]["batch"]["merkle_index"])
bundle_case("an_index_written_with_a_decimal_point_is_the_same_number", whole_number, valid=True, verdict="NOT CHECKED",
            anchor="receipt", note="0.0 and 0 are one JSON number")
bundle_case("a_receipt_whose_approval_digest_is_an_empty_list",
            decision_with({"approval_method": "passkey", "approval_digest": []}, None), valid=False, verdict="INVALID",
            anchor="receipt", error="approval_digest is not 64 lowercase hex characters",
            note="present and not a digest: an error in both languages, not 'absent' in one")

# ── bundles of the wrong shape: refused, never converted ─────────────────────────────────


def misshapen(name, edit, error):
    b = copy.deepcopy(honest)
    edit(b)
    bundle_case(name, b, valid=False, verdict=None, anchor=None, error="bundle is malformed: " + error)


def _set(path, value):
    def edit(b):
        node = b
        for step in path[:-1]:
            node = node[step]
        node[path[-1]] = value
    return edit


misshapen("a_decision_id_longer_than_an_identifier", _set(["decision_id"], "d" * 129), "decision_id is longer than 128 characters")
misshapen("an_event_id_longer_than_an_identifier", _set(["events", 0, "event_id"], "e" * 129),
          "events[0].event_id is longer than 128 characters")
misshapen("a_label_longer_than_an_identifier", _set(["events", 0, "event_type"], "y" * 129),
          "events[0].event_type is longer than 128 characters")
misshapen("an_event_without_an_id", _set(["events", 0, "event_id"], None), "events[0].event_id is missing")
misshapen("events_given_as_an_object", _set(["events"], {"0": {}}), "events must be a list")
misshapen("an_event_given_as_text", _set(["events", 1], "event"), "events[1] must be an object")
misshapen("a_sequence_number_given_as_text", _set(["events", 0, "batch", "seq"], "11"), "events[0].batch.seq must be an integer")
misshapen("a_sequence_number_that_is_true", _set(["events", 0, "batch", "seq"], True), "events[0].batch.seq must be an integer")
misshapen("a_sequence_number_beyond_exact_integers", _set(["events", 0, "batch", "seq"], 2**53),
          "events[0].batch.seq must be an integer")
misshapen("a_merkle_index_with_a_fraction", _set(["events", 0, "batch", "merkle_index"], 1.5),
          "events[0].batch.merkle_index must be an integer")
misshapen("a_proof_that_is_not_a_list_of_strings", _set(["events", 0, "batch", "merkle_proof"], [1]),
          "events[0].batch.merkle_proof must be a list of strings")
misshapen("an_epoch_with_a_text_index", _set(["events", 0, "epoch"], {"leaf_index": "1"}), "events[0].epoch.leaf_index must be an integer")
misshapen("keys_given_as_a_list", _set(["keys"], []), "keys must be an object")
misshapen("a_program_id_that_is_a_number", _set(["programs", "audit_anchor"], 5), "programs.audit_anchor must be a string")
misshapen("a_version_that_is_a_number", _set(["bundle_version"], 1), "bundle_version must be a string")

# ── tokens and key sets: what the strict reader refuses ──────────────────────────────────
tokens: dict[str, dict] = {}


def token_case(name, token, jwks, *, valid, error=None, note=None):
    tokens[name] = {"token": token, "jwks": jwks, "valid": valid, "error_contains": error, "note": note}


RECEIPT_CLAIMS = {**ISSUED, "jti": "rcp_tokens", "decision_id": DEC, "agent_id": "agent_demo", "status": "success"}
honest_token = _jws(regent.rk, "rk-1", "receipt+jwt", RECEIPT_CLAIMS)
token_case("honest", honest_token, regent.receipt_jwks, valid=True)
small_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
token_case("signed_by_a_1024_bit_key", _jws(small_key, "s", "receipt+jwt", RECEIPT_CLAIMS),
           {"keys": [_jwk(small_key.public_key(), "s")]}, valid=False, error="signature does not verify",
           note="the signature is good; a key this small verifies nothing")
odd_key = rsa.generate_private_key(public_exponent=3, key_size=2048)
token_case("signed_by_a_key_with_exponent_3", _jws(odd_key, "o", "receipt+jwt", RECEIPT_CLAIMS),
           {"keys": [_jwk(odd_key.public_key(), "o")]}, valid=False, error="signature does not verify")


def raw_jws(key, header: bytes, payload: bytes) -> str:
    h, pl = b64u(header), b64u(payload)
    return f"{h}.{pl}." + b64u(key.sign(f"{h}.{pl}".encode(), padding.PKCS1v15(), hashes.SHA256()))


HEAD = json.dumps({"alg": "RS256", "kid": "rk-1", "typ": "receipt+jwt"}, separators=(",", ":")).encode()
BODY = json.dumps(RECEIPT_CLAIMS, separators=(",", ":")).encode()
token_case("kid_is_a_number", raw_jws(regent.rk, b'{"alg":"RS256","kid":5,"typ":"receipt+jwt"}', BODY), regent.receipt_jwks,
           valid=False, error="kid is not a string")
token_case("payload_with_a_byte_order_mark", raw_jws(regent.rk, HEAD, b"\xef\xbb\xbf" + BODY), regent.receipt_jwks,
           valid=False, error="starts with a byte order mark")
token_case("payload_is_a_list", raw_jws(regent.rk, HEAD, b"[" + BODY + b"]"), regent.receipt_jwks,
           valid=False, error="is not a JSON object")
token_case("payload_in_latin_1", raw_jws(regent.rk, HEAD, BODY[:-1] + b',"n":"\xe9"}'), regent.receipt_jwks,
           valid=False, error="is not UTF-8")
token_case("key_set_whose_keys_is_not_a_list", honest_token, {"keys": {"0": regent.receipt_jwks["keys"][0]}}, valid=False,
           error="no RSA key")
filler = [{"kty": "RSA", "kid": f"filler-{i}", "n": "AQAB", "e": "AQAB"} for i in range(16)]
token_case("the_right_key_is_the_17th_of_its_set", honest_token, {"keys": filler + regent.receipt_jwks["keys"]}, valid=False,
           error="no RSA key", note="a key set is read up to its 16th key")
token_case("the_right_key_is_the_16th_of_its_set", honest_token, {"keys": filler[:15] + regent.receipt_jwks["keys"]}, valid=True)
token_case("an_expiry_that_is_true_is_not_a_time", _jws(regent.rk, "rk-1", "receipt+jwt", {**RECEIPT_CLAIMS, "exp": True}),
           regent.receipt_jwks, valid=True, note="in Python true is the integer 1; in JSON it is not a number")

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bundle_vectors.json")
with open(out, "w") as f:
    json.dump({"approvals": approvals, "now": NOW, "receipt_jwks": regent.receipt_jwks,
               "checkpoint_jwks": regent.checkpoint_jwks, "bundles": bundles, "tokens": tokens},
              f, indent=1, sort_keys=True, ensure_ascii=False)
    f.write("\n")
print("wrote", out, "approvals:", len(approvals), "bundles:", len(bundles), "tokens:", len(tokens))
