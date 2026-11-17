"""What this version says about the owner's approval behind a receipt.

A receipt names its approval by digest: `approval_digest` is the SHA-256 of the approval
evidence. When an admin of the organization asks for it, an evidence bundle carries an
`approval` block with the exact string that was hashed. This version checks ONE thing about
that block, with no call to Regent:

    sha256(evidence_canonical) == the approval_digest of a VERIFIED receipt

so the evidence in a bundle cannot be edited, swapped for other evidence or attached to
another decision without the bundle turning INVALID.

It does NOT verify the owner's signature inside the evidence, and it does not check that
the terms shown beside the evidence are the terms that were approved. Its verdict on an
approval is therefore never better than NOT CHECKED, it never returns terms, and it never
prints the words a later version uses for a verified signature. A bundle can be VALID
while its approval is NOT CHECKED: the two verdicts are separate, and both are printed.

Two rules it shares with the versions that do verify the signature:

* THE ANCHOR IS THE RECEIPT, AND ONLY THE RECEIPT. The digest an approval is compared
  with comes from the claims of a receipt whose signature verified. Nothing else in a
  bundle can name it: an event's id and type are labels beside its payload, not part of
  what is hashed into the trail. Without a verified receipt nothing is compared.
* NOTHING THE BLOCK MERELY SAYS IS REPEATED AS A FINDING. The method and the scope are
  the receipt's. Dates, the approver's id and "applied" are the organization's statements
  and are returned under `stated`.

Malformed input is an INVALID result, never an exception.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .strict import (  # noqa: F401 — Malformed and unprintable are part of this module's interface
    _HEX64,
    Malformed,
    _parse,
    _plain,
    _same,
    string_list,
    unprintable,
)

VERIFIES_SIGNATURE = False   # this version compares the evidence with the receipt's digest and nothing more
PINS_REFUSED = ("an approver key, an origin or a relying party id was required, and this version cannot require them: "
                "it does not verify the owner's signature")
ON_FILE = "on_file"
_RECORDS = ("on_file", "no_signature", "not_retained", "not_recorded", "unavailable")
MAX_CHANGES = 1000  # listed changes to one mandate


@dataclass
class SignedApproval:
    """The approval evidence a bundle carries, as far as this version looks at it."""
    label: str
    anchored: bool = False               # its bytes hash to the digest a verified receipt names
    evidence_ok: bool | None = None      # the evidence bytes hash to the digest
    signature_ok: bool | None = None     # always None: this version does not verify the owner's signature
    terms: Any = None                    # always None: no terms are returned by this version
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass
class ApprovalResult:
    """`valid` is False when the block contradicts the receipt (the bundle is then INVALID),
    and None otherwise. It is never True in this version: read `verdict`."""
    valid: bool | None = None
    consistent: bool | None = None       # always None in this version
    record: str | None = None
    method: str | None = None            # the receipt's
    scope: str | None = None             # the receipt's
    names: str | None = None             # what the receipt's approval covers, derived here
    terms: Any = None                    # always None in this version
    stated: dict[str, Any] = field(default_factory=dict)  # the organization's own statements
    signed: SignedApproval | None = None
    changes: list[SignedApproval] = field(default_factory=list)  # always empty: changes are counted, not checked
    changes_listed: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # The answer in one word and one reason, in this program's own words (see `summary`):
    # INVALID or NOT CHECKED. A bundle can be VALID while its approval is NOT CHECKED: read
    # this, not the bundle's verdict, to know what was and was not verified.
    verdict: str = "NOT CHECKED"
    why: str = ""

    def to_dict(self) -> dict[str, Any]:
        def one(s: SignedApproval | None) -> dict[str, Any] | None:
            return None if s is None else {**s.__dict__, "ok": s.ok}

        return {"verdict": self.verdict, "why": self.why,
                "valid": self.valid, "consistent": self.consistent, "record": self.record, "method": self.method, "scope": self.scope,
                "names": self.names, "terms": self.terms, "stated": self.stated, "signed": one(self.signed),
                "changes": [one(c) for c in self.changes], "changes_listed": self.changes_listed,
                "errors": self.errors, "warnings": self.warnings}


def _check_evidence(part: dict[str, Any], digest: str) -> SignedApproval:
    s = SignedApproval(label="approval")
    try:
        evidence, evidence_raw = _parse(part.get("evidence_canonical"), "evidence_canonical")
        s.evidence_ok = hashlib.sha256(evidence_raw).hexdigest() == digest
        if not s.evidence_ok:
            s.errors.append("evidence: the bytes do not hash to the digest that names them")
        if "evidence" in part and not _same(part["evidence"], evidence):
            s.errors.append("evidence: the object shown is not what the hashed bytes say")
    except Malformed as exc:
        s.errors.append(f"malformed: {exc}")
    return s


def _passkey_named(method: Any) -> bool:
    return isinstance(method, str) and "passkey" in method.split("+")


def verify_approval(approval: Any, receipt_claims: dict[str, Any] | None = None, *,
                    approver_keys: list[str] | None = None, origins: list[str] | None = None,
                    rp_ids: list[str] | None = None) -> ApprovalResult:
    """Compare a bundle's `approval` block with the claims of a VERIFIED receipt.

    `receipt_claims`: the claims of a receipt whose signature verified, or None when there
    is no such receipt (nothing is then compared). Never pass claims from anything else.
    `approver_keys`, `origins`, `rp_ids` pin the owner's key and site in versions that
    verify the owner's signature. This one does not, so passing any of them is an error:
    a requirement that cannot be enforced must not look as if it was.
    """
    res = ApprovalResult()
    try:
        _verify(res, approval, receipt_claims, {"approver_keys": approver_keys, "origins": origins, "rp_ids": rp_ids})
    except Malformed as exc:
        res.errors.append(f"approval block is malformed: {exc}")
    except Exception as exc:  # noqa: BLE001 — a verifier answers INVALID, it does not crash
        res.errors.append(f"approval block could not be read ({type(exc).__name__})")
    if res.errors:
        res.valid = False
    res.verdict, res.why = summary(res, anchored=isinstance(receipt_claims, dict))
    return res


_NOTHING = {
    "on_file": "this version does not verify it",
    "no_signature": "no signature was taken",
    "not_retained": "its evidence is not on file",
    "not_recorded": "none was recorded",
    "unavailable": "it could not be looked up",
}


def summary(res: ApprovalResult, *, anchored: bool, pinned: bool = True, bundle_valid: bool = True) -> tuple[str, str]:
    """(verdict, why): the approval in one word and one short reason, in this program's own
    words. `anchored`: a receipt valid in full names this decision. `pinned`: that receipt
    was checked with a key the reader supplied, not one the bundle brought. Nothing a
    bundle says is repeated in either string, and both fit one line of output."""
    del bundle_valid   # read by builds that can say SIGNATURE VALID; this one never does
    if res.valid is False:
        return "INVALID", "a check failed, see the errors"
    if res.record is None:
        return "NOT CHECKED", "the bundle does not carry it"
    if not anchored:
        return "NOT CHECKED", "no verified receipt for this decision"
    if not pinned:
        return "NOT CHECKED", "the receipt key came from the bundle"
    return "NOT CHECKED", _NOTHING.get(res.record, "nothing to verify")


def _yn(v: bool | None) -> str:
    return "?" if v is None else ("yes" if v else "NO")


def lines(res: ApprovalResult, *, anchored: bool, pinned: bool = True) -> list[str]:
    """The approval as indented lines of text for a person. The caller escapes and wraps
    them: values a bundle supplied are inside."""
    if res.record is None:
        return []
    said = ("no verified receipt for this decision" if not anchored
            else (res.method or "an approval, method not named") if (res.method or res.names) else "no approval")
    out = [f"  approval: {'INVALID' if res.valid is False else 'NOT CHECKED'} (record {res.record}; the receipt says: {said}"
           + (f", covering {res.names}" if res.names else "") + ")"]
    if res.signed is not None:
        out.append(f"        evidence: {'named by the receipt' if res.signed.anchored else 'NOT named by the receipt'}, "
                   f"bytes match its digest: {_yn(res.signed.evidence_ok)}")
        if res.signed.anchored and not pinned:
            out.append("        that receipt was checked with the key inside the bundle")
        out.append("        owner's signature: NOT CHECKED; terms: NOT CHECKED")
    if res.changes_listed:
        out.append(f"        listed changes to the mandate: {res.changes_listed}, NOT CHECKED")
    if res.stated:
        out.append("        stated by the organization, not verified: "
                   + ", ".join(f"{k}={v}" for k, v in sorted(res.stated.items())))
    return out


def _verify(res: ApprovalResult, approval: Any, claims: dict[str, Any] | None, opts: dict[str, Any]) -> None:
    for name in ("approver_keys", "origins", "rp_ids"):
        opts[name] = string_list(opts.get(name), name)
    if any(opts[name] is not None for name in ("approver_keys", "origins", "rp_ids")):
        res.errors.append(PINS_REFUSED)
    verified = isinstance(claims, dict)
    claims = claims if verified else {}
    named = claims.get("approval_digest")
    if named is not None and not (isinstance(named, str) and _HEX64.fullmatch(named)):
        raise Malformed("the receipt's approval_digest is not 64 lowercase hex characters")
    res.method = _plain(claims.get("approval_method"), 40)
    res.scope = _plain(claims.get("approval_scope"), 40)
    if named or res.method:
        # a receipt that names no scope names a mandate approval: one approval then stands
        # behind every purchase made under that mandate
        res.names = "this purchase" if res.scope == "purchase" else "the creation of the mandate"

    if approval is None:
        if named:
            res.warnings.append("the receipt names an approval by digest, but the bundle does not carry it; "
                                "ask the organization for a bundle with the approval revealed")
        return
    if not isinstance(approval, dict):
        raise Malformed("it is not an object")
    record = approval.get("record")
    res.record = record if record in _RECORDS else "unknown"
    res.stated = {k: _plain(approval.get(k)) for k in ("approved_at", "applied_at", "approver", "kind", "subject_ref")
                  if _plain(approval.get(k)) is not None}

    if not verified:
        res.warnings.append("there is no verified receipt, so the approval in the bundle cannot be tied to this "
                            "decision and was not checked")
        return

    stated_digest = approval.get("evidence_digest")
    block_scope = approval.get("scope")
    receipt_scope = "purchase" if res.scope == "purchase" else "mandate"
    if (named or res.method) and isinstance(block_scope, str) and block_scope != receipt_scope:
        res.errors.append(f"the receipt says the approval covers the {receipt_scope}, the bundle says otherwise")
    block_method = approval.get("method")
    if res.method and isinstance(block_method, str) and block_method != res.method:
        res.errors.append(f"the receipt says the approval was by {res.method}, the bundle says otherwise")

    if record == ON_FILE:
        if not named:
            res.errors.append("nothing anchored names this approval: the receipt carries no approval digest")
            return
        if stated_digest != named:
            res.errors.append("the approval in the bundle is not the one the receipt names (digests differ)")
        res.signed = _check_evidence(approval, named)
        res.signed.anchored = res.signed.evidence_ok is True  # named by the receipt only if its bytes hash to the digest
        res.errors.extend(f"approval: {e}" for e in res.signed.errors)
        if not res.signed.errors:
            res.warnings.append("the approval evidence in the bundle is the one the receipt names; this version does "
                                "not verify the owner's signature inside it, and the terms shown beside it are "
                                "covered by nothing it checks")
    elif record == "no_signature":
        if named:
            res.errors.append("the receipt names an approval by digest; the bundle says no signature was taken")
        elif not res.method:
            res.warnings.append("the bundle states an approval the receipt does not name; it is not repeated here")
        elif _passkey_named(res.method):
            res.warnings.append("the receipt says a passkey approved this and names no digest of it (approvals recorded "
                                "before digests were kept): there is nothing to verify")
        else:
            res.warnings.append(f"approved without a passkey ({res.method}): there is no signature to verify")
    elif record == "not_retained":
        if not named:
            res.errors.append("the bundle says the evidence was not kept, but the receipt names no approval digest")
        elif stated_digest != named:
            res.errors.append("the approval in the bundle is not the one the receipt names (digests differ)")
        else:
            res.warnings.append("the receipt names an approval whose evidence is not on file; it cannot be verified")
    elif record == "not_recorded":
        if named or res.method:
            res.errors.append("the receipt names an approval; the bundle says none was recorded")
        else:
            res.warnings.append("the receipt names no approval, and the bundle says none was recorded")
    elif record == "unavailable":
        res.warnings.append("the approval could not be looked up when the bundle was built; ask for the bundle again")
    else:
        res.errors.append("unknown approval record state")

    changes = approval.get("changes")
    if changes is None:
        changes = []
    if not isinstance(changes, list):
        raise Malformed("changes is not a list")
    if len(changes) > MAX_CHANGES:
        raise Malformed(f"more than {MAX_CHANGES} changes")
    res.changes_listed = len(changes)
    if changes:
        res.warnings.append(f"the bundle lists {len(changes)} change(s) to the mandate; this version does not check "
                            "them, and the list itself (complete or not, applied or not) is the organization's statement")
