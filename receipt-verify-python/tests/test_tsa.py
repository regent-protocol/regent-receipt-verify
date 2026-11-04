"""RFC 3161 tokens: the real public TSAs (fixtures), then a TSA of our own making so the
failure cases a bank's checklist names (expired certificate, altered content, forged
signature, wrong purpose, untrusted root) are exercised deterministically."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from asn1crypto import algos, cms, core, tsp, x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from regent_receipt_verify.bundle import norm_hex, verify_bundle
from regent_receipt_verify.tsa import default_roots, load_roots, verify_token

HERE = os.path.dirname(__file__)
TEST_DIGEST = hashlib.sha256(b"regent epoch test").digest()
UTC = timezone.utc


def _token_from_response(path: str) -> bytes:
    seq = core.Sequence.load(open(path, "rb").read())
    return seq[1].dump()


@pytest.mark.parametrize("name,signer,root", [
    ("digicert-regent-epoch-test.tsr", "DigiCert", "DigiCert Trusted Root G4"),
    ("sectigo-regent-epoch-test.tsr", "Sectigo", "USERTrust RSA Certification Authority"),
])
def test_real_public_tsa_tokens_verify_against_the_shipped_roots(name, signer, root):
    tok = _token_from_response(os.path.join(HERE, "fixtures", name))
    r = verify_token(tok, TEST_DIGEST)
    assert r.ok, r.errors
    assert r.digest_ok and r.signature_ok and r.chain_ok and r.valid_at_gen_time
    assert signer in (r.signer or "") and r.root == root
    assert r.gen_time is not None and r.gen_time.year >= 2026
    assert json.dumps(r.to_dict())  # serialisable for --json


def test_the_wrong_digest_or_a_flipped_signature_byte_fails():
    tok = _token_from_response(os.path.join(HERE, "fixtures", "digicert-regent-epoch-test.tsr"))
    r = verify_token(tok, hashlib.sha256(b"some other root").digest())
    assert not r.ok and r.digest_ok is False and any("messageImprint" in e for e in r.errors)
    # the signature is the last big OCTET STRING in the token: corrupt one byte of it
    si = cms.ContentInfo.load(tok)["content"]["signer_infos"][0]
    sig = si["signature"].native
    bad = tok.replace(sig, sig[:-1] + bytes([sig[-1] ^ 0x01]), 1)
    r = verify_token(bad, TEST_DIGEST)
    assert not r.ok and r.signature_ok is False and any("does not verify" in e for e in r.errors)


def test_no_roots_means_chain_not_checked_and_not_ok():
    tok = _token_from_response(os.path.join(HERE, "fixtures", "sectigo-regent-epoch-test.tsr"))
    r = verify_token(tok, TEST_DIGEST, roots=[])
    assert not r.ok and r.signature_ok and r.chain_ok is None and any("not checked" in e for e in r.errors)
    assert len(default_roots()) == 2


# ── a TSA of our own, for the deterministic failure cases ──────────────────────

def _cert(subject: str, issuer_name: x509.Name | None, issuer_key, key, not_before: datetime, not_after: datetime, *,
          ca: bool, tsa_eku: bool):  # noqa: ANN001, ANN202
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject)])
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name or name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(not_before).not_valid_after(not_after)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if tsa_eku:
        b = b.add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
    elif not ca:
        b = b.add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CODE_SIGNING]), critical=True)
    return b.sign(issuer_key or key, hashes.SHA256())


def make_tsa(leaf_valid: tuple[datetime, datetime], *, tsa_eku: bool = True):  # noqa: ANN202
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = _cert("Test TSA Root", None, None, root_key, datetime(2020, 1, 1, tzinfo=UTC), datetime(2040, 1, 1, tzinfo=UTC),
                 ca=True, tsa_eku=False)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = _cert("Test TSA Signer", root.subject, root_key, leaf_key, leaf_valid[0], leaf_valid[1], ca=False, tsa_eku=tsa_eku)
    return root, leaf, leaf_key


def make_token(leaf, leaf_key, digest: bytes, gen_time: datetime, *, include_root=None) -> bytes:  # noqa: ANN001
    info = tsp.TSTInfo({
        "version": "v1", "policy": "1.3.6.1.4.1.99999.1",
        "message_imprint": tsp.MessageImprint({"hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
                                               "hashed_message": digest}),
        "serial_number": 7, "gen_time": gen_time,
    })
    content = info.dump()
    leaf_a = ax509.Certificate.load(leaf.public_bytes(serialization.Encoding.DER))
    attrs = cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
        cms.CMSAttribute({"type": "message_digest", "values": [hashlib.sha256(content).digest()]}),
    ])
    signature = leaf_key.sign(attrs.dump(), padding.PKCS1v15(), hashes.SHA256())  # CMSAttributes dumps as a SET
    certs = [leaf_a] + ([ax509.Certificate.load(include_root.public_bytes(serialization.Encoding.DER))] if include_root else [])
    si = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber({
            "issuer": leaf_a.issuer, "serial_number": leaf_a.serial_number})}),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "rsassa_pkcs1v15"}),
        "signature": signature,
    })
    sd = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        "encap_content_info": cms.EncapsulatedContentInfo({"content_type": "tst_info", "content": core.ParsableOctetString(content)}),
        "certificates": certs,
        "signer_infos": [si],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": sd}).dump()


GEN = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)


def test_our_own_tsa_verifies_only_against_its_own_root():
    root, leaf, key = make_tsa((GEN - timedelta(days=30), GEN + timedelta(days=365)))
    tok = make_token(leaf, key, TEST_DIGEST, GEN)
    good = verify_token(tok, TEST_DIGEST, roots=[root])
    assert good.ok and good.root == "Test TSA Root" and good.signer == "Test TSA Signer" and good.gen_time == GEN
    untrusted = verify_token(tok, TEST_DIGEST)  # the shipped roots do not know this TSA
    assert not untrusted.ok and untrusted.chain_ok is False and any("trusted root" in e for e in untrusted.errors)
    assert load_roots(root.public_bytes(serialization.Encoding.PEM))[0] == root


def test_an_expired_certificate_at_the_certified_time_fails():
    root, leaf, key = make_tsa((datetime(2021, 1, 1, tzinfo=UTC), datetime(2022, 1, 1, tzinfo=UTC)))
    tok = make_token(leaf, key, TEST_DIGEST, GEN)
    r = verify_token(tok, TEST_DIGEST, roots=[root])
    assert not r.ok and r.signature_ok and r.chain_ok and r.valid_at_gen_time is False
    assert any("not valid at the time" in e for e in r.errors)


def test_altered_content_and_wrong_purpose_fail():
    root, leaf, key = make_tsa((GEN - timedelta(days=1), GEN + timedelta(days=1)))
    tok = make_token(leaf, key, TEST_DIGEST, GEN)
    # move genTime inside the signed TSTInfo: message-digest no longer matches
    tampered = tok.replace(b"20261104120000Z", b"20261004120000Z", 1)
    r = verify_token(tampered, TEST_DIGEST, roots=[root])
    assert not r.ok and r.signature_ok is False and any("content altered" in e for e in r.errors)
    root2, leaf2, key2 = make_tsa((GEN - timedelta(days=1), GEN + timedelta(days=1)), tsa_eku=False)
    r2 = verify_token(make_token(leaf2, key2, TEST_DIGEST, GEN), TEST_DIGEST, roots=[root2])
    assert not r2.ok and any("timeStamping EKU" in e for e in r2.errors)


# ── inside a bundle ────────────────────────────────────────────────────────────

V = json.load(open(os.path.join(HERE, "..", "..", "receipt-verify-vectors", "vectors.json")))


def _epoch_bundle():  # noqa: ANN202
    cases = V["bundle"]["cases"]
    name = next(n for n, c in cases.items() if c["valid"] and any(e.get("epoch") for e in c["bundle"]["events"]))
    return copy.deepcopy(cases[name]["bundle"])


def test_bundle_reports_the_rfc3161_clock_and_rejects_a_bad_token():
    b = _epoch_bundle()
    ep = next(e["epoch"] for e in b["events"] if e.get("epoch"))
    root, leaf, key = make_tsa((GEN - timedelta(days=1), GEN + timedelta(days=1)))
    tok = make_token(leaf, key, bytes.fromhex(norm_hex(ep["root"])), GEN)
    import base64
    ep.update({"tsa_status": "complete", "tsa_token_b64": base64.b64encode(tok).decode(),
               "tsa_url": "http://tsa.test", "tsa_time": "2026-11-04T12:00:00Z"})
    res = verify_bundle(b, tsa_roots=[root])
    assert res.valid, res.errors
    ev = next(e for e in res.events if e.tsa_ok is not None)
    assert ev.tsa_ok and ev.tsa_time == "2026-11-04T12:00:00Z" and ev.tsa_signer == "Test TSA Signer"
    assert json.dumps(res.to_dict())
    # a token over another root is not evidence for this epoch
    ep["tsa_token_b64"] = base64.b64encode(make_token(leaf, key, hashlib.sha256(b"other").digest(), GEN)).decode()
    res = verify_bundle(b, tsa_roots=[root])
    assert not res.valid and any("rfc3161" in e for e in res.errors)
    # without the token nothing is claimed and nothing fails
    for k in ("tsa_token_b64", "tsa_status", "tsa_url", "tsa_time"):
        ep.pop(k, None)
    res = verify_bundle(b)
    assert res.valid and all(e.tsa_ok is None for e in res.events)
