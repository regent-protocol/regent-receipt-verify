"""RFC 3161 time-stamp tokens on epochs, verified offline.

An evidence bundle's epoch may carry `tsa_token_b64`: a TimeStampToken a public Time
Stamping Authority (DigiCert, Sectigo) signed over the epoch root at seal time. It says
"this exact 32-byte root existed no later than genTime", on the TSA's clock and signature,
with nothing of Regent's in the loop. This module checks that claim the way a PDF reader
checks a document timestamp:

  1. the token is CMS SignedData over a TSTInfo;
  2. TSTInfo.messageImprint is SHA-256 of nothing else than the epoch root we were given;
  3. the signer's signed attributes name that TSTInfo (message-digest) and the signature
     over them verifies with the certificate the token carries;
  4. that certificate is a time-stamping certificate, valid at genTime, and chains to a
     root the caller trusts (by default the Mozilla-store roots of the two TSAs we use,
     shipped in tsa_roots.pem; pass your own to trust something else).

Two dependencies do the work: asn1crypto reads the CMS structures (the large public TSAs
emit certificate SETs a strict DER parser rejects), cryptography checks the signatures.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from importlib import resources
from typing import Any

from asn1crypto import cms, tsp, x509 as ax509
from cryptography import x509

# Importing asn1crypto.tsp registers the TSTInfo content type with cms; without it the
# OID stays a bare string and the token reads as "not a TSTInfo".
_TST_INFO = {"tst_info", tsp.TSTInfo and "1.2.840.113549.1.9.16.1.4"}
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

_HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
_HASHLIB = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}
_RSA_ALGS = {"rsassa_pkcs1v15", "sha256_rsa", "sha384_rsa", "sha512_rsa"}
_EC_ALGS = {"ecdsa", "sha256_ecdsa", "sha384_ecdsa", "sha512_ecdsa"}


@dataclass
class TsaResult:
    ok: bool = False
    digest_ok: bool | None = None
    signature_ok: bool | None = None
    chain_ok: bool | None = None
    valid_at_gen_time: bool | None = None
    gen_time: datetime | None = None
    signer: str | None = None
    root: str | None = None
    policy: str | None = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["gen_time"] = self.gen_time.isoformat().replace("+00:00", "Z") if self.gen_time else None
        return d


def default_roots() -> list[x509.Certificate]:
    """The TSA roots shipped with the package (DigiCert Trusted Root G4, USERTrust RSA)."""
    pem = resources.files(__package__).joinpath("tsa_roots.pem").read_bytes()
    return x509.load_pem_x509_certificates(pem)


def load_roots(pem: bytes) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(pem)


def _cn(name: x509.Name) -> str:
    cns = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(cns[0].value) if cns else name.rfc4514_string()


def _verify_sig(pub: Any, sig: bytes, data: bytes, alg: str, hash_name: str) -> bool:
    h = _HASHES.get(hash_name)
    if h is None:
        return False
    try:
        if isinstance(pub, rsa.RSAPublicKey) and alg in _RSA_ALGS:
            pub.verify(sig, data, padding.PKCS1v15(), h())
        elif isinstance(pub, ec.EllipticCurvePublicKey) and alg in _EC_ALGS:
            pub.verify(sig, data, ec.ECDSA(h()))
        else:
            return False
        return True
    except InvalidSignature:
        return False


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    if cert.issuer != issuer.subject:
        return False
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except Exception:  # noqa: BLE001 — wrong key, wrong algorithm, bad signature: all "no"
        return False


def verify_token(token: bytes, expected_digest: bytes, roots: list[x509.Certificate] | None = None) -> TsaResult:
    """`token` is the DER TimeStampToken; `expected_digest` the 32 raw bytes of the epoch
    root; `roots` the certificates to trust (None = the packaged TSA roots; an empty list
    = do not check the chain, which leaves the result not ok)."""
    res = TsaResult()
    try:
        ci = cms.ContentInfo.load(token)
        if ci["content_type"].native != "signed_data":
            res.errors.append("token is not CMS SignedData")
            return res
        sd = ci["content"]
        eci = sd["encap_content_info"]
        if eci["content_type"].native not in _TST_INFO:
            res.errors.append("SignedData does not carry a TSTInfo")
            return res
        content = eci["content"].contents  # the TSTInfo DER, what message-digest covers
        info = tsp.TSTInfo.load(content)
        res.gen_time = info["gen_time"].native
        res.policy = info["policy"].native
        imprint = info["message_imprint"]
    except Exception as exc:  # noqa: BLE001
        res.errors.append(f"unreadable token: {exc}")
        return res

    # 2. the digest
    res.digest_ok = (imprint["hash_algorithm"]["algorithm"].native == "sha256"
                     and imprint["hashed_message"].native == expected_digest)
    if not res.digest_ok:
        res.errors.append("token does not name this epoch root (messageImprint differs)")

    # 3. the signature
    try:
        si = sd["signer_infos"][0]
        hash_name = si["digest_algorithm"]["algorithm"].native
        sig_alg = si["signature_algorithm"]["algorithm"].native
        attrs = si["signed_attrs"]
        by_type = {a["type"].native: a["values"] for a in attrs}
        if by_type.get("content_type") is None or by_type["content_type"][0].native not in _TST_INFO:
            raise ValueError("signed content-type is not TSTInfo")
        md = by_type["message_digest"][0].native
        if md != _HASHLIB[hash_name](content).digest():
            raise ValueError("signed message-digest does not match the TSTInfo (content altered)")
        signer_cert = _find_signer(sd, si)
        if signer_cert is None:
            raise ValueError("signer certificate not in the token")
        leaf = x509.load_der_x509_certificate(signer_cert.dump())
        res.signer = _cn(leaf.subject)
        signed_bytes = b"\x31" + attrs.dump()[1:]  # the [0] IMPLICIT tag is signed as a SET
        if not _verify_sig(leaf.public_key(), si["signature"].native, signed_bytes, sig_alg, hash_name):
            raise ValueError("signature does not verify with the signer certificate")
        res.signature_ok = True
    except (ValueError, KeyError, IndexError) as exc:
        res.signature_ok = False
        res.errors.append(f"signature: {exc}")
        return res
    except Exception as exc:  # noqa: BLE001
        res.signature_ok = False
        res.errors.append(f"signature unreadable: {exc}")
        return res

    # 4. the certificate: purpose, validity at genTime, chain to a trusted root
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        has_tsa = x509.ExtendedKeyUsageOID.TIME_STAMPING in eku
    except x509.ExtensionNotFound:
        has_tsa = False
    if not has_tsa:
        res.errors.append("signer certificate is not a time-stamping certificate (no timeStamping EKU)")
    included = [x509.load_der_x509_certificate(c.chosen.dump()) for c in (sd["certificates"] or [])]
    trusted = default_roots() if roots is None else list(roots)
    chain: list[x509.Certificate] = [leaf]
    current = leaf
    res.chain_ok = None if not trusted else False
    for _ in range(6):
        anchor = next((r for r in trusted if _issued_by(current, r)), None)
        if anchor is not None:
            res.chain_ok = True
            res.root = _cn(anchor.subject)
            break
        parent = next((c for c in included if c is not current and c.subject != current.subject and _issued_by(current, c)), None)
        if parent is None:
            break
        chain.append(parent)
        current = parent
    if res.chain_ok is False:
        res.errors.append("no path from the signer certificate to a trusted root")
    elif res.chain_ok is None:
        res.errors.append("certificate chain not checked (no trusted roots given)")
    gt = res.gen_time
    res.valid_at_gen_time = all(c.not_valid_before_utc <= gt <= c.not_valid_after_utc for c in chain) if gt else False
    if not res.valid_at_gen_time:
        res.errors.append("a certificate in the chain was not valid at the time the token certifies")
    res.ok = bool(res.digest_ok and res.signature_ok and res.chain_ok and res.valid_at_gen_time and has_tsa)
    return res


def _find_signer(sd: cms.SignedData, si: cms.SignerInfo) -> ax509.Certificate | None:
    sid = si["sid"]
    for c in sd["certificates"] or []:
        cert = c.chosen
        if sid.name == "issuer_and_serial_number":
            if cert.serial_number == sid.chosen["serial_number"].native and cert.issuer == sid.chosen["issuer"]:
                return cert
        elif sid.name == "subject_key_identifier" and cert.key_identifier == sid.native:
            return cert
    return None
