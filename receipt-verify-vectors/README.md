# Test vectors

`vectors.json` is minted by Regent's real token issuer (`make_vectors.py` runs inside the
Regent control-plane codebase, which is not in this repository). It carries a JWKS, a second
JWKS that must NOT verify, an allow token and a receipt with mandate and policy commitments, the
owner's reveals, and the expected outcome of every check. Both packages run every case.
