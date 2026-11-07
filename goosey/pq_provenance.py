# SPDX-License-Identifier: CC0-1.0
# Contributed by Quantova Inc and dedicated to the public domain under CC0-1.0.

"""Optional post quantum provenance for collected evidence.

Signs an exported evidence file, such as a JSON artifact collected from a
tenant, with FIPS 204 ML-DSA so an investigator or a court can confirm the
evidence is authentic and has not been altered after collection, using a
signature scheme that stays safe once large quantum computers exist. This gives
the collected output a tamper evident chain of custody.

The attestation is self contained. It carries the public key and the
signature, so a verifier needs only the attestation and the evidence file.
Integrity is always covered by the file digest and authenticity is covered when
the verifier pins the expected public key.

The scheme is provided by the optional dilithium-py package. Install it with
`pip install dilithium-py`.

Command line usage:
    python -m goosey.pq_provenance keygen signer.json
    python -m goosey.pq_provenance attest signer.json evidence.json
    python -m goosey.pq_provenance verify evidence.json evidence.json.attestation.json
"""

import base64
import hashlib
import json
import sys

SCHEME = "ML-DSA-65"
ISSUER = "Quantova"


def _backend():
    """Return the ML-DSA backend or raise if dilithium-py is not installed."""
    try:
        from dilithium_py.ml_dsa import ML_DSA_65
    except ImportError as error:
        raise RuntimeError(
            "Post quantum provenance needs dilithium-py. Install it with pip install dilithium-py."
        ) from error
    return ML_DSA_65


def generate_keypair():
    """Return a fresh (public_key, secret_key) pair for the signer."""
    return _backend().keygen()


def build_attestation(payload, public_key, secret_key):
    """Return a self contained attestation over the payload bytes."""
    signature = _backend().sign(secret_key, payload, deterministic=True)
    return {
        "scheme": SCHEME,
        "issuer": ISSUER,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_attestation(payload, attestation, expected_public_key=None):
    """Return True when the attestation matches the payload.

    The file digest is always checked. When expected_public_key is given the
    signer is pinned too, so a valid signature made under a different key is
    rejected.
    """
    if attestation.get("payload_sha256") != hashlib.sha256(payload).hexdigest():
        return False
    try:
        public_key = base64.b64decode(attestation["public_key"], validate=True)
        signature = base64.b64decode(attestation["signature"], validate=True)
    except (ValueError, KeyError):
        return False
    if expected_public_key is not None and public_key != expected_public_key:
        return False
    try:
        return bool(_backend().verify(public_key, payload, signature))
    except (ValueError, TypeError):
        return False


def save_signer(path, public_key, secret_key):
    """Write a signer key file that load_signer reads back."""
    data = {
        "scheme": SCHEME,
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "secret_key": base64.b64encode(secret_key).decode("ascii"),
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)


def load_signer(path):
    """Read (public_key, secret_key) from a signer key file."""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return base64.b64decode(data["public_key"]), base64.b64decode(data["secret_key"])


def _main(argv):
    if len(argv) == 2 and argv[0] == "keygen":
        public_key, secret_key = generate_keypair()
        save_signer(argv[1], public_key, secret_key)
        print(f"wrote {SCHEME} signer to {argv[1]}")
        return 0
    if len(argv) == 3 and argv[0] == "attest":
        public_key, secret_key = load_signer(argv[1])
        with open(argv[2], "rb") as handle:
            payload = handle.read()
        attestation = build_attestation(payload, public_key, secret_key)
        out = argv[2] + ".attestation.json"
        with open(out, "w", encoding="utf-8") as handle:
            json.dump(attestation, handle, indent=2)
        print(f"wrote attestation to {out}")
        return 0
    if len(argv) == 3 and argv[0] == "verify":
        with open(argv[1], "rb") as handle:
            payload = handle.read()
        with open(argv[2], "r", encoding="utf-8") as handle:
            attestation = json.load(handle)
        ok = verify_attestation(payload, attestation)
        print("valid" if ok else "invalid")
        return 0 if ok else 1
    print("usage: python -m goosey.pq_provenance keygen <key> | attest <key> <file> | verify <file> <attestation>")
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
