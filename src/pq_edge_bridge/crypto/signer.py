"""ML-DSA-65 (NIST FIPS 204) digital signing and verification."""

from __future__ import annotations

from dataclasses import dataclass

import oqs

from pq_edge_bridge.exceptions import KeyFormatError, SignatureVerificationError

SIG_ALGORITHM = "ML-DSA-65"
ML_DSA_65_PUBLIC_KEY_BYTES = 1952
ML_DSA_65_SECRET_KEY_BYTES = 4032
ML_DSA_65_SIGNATURE_BYTES = 3309


@dataclass(frozen=True, slots=True)
class SigningKeyPair:
    """ML-DSA-65 public and secret keypair."""

    public_key: bytes
    secret_key: bytes


def generate_signing_keypair() -> SigningKeyPair:
    """Generate a fresh ML-DSA-65 signing keypair via liboqs."""
    with oqs.Signature(SIG_ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    return SigningKeyPair(public_key=bytes(public_key), secret_key=bytes(secret_key))


def sign_message(secret_key: bytes, message: bytes) -> bytes:
    """Sign ``message`` with an ML-DSA-65 secret key."""
    if len(secret_key) != ML_DSA_65_SECRET_KEY_BYTES:
        raise KeyFormatError(
            f"Invalid ML-DSA-65 secret key length: expected {ML_DSA_65_SECRET_KEY_BYTES} bytes, "
            f"got {len(secret_key)}"
        )
    try:
        with oqs.Signature(SIG_ALGORITHM, secret_key=secret_key) as signer:
            signature = signer.sign(message)
        return bytes(signature)
    except Exception as exc:
        raise KeyFormatError(f"ML-DSA-65 signing failed: {exc}") from exc


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> None:
    """Verify an ML-DSA-65 signature; raises ``SignatureVerificationError`` on failure."""
    if len(public_key) != ML_DSA_65_PUBLIC_KEY_BYTES:
        raise KeyFormatError(
            f"Invalid ML-DSA-65 public key length: expected {ML_DSA_65_PUBLIC_KEY_BYTES} bytes, "
            f"got {len(public_key)}"
        )
    if not signature:
        raise SignatureVerificationError("Empty ML-DSA-65 signature")
    try:
        with oqs.Signature(SIG_ALGORITHM) as verifier:
            is_valid = verifier.verify(message, signature, public_key)
    except Exception as exc:
        raise SignatureVerificationError(f"ML-DSA-65 verification error: {exc}") from exc
    if not is_valid:
        raise SignatureVerificationError("ML-DSA-65 signature verification failed")
