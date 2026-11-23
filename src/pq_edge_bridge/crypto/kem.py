"""ML-KEM-768 (NIST FIPS 203) key encapsulation and HKDF-SHA256 key derivation."""

from __future__ import annotations

from dataclasses import dataclass

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pq_edge_bridge.exceptions import DecryptionError, KeyFormatError

KEM_ALGORITHM = "ML-KEM-768"
ML_KEM_768_PUBLIC_KEY_BYTES = 1184
ML_KEM_768_SECRET_KEY_BYTES = 2400
ML_KEM_768_CIPHERTEXT_BYTES = 1088
ML_KEM_768_SHARED_SECRET_BYTES = 32
AES_256_KEY_BYTES = 32

FULL_KEM_HKDF_INFO = b"pq-edge-bridge-v1-full-kem-aes256gcm"
SESSION_ROOT_HKDF_INFO = b"pq-edge-bridge-v1-session-root"
SESSION_MSG_HKDF_INFO = b"pq-edge-bridge-v1-session-msg"


@dataclass(frozen=True, slots=True)
class KEMKeyPair:
    """ML-KEM-768 public and secret keypair."""

    public_key: bytes
    secret_key: bytes


def generate_kem_keypair() -> KEMKeyPair:
    """Generate a fresh ML-KEM-768 keypair via liboqs."""
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    return KEMKeyPair(public_key=bytes(public_key), secret_key=bytes(secret_key))


def encapsulate(peer_public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a fresh shared secret against a peer's ML-KEM-768 public key.

    Returns:
        Tuple of ``(kem_ciphertext, shared_secret)``.
    """
    if len(peer_public_key) != ML_KEM_768_PUBLIC_KEY_BYTES:
        raise KeyFormatError(
            f"Invalid ML-KEM-768 public key length: expected {ML_KEM_768_PUBLIC_KEY_BYTES} bytes, "
            f"got {len(peer_public_key)}"
        )
    try:
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            ciphertext, shared_secret = kem.encap_secret(peer_public_key)
        return bytes(ciphertext), bytes(shared_secret)
    except Exception as exc:
        raise KeyFormatError(f"ML-KEM-768 encapsulation failed: {exc}") from exc


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate an ML-KEM-768 ciphertext using the local secret key."""
    if len(secret_key) != ML_KEM_768_SECRET_KEY_BYTES:
        raise KeyFormatError(
            f"Invalid ML-KEM-768 secret key length: expected {ML_KEM_768_SECRET_KEY_BYTES} bytes, "
            f"got {len(secret_key)}"
        )
    if len(ciphertext) != ML_KEM_768_CIPHERTEXT_BYTES:
        raise DecryptionError(
            f"Invalid ML-KEM-768 ciphertext length: expected {ML_KEM_768_CIPHERTEXT_BYTES} bytes, "
            f"got {len(ciphertext)}"
        )
    try:
        with oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key=secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return bytes(shared_secret)
    except Exception as exc:
        raise DecryptionError(f"ML-KEM-768 decapsulation failed: {exc}") from exc


def derive_aes_key(
    shared_secret: bytes,
    *,
    salt: bytes,
    info: bytes = FULL_KEM_HKDF_INFO,
) -> bytes:
    """Derive a 256-bit AES key from a shared secret using HKDF-SHA256."""
    if len(shared_secret) != ML_KEM_768_SHARED_SECRET_BYTES:
        raise DecryptionError(
            f"Invalid shared secret length: expected {ML_KEM_768_SHARED_SECRET_BYTES} bytes, "
            f"got {len(shared_secret)}"
        )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_256_KEY_BYTES,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)
