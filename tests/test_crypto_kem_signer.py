"""Unit tests for ML-KEM-768, HKDF-SHA256, and ML-DSA-65 primitives."""

from __future__ import annotations

import pytest

from pq_edge_bridge.crypto.kem import (
    ML_KEM_768_CIPHERTEXT_BYTES,
    ML_KEM_768_PUBLIC_KEY_BYTES,
    ML_KEM_768_SECRET_KEY_BYTES,
    ML_KEM_768_SHARED_SECRET_BYTES,
    decapsulate,
    derive_aes_key,
    encapsulate,
    generate_kem_keypair,
)
from pq_edge_bridge.crypto.signer import (
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SECRET_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
    generate_signing_keypair,
    sign_message,
    verify_signature,
)
from pq_edge_bridge.exceptions import DecryptionError, KeyFormatError, SignatureVerificationError


def test_ml_kem_768_round_trip_and_hkdf() -> None:
    kp = generate_kem_keypair()
    assert len(kp.public_key) == ML_KEM_768_PUBLIC_KEY_BYTES
    assert len(kp.secret_key) == ML_KEM_768_SECRET_KEY_BYTES

    ct, ss_enc = encapsulate(kp.public_key)
    assert len(ct) == ML_KEM_768_CIPHERTEXT_BYTES
    assert len(ss_enc) == ML_KEM_768_SHARED_SECRET_BYTES

    ss_dec = decapsulate(kp.secret_key, ct)
    assert ss_dec == ss_enc

    key1 = derive_aes_key(ss_enc, salt=b"node-01\x00\x00\x00\x00\x00\x00\x00\x01")
    key2 = derive_aes_key(ss_dec, salt=b"node-01\x00\x00\x00\x00\x00\x00\x00\x01")
    key3 = derive_aes_key(ss_dec, salt=b"node-01\x00\x00\x00\x00\x00\x00\x00\x02")
    assert len(key1) == 32
    assert key1 == key2
    assert key1 != key3


def test_ml_kem_768_wrong_key_implicit_rejection() -> None:
    kp1 = generate_kem_keypair()
    kp2 = generate_kem_keypair()
    ct, ss_enc = encapsulate(kp1.public_key)
    ss_wrong = decapsulate(kp2.secret_key, ct)
    assert ss_wrong != ss_enc


def test_ml_kem_768_invalid_lengths() -> None:
    kp = generate_kem_keypair()
    with pytest.raises(KeyFormatError):
        encapsulate(b"short")
    with pytest.raises(KeyFormatError):
        decapsulate(b"short", b"\x00" * ML_KEM_768_CIPHERTEXT_BYTES)
    with pytest.raises(DecryptionError):
        decapsulate(kp.secret_key, b"short")


def test_ml_dsa_65_sign_verify_and_tamper() -> None:
    kp = generate_signing_keypair()
    assert len(kp.public_key) == ML_DSA_65_PUBLIC_KEY_BYTES
    assert len(kp.secret_key) == ML_DSA_65_SECRET_KEY_BYTES

    msg = b'{"imu":{"ax":0.01,"ay":-0.02,"az":9.81}}'
    sig = sign_message(kp.secret_key, msg)
    assert len(sig) <= ML_DSA_65_SIGNATURE_BYTES

    verify_signature(kp.public_key, msg, sig)

    with pytest.raises(SignatureVerificationError):
        verify_signature(kp.public_key, msg + b" ", sig)

    tampered_sig = bytearray(sig)
    tampered_sig[10] ^= 0xFF
    with pytest.raises(SignatureVerificationError):
        verify_signature(kp.public_key, msg, bytes(tampered_sig))

    other_kp = generate_signing_keypair()
    with pytest.raises(SignatureVerificationError):
        verify_signature(other_kp.public_key, msg, sig)
