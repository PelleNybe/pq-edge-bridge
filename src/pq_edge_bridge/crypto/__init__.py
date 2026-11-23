"""Post-quantum cryptographic primitives, envelopes, sessions, and key management."""

from __future__ import annotations

from pq_edge_bridge.crypto.envelope import (
    FLAG_FULL_KEM,
    FLAG_SESSION,
    MAGIC,
    PROTOCOL_VERSION,
    DecryptedEnvelope,
    EnvelopeHeader,
    ReplayProtector,
    pack_envelope,
    parse_envelope_header,
    unpack_and_decrypt,
    verify_envelope,
)
from pq_edge_bridge.crypto.kem import (
    KEM_ALGORITHM,
    KEMKeyPair,
    decapsulate,
    derive_aes_key,
    encapsulate,
    generate_kem_keypair,
)
from pq_edge_bridge.crypto.keys import (
    generate_node_keypairs,
    load_key_bytes,
    write_public_key_atomic,
    write_secret_key_atomic,
)
from pq_edge_bridge.crypto.session import OutboundKeyMaterial, SessionManager
from pq_edge_bridge.crypto.signer import (
    SIG_ALGORITHM,
    SigningKeyPair,
    generate_signing_keypair,
    sign_message,
    verify_signature,
)

__all__ = [
    "FLAG_FULL_KEM",
    "FLAG_SESSION",
    "KEM_ALGORITHM",
    "MAGIC",
    "PROTOCOL_VERSION",
    "SIG_ALGORITHM",
    "DecryptedEnvelope",
    "EnvelopeHeader",
    "KEMKeyPair",
    "OutboundKeyMaterial",
    "ReplayProtector",
    "SessionManager",
    "SigningKeyPair",
    "decapsulate",
    "derive_aes_key",
    "encapsulate",
    "generate_kem_keypair",
    "generate_node_keypairs",
    "generate_signing_keypair",
    "load_key_bytes",
    "pack_envelope",
    "parse_envelope_header",
    "sign_message",
    "unpack_and_decrypt",
    "verify_envelope",
    "verify_signature",
    "write_public_key_atomic",
    "write_secret_key_atomic",
]
