"""Typed exception hierarchy for pq-edge-bridge."""

from __future__ import annotations


class PQBridgeError(Exception):
    """Base exception for all pq-edge-bridge errors."""


class ConfigurationError(PQBridgeError):
    """Raised when configuration loading or validation fails."""


class CryptoError(PQBridgeError):
    """Base exception for cryptographic operations."""


class KeyFormatError(CryptoError):
    """Raised when a key file or key material is invalid or malformed."""


class SignatureVerificationError(CryptoError):
    """Raised when ML-DSA-65 signature verification fails."""


class DecryptionError(CryptoError):
    """Raised when ML-KEM-768 decapsulation or AES-256-GCM decryption fails."""


class EnvelopeFormatError(CryptoError):
    """Raised when a PQC wire envelope is truncated, malformed, or unsupported."""


class ReplayError(CryptoError):
    """Raised when an envelope fails timestamp freshness or sequence replay checks."""


class SessionError(CryptoError):
    """Raised when session establishment, lookup, or rotation fails."""


class StorageError(PQBridgeError):
    """Raised when the SQLite store-and-forward buffer encounters an error."""


class BufferFullError(StorageError):
    """Raised when the store-and-forward buffer is full under reject_new policy."""


class TransportError(PQBridgeError):
    """Raised when a transport adapter fails to connect, publish, or subscribe."""
