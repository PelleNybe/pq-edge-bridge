"""Session key caching and automatic rotation for edge-optimized PQC telemetry."""

from __future__ import annotations

import os
import struct
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from pq_edge_bridge.crypto.kem import (
    SESSION_MSG_HKDF_INFO,
    SESSION_ROOT_HKDF_INFO,
    decapsulate,
    derive_aes_key,
    encapsulate,
)
from pq_edge_bridge.exceptions import SessionError


@dataclass(frozen=True, slots=True)
class OutboundKeyMaterial:
    """Per-message key material produced by the outbound session state machine."""

    session_id: bytes
    sequence: int
    msg_key: bytes
    nonce: bytes
    kem_ciphertext: bytes  # Non-empty on session establishment/rotation, b"" otherwise
    rotated: bool


@dataclass(slots=True)
class _InboundSessionEntry:
    root_key: bytes
    created_at: float


class SessionManager:
    """Thread-safe session key manager with time- and message-count-based rotation."""

    def __init__(
        self,
        *,
        max_messages: int = 1000,
        max_age_seconds: float = 600.0,
        max_cached_sessions: int = 256,
        inbound_ttl_seconds: float | None = None,
    ) -> None:
        if max_messages < 1:
            raise ValueError("max_messages must be >= 1")
        if max_age_seconds <= 0.0:
            raise ValueError("max_age_seconds must be > 0")
        if max_cached_sessions < 1:
            raise ValueError("max_cached_sessions must be >= 1")

        self._max_messages = max_messages
        self._max_age_seconds = max_age_seconds
        self._max_cached_sessions = max_cached_sessions
        # Allow a generous grace window on the receiver for rotation boundaries / clock drift
        self._inbound_ttl_seconds = (
            inbound_ttl_seconds if inbound_ttl_seconds is not None else max_age_seconds * 2.0
        )

        self._lock = threading.Lock()
        self._sequence: int = 0
        self._session_id: bytes | None = None
        self._root_key: bytes | None = None
        self._nonce_prefix: bytes = b""
        self._session_created_at: float = 0.0
        self._session_msg_count: int = 0
        self._rotation_count: int = 0
        self._inbound_cache: OrderedDict[tuple[str, bytes], _InboundSessionEntry] = OrderedDict()

    @property
    def rotation_count(self) -> int:
        """Total number of outbound session key rotations performed."""
        with self._lock:
            return self._rotation_count

    @property
    def current_session_id(self) -> bytes | None:
        """Currently active outbound session ID, or None if uninitialized."""
        with self._lock:
            return self._session_id

    @property
    def current_message_count(self) -> int:
        """Number of messages encrypted under the current outbound session."""
        with self._lock:
            return self._session_msg_count

    def force_rotate(self) -> None:
        """Invalidate the active outbound session so the next message triggers a fresh KEM."""
        with self._lock:
            self._session_id = None
            self._root_key = None
            self._nonce_prefix = b""
            self._session_msg_count = 0

    def next_outbound_key(
        self,
        peer_kem_public_key: bytes,
        *,
        now: float | None = None,
    ) -> OutboundKeyMaterial:
        """Obtain per-message AES-256 key and nonce, rotating the ML-KEM-768 session if due."""
        current_time = time.monotonic() if now is None else now
        with self._lock:
            needs_rotation = (
                self._session_id is None
                or self._root_key is None
                or self._session_msg_count >= self._max_messages
                or (current_time - self._session_created_at) >= self._max_age_seconds
            )

            kem_ct = b""
            rotated = False
            if needs_rotation:
                kem_ct, shared_secret = encapsulate(peer_kem_public_key)
                session_id = os.urandom(16)
                nonce_prefix = os.urandom(4)
                root_key = derive_aes_key(
                    shared_secret,
                    salt=session_id,
                    info=SESSION_ROOT_HKDF_INFO,
                )
                self._session_id = session_id
                self._root_key = root_key
                self._nonce_prefix = nonce_prefix
                self._session_created_at = current_time
                self._session_msg_count = 0
                self._rotation_count += 1
                rotated = True

            assert self._session_id is not None
            assert self._root_key is not None

            seq = self._sequence
            self._sequence += 1
            self._session_msg_count += 1

            seq_bytes = struct.pack(">Q", seq)
            msg_key = derive_aes_key(
                self._root_key,
                salt=self._session_id + seq_bytes,
                info=SESSION_MSG_HKDF_INFO,
            )
            nonce = self._nonce_prefix + seq_bytes

            return OutboundKeyMaterial(
                session_id=self._session_id,
                sequence=seq,
                msg_key=msg_key,
                nonce=nonce,
                kem_ciphertext=kem_ct,
                rotated=rotated,
            )

    def resolve_inbound_key(
        self,
        *,
        sender_id: str,
        session_id: bytes,
        sequence: int,
        kem_ciphertext: bytes,
        local_kem_secret_key: bytes,
        now: float | None = None,
    ) -> bytes:
        """Resolve or establish the per-message AES-256 key for an inbound session envelope."""
        if len(session_id) != 16:
            raise SessionError(f"Invalid session_id length: expected 16, got {len(session_id)}")

        current_time = time.monotonic() if now is None else now
        cache_key = (sender_id, session_id)
        seq_bytes = struct.pack(">Q", sequence)

        with self._lock:
            if kem_ciphertext:
                shared_secret = decapsulate(local_kem_secret_key, kem_ciphertext)
                root_key = derive_aes_key(
                    shared_secret,
                    salt=session_id,
                    info=SESSION_ROOT_HKDF_INFO,
                )
                self._inbound_cache[cache_key] = _InboundSessionEntry(
                    root_key=root_key,
                    created_at=current_time,
                )
                self._inbound_cache.move_to_end(cache_key)
                while len(self._inbound_cache) > self._max_cached_sessions:
                    self._inbound_cache.popitem(last=False)
            else:
                entry = self._inbound_cache.get(cache_key)
                if entry is None:
                    raise SessionError(
                        f"Unknown session {session_id.hex()} from sender '{sender_id}'"
                    )
                if (current_time - entry.created_at) > self._inbound_ttl_seconds:
                    del self._inbound_cache[cache_key]
                    raise SessionError(
                        f"Expired session {session_id.hex()} from sender '{sender_id}'"
                    )
                self._inbound_cache.move_to_end(cache_key)
                root_key = entry.root_key

        return derive_aes_key(
            root_key,
            salt=session_id + seq_bytes,
            info=SESSION_MSG_HKDF_INFO,
        )
