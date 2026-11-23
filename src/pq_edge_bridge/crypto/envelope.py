"""Versioned hybrid Post-Quantum Cryptography (PQC) wire envelope & replay protection."""

from __future__ import annotations

import os
import struct
import threading
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pq_edge_bridge.crypto.kem import (
    FULL_KEM_HKDF_INFO,
    ML_KEM_768_CIPHERTEXT_BYTES,
    decapsulate,
    derive_aes_key,
    encapsulate,
)
from pq_edge_bridge.crypto.session import SessionManager
from pq_edge_bridge.crypto.signer import sign_message, verify_signature
from pq_edge_bridge.exceptions import (
    DecryptionError,
    EnvelopeFormatError,
    ReplayError,
)

MAGIC = b"PQEB"
PROTOCOL_VERSION = 0x01
FLAG_FULL_KEM = 0x00
FLAG_SESSION = 0x01
NONCE_BYTES = 12
SESSION_ID_BYTES = 16
MAX_SENDER_ID_BYTES = 64
MAX_TOPIC_BYTES = 1024


@dataclass(frozen=True, slots=True)
class EnvelopeHeader:
    """Parsed metadata header of a pq-edge-bridge wire envelope."""

    version: int
    flags: int
    sender_id: str
    topic: str
    timestamp_ns: int
    sequence: int
    session_id: bytes
    kem_ct_len: int
    ciphertext_len: int
    signature_len: int
    total_bytes: int

    @property
    def is_session_mode(self) -> bool:
        """Return True if the envelope uses session-key reuse mode."""
        return bool(self.flags & FLAG_SESSION)


@dataclass(frozen=True, slots=True)
class DecryptedEnvelope:
    """Authenticated, verified, and decrypted telemetry envelope."""

    header: EnvelopeHeader
    payload: bytes


@dataclass(slots=True)
class _SenderReplayState:
    highest_seq: int | None = None
    bitmap: int = 0


class ReplayProtector:
    """Thread-safe per-sender timestamp freshness and sliding-window sequence replay guard."""

    def __init__(
        self,
        *,
        max_clock_skew_seconds: float = 300.0,
        window_size: int = 1024,
    ) -> None:
        if window_size < 1:
            raise ValueError("window_size must be >= 1")
        self._max_clock_skew_ns = (
            int(max_clock_skew_seconds * 1_000_000_000) if max_clock_skew_seconds > 0 else 0
        )
        self._window_size = window_size
        self._window_mask = (1 << window_size) - 1
        self._lock = threading.Lock()
        self._senders: dict[str, _SenderReplayState] = {}

    def check_and_update(
        self,
        sender_id: str,
        timestamp_ns: int,
        sequence: int,
        *,
        now_ns: int | None = None,
    ) -> None:
        """Validate freshness and sequence uniqueness; update state on success."""
        current_ns = time.time_ns() if now_ns is None else now_ns
        if self._max_clock_skew_ns > 0 and abs(current_ns - timestamp_ns) > self._max_clock_skew_ns:
            skew_sec = (current_ns - timestamp_ns) / 1e9
            raise ReplayError(
                f"Envelope timestamp outside allowed clock skew window ({skew_sec:.3f}s)"
            )

        with self._lock:
            state = self._senders.get(sender_id)
            if state is None:
                self._senders[sender_id] = _SenderReplayState(highest_seq=sequence, bitmap=1)
                return

            assert state.highest_seq is not None
            if sequence > state.highest_seq:
                shift = sequence - state.highest_seq
                if shift >= self._window_size:
                    state.bitmap = 1
                else:
                    state.bitmap = ((state.bitmap << shift) | 1) & self._window_mask
                state.highest_seq = sequence
            else:
                offset = state.highest_seq - sequence
                if offset >= self._window_size:
                    raise ReplayError(
                        f"Sequence {sequence} is older than replay window "
                        f"(highest={state.highest_seq}, window={self._window_size})"
                    )
                if (state.bitmap >> offset) & 1:
                    raise ReplayError(
                        f"Replayed or duplicate sequence {sequence} for sender '{sender_id}'"
                    )
                state.bitmap |= 1 << offset


def pack_envelope(
    *,
    payload: bytes,
    sender_id: str,
    topic: str,
    peer_kem_public_key: bytes,
    local_sig_secret_key: bytes,
    sequence: int | None = None,
    timestamp_ns: int | None = None,
    session_manager: SessionManager | None = None,
) -> bytes:
    """Encrypt ``payload`` with ML-KEM-768 + AES-256-GCM and sign with ML-DSA-65."""
    sender_bytes = sender_id.encode("utf-8")
    if not (1 <= len(sender_bytes) <= MAX_SENDER_ID_BYTES):
        raise EnvelopeFormatError(
            f"sender_id UTF-8 length must be 1..{MAX_SENDER_ID_BYTES} bytes"
        )
    topic_bytes = topic.encode("utf-8")
    if len(topic_bytes) > MAX_TOPIC_BYTES:
        raise EnvelopeFormatError(f"topic UTF-8 length must be <= {MAX_TOPIC_BYTES} bytes")
    if sequence is not None and sequence < 0:
        raise EnvelopeFormatError(f"sequence must be >= 0, got {sequence}")

    ts_ns = time.time_ns() if timestamp_ns is None else timestamp_ns

    if session_manager is not None:
        flags = FLAG_SESSION
        mat = session_manager.next_outbound_key(peer_kem_public_key)
        seq = mat.sequence if sequence is None else sequence
        session_id = mat.session_id
        kem_ct = mat.kem_ciphertext
        aes_key = mat.msg_key
        nonce = mat.nonce
    else:
        flags = FLAG_FULL_KEM
        seq = 0 if sequence is None else sequence
        session_id = b"\x00" * SESSION_ID_BYTES
        kem_ct, shared_secret = encapsulate(peer_kem_public_key)
        salt = sender_bytes + struct.pack(">Q", seq)
        aes_key = derive_aes_key(shared_secret, salt=salt, info=FULL_KEM_HKDF_INFO)
        nonce = os.urandom(NONCE_BYTES)

    header_bytes = b"".join(
        [
            MAGIC,
            struct.pack(">BBB", PROTOCOL_VERSION, flags, len(sender_bytes)),
            sender_bytes,
            struct.pack(">H", len(topic_bytes)),
            topic_bytes,
            struct.pack(">QQ", ts_ns, seq),
            session_id,
            struct.pack(">H", len(kem_ct)),
            kem_ct,
            nonce,
        ]
    )

    aesgcm = AESGCM(aes_key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, payload, associated_data=header_bytes)

    signed_frame = b"".join(
        [
            header_bytes,
            struct.pack(">I", len(ciphertext_and_tag)),
            ciphertext_and_tag,
        ]
    )
    signature = sign_message(local_sig_secret_key, signed_frame)

    return b"".join(
        [
            signed_frame,
            struct.pack(">H", len(signature)),
            signature,
        ]
    )


@dataclass(frozen=True, slots=True)
class _ParsedFrame:
    header: EnvelopeHeader
    aad_bytes: bytes
    session_id: bytes
    kem_ct: bytes
    nonce: bytes
    ciphertext_and_tag: bytes
    signed_frame: bytes
    signature: bytes


def _parse_frame(raw: bytes) -> _ParsedFrame:
    mv = memoryview(raw)
    total = len(raw)
    offset = 0

    def _need(n: int) -> None:
        if offset + n > total:
            raise EnvelopeFormatError(
                f"Truncated envelope at offset {offset}: need {n} bytes, have {total - offset}"
            )

    _need(7)  # magic(4) + version(1) + flags(1) + sender_id_len(1)
    if bytes(mv[0:4]) != MAGIC:
        raise EnvelopeFormatError(f"Invalid magic bytes: {bytes(mv[0:4])!r}")
    version, flags, sender_len = struct.unpack_from(">BBB", mv, 4)
    offset = 7

    if version != PROTOCOL_VERSION:
        raise EnvelopeFormatError(f"Unsupported protocol version: {version}")
    if flags not in (FLAG_FULL_KEM, FLAG_SESSION):
        raise EnvelopeFormatError(f"Unsupported envelope flags: 0x{flags:02x}")
    if not (1 <= sender_len <= MAX_SENDER_ID_BYTES):
        raise EnvelopeFormatError(f"Invalid sender_id length: {sender_len}")

    _need(sender_len + 2)
    try:
        sender_id = bytes(mv[offset : offset + sender_len]).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EnvelopeFormatError("sender_id is not valid UTF-8") from exc
    offset += sender_len

    (topic_len,) = struct.unpack_from(">H", mv, offset)
    offset += 2
    if topic_len > MAX_TOPIC_BYTES:
        raise EnvelopeFormatError(f"topic length exceeds maximum: {topic_len}")

    _need(topic_len + 8 + 8 + SESSION_ID_BYTES + 2)
    try:
        topic = bytes(mv[offset : offset + topic_len]).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EnvelopeFormatError("topic is not valid UTF-8") from exc
    offset += topic_len

    timestamp_ns, sequence = struct.unpack_from(">QQ", mv, offset)
    offset += 16

    session_id = bytes(mv[offset : offset + SESSION_ID_BYTES])
    offset += SESSION_ID_BYTES

    (kem_ct_len,) = struct.unpack_from(">H", mv, offset)
    offset += 2

    if kem_ct_len not in (0, ML_KEM_768_CIPHERTEXT_BYTES):
        raise EnvelopeFormatError(f"Unexpected ML-KEM-768 ciphertext length: {kem_ct_len}")
    if flags == FLAG_FULL_KEM and kem_ct_len != ML_KEM_768_CIPHERTEXT_BYTES:
        raise EnvelopeFormatError("Full-KEM envelope must include 1088-byte KEM ciphertext")

    _need(kem_ct_len + NONCE_BYTES + 4)
    kem_ct = bytes(mv[offset : offset + kem_ct_len])
    offset += kem_ct_len

    nonce = bytes(mv[offset : offset + NONCE_BYTES])
    offset += NONCE_BYTES
    aad_end = offset

    (ct_len,) = struct.unpack_from(">I", mv, offset)
    offset += 4
    if ct_len < 16:
        raise EnvelopeFormatError(f"Ciphertext shorter than 16-byte GCM tag: {ct_len}")

    _need(ct_len + 2)
    ciphertext_and_tag = bytes(mv[offset : offset + ct_len])
    offset += ct_len
    signed_end = offset

    (sig_len,) = struct.unpack_from(">H", mv, offset)
    offset += 2
    _need(sig_len)
    signature = bytes(mv[offset : offset + sig_len])
    offset += sig_len

    if offset != total:
        raise EnvelopeFormatError(f"Trailing bytes in envelope: {total - offset}")

    header = EnvelopeHeader(
        version=version,
        flags=flags,
        sender_id=sender_id,
        topic=topic,
        timestamp_ns=timestamp_ns,
        sequence=sequence,
        session_id=session_id,
        kem_ct_len=kem_ct_len,
        ciphertext_len=ct_len,
        signature_len=sig_len,
        total_bytes=total,
    )
    return _ParsedFrame(
        header=header,
        aad_bytes=bytes(mv[:aad_end]),
        session_id=session_id,
        kem_ct=kem_ct,
        nonce=nonce,
        ciphertext_and_tag=ciphertext_and_tag,
        signed_frame=bytes(mv[:signed_end]),
        signature=signature,
    )


def parse_envelope_header(raw: bytes) -> EnvelopeHeader:
    """Parse and validate envelope framing without verifying signature or decrypting."""
    return _parse_frame(raw).header


def verify_envelope(raw: bytes, *, peer_sig_public_key: bytes) -> EnvelopeHeader:
    """Parse an envelope and verify its ML-DSA-65 signature without decrypting."""
    parsed = _parse_frame(raw)
    verify_signature(peer_sig_public_key, parsed.signed_frame, parsed.signature)
    return parsed.header


def unpack_and_decrypt(
    raw: bytes,
    *,
    local_kem_secret_key: bytes,
    peer_sig_public_key: bytes,
    replay_protector: ReplayProtector | None = None,
    session_manager: SessionManager | None = None,
    now_ns: int | None = None,
) -> DecryptedEnvelope:
    """Verify ML-DSA-65 signature, enforce replay protection, and decrypt AES-256-GCM payload."""
    parsed = _parse_frame(raw)
    hdr = parsed.header

    # 1. Verify-then-Decrypt: authenticate entire frame before touching KEM or AES-GCM
    verify_signature(peer_sig_public_key, parsed.signed_frame, parsed.signature)

    # 2. Replay & timestamp freshness protection
    if replay_protector is not None:
        replay_protector.check_and_update(
            hdr.sender_id,
            hdr.timestamp_ns,
            hdr.sequence,
            now_ns=now_ns,
        )

    # 3. Key derivation (Full-KEM or Session-Reuse)
    if hdr.flags == FLAG_FULL_KEM:
        shared_secret = decapsulate(local_kem_secret_key, parsed.kem_ct)
        salt = hdr.sender_id.encode("utf-8") + struct.pack(">Q", hdr.sequence)
        aes_key = derive_aes_key(shared_secret, salt=salt, info=FULL_KEM_HKDF_INFO)
    else:
        if session_manager is None:
            session_manager = SessionManager()
        aes_key = session_manager.resolve_inbound_key(
            sender_id=hdr.sender_id,
            session_id=parsed.session_id,
            sequence=hdr.sequence,
            kem_ciphertext=parsed.kem_ct,
            local_kem_secret_key=local_kem_secret_key,
        )

    # 4. Authenticated AES-256-GCM decryption
    aesgcm = AESGCM(aes_key)
    try:
        plaintext = aesgcm.decrypt(
            parsed.nonce,
            parsed.ciphertext_and_tag,
            associated_data=parsed.aad_bytes,
        )
    except InvalidTag as exc:
        raise DecryptionError("AES-256-GCM authentication tag verification failed") from exc

    return DecryptedEnvelope(header=hdr, payload=plaintext)
