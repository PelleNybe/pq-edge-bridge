"""Unit tests for SessionManager caching and time/message-count rotation."""

from __future__ import annotations

import pytest

from pq_edge_bridge.crypto.envelope import pack_envelope, unpack_and_decrypt
from pq_edge_bridge.crypto.kem import ML_KEM_768_CIPHERTEXT_BYTES, generate_kem_keypair
from pq_edge_bridge.crypto.session import SessionManager
from pq_edge_bridge.crypto.signer import generate_signing_keypair
from pq_edge_bridge.exceptions import SessionError


def test_session_rotation_by_message_count() -> None:
    edge_sig = generate_signing_keypair()
    cloud_kem = generate_kem_keypair()

    sender_mgr = SessionManager(max_messages=3, max_age_seconds=600.0)
    receiver_mgr = SessionManager(max_messages=3, max_age_seconds=600.0)

    seen_sessions: list[bytes] = []
    kem_lengths: list[int] = []

    for i in range(7):
        raw = pack_envelope(
            payload=f"telemetry-{i}".encode(),
            sender_id="edge-01",
            topic="telemetry/imu",
            peer_kem_public_key=cloud_kem.public_key,
            local_sig_secret_key=edge_sig.secret_key,
            session_manager=sender_mgr,
        )
        dec = unpack_and_decrypt(
            raw,
            local_kem_secret_key=cloud_kem.secret_key,
            peer_sig_public_key=edge_sig.public_key,
            session_manager=receiver_mgr,
        )
        assert dec.payload == f"telemetry-{i}".encode()
        assert dec.header.is_session_mode
        assert dec.header.sequence == i
        seen_sessions.append(dec.header.session_id)
        kem_lengths.append(dec.header.kem_ct_len)

    # Rotations at index 0, 3, 6
    assert kem_lengths == [
        ML_KEM_768_CIPHERTEXT_BYTES,
        0,
        0,
        ML_KEM_768_CIPHERTEXT_BYTES,
        0,
        0,
        ML_KEM_768_CIPHERTEXT_BYTES,
    ]
    assert seen_sessions[0] == seen_sessions[1] == seen_sessions[2]
    assert seen_sessions[3] == seen_sessions[4] == seen_sessions[5]
    assert seen_sessions[0] != seen_sessions[3]
    assert seen_sessions[3] != seen_sessions[6]
    assert sender_mgr.rotation_count == 3


def test_session_rotation_by_elapsed_time() -> None:
    cloud_kem = generate_kem_keypair()
    mgr = SessionManager(max_messages=1000, max_age_seconds=10.0)

    m0 = mgr.next_outbound_key(cloud_kem.public_key, now=100.0)
    m1 = mgr.next_outbound_key(cloud_kem.public_key, now=105.0)
    m2 = mgr.next_outbound_key(cloud_kem.public_key, now=110.5)

    assert m0.rotated is True
    assert m1.rotated is False
    assert m1.session_id == m0.session_id
    assert m2.rotated is True
    assert m2.session_id != m0.session_id
    assert len(m2.kem_ciphertext) == ML_KEM_768_CIPHERTEXT_BYTES


def test_unknown_or_expired_inbound_session_rejected() -> None:
    cloud_kem = generate_kem_keypair()
    mgr = SessionManager(max_messages=100, max_age_seconds=5.0, inbound_ttl_seconds=5.0)

    with pytest.raises(SessionError):
        mgr.resolve_inbound_key(
            sender_id="edge-01",
            session_id=b"\x11" * 16,
            sequence=0,
            kem_ciphertext=b"",
            local_kem_secret_key=cloud_kem.secret_key,
            now=100.0,
        )

    kem_ct, _ = __import__("pq_edge_bridge.crypto.kem", fromlist=["encapsulate"]).encapsulate(
        cloud_kem.public_key
    )
    sid = b"\x22" * 16
    k0 = mgr.resolve_inbound_key(
        sender_id="edge-01",
        session_id=sid,
        sequence=0,
        kem_ciphertext=kem_ct,
        local_kem_secret_key=cloud_kem.secret_key,
        now=100.0,
    )
    assert len(k0) == 32

    with pytest.raises(SessionError):
        mgr.resolve_inbound_key(
            sender_id="edge-01",
            session_id=sid,
            sequence=1,
            kem_ciphertext=b"",
            local_kem_secret_key=cloud_kem.secret_key,
            now=106.0,
        )
