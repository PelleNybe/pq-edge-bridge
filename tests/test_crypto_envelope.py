"""Unit tests for PQC wire envelope, replay protection, and CLI commands."""

from __future__ import annotations

import stat
import time
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from pq_edge_bridge.cli import app
from pq_edge_bridge.crypto.envelope import (
    ReplayProtector,
    pack_envelope,
    parse_envelope_header,
    unpack_and_decrypt,
    verify_envelope,
)
from pq_edge_bridge.crypto.kem import generate_kem_keypair
from pq_edge_bridge.crypto.signer import generate_signing_keypair
from pq_edge_bridge.exceptions import (
    DecryptionError,
    EnvelopeFormatError,
    ReplayError,
    SignatureVerificationError,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_envelope_round_trip_full_kem() -> None:
    edge_sig = generate_signing_keypair()
    cloud_kem = generate_kem_keypair()

    payload = b'{"temp_c": 24.5, "pressure_hpa": 1013.2}'
    raw = pack_envelope(
        payload=payload,
        sender_id="edge-gw-01",
        topic="telemetry/env",
        peer_kem_public_key=cloud_kem.public_key,
        local_sig_secret_key=edge_sig.secret_key,
        sequence=42,
    )

    hdr = parse_envelope_header(raw)
    assert hdr.sender_id == "edge-gw-01"
    assert hdr.topic == "telemetry/env"
    assert hdr.sequence == 42
    assert not hdr.is_session_mode

    verified_hdr = verify_envelope(raw, peer_sig_public_key=edge_sig.public_key)
    assert verified_hdr == hdr

    dec = unpack_and_decrypt(
        raw,
        local_kem_secret_key=cloud_kem.secret_key,
        peer_sig_public_key=edge_sig.public_key,
    )
    assert dec.payload == payload
    assert dec.header == hdr


def test_envelope_tamper_and_wrong_key_rejection() -> None:
    edge_sig = generate_signing_keypair()
    rogue_sig = generate_signing_keypair()
    cloud_kem = generate_kem_keypair()
    wrong_kem = generate_kem_keypair()

    raw = pack_envelope(
        payload=b"critical-command:arm",
        sender_id="c2-server",
        topic="cmd/arm",
        peer_kem_public_key=cloud_kem.public_key,
        local_sig_secret_key=edge_sig.secret_key,
        sequence=1,
    )

    # Wrong signing public key
    with pytest.raises(SignatureVerificationError):
        unpack_and_decrypt(
            raw,
            local_kem_secret_key=cloud_kem.secret_key,
            peer_sig_public_key=rogue_sig.public_key,
        )

    # Wrong KEM secret key (signature passes, AES-GCM tag fails)
    with pytest.raises(DecryptionError):
        unpack_and_decrypt(
            raw,
            local_kem_secret_key=wrong_kem.secret_key,
            peer_sig_public_key=edge_sig.public_key,
        )

    # Bit flip in ciphertext / header -> SignatureVerificationError
    for idx in (10, 50, len(raw) // 2, len(raw) - 20):
        tampered = bytearray(raw)
        tampered[idx] ^= 0x01
        with pytest.raises(SignatureVerificationError):
            unpack_and_decrypt(
                bytes(tampered),
                local_kem_secret_key=cloud_kem.secret_key,
                peer_sig_public_key=edge_sig.public_key,
            )

    # Truncated & trailing bytes
    with pytest.raises(EnvelopeFormatError):
        parse_envelope_header(raw[:-1])
    with pytest.raises(EnvelopeFormatError):
        parse_envelope_header(raw + b"\x00")


def test_replay_protection() -> None:
    edge_sig = generate_signing_keypair()
    cloud_kem = generate_kem_keypair()
    guard = ReplayProtector(max_clock_skew_seconds=60.0, window_size=64)

    now = time.time_ns()
    e1 = pack_envelope(
        payload=b"msg-1",
        sender_id="node-a",
        topic="t/1",
        peer_kem_public_key=cloud_kem.public_key,
        local_sig_secret_key=edge_sig.secret_key,
        sequence=10,
        timestamp_ns=now,
    )
    e2 = pack_envelope(
        payload=b"msg-2",
        sender_id="node-a",
        topic="t/1",
        peer_kem_public_key=cloud_kem.public_key,
        local_sig_secret_key=edge_sig.secret_key,
        sequence=8,
        timestamp_ns=now,
    )

    # First delivery succeeds
    unpack_and_decrypt(
        e1,
        local_kem_secret_key=cloud_kem.secret_key,
        peer_sig_public_key=edge_sig.public_key,
        replay_protector=guard,
        now_ns=now,
    )
    # Replaying e1 fails
    with pytest.raises(ReplayError):
        unpack_and_decrypt(
            e1,
            local_kem_secret_key=cloud_kem.secret_key,
            peer_sig_public_key=edge_sig.public_key,
            replay_protector=guard,
            now_ns=now,
        )

    # Slightly out-of-order within window succeeds once
    unpack_and_decrypt(
        e2,
        local_kem_secret_key=cloud_kem.secret_key,
        peer_sig_public_key=edge_sig.public_key,
        replay_protector=guard,
        now_ns=now,
    )
    # Replaying e2 fails
    with pytest.raises(ReplayError):
        unpack_and_decrypt(
            e2,
            local_kem_secret_key=cloud_kem.secret_key,
            peer_sig_public_key=edge_sig.public_key,
            replay_protector=guard,
            now_ns=now,
        )

    # Stale timestamp fails
    stale = pack_envelope(
        payload=b"stale",
        sender_id="node-a",
        topic="t/1",
        peer_kem_public_key=cloud_kem.public_key,
        local_sig_secret_key=edge_sig.secret_key,
        sequence=11,
        timestamp_ns=now - 120_000_000_000,
    )
    with pytest.raises(ReplayError):
        unpack_and_decrypt(
            stale,
            local_kem_secret_key=cloud_kem.secret_key,
            peer_sig_public_key=edge_sig.public_key,
            replay_protector=guard,
            now_ns=now,
        )


def test_cli_keygen_permissions_and_roundtrip(tmp_path: Path) -> None:
    runner = CliRunner()
    keys_dir = tmp_path / "keys"

    res_edge = runner.invoke(app, ["keygen", "--output-dir", str(keys_dir), "--prefix", "edge"])
    assert res_edge.exit_code == 0, res_edge.output

    res_cloud = runner.invoke(app, ["keygen", "--output-dir", str(keys_dir), "--prefix", "cloud"])
    assert res_cloud.exit_code == 0, res_cloud.output

    # Verify strict 0o600 on secret keys
    for sec in ("edge.kem.key", "edge.sig.key", "cloud.kem.key", "cloud.sig.key"):
        mode = stat.S_IMODE((keys_dir / sec).stat().st_mode)
        assert mode == 0o600, f"{sec} has mode {oct(mode)}, expected 0o600"

    env_file = tmp_path / "telemetry.pqeb"
    dec_file = tmp_path / "telemetry.out"

    res_enc = runner.invoke(
        app,
        [
            "encrypt",
            "--peer-kem-pub",
            str(keys_dir / "cloud.kem.pub"),
            "--sig-key",
            str(keys_dir / "edge.sig.key"),
            "--sender-id",
            "edge-01",
            "--topic",
            "telemetry/gps",
            "--message",
            '{"lat":59.3293,"lon":18.0686}',
            "--out",
            str(env_file),
        ],
    )
    assert res_enc.exit_code == 0, res_enc.output

    res_ver = runner.invoke(
        app,
        [
            "verify",
            "--peer-sig-pub",
            str(keys_dir / "edge.sig.pub"),
            "--in",
            str(env_file),
        ],
    )
    assert res_ver.exit_code == 0, res_ver.output

    res_insp = runner.invoke(app, ["inspect", "--in", str(env_file)])
    assert res_insp.exit_code == 0, res_insp.output
    assert "edge-01" in res_insp.output

    res_dec = runner.invoke(
        app,
        [
            "decrypt",
            "--kem-key",
            str(keys_dir / "cloud.kem.key"),
            "--peer-sig-pub",
            str(keys_dir / "edge.sig.pub"),
            "--in",
            str(env_file),
            "--out",
            str(dec_file),
        ],
    )
    assert res_dec.exit_code == 0, res_dec.output
    assert dec_file.read_text(encoding="utf-8") == '{"lat":59.3293,"lon":18.0686}'


def test_negative_sequence_and_operator_cli_commands(tmp_path: Path) -> None:
    edge_sig = generate_signing_keypair()
    cloud_kem = generate_kem_keypair()

    with pytest.raises(EnvelopeFormatError, match="sequence must be >= 0"):
        pack_envelope(
            payload=b"bad",
            sender_id="edge-01",
            topic="t/1",
            peer_kem_public_key=cloud_kem.public_key,
            local_sig_secret_key=edge_sig.secret_key,
            sequence=-1,
        )

    runner = CliRunner()
    cfg_out = tmp_path / "config.yaml"
    res_init = runner.invoke(
        app,
        ["init-config", "--out", str(cfg_out), "--node-id", "edge-99"],
    )
    assert res_init.exit_code == 0, res_init.output
    assert "edge-99" in cfg_out.read_text(encoding="utf-8")

    from pq_edge_bridge.storage.buffer import StoreAndForwardBuffer

    db_path = tmp_path / "buf.db"
    with StoreAndForwardBuffer(db_path) as buf:
        buf.enqueue("telemetry/test", b"12345")

    res_stats = runner.invoke(app, ["buffer-stats", "--db", str(db_path)])
    assert res_stats.exit_code == 0, res_stats.output
    assert "1" in res_stats.output
    assert "5 B" in res_stats.output
