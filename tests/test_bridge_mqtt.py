"""End-to-end integration tests for TelemetryBridge + MqttBridgeTransport + SQLite WAL buffer."""

from __future__ import annotations

import asyncio
import contextlib
import struct
from typing import TYPE_CHECKING

import paho.mqtt.client as mqtt
import pytest

from pq_edge_bridge.bridge import BridgeKeyMaterial, TelemetryBridge
from pq_edge_bridge.config import BridgeConfig, MqttConfig, StorageConfig
from pq_edge_bridge.crypto.envelope import (
    ReplayProtector,
    pack_envelope,
    unpack_and_decrypt,
)
from pq_edge_bridge.crypto.kem import generate_kem_keypair
from pq_edge_bridge.crypto.session import SessionManager
from pq_edge_bridge.crypto.signer import generate_signing_keypair
from pq_edge_bridge.storage.buffer import StoreAndForwardBuffer
from pq_edge_bridge.transport.mqtt_adapter import MqttBridgeTransport

if TYPE_CHECKING:
    from pathlib import Path


class _MiniMqttBroker:
    """Real asyncio TCP MQTT 3.1.1 broker for deterministic integration testing."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.port = port
        self._server: asyncio.Server | None = None
        self._clients: set[asyncio.StreamWriter] = set()
        self._subs: dict[asyncio.StreamWriter, list[str]] = {}
        self.published: list[tuple[str, bytes]] = []
        self._next_pkt_id = 1
        self._offline = False

    async def start(self) -> int:
        self._server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            reuse_address=True,
            reuse_port=True,
        )
        sock = self._server.sockets[0]
        self.port = int(sock.getsockname()[1])
        return self.port

    async def go_offline(self) -> None:
        self._offline = True
        for writer in list(self._clients):
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        self._clients.clear()
        self._subs.clear()

    def go_online(self) -> None:
        self._offline = False

    async def stop(self) -> None:
        await self.go_offline()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    @staticmethod
    def _encode_remaining_length(n: int) -> bytes:
        out = bytearray()
        while True:
            digit = n % 128
            n //= 128
            if n > 0:
                digit |= 0x80
            out.append(digit)
            if n == 0:
                break
        return bytes(out)

    @staticmethod
    async def _read_remaining_length(reader: asyncio.StreamReader) -> int:
        multiplier = 1
        value = 0
        while True:
            b = (await reader.readexactly(1))[0]
            value += (b & 0x7F) * multiplier
            if (b & 0x80) == 0:
                return value
            multiplier *= 128

    @staticmethod
    def _topic_matches(sub_filter: str, topic: str) -> bool:
        if sub_filter.endswith("/#"):
            prefix = sub_filter[:-1]
            return topic.startswith(prefix) or topic == sub_filter[:-2]
        return sub_filter == topic

    async def publish_to_subscribers(self, topic: str, payload: bytes) -> None:
        topic_bytes = topic.encode("utf-8")
        pkt_id = self._next_pkt_id
        self._next_pkt_id = (self._next_pkt_id % 65535) + 1
        body = (
            struct.pack(">H", len(topic_bytes))
            + topic_bytes
            + struct.pack(">H", pkt_id)
            + payload
        )
        frame = bytes([0x32]) + self._encode_remaining_length(len(body)) + body
        for writer, filters in list(self._subs.items()):
            if any(self._topic_matches(f, topic) for f in filters):
                with contextlib.suppress(Exception):
                    writer.write(frame)
                    await writer.drain()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self._offline:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return
        self._clients.add(writer)
        self._subs[writer] = []
        try:
            while True:
                first_byte_raw = await reader.read(1)
                if not first_byte_raw:
                    break
                header_byte = first_byte_raw[0]
                pkt_type = header_byte >> 4
                rem_len = await self._read_remaining_length(reader)
                body = await reader.readexactly(rem_len) if rem_len > 0 else b""

                if pkt_type == 1:  # CONNECT
                    writer.write(b"\x20\x02\x00\x00")
                    await writer.drain()
                elif pkt_type == 8:  # SUBSCRIBE
                    pkt_id = struct.unpack_from(">H", body, 0)[0]
                    offset = 2
                    grants: list[int] = []
                    while offset < len(body):
                        tlen = struct.unpack_from(">H", body, offset)[0]
                        offset += 2
                        topic_filter = body[offset : offset + tlen].decode("utf-8")
                        offset += tlen
                        _req_qos = body[offset]
                        offset += 1
                        self._subs[writer].append(topic_filter)
                        grants.append(1)
                    suback = struct.pack(">H", pkt_id) + bytes(grants)
                    writer.write(b"\x90" + self._encode_remaining_length(len(suback)) + suback)
                    await writer.drain()
                elif pkt_type == 3:  # PUBLISH
                    qos = (header_byte >> 1) & 0x03
                    tlen = struct.unpack_from(">H", body, 0)[0]
                    topic = body[2 : 2 + tlen].decode("utf-8")
                    offset = 2 + tlen
                    if qos > 0:
                        pkt_id = struct.unpack_from(">H", body, offset)[0]
                        offset += 2
                        writer.write(b"\x40\x02" + struct.pack(">H", pkt_id))
                        await writer.drain()
                    payload = body[offset:]
                    self.published.append((topic, payload))
                    await self.publish_to_subscribers(topic, payload)
                elif pkt_type == 12:  # PINGREQ
                    writer.write(b"\xd0\x00")
                    await writer.drain()
                elif pkt_type == 14:  # DISCONNECT
                    break
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            self._clients.discard(writer)
            self._subs.pop(writer, None)
            writer.close()


@pytest.mark.asyncio
async def test_mqtt_bridge_offline_buffering_and_command_unwrap(tmp_path: Path) -> None:
    edge_kem = generate_kem_keypair()
    edge_sig = generate_signing_keypair()
    cloud_kem = generate_kem_keypair()
    cloud_sig = generate_signing_keypair()

    local_broker = _MiniMqttBroker()
    upstream_broker = _MiniMqttBroker()
    local_port = await local_broker.start()
    upstream_port = await upstream_broker.start()

    cfg = BridgeConfig(
        node_id="edge-gw-test",
        flush_interval_seconds=0.1,
        storage=StorageConfig(db_path=tmp_path / "bridge.db"),
        mqtt=MqttConfig(
            local_host="127.0.0.1",
            local_port=local_port,
            upstream_host="127.0.0.1",
            upstream_port=upstream_port,
            reconnect_min_delay=1.0,
            reconnect_max_delay=2.0,
        ),
    )
    keys = BridgeKeyMaterial(
        local_kem_secret_key=edge_kem.secret_key,
        local_sig_secret_key=edge_sig.secret_key,
        peer_kem_public_key=cloud_kem.public_key,
        peer_sig_public_key=cloud_sig.public_key,
    )
    buffer = StoreAndForwardBuffer(cfg.storage.db_path)
    transport = MqttBridgeTransport(cfg.mqtt, node_id=cfg.node_id)
    bridge = TelemetryBridge(config=cfg, keys=keys, transport=transport, buffer=buffer)

    await bridge.start()

    # Wait until both MQTT clients connect
    for _ in range(50):
        if transport.is_local_connected and transport.is_upstream_connected:
            break
        await asyncio.sleep(0.05)
    assert transport.is_local_connected
    assert transport.is_upstream_connected

    # Simulate upstream broker outage
    await upstream_broker.go_offline()
    for _ in range(50):
        if not transport.is_upstream_connected:
            break
        await asyncio.sleep(0.05)
    assert not transport.is_upstream_connected

    # Publish 5 local telemetry messages while upstream is offline
    local_pub = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    local_pub.connect("127.0.0.1", local_port, keepalive=30)
    local_pub.loop_start()
    try:
        for i in range(5):
            info = local_pub.publish(f"telemetry/imu/{i}", f"sample-{i}".encode(), qos=1)
            info.wait_for_publish(timeout=2.0)

        # Give bridge time to encrypt & buffer all 5 into SQLite WAL
        for _ in range(50):
            if (await buffer.astats()).message_count == 5:
                break
            await asyncio.sleep(0.05)
        assert (await buffer.astats()).message_count == 5
        assert len(upstream_broker.published) == 0

        # Bring upstream broker back online on the exact same port
        upstream_broker.go_online()
        for _ in range(80):
            if transport.is_upstream_connected and len(upstream_broker.published) == 5:
                break
            await asyncio.sleep(0.1)

        assert len(upstream_broker.published) == 5
        assert (await buffer.astats()).message_count == 0

        # Verify strict FIFO order and real PQC decryption on cloud side
        cloud_session = SessionManager()
        cloud_replay = ReplayProtector()
        decoded_payloads: list[bytes] = []
        for idx, (up_topic, env_bytes) in enumerate(upstream_broker.published):
            assert up_topic == f"pqc/telemetry/telemetry/imu/{idx}"
            dec = unpack_and_decrypt(
                env_bytes,
                local_kem_secret_key=cloud_kem.secret_key,
                peer_sig_public_key=edge_sig.public_key,
                replay_protector=cloud_replay,
                session_manager=cloud_session,
            )
            decoded_payloads.append(dec.payload)
        assert decoded_payloads == [f"sample-{i}".encode() for i in range(5)]

        # Test reverse path: cloud sends signed PQC command -> edge unwraps to local broker
        local_before = len(local_broker.published)
        cmd_env = pack_envelope(
            payload=b'{"action":"calibrate_imu"}',
            sender_id="cloud-c2",
            topic="cmd/imu",
            peer_kem_public_key=edge_kem.public_key,
            local_sig_secret_key=cloud_sig.secret_key,
            sequence=0,
        )
        await upstream_broker.publish_to_subscribers("pqc/cmd/imu", cmd_env)

        for _ in range(50):
            if len(local_broker.published) > local_before:
                break
            await asyncio.sleep(0.05)

        cmd_msgs = [m for m in local_broker.published[local_before:] if m[0] == "cmd/imu"]
        assert len(cmd_msgs) == 1
        assert cmd_msgs[0][1] == b'{"action":"calibrate_imu"}'
    finally:
        local_pub.disconnect()
        local_pub.loop_stop()
        await bridge.stop()
        await upstream_broker.stop()
        await local_broker.stop()
