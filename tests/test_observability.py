"""Integration tests for the /healthz and Prometheus /metrics HTTP endpoint."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

import pytest

from pq_edge_bridge.bridge import BridgeKeyMaterial, TelemetryBridge
from pq_edge_bridge.config import BridgeConfig, StorageConfig
from pq_edge_bridge.crypto.kem import generate_kem_keypair
from pq_edge_bridge.crypto.signer import generate_signing_keypair
from pq_edge_bridge.observability import ObservabilityServer
from pq_edge_bridge.storage.buffer import StoreAndForwardBuffer
from pq_edge_bridge.transport.base import BaseTransport, TelemetryCallback, TransportMessage

if TYPE_CHECKING:
    from pathlib import Path


class _LoopbackTransport(BaseTransport):
    def __init__(self) -> None:
        self._connected = True
        self.published_upstream: list[tuple[str, bytes]] = []
        self.published_local: list[tuple[str, bytes]] = []

    @property
    def is_upstream_connected(self) -> bool:
        return self._connected

    async def start(
        self,
        *,
        on_local_telemetry: TelemetryCallback,
        on_upstream_command: TelemetryCallback,
    ) -> None:
        _ = (on_local_telemetry, on_upstream_command)

    async def stop(self) -> None:
        self._connected = False

    async def publish_upstream(self, topic: str, payload: bytes) -> None:
        self.published_upstream.append((topic, payload))

    async def publish_local(self, topic: str, payload: bytes) -> None:
        self.published_local.append((topic, payload))


async def _http_request(host: str, port: int, method: str, path: str) -> tuple[int, str, str]:
    reader, writer = await asyncio.open_connection(host, port)
    try:
        req = f"{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
        writer.write(req.encode("ascii"))
        await writer.drain()
        raw = await reader.read()
    finally:
        writer.close()
        await writer.wait_closed()

    head, body = raw.split(b"\r\n\r\n", 1)
    head_lines = head.decode("ascii").split("\r\n")
    status_code = int(head_lines[0].split(" ", 2)[1])
    content_type = ""
    for line in head_lines[1:]:
        if line.lower().startswith("content-type:"):
            content_type = line.split(":", 1)[1].strip()
    return status_code, content_type, body.decode("utf-8")


@pytest.mark.asyncio
async def test_observability_healthz_and_prometheus_metrics(tmp_path: Path) -> None:
    edge_kem = generate_kem_keypair()
    edge_sig = generate_signing_keypair()
    cloud_kem = generate_kem_keypair()
    cloud_sig = generate_signing_keypair()

    cfg = BridgeConfig(
        node_id="obs-node-01",
        flush_interval_seconds=0.05,
        storage=StorageConfig(db_path=tmp_path / "obs.db"),
    )
    keys = BridgeKeyMaterial(
        local_kem_secret_key=edge_kem.secret_key,
        local_sig_secret_key=edge_sig.secret_key,
        peer_kem_public_key=cloud_kem.public_key,
        peer_sig_public_key=cloud_sig.public_key,
    )
    buffer = StoreAndForwardBuffer(cfg.storage.db_path)
    transport = _LoopbackTransport()
    bridge = TelemetryBridge(config=cfg, keys=keys, transport=transport, buffer=buffer)
    obs = ObservabilityServer(bridge, host="127.0.0.1", port=0)

    await bridge.start()
    await obs.start()
    try:
        await bridge.handle_local_telemetry(TransportMessage(topic="telemetry/imu", payload=b"ok"))
        await bridge.flush_once()

        # Invalid inbound command increments commands_rejected_total
        await bridge.handle_upstream_command(
            TransportMessage(topic="pqc/cmd/bad", payload=b"corrupt")
        )

        port = obs.bound_port
        code_h, ct_h, body_h = await _http_request("127.0.0.1", port, "GET", "/healthz")
        assert code_h == 200
        assert ct_h == "application/json"
        health = json.loads(body_h)
        assert health["status"] == "ok"
        assert health["node_id"] == "obs-node-01"
        assert health["upstream_connected"] is True
        assert health["buffer_messages"] == 0
        assert health["session_rotations"] == 1

        code_m, ct_m, body_m = await _http_request("127.0.0.1", port, "GET", "/metrics")
        assert code_m == 200
        assert "text/plain" in ct_m
        assert 'pq_bridge_telemetry_received_total{node_id="obs-node-01"} 1' in body_m
        assert 'pq_bridge_telemetry_forwarded_total{node_id="obs-node-01"} 1' in body_m
        assert 'pq_bridge_commands_rejected_total{node_id="obs-node-01"} 1' in body_m
        assert 'pq_bridge_session_rotations_total{node_id="obs-node-01"} 1' in body_m

        code_404, _, _ = await _http_request("127.0.0.1", port, "GET", "/nope")
        assert code_404 == 404

        code_405, _, _ = await _http_request("127.0.0.1", port, "POST", "/healthz")
        assert code_405 == 405
    finally:
        await obs.stop()
        await bridge.stop()
