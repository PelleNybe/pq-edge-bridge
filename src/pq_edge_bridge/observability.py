"""Zero-dependency asyncio HTTP server for /healthz and Prometheus /metrics."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pq_edge_bridge.bridge import BridgeMetricsSnapshot, TelemetryBridge

logger = logging.getLogger(__name__)


def _escape_prom_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def format_prometheus_metrics(snap: BridgeMetricsSnapshot) -> str:
    """Format a :class:`BridgeMetricsSnapshot` in Prometheus 0.0.4 text exposition format."""
    node = _escape_prom_label(snap.node_id)
    lines = [
        "# HELP pq_bridge_upstream_connected Upstream PQC transport connection state (1/0).",
        "# TYPE pq_bridge_upstream_connected gauge",
        f'pq_bridge_upstream_connected{{node_id="{node}"}} {1 if snap.upstream_connected else 0}',
        "# HELP pq_bridge_buffer_messages Number of envelopes queued in SQLite WAL buffer.",
        "# TYPE pq_bridge_buffer_messages gauge",
        f'pq_bridge_buffer_messages{{node_id="{node}"}} {snap.buffer_messages}',
        "# HELP pq_bridge_buffer_bytes Total payload bytes queued in SQLite WAL buffer.",
        "# TYPE pq_bridge_buffer_bytes gauge",
        f'pq_bridge_buffer_bytes{{node_id="{node}"}} {snap.buffer_bytes}',
        "# HELP pq_bridge_telemetry_received_total Total local telemetry messages wrapped.",
        "# TYPE pq_bridge_telemetry_received_total counter",
        f'pq_bridge_telemetry_received_total{{node_id="{node}"}} {snap.telemetry_received_total}',
        "# HELP pq_bridge_telemetry_forwarded_total Total PQC envelopes ACKed upstream.",
        "# TYPE pq_bridge_telemetry_forwarded_total counter",
        f'pq_bridge_telemetry_forwarded_total{{node_id="{node}"}} {snap.telemetry_forwarded_total}',
        "# HELP pq_bridge_commands_received_total Total valid inbound PQC commands decrypted.",
        "# TYPE pq_bridge_commands_received_total counter",
        f'pq_bridge_commands_received_total{{node_id="{node}"}} {snap.commands_received_total}',
        "# HELP pq_bridge_commands_rejected_total Total invalid/replayed inbound commands dropped.",
        "# TYPE pq_bridge_commands_rejected_total counter",
        f'pq_bridge_commands_rejected_total{{node_id="{node}"}} {snap.commands_rejected_total}',
        "# HELP pq_bridge_session_rotations_total Total ML-KEM-768 session key rotations.",
        "# TYPE pq_bridge_session_rotations_total counter",
        f'pq_bridge_session_rotations_total{{node_id="{node}"}} {snap.session_rotations_total}',
    ]
    return "\n".join(lines) + "\n"


class ObservabilityServer:
    """Lightweight localhost HTTP endpoint for /healthz and Prometheus /metrics."""

    def __init__(
        self,
        bridge: TelemetryBridge,
        *,
        host: str = "127.0.0.1",
        port: int = 9108,
    ) -> None:
        self._bridge = bridge
        self._host = host
        self._port = port
        self._server: asyncio.Server | None = None

    @property
    def bound_port(self) -> int:
        """Return the actual TCP port bound by the server."""
        if self._server is None or not self._server.sockets:
            return self._port
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> None:
        """Start listening for HTTP requests."""
        self._server = await asyncio.start_server(
            self._handle_connection,
            self._host,
            self._port,
        )
        logger.info(
            "Observability HTTP server listening on http://%s:%d", self._host, self.bound_port
        )

    async def stop(self) -> None:
        """Stop the HTTP server cleanly."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            raw_line = await asyncio.wait_for(reader.readline(), timeout=2.0)
            if not raw_line:
                return
            parts = raw_line.decode("ascii", errors="replace").strip().split()
            if len(parts) < 2:
                await self._send_response(
                    writer, 400, "Bad Request", "text/plain", b"Bad Request\n"
                )
                return

            method, path = parts[0].upper(), parts[1].split("?", 1)[0]
            # Drain remaining request headers
            while True:
                hdr = await asyncio.wait_for(reader.readline(), timeout=2.0)
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break

            if method != "GET":
                await self._send_response(
                    writer, 405, "Method Not Allowed", "text/plain", b"Method Not Allowed\n"
                )
                return

            if path == "/healthz":
                snap = await self._bridge.snapshot_metrics()
                status_code = 200 if snap.running else 503
                reason = "OK" if snap.running else "Service Unavailable"
                body = json.dumps(
                    {
                        "status": "ok" if snap.running else "stopping",
                        "node_id": snap.node_id,
                        "upstream_connected": snap.upstream_connected,
                        "buffer_messages": snap.buffer_messages,
                        "buffer_bytes": snap.buffer_bytes,
                        "session_rotations": snap.session_rotations_total,
                    }
                ).encode("utf-8")
                await self._send_response(writer, status_code, reason, "application/json", body)
            elif path == "/metrics":
                snap = await self._bridge.snapshot_metrics()
                body = format_prometheus_metrics(snap).encode("utf-8")
                await self._send_response(
                    writer,
                    200,
                    "OK",
                    "text/plain; version=0.0.4; charset=utf-8",
                    body,
                )
            else:
                await self._send_response(writer, 404, "Not Found", "text/plain", b"Not Found\n")
        except (TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    @staticmethod
    async def _send_response(
        writer: asyncio.StreamWriter,
        status: int,
        reason: str,
        content_type: str,
        body: bytes,
    ) -> None:
        headers = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        writer.write(headers + body)
        await writer.drain()
