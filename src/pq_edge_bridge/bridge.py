"""Core async telemetry bridge engine tying crypto, SQLite WAL buffer, and transports."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pq_edge_bridge.crypto.envelope import (
    ReplayProtector,
    pack_envelope,
    unpack_and_decrypt,
)
from pq_edge_bridge.crypto.session import SessionManager
from pq_edge_bridge.exceptions import CryptoError, TransportError

if TYPE_CHECKING:
    from pq_edge_bridge.config import BridgeConfig
    from pq_edge_bridge.storage.buffer import StoreAndForwardBuffer
    from pq_edge_bridge.transport.base import BaseTransport, TransportMessage

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class BridgeKeyMaterial:
    """Loaded raw cryptographic keys required by a bridge node."""

    local_kem_secret_key: bytes
    local_sig_secret_key: bytes
    peer_kem_public_key: bytes
    peer_sig_public_key: bytes


class TelemetryBridge:
    """Asynchronous Post-Quantum telemetry bridge with offline store-and-forward."""

    def __init__(
        self,
        *,
        config: BridgeConfig,
        keys: BridgeKeyMaterial,
        transport: BaseTransport,
        buffer: StoreAndForwardBuffer,
    ) -> None:
        self._config = config
        self._keys = keys
        self._transport = transport
        self._buffer = buffer

        self._session_manager: SessionManager | None = (
            SessionManager(
                max_messages=config.crypto.session_max_messages,
                max_age_seconds=config.crypto.session_max_age_seconds,
                max_cached_sessions=config.crypto.max_cached_sessions,
            )
            if config.crypto.session_mode
            else None
        )
        self._replay_protector = ReplayProtector(
            max_clock_skew_seconds=config.crypto.max_clock_skew_seconds,
            window_size=config.crypto.replay_window_size,
        )
        self._full_kem_seq = 0
        self._seq_lock = asyncio.Lock()

        self._flush_event = asyncio.Event()
        self._flush_task: asyncio.Task[None] | None = None
        self._running = False

    def _map_outbound_topic(self, local_topic: str) -> str:
        prefix = self._config.mqtt.upstream_telemetry_prefix.strip("/")
        cleaned = local_topic.lstrip("/")
        return f"{prefix}/{cleaned}" if prefix else cleaned

    def _map_inbound_topic(self, upstream_topic: str) -> str:
        local_prefix = self._config.mqtt.local_command_prefix.strip("/")
        cleaned = upstream_topic.lstrip("/")
        if cleaned.startswith("pqc/cmd/"):
            cleaned = cleaned[len("pqc/cmd/") :]
        elif cleaned.startswith("pqc/"):
            cleaned = cleaned[len("pqc/") :]
        return f"{local_prefix}/{cleaned}" if local_prefix else cleaned

    async def start(self) -> None:
        """Start the transport adapter and background store-and-forward flush loop."""
        self._running = True
        await self._transport.start(
            on_local_telemetry=self.handle_local_telemetry,
            on_upstream_command=self.handle_upstream_command,
        )
        self._flush_task = asyncio.create_task(self._flush_loop())
        self._flush_event.set()
        logger.info("pq-edge-bridge started (node_id=%s)", self._config.node_id)

    async def stop(self) -> None:
        """Stop the flush loop, disconnect transport, and close buffer."""
        self._running = False
        self._flush_event.set()
        if self._flush_task is not None:
            self._flush_task.cancel()
            await asyncio.gather(self._flush_task, return_exceptions=True)
            self._flush_task = None
        await self._transport.stop()
        await self._buffer.aclose()
        logger.info("pq-edge-bridge stopped")

    async def handle_local_telemetry(self, msg: TransportMessage) -> None:
        """Wrap local plaintext telemetry in a PQC envelope and persist to WAL buffer."""
        seq: int | None = None
        if self._session_manager is None:
            async with self._seq_lock:
                seq = self._full_kem_seq
                self._full_kem_seq += 1

        envelope = pack_envelope(
            payload=msg.payload,
            sender_id=self._config.node_id,
            topic=msg.topic,
            peer_kem_public_key=self._keys.peer_kem_public_key,
            local_sig_secret_key=self._keys.local_sig_secret_key,
            sequence=seq,
            session_manager=self._session_manager,
        )
        upstream_topic = self._map_outbound_topic(msg.topic)
        await self._buffer.aenqueue(upstream_topic, envelope)
        self._flush_event.set()

    async def handle_upstream_command(self, msg: TransportMessage) -> None:
        """Verify, decrypt, and forward an inbound PQC command to the local bus."""
        try:
            decrypted = unpack_and_decrypt(
                msg.payload,
                local_kem_secret_key=self._keys.local_kem_secret_key,
                peer_sig_public_key=self._keys.peer_sig_public_key,
                replay_protector=self._replay_protector,
                session_manager=self._session_manager,
            )
        except CryptoError as exc:
            logger.warning(
                "Rejected inbound PQC command on '%s': %s",
                msg.topic,
                exc,
            )
            return

        target_topic = decrypted.header.topic or self._map_inbound_topic(msg.topic)
        try:
            await self._transport.publish_local(target_topic, decrypted.payload)
        except TransportError as exc:
            logger.error("Failed to publish decrypted command to '%s': %s", target_topic, exc)

    async def flush_once(self) -> int:
        """Flush available buffered envelopes in strict FIFO order; return count acked."""
        if not self._transport.is_upstream_connected:
            return 0

        total_acked = 0
        while self._running and self._transport.is_upstream_connected:
            batch = await self._buffer.apeek_batch(limit=self._config.flush_batch_size)
            if not batch:
                break

            acked_ids: list[int] = []
            for item in batch:
                try:
                    await self._transport.publish_upstream(item.topic, item.payload)
                    acked_ids.append(item.id)
                except TransportError as exc:
                    logger.debug("Upstream publish deferred for id=%d: %s", item.id, exc)
                    break

            if acked_ids:
                await self._buffer.aack(acked_ids)
                total_acked += len(acked_ids)
            else:
                break

            if len(acked_ids) < len(batch):
                break

        return total_acked

    async def _flush_loop(self) -> None:
        while self._running:
            try:
                await asyncio.wait_for(
                    self._flush_event.wait(),
                    timeout=self._config.flush_interval_seconds,
                )
            except TimeoutError:
                pass
            except asyncio.CancelledError:
                break
            self._flush_event.clear()
            if self._running:
                try:
                    await self.flush_once()
                except Exception:
                    logger.exception("Unexpected error during store-and-forward flush")
