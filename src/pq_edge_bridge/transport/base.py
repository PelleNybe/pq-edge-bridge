"""Abstract asynchronous transport interface for pq-edge-bridge adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

TelemetryCallback = Callable[["TransportMessage"], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class TransportMessage:
    """Normalized message exchanged between local bus and upstream PQC transport."""

    topic: str
    payload: bytes


class BaseTransport(ABC):
    """Abstract base class for async edge-to-upstream transport adapters."""

    @property
    @abstractmethod
    def is_upstream_connected(self) -> bool:
        """Return True if the upstream encrypted link is currently connected."""

    @abstractmethod
    async def start(
        self,
        *,
        on_local_telemetry: TelemetryCallback,
        on_upstream_command: TelemetryCallback,
    ) -> None:
        """Start the transport adapter and register async message handlers."""

    @abstractmethod
    async def stop(self) -> None:
        """Gracefully disconnect and release transport resources."""

    @abstractmethod
    async def publish_upstream(self, topic: str, payload: bytes) -> None:
        """Publish a signed PQC envelope to the upstream broker/network."""

    @abstractmethod
    async def publish_local(self, topic: str, payload: bytes) -> None:
        """Publish a decrypted plaintext command to the local edge bus."""
