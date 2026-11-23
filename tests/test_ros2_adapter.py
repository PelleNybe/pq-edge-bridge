"""Unit tests for the optional ROS 2 / DDS bridge adapter."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pq_edge_bridge.config import Ros2Config
from pq_edge_bridge.exceptions import TransportError
from pq_edge_bridge.transport.ros2_adapter import ROS2_AVAILABLE, Ros2BridgeTransport

if TYPE_CHECKING:
    from pq_edge_bridge.transport.base import TransportMessage


@pytest.mark.asyncio
async def test_ros2_adapter_graceful_when_unavailable() -> None:
    cfg = Ros2Config(enabled=True)
    adapter = Ros2BridgeTransport(cfg)

    async def _noop(_msg: TransportMessage) -> None:
        return None

    if not ROS2_AVAILABLE:
        with pytest.raises(TransportError, match="not available"):
            await adapter.start(on_local_telemetry=_noop, on_upstream_command=_noop)
        with pytest.raises(TransportError, match="not running"):
            await adapter.publish_local("/cmd/raw", b"hello")
    else:
        await adapter.start(on_local_telemetry=_noop, on_upstream_command=_noop)
        assert adapter.is_upstream_connected
        await adapter.publish_local("/cmd/raw", b"hello")
        await adapter.stop()
