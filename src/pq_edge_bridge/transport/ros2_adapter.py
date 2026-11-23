"""Optional ROS 2 / DDS bridge adapter (rclpy)."""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import TYPE_CHECKING, Any

from pq_edge_bridge.exceptions import TransportError
from pq_edge_bridge.transport.base import BaseTransport, TelemetryCallback, TransportMessage

if TYPE_CHECKING:
    from pq_edge_bridge.config import Ros2Config

logger = logging.getLogger(__name__)

try:
    import rclpy
    from rclpy.executors import SingleThreadedExecutor
    from rclpy.node import Node
    from rclpy.qos import QoSProfile
    from std_msgs.msg import UInt8MultiArray

    ROS2_AVAILABLE = True
except ImportError:  # pragma: no cover - covered in non-ROS environments
    rclpy = None
    SingleThreadedExecutor = None
    Node = Any
    QoSProfile = None
    UInt8MultiArray = None
    ROS2_AVAILABLE = False


class Ros2BridgeTransport(BaseTransport):
    """Bridges ROS 2 DDS topics (UInt8MultiArray) with the pq-edge-bridge async pipeline."""

    def __init__(
        self,
        config: Ros2Config,
        *,
        upstream_sink: BaseTransport | None = None,
    ) -> None:
        self._config = config
        self._upstream_sink = upstream_sink
        self._loop: asyncio.AbstractEventLoop | None = None
        self._local_queue: asyncio.Queue[TransportMessage] = asyncio.Queue()
        self._dispatch_task: asyncio.Task[None] | None = None

        self._node: Any = None
        self._executor: Any = None
        self._spin_thread: threading.Thread | None = None
        self._publishers: dict[str, Any] = {}
        self._subscriptions: list[Any] = []
        self._owns_rclpy_init = False
        self._running = False

    @property
    def is_upstream_connected(self) -> bool:
        """Return upstream connectivity status (delegates to upstream_sink if attached)."""
        if self._upstream_sink is not None:
            return self._upstream_sink.is_upstream_connected
        return self._running

    async def start(
        self,
        *,
        on_local_telemetry: TelemetryCallback,
        on_upstream_command: TelemetryCallback,
    ) -> None:
        """Initialize the rclpy node, subscriptions, publishers, and executor thread."""
        if not ROS2_AVAILABLE:
            raise TransportError(
                "ROS 2 (rclpy / std_msgs) is not available in the current Python environment"
            )

        self._loop = asyncio.get_running_loop()
        self._running = True

        if not rclpy.ok():
            rclpy.init()
            self._owns_rclpy_init = True

        self._node = rclpy.create_node(self._config.node_name)
        qos = QoSProfile(depth=self._config.qos_depth)

        for topic in self._config.inbound_topics:
            sub = self._node.create_subscription(
                UInt8MultiArray,
                topic,
                lambda msg, t=topic: self._on_ros_message(t, msg),
                qos,
            )
            self._subscriptions.append(sub)

        for topic in self._config.outbound_command_topics:
            self._publishers[topic] = self._node.create_publisher(UInt8MultiArray, topic, qos)

        self._executor = SingleThreadedExecutor()
        self._executor.add_node(self._node)
        self._spin_thread = threading.Thread(
            target=self._spin_loop,
            name=f"{self._config.node_name}-spin",
            daemon=True,
        )
        self._spin_thread.start()

        self._dispatch_task = asyncio.create_task(self._drain_local(on_local_telemetry))
        logger.info(
            "ROS 2 bridge node '%s' started (inbound=%s, outbound=%s)",
            self._config.node_name,
            self._config.inbound_topics,
            self._config.outbound_command_topics,
        )

    def _spin_loop(self) -> None:
        while self._running and rclpy.ok():
            try:
                self._executor.spin_once(timeout_sec=0.1)
            except Exception:
                if self._running:
                    logger.exception("ROS 2 executor spin error")
                break

    def _on_ros_message(self, topic: str, msg: Any) -> None:
        if self._loop is not None and self._running:
            payload = bytes(msg.data)
            item = TransportMessage(topic=topic, payload=payload)
            self._loop.call_soon_threadsafe(self._local_queue.put_nowait, item)

    async def _drain_local(self, callback: TelemetryCallback) -> None:
        while self._running:
            try:
                msg = await self._local_queue.get()
            except asyncio.CancelledError:
                break
            try:
                await callback(msg)
            except Exception:
                logger.exception("Unhandled error in ROS 2 telemetry handler for '%s'", msg.topic)
            finally:
                self._local_queue.task_done()

    async def stop(self) -> None:
        """Stop the ROS 2 executor thread and destroy node resources."""
        self._running = False
        if self._dispatch_task is not None:
            self._dispatch_task.cancel()
            await asyncio.gather(self._dispatch_task, return_exceptions=True)
            self._dispatch_task = None

        if self._spin_thread is not None and self._spin_thread.is_alive():
            self._spin_thread.join(timeout=2.0)
            self._spin_thread = None

        if self._executor is not None and self._node is not None:
            self._executor.remove_node(self._node)
            self._executor.shutdown()
            self._executor = None

        if self._node is not None:
            self._node.destroy_node()
            self._node = None

        self._subscriptions.clear()
        self._publishers.clear()

        if self._owns_rclpy_init and ROS2_AVAILABLE and rclpy.ok():
            rclpy.shutdown()
            self._owns_rclpy_init = False

    async def publish_upstream(self, topic: str, payload: bytes) -> None:
        """Delegate upstream PQC envelope publishing to the attached upstream sink."""
        if self._upstream_sink is None:
            raise TransportError("No upstream transport sink configured for ROS 2 bridge")
        await self._upstream_sink.publish_upstream(topic, payload)

    async def publish_local(self, topic: str, payload: bytes) -> None:
        """Publish a decrypted command payload onto a local ROS 2 topic."""
        if not ROS2_AVAILABLE or self._node is None:
            raise TransportError("ROS 2 bridge node is not running")
        pub = self._publishers.get(topic)
        if pub is None:
            qos = QoSProfile(depth=self._config.qos_depth)
            pub = self._node.create_publisher(UInt8MultiArray, topic, qos)
            self._publishers[topic] = pub

        msg = UInt8MultiArray()
        msg.data = list(payload)
        pub.publish(msg)
