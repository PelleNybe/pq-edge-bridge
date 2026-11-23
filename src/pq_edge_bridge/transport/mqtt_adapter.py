"""Production Paho MQTT v2 async bridge adapter."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion, MQTTErrorCode

from pq_edge_bridge.exceptions import TransportError
from pq_edge_bridge.transport.base import BaseTransport, TelemetryCallback, TransportMessage

if TYPE_CHECKING:
    from paho.mqtt.properties import Properties
    from paho.mqtt.reasoncodes import ReasonCode

    from pq_edge_bridge.config import MqttConfig

logger = logging.getLogger(__name__)


class MqttBridgeTransport(BaseTransport):
    """Dual-client Paho MQTT v2 adapter bridging local plaintext and upstream PQC topics."""

    def __init__(self, config: MqttConfig, *, node_id: str) -> None:
        self._config = config
        self._node_id = node_id
        self._loop: asyncio.AbstractEventLoop | None = None

        self._local_queue: asyncio.Queue[TransportMessage] = asyncio.Queue()
        self._upstream_queue: asyncio.Queue[TransportMessage] = asyncio.Queue()
        self._dispatch_tasks: list[asyncio.Task[None]] = []

        self._local_connected = False
        self._upstream_connected = False
        self._running = False

        self._local_client = mqtt.Client(
            callback_api_version=CallbackAPIVersion.VERSION2,
            client_id=f"{node_id}-local",
            clean_session=True,
        )
        self._upstream_client = mqtt.Client(
            callback_api_version=CallbackAPIVersion.VERSION2,
            client_id=f"{node_id}-upstream",
            clean_session=False,
        )

        self._configure_clients()

    def _configure_clients(self) -> None:
        self._local_client.reconnect_delay_set(
            min_delay=int(max(1, self._config.reconnect_min_delay)),
            max_delay=int(max(1, self._config.reconnect_max_delay)),
        )
        self._upstream_client.reconnect_delay_set(
            min_delay=int(max(1, self._config.reconnect_min_delay)),
            max_delay=int(max(1, self._config.reconnect_max_delay)),
        )

        if self._config.upstream_username is not None:
            self._upstream_client.username_pw_set(
                self._config.upstream_username,
                self._config.upstream_password,
            )
        if self._config.upstream_tls:
            ca_certs = (
                str(self._config.upstream_ca_certs)
                if self._config.upstream_ca_certs is not None
                else None
            )
            self._upstream_client.tls_set(ca_certs=ca_certs)

        self._local_client.on_connect = self._on_local_connect
        self._local_client.on_disconnect = self._on_local_disconnect
        self._local_client.on_message = self._on_local_message

        self._upstream_client.on_connect = self._on_upstream_connect
        self._upstream_client.on_disconnect = self._on_upstream_disconnect
        self._upstream_client.on_message = self._on_upstream_message

    @property
    def is_upstream_connected(self) -> bool:
        """Return True when the upstream MQTT client is connected."""
        return self._upstream_connected

    @property
    def is_local_connected(self) -> bool:
        """Return True when the local MQTT client is connected."""
        return self._local_connected

    def _on_local_connect(
        self,
        client: mqtt.Client,
        _userdata: Any,
        _flags: mqtt.ConnectFlags,
        reason_code: ReasonCode,
        _properties: Properties | None,
    ) -> None:
        if reason_code == 0:
            self._local_connected = True
            for topic in self._config.local_telemetry_topics:
                client.subscribe(topic, qos=self._config.qos)
            logger.info(
                "Local MQTT connected (%s:%d), subscribed to %s",
                self._config.local_host,
                self._config.local_port,
                self._config.local_telemetry_topics,
            )
        else:
            logger.warning("Local MQTT connection failed: %s", reason_code)

    def _on_local_disconnect(
        self,
        _client: mqtt.Client,
        _userdata: Any,
        _disconnect_flags: mqtt.DisconnectFlags,
        reason_code: ReasonCode,
        _properties: Properties | None,
    ) -> None:
        self._local_connected = False
        logger.warning("Local MQTT disconnected: %s", reason_code)

    def _on_local_message(
        self,
        _client: mqtt.Client,
        _userdata: Any,
        msg: mqtt.MQTTMessage,
    ) -> None:
        if self._loop is not None and self._running:
            item = TransportMessage(topic=msg.topic, payload=bytes(msg.payload))
            self._loop.call_soon_threadsafe(self._local_queue.put_nowait, item)

    def _on_upstream_connect(
        self,
        client: mqtt.Client,
        _userdata: Any,
        _flags: mqtt.ConnectFlags,
        reason_code: ReasonCode,
        _properties: Properties | None,
    ) -> None:
        if reason_code == 0:
            self._upstream_connected = True
            for topic in self._config.upstream_command_topics:
                client.subscribe(topic, qos=self._config.qos)
            logger.info(
                "Upstream MQTT connected (%s:%d), subscribed to %s",
                self._config.upstream_host,
                self._config.upstream_port,
                self._config.upstream_command_topics,
            )
        else:
            logger.warning("Upstream MQTT connection failed: %s", reason_code)

    def _on_upstream_disconnect(
        self,
        _client: mqtt.Client,
        _userdata: Any,
        _disconnect_flags: mqtt.DisconnectFlags,
        reason_code: ReasonCode,
        _properties: Properties | None,
    ) -> None:
        self._upstream_connected = False
        logger.warning("Upstream MQTT disconnected: %s", reason_code)

    def _on_upstream_message(
        self,
        _client: mqtt.Client,
        _userdata: Any,
        msg: mqtt.MQTTMessage,
    ) -> None:
        if self._loop is not None and self._running:
            item = TransportMessage(topic=msg.topic, payload=bytes(msg.payload))
            self._loop.call_soon_threadsafe(self._upstream_queue.put_nowait, item)

    async def _drain_queue(
        self,
        queue: asyncio.Queue[TransportMessage],
        callback: TelemetryCallback,
        name: str,
    ) -> None:
        while self._running:
            try:
                msg = await queue.get()
            except asyncio.CancelledError:
                break
            try:
                await callback(msg)
            except Exception:
                logger.exception("Unhandled error in %s handler for topic '%s'", name, msg.topic)
            finally:
                queue.task_done()

    async def start(
        self,
        *,
        on_local_telemetry: TelemetryCallback,
        on_upstream_command: TelemetryCallback,
    ) -> None:
        """Connect local and upstream MQTT clients and start async dispatchers."""
        self._loop = asyncio.get_running_loop()
        self._running = True

        self._dispatch_tasks = [
            asyncio.create_task(
                self._drain_queue(self._local_queue, on_local_telemetry, "local_telemetry")
            ),
            asyncio.create_task(
                self._drain_queue(self._upstream_queue, on_upstream_command, "upstream_command")
            ),
        ]

        self._local_client.connect_async(
            self._config.local_host,
            self._config.local_port,
            keepalive=self._config.keepalive_seconds,
        )
        self._upstream_client.connect_async(
            self._config.upstream_host,
            self._config.upstream_port,
            keepalive=self._config.keepalive_seconds,
        )
        self._local_client.loop_start()
        self._upstream_client.loop_start()

    async def stop(self) -> None:
        """Disconnect both MQTT clients and stop dispatcher tasks."""
        self._running = False
        for task in self._dispatch_tasks:
            task.cancel()
        if self._dispatch_tasks:
            await asyncio.gather(*self._dispatch_tasks, return_exceptions=True)
        self._dispatch_tasks.clear()

        self._local_client.disconnect()
        self._upstream_client.disconnect()
        self._local_client.loop_stop()
        self._upstream_client.loop_stop()
        self._local_connected = False
        self._upstream_connected = False

    async def publish_upstream(self, topic: str, payload: bytes) -> None:
        """Publish an encrypted PQC envelope to the upstream broker and await PUBACK."""
        if not self._upstream_connected:
            raise TransportError("Upstream MQTT broker is not connected")
        info = self._upstream_client.publish(topic, payload, qos=self._config.qos)
        if info.rc != MQTTErrorCode.MQTT_ERR_SUCCESS:
            raise TransportError(f"Upstream MQTT publish failed with rc={info.rc}")
        try:
            await asyncio.to_thread(info.wait_for_publish, timeout=5.0)
        except Exception as exc:
            raise TransportError(f"Upstream MQTT publish confirmation failed: {exc}") from exc
        if not info.is_published():
            raise TransportError("Upstream MQTT publish timed out waiting for PUBACK")

    async def publish_local(self, topic: str, payload: bytes) -> None:
        """Publish a decrypted command payload to the local MQTT broker."""
        if not self._local_connected:
            raise TransportError("Local MQTT broker is not connected")
        info = self._local_client.publish(topic, payload, qos=self._config.qos)
        if info.rc != MQTTErrorCode.MQTT_ERR_SUCCESS:
            raise TransportError(f"Local MQTT publish failed with rc={info.rc}")
        try:
            await asyncio.to_thread(info.wait_for_publish, timeout=5.0)
        except Exception as exc:
            raise TransportError(f"Local MQTT publish confirmation failed: {exc}") from exc
