"""Example cloud/C2 PQC receiver for pq-edge-bridge upstream MQTT telemetry."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion

from pq_edge_bridge.crypto.envelope import ReplayProtector, unpack_and_decrypt
from pq_edge_bridge.crypto.kem import ML_KEM_768_SECRET_KEY_BYTES
from pq_edge_bridge.crypto.keys import load_key_bytes
from pq_edge_bridge.crypto.session import SessionManager
from pq_edge_bridge.crypto.signer import ML_DSA_65_PUBLIC_KEY_BYTES
from pq_edge_bridge.exceptions import CryptoError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cloud_receiver")


def main() -> None:
    parser = argparse.ArgumentParser(description="Cloud PQC telemetry receiver.")
    parser.add_argument("--broker", default="127.0.0.1", help="Upstream MQTT broker host.")
    parser.add_argument("--port", type=int, default=1883, help="Upstream MQTT broker port.")
    parser.add_argument("--topic", default="pqc/telemetry/#", help="MQTT topic filter.")
    parser.add_argument("--kem-key", type=Path, required=True, help="Cloud ML-KEM-768 secret key.")
    parser.add_argument(
        "--peer-sig-pub", type=Path, required=True, help="Edge ML-DSA-65 public key."
    )
    args = parser.parse_args()

    kem_sk = load_key_bytes(args.kem_key, expected_length=ML_KEM_768_SECRET_KEY_BYTES)
    peer_sig_pk = load_key_bytes(args.peer_sig_pub, expected_length=ML_DSA_65_PUBLIC_KEY_BYTES)
    session_mgr = SessionManager()
    replay_guard = ReplayProtector()

    def on_connect(client: mqtt.Client, *_args: Any) -> None:
        logger.info("Connected to %s:%d, subscribing to %s", args.broker, args.port, args.topic)
        client.subscribe(args.topic, qos=1)

    def on_message(_client: mqtt.Client, _userdata: Any, msg: mqtt.MQTTMessage) -> None:
        try:
            dec = unpack_and_decrypt(
                bytes(msg.payload),
                local_kem_secret_key=kem_sk,
                peer_sig_public_key=peer_sig_pk,
                replay_protector=replay_guard,
                session_manager=session_mgr,
            )
            logger.info(
                "[VERIFIED] sender=%s seq=%d topic=%s payload=%s",
                dec.header.sender_id,
                dec.header.sequence,
                dec.header.topic,
                dec.payload.decode("utf-8", errors="replace"),
            )
        except CryptoError as exc:
            logger.warning("[REJECTED] topic=%s reason=%s", msg.topic, exc)

    client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(args.broker, args.port, keepalive=30)
    client.loop_forever()


if __name__ == "__main__":
    main()
