"""Pydantic v2 configuration models for pq-edge-bridge."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from pq_edge_bridge.exceptions import ConfigurationError


class CryptoConfig(BaseModel):
    """Post-quantum cryptographic parameters and key paths."""

    kem_algorithm: Literal["ML-KEM-768"] = "ML-KEM-768"
    sig_algorithm: Literal["ML-DSA-65"] = "ML-DSA-65"
    session_mode: bool = True
    session_max_messages: int = Field(default=1000, ge=1)
    session_max_age_seconds: float = Field(default=600.0, gt=0.0)
    max_cached_sessions: int = Field(default=256, ge=1)
    max_clock_skew_seconds: float = Field(default=300.0, gt=0.0)
    replay_window_size: int = Field(default=1024, ge=64)
    local_kem_secret_key_path: Path | None = None
    local_sig_secret_key_path: Path | None = None
    peer_kem_public_key_path: Path | None = None
    peer_sig_public_key_path: Path | None = None


class StorageConfig(BaseModel):
    """SQLite WAL-mode store-and-forward buffer configuration."""

    db_path: Path = Path("pq_edge_bridge.db")
    max_bytes: int = Field(default=64 * 1024 * 1024, ge=4096)
    max_messages: int = Field(default=100_000, ge=1)
    overflow_policy: Literal["drop_oldest", "reject_new"] = "drop_oldest"


class MqttConfig(BaseModel):
    """Local and upstream MQTT broker configuration."""

    enabled: bool = True
    local_host: str = "127.0.0.1"
    local_port: int = Field(default=1883, ge=1, le=65535)
    upstream_host: str = "127.0.0.1"
    upstream_port: int = Field(default=1883, ge=1, le=65535)
    upstream_tls: bool = False
    upstream_ca_certs: Path | None = None
    upstream_username: str | None = None
    upstream_password: str | None = None
    local_telemetry_topics: list[str] = Field(default_factory=lambda: ["telemetry/#"])
    upstream_telemetry_prefix: str = "pqc/telemetry"
    upstream_command_topics: list[str] = Field(default_factory=lambda: ["pqc/cmd/#"])
    local_command_prefix: str = "cmd"
    qos: Literal[0, 1, 2] = 1
    keepalive_seconds: int = Field(default=30, ge=5, le=3600)
    reconnect_min_delay: float = Field(default=1.0, gt=0.0)
    reconnect_max_delay: float = Field(default=30.0, gt=0.0)


class Ros2Config(BaseModel):
    """Optional ROS 2 / DDS bridge configuration."""

    enabled: bool = False
    node_name: str = "pq_edge_bridge_node"
    inbound_topics: list[str] = Field(default_factory=lambda: ["/telemetry/raw"])
    outbound_command_topics: list[str] = Field(default_factory=lambda: ["/cmd/raw"])
    upstream_topic_prefix: str = "pqc/ros2"
    qos_depth: int = Field(default=10, ge=1)


class ObservabilityConfig(BaseModel):
    """Optional localhost HTTP endpoint for /healthz and Prometheus /metrics."""

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = Field(default=9108, ge=0, le=65535)


class BridgeConfig(BaseModel):
    """Top-level configuration for pq-edge-bridge."""

    node_id: str = Field(default="edge-node-01", min_length=1, max_length=64)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    flush_batch_size: int = Field(default=32, ge=1, le=1024)
    flush_interval_seconds: float = Field(default=0.25, gt=0.0)
    crypto: CryptoConfig = Field(default_factory=CryptoConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    mqtt: MqttConfig = Field(default_factory=MqttConfig)
    ros2: Ros2Config = Field(default_factory=Ros2Config)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)

    @field_validator("node_id")
    @classmethod
    def _validate_node_id(cls, value: str) -> str:
        encoded = value.encode("utf-8")
        if not (1 <= len(encoded) <= 64):
            raise ValueError("node_id UTF-8 encoding must be between 1 and 64 bytes")
        return value

    @classmethod
    def from_yaml(cls, path: Path) -> BridgeConfig:
        """Load and validate configuration from a YAML file with optional env overrides."""
        if not path.is_file():
            raise ConfigurationError(f"Configuration file not found: {path}")
        try:
            raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ConfigurationError(f"Invalid YAML in {path}: {exc}") from exc
        if raw is None:
            raw = {}
        if not isinstance(raw, dict):
            raise ConfigurationError(f"Configuration root in {path} must be a mapping")

        # Allow environment variable overrides for common deployment secrets/endpoints
        if env_node := os.environ.get("PQ_BRIDGE_NODE_ID"):
            raw["node_id"] = env_node
        if env_up_host := os.environ.get("PQ_BRIDGE_UPSTREAM_HOST"):
            raw.setdefault("mqtt", {})["upstream_host"] = env_up_host
        if env_up_port := os.environ.get("PQ_BRIDGE_UPSTREAM_PORT"):
            raw.setdefault("mqtt", {})["upstream_port"] = int(env_up_port)
        if env_up_user := os.environ.get("PQ_BRIDGE_UPSTREAM_USERNAME"):
            raw.setdefault("mqtt", {})["upstream_username"] = env_up_user
        if env_up_pass := os.environ.get("PQ_BRIDGE_UPSTREAM_PASSWORD"):
            raw.setdefault("mqtt", {})["upstream_password"] = env_up_pass

        try:
            return cls.model_validate(raw)
        except Exception as exc:
            raise ConfigurationError(f"Configuration validation failed: {exc}") from exc
