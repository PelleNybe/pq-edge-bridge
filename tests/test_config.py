"""Unit tests for Pydantic v2 configuration loading and environment overrides."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pq_edge_bridge.config import BridgeConfig
from pq_edge_bridge.exceptions import ConfigurationError

if TYPE_CHECKING:
    from pathlib import Path


def test_config_from_yaml_and_env_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(
        """
node_id: "yaml-node"
mqtt:
  upstream_host: "yaml.example.com"
  upstream_port: 1883
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("PQ_BRIDGE_NODE_ID", "env-node-override")
    monkeypatch.setenv("PQ_BRIDGE_UPSTREAM_HOST", "env.example.com")
    monkeypatch.setenv("PQ_BRIDGE_UPSTREAM_PORT", "8883")

    cfg = BridgeConfig.from_yaml(cfg_path)
    assert cfg.node_id == "env-node-override"
    assert cfg.mqtt.upstream_host == "env.example.com"
    assert cfg.mqtt.upstream_port == 8883


def test_config_invalid_yaml_and_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="not found"):
        BridgeConfig.from_yaml(tmp_path / "missing.yaml")

    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("- not a mapping\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="must be a mapping"):
        BridgeConfig.from_yaml(bad_yaml)
