# Operator Manual — `pq-edge-bridge`

**Organization:** Corax CoLAB  
**Author:** Pelle Nyberg (`@PelleNybe`)

---

## 1. Prerequisites & Installation

### 1.1 Build `liboqs` (x86_64 & ARM64)
Run the reproducible build script (supports Ubuntu/Debian x86_64 and ARM64 such as Raspberry Pi 5 / NVIDIA Jetson):

```bash
chmod +x deploy/scripts/install_liboqs.sh
./deploy/scripts/install_liboqs.sh
```

### 1.2 Install `pq-edge-bridge`
```bash
pip install .
# Optional ROS 2 support (inside a sourced ROS 2 environment):
# pip install ".[ros2]"
```

---

## 2. Key Provisioning (`chmod 600`)

Generate separate ML-KEM-768 and ML-DSA-65 keypairs for the **edge node** and the **cloud/upstream** endpoint:

```bash
pq-edge-bridge keygen --output-dir /etc/pq-edge-bridge/keys --prefix edge-01
pq-edge-bridge keygen --output-dir /tmp/cloud-keys --prefix cloud
```

Exchange **only `.pub` files** between peers:
- Copy `cloud.kem.pub` and `cloud.sig.pub` to `/etc/pq-edge-bridge/keys/` on the edge device.
- Copy `edge-01.kem.pub` and `edge-01.sig.pub` to the cloud receiver.

Private keys (`*.key`) are created atomically with `0600` permissions and must never leave their host.

---

## 3. Configuration (`config.yaml`)

Generate a starter configuration file with:

```bash
pq-edge-bridge init-config --out /etc/pq-edge-bridge/config.yaml --node-id edge-gw-01 --keys-dir /etc/pq-edge-bridge/keys
```

Or customize from [examples/config.mqtt.yaml](../examples/config.mqtt.yaml) / [examples/config.ros2.yaml](../examples/config.ros2.yaml):

```yaml
node_id: "edge-gw-01"
log_level: "INFO"
flush_batch_size: 32
flush_interval_seconds: 0.25

crypto:
  session_mode: true
  session_max_messages: 1000
  session_max_age_seconds: 600.0
  max_clock_skew_seconds: 300.0
  replay_window_size: 1024
  local_kem_secret_key_path: /etc/pq-edge-bridge/keys/edge-01.kem.key
  local_sig_secret_key_path: /etc/pq-edge-bridge/keys/edge-01.sig.key
  peer_kem_public_key_path: /etc/pq-edge-bridge/keys/cloud.kem.pub
  peer_sig_public_key_path: /etc/pq-edge-bridge/keys/cloud.sig.pub

storage:
  db_path: /var/lib/pq-edge-bridge/buffer.db
  max_bytes: 67108864        # 64 MiB
  max_messages: 100000
  overflow_policy: "drop_oldest"

mqtt:
  enabled: true
  local_host: "127.0.0.1"
  local_port: 1883
  upstream_host: "broker.example.com"
  upstream_port: 8883
  upstream_tls: true
  local_telemetry_topics:
    - "telemetry/#"
  upstream_telemetry_prefix: "pqc/telemetry"
  upstream_command_topics:
    - "pqc/cmd/#"
  local_command_prefix: "cmd"
  qos: 1
```

Environment variable overrides:
- `PQ_BRIDGE_NODE_ID`
- `PQ_BRIDGE_UPSTREAM_HOST`
- `PQ_BRIDGE_UPSTREAM_PORT`
- `PQ_BRIDGE_UPSTREAM_USERNAME`
- `PQ_BRIDGE_UPSTREAM_PASSWORD`

---

## 4. Running as a Hardened Systemd Service

```bash
sudo useradd --system --home-dir /var/lib/pq-edge-bridge --create-home pqbridge
sudo mkdir -p /etc/pq-edge-bridge/keys
sudo chown -R pqbridge:pqbridge /etc/pq-edge-bridge /var/lib/pq-edge-bridge
sudo cp deploy/systemd/pq-edge-bridge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pq-edge-bridge
sudo journalctl -u pq-edge-bridge -f
```

---

## 5. Multi-Arch Docker Deployment

```bash
docker build -f deploy/docker/Dockerfile -t ghcr.io/pellenybe/pq-edge-bridge:latest .
docker run --rm \
  -v /etc/pq-edge-bridge:/etc/pq-edge-bridge:ro \
  -v pqbridge-data:/var/lib/pq-edge-bridge \
  ghcr.io/pellenybe/pq-edge-bridge:latest \
  run --config /etc/pq-edge-bridge/config.yaml
```

---

## 6. Monitoring & Cloud Receiver

Inspect the SQLite WAL store-and-forward queue depth at any time:

```bash
pq-edge-bridge buffer-stats --db /var/lib/pq-edge-bridge/buffer.db
```

Enable the optional localhost Prometheus `/metrics` & `/healthz` endpoint in `config.yaml` for Grafana or Docker healthchecks:

```yaml
observability:
  enabled: true
  host: "127.0.0.1"
  port: 9108
```

Run the reference cloud-side receiver ([examples/cloud_receiver.py](../examples/cloud_receiver.py)) to verify and decrypt upstream telemetry:

```bash
python examples/cloud_receiver.py \
  --broker broker.example.com --port 1883 \
  --kem-key ./keys/cloud.kem.key \
  --peer-sig-pub ./keys/edge-01.sig.pub
```
