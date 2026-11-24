"""Typer CLI for pq-edge-bridge: keygen, encrypt, decrypt, verify, inspect, and daemon run."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.console import Console
from rich.table import Table

from pq_edge_bridge import __version__
from pq_edge_bridge.bridge import BridgeKeyMaterial, TelemetryBridge
from pq_edge_bridge.config import BridgeConfig
from pq_edge_bridge.crypto.envelope import (
    pack_envelope,
    parse_envelope_header,
    unpack_and_decrypt,
    verify_envelope,
)
from pq_edge_bridge.crypto.kem import (
    ML_KEM_768_PUBLIC_KEY_BYTES,
    ML_KEM_768_SECRET_KEY_BYTES,
)
from pq_edge_bridge.crypto.keys import (
    generate_node_keypairs,
    load_key_bytes,
    public_key_fingerprint,
)
from pq_edge_bridge.crypto.signer import (
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SECRET_KEY_BYTES,
)
from pq_edge_bridge.exceptions import PQBridgeError
from pq_edge_bridge.observability import ObservabilityServer
from pq_edge_bridge.storage.buffer import StoreAndForwardBuffer
from pq_edge_bridge.transport.mqtt_adapter import MqttBridgeTransport
from pq_edge_bridge.transport.ros2_adapter import Ros2BridgeTransport

if TYPE_CHECKING:
    from pq_edge_bridge.transport.base import BaseTransport

app = typer.Typer(
    name="pq-edge-bridge",
    help="Post-Quantum Telemetry Bridge for Edge, IoT, and Robotics (ML-KEM-768 + ML-DSA-65).",
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"pq-edge-bridge {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Print version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """pq-edge-bridge CLI."""


@app.command()
def keygen(
    output_dir: Path = typer.Option(
        Path("./keys"),
        "--output-dir",
        "-o",
        help="Directory to write generated ML-KEM-768 and ML-DSA-65 keypairs.",
    ),
    prefix: str = typer.Option(
        "node",
        "--prefix",
        "-p",
        help="Filename prefix for generated keys (e.g. edge-gw-01).",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing key files if present.",
    ),
) -> None:
    """Generate ML-KEM-768 and ML-DSA-65 keypairs with strict chmod 600 on private keys."""
    try:
        paths = generate_node_keypairs(output_dir, prefix=prefix, overwrite=force)
    except PQBridgeError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    kem_fp = public_key_fingerprint(paths["kem_public"].read_bytes())
    sig_fp = public_key_fingerprint(paths["sig_public"].read_bytes())

    table = Table(title=f"Generated PQC Keypairs ({prefix})")
    table.add_column("Key Type", style="cyan")
    table.add_column("Algorithm", style="green")
    table.add_column("Path")
    table.add_column("Mode", style="yellow")
    table.add_column("SHA-256 Fingerprint", style="magenta")
    table.add_row("KEM Public", "ML-KEM-768", str(paths["kem_public"]), "0644", kem_fp)
    table.add_row("KEM Secret", "ML-KEM-768", str(paths["kem_secret"]), "0600", "-")
    table.add_row("Signing Public", "ML-DSA-65", str(paths["sig_public"]), "0644", sig_fp)
    table.add_row("Signing Secret", "ML-DSA-65", str(paths["sig_secret"]), "0600", "-")
    console.print(table)


@app.command()
def encrypt(
    peer_kem_pub: Path = typer.Option(..., "--peer-kem-pub", help="Peer ML-KEM-768 public key."),
    sig_key: Path = typer.Option(..., "--sig-key", help="Local ML-DSA-65 secret key."),
    sender_id: str = typer.Option("edge-node-01", "--sender-id", help="Sender identifier."),
    topic: str = typer.Option("telemetry/raw", "--topic", help="Telemetry topic."),
    sequence: int = typer.Option(0, "--sequence", help="Monotonic sequence number."),
    input_file: Path | None = typer.Option(None, "--in", "-i", help="Plaintext input file."),
    message: str | None = typer.Option(None, "--message", "-m", help="Inline UTF-8 payload."),
    output_file: Path = typer.Option(..., "--out", "-o", help="Output PQC envelope file."),
) -> None:
    """Encrypt and sign a payload into a pq-edge-bridge binary envelope."""
    if (input_file is None) == (message is None):
        err_console.print("[red]Error:[/red] Provide exactly one of --in or --message.")
        raise typer.Exit(code=2)

    try:
        payload = (
            input_file.read_bytes()
            if input_file is not None
            else message.encode("utf-8")  # type: ignore[union-attr]
        )
        kem_pk = load_key_bytes(peer_kem_pub, expected_length=ML_KEM_768_PUBLIC_KEY_BYTES)
        sig_sk = load_key_bytes(sig_key, expected_length=ML_DSA_65_SECRET_KEY_BYTES)
        envelope = pack_envelope(
            payload=payload,
            sender_id=sender_id,
            topic=topic,
            peer_kem_public_key=kem_pk,
            local_sig_secret_key=sig_sk,
            sequence=sequence,
        )
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_bytes(envelope)
    except PQBridgeError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[green]Encrypted & signed[/green] {len(payload)} B -> {output_file} ({len(envelope)} B)"
    )


@app.command()
def decrypt(
    kem_key: Path = typer.Option(..., "--kem-key", help="Local ML-KEM-768 secret key."),
    peer_sig_pub: Path = typer.Option(..., "--peer-sig-pub", help="Peer ML-DSA-65 public key."),
    input_file: Path = typer.Option(..., "--in", "-i", help="Input PQC envelope file."),
    output_file: Path | None = typer.Option(
        None, "--out", "-o", help="Write decrypted plaintext to file (default: stdout)."
    ),
) -> None:
    """Verify ML-DSA-65 signature and decrypt a pq-edge-bridge binary envelope."""
    try:
        raw = input_file.read_bytes()
        kem_sk = load_key_bytes(kem_key, expected_length=ML_KEM_768_SECRET_KEY_BYTES)
        sig_pk = load_key_bytes(peer_sig_pub, expected_length=ML_DSA_65_PUBLIC_KEY_BYTES)
        decrypted = unpack_and_decrypt(
            raw,
            local_kem_secret_key=kem_sk,
            peer_sig_public_key=sig_pk,
        )
    except PQBridgeError as exc:
        err_console.print(f"[red]Verification/Decryption failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_bytes(decrypted.payload)
        console.print(f"[green]Decrypted[/green] {len(decrypted.payload)} B -> {output_file}")
    else:
        sys.stdout.buffer.write(decrypted.payload)
        sys.stdout.buffer.flush()


@app.command()
def verify(
    peer_sig_pub: Path = typer.Option(..., "--peer-sig-pub", help="Peer ML-DSA-65 public key."),
    input_file: Path = typer.Option(..., "--in", "-i", help="Input PQC envelope file."),
) -> None:
    """Verify the ML-DSA-65 signature of a PQC envelope without decrypting."""
    try:
        raw = input_file.read_bytes()
        sig_pk = load_key_bytes(peer_sig_pub, expected_length=ML_DSA_65_PUBLIC_KEY_BYTES)
        hdr = verify_envelope(raw, peer_sig_public_key=sig_pk)
    except PQBridgeError as exc:
        err_console.print(f"[red]Signature invalid:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[green]VALID ML-DSA-65 signature[/green] | sender={hdr.sender_id} "
        f"topic={hdr.topic} seq={hdr.sequence} bytes={hdr.total_bytes}"
    )


@app.command()
def inspect(
    input_file: Path = typer.Option(..., "--in", "-i", help="Input PQC envelope file."),
) -> None:
    """Inspect wire metadata of a pq-edge-bridge envelope without decrypting."""
    try:
        hdr = parse_envelope_header(input_file.read_bytes())
    except PQBridgeError as exc:
        err_console.print(f"[red]Invalid envelope:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title="PQC Envelope Header")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("Protocol Version", f"0x{hdr.version:02x}")
    table.add_row("Mode", "Session Reuse" if hdr.is_session_mode else "Full Per-Message KEM")
    table.add_row("Sender ID", hdr.sender_id)
    table.add_row("Topic", hdr.topic)
    table.add_row("Timestamp (ns)", str(hdr.timestamp_ns))
    table.add_row("Sequence", str(hdr.sequence))
    table.add_row("Session ID", hdr.session_id.hex())
    table.add_row("KEM Ciphertext", f"{hdr.kem_ct_len} B")
    table.add_row("AEAD Ciphertext+Tag", f"{hdr.ciphertext_len} B")
    table.add_row("ML-DSA-65 Signature", f"{hdr.signature_len} B")
    table.add_row("Total Envelope Size", f"{hdr.total_bytes} B")
    console.print(table)


@app.command("init-config")
def init_config(
    out: Path = typer.Option(
        Path("config.yaml"),
        "--out",
        "-o",
        help="Destination path for the generated YAML configuration file.",
    ),
    node_id: str = typer.Option("edge-gw-01", "--node-id", help="Edge node identifier."),
    keys_dir: Path = typer.Option(Path("./keys"), "--keys-dir", help="Key directory path."),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing file."),
) -> None:
    """Generate a production-ready starter config.yaml."""
    if out.exists() and not force:
        err_console.print(f"[red]Error:[/red] {out} already exists (use --force to overwrite).")
        raise typer.Exit(code=1)

    template = f"""# pq-edge-bridge configuration (Corax CoLAB)
node_id: "{node_id}"
log_level: "INFO"
flush_batch_size: 32
flush_interval_seconds: 0.25

crypto:
  session_mode: true
  session_max_messages: 1000
  session_max_age_seconds: 600.0
  max_clock_skew_seconds: 300.0
  replay_window_size: 1024
  local_kem_secret_key_path: "{keys_dir}/{node_id}.kem.key"
  local_sig_secret_key_path: "{keys_dir}/{node_id}.sig.key"
  peer_kem_public_key_path: "{keys_dir}/cloud.kem.pub"
  peer_sig_public_key_path: "{keys_dir}/cloud.sig.pub"

storage:
  db_path: "./pq_edge_bridge.db"
  max_bytes: 67108864
  max_messages: 100000
  overflow_policy: "drop_oldest"

mqtt:
  enabled: true
  local_host: "127.0.0.1"
  local_port: 1883
  upstream_host: "127.0.0.1"
  upstream_port: 1883
  upstream_tls: false
  local_telemetry_topics:
    - "telemetry/#"
  upstream_telemetry_prefix: "pqc/telemetry"
  upstream_command_topics:
    - "pqc/cmd/#"
  local_command_prefix: "cmd"
  qos: 1

ros2:
  enabled: false
  node_name: "pq_edge_bridge_node"
  inbound_topics:
    - "/telemetry/raw"
  outbound_command_topics:
    - "/cmd/raw"
  upstream_topic_prefix: "pqc/ros2"
  qos_depth: 10

observability:
  enabled: false
  host: "127.0.0.1"
  port: 9108
"""
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(template, encoding="utf-8")
    console.print(f"[green]Wrote starter configuration[/green] -> {out}")


@app.command("buffer-stats")
def buffer_stats(
    db_path: Path = typer.Option(
        Path("./pq_edge_bridge.db"),
        "--db",
        help="Path to the SQLite WAL store-and-forward database.",
    ),
) -> None:
    """Inspect queue occupancy of a pq-edge-bridge SQLite WAL buffer."""
    if not db_path.is_file():
        err_console.print(f"[red]Error:[/red] Database file not found: {db_path}")
        raise typer.Exit(code=1)

    with StoreAndForwardBuffer(db_path) as buf:
        st = buf.stats()

    table = Table(title=f"Store-and-Forward Buffer ({db_path})")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_row("Queued Messages", str(st.message_count))
    table.add_row("Queued Payload Bytes", f"{st.total_bytes:,} B")
    table.add_row(
        "Oldest Timestamp (ns)",
        str(st.oldest_created_at_ns) if st.oldest_created_at_ns is not None else "-",
    )
    table.add_row(
        "Newest Timestamp (ns)",
        str(st.newest_created_at_ns) if st.newest_created_at_ns is not None else "-",
    )
    console.print(table)


@app.command()
def run(
    config_file: Path = typer.Option(
        ...,
        "--config",
        "-c",
        help="Path to YAML configuration file.",
    ),
) -> None:
    """Run the pq-edge-bridge async daemon."""
    try:
        cfg = BridgeConfig.from_yaml(config_file)
    except PQBridgeError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    logging.basicConfig(
        level=getattr(logging, cfg.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    try:
        if (
            cfg.crypto.local_kem_secret_key_path is None
            or cfg.crypto.local_sig_secret_key_path is None
            or cfg.crypto.peer_kem_public_key_path is None
            or cfg.crypto.peer_sig_public_key_path is None
        ):
            raise PQBridgeError("All four key paths must be configured under crypto.*_key_path")

        keys = BridgeKeyMaterial(
            local_kem_secret_key=load_key_bytes(
                cfg.crypto.local_kem_secret_key_path,
                expected_length=ML_KEM_768_SECRET_KEY_BYTES,
            ),
            local_sig_secret_key=load_key_bytes(
                cfg.crypto.local_sig_secret_key_path,
                expected_length=ML_DSA_65_SECRET_KEY_BYTES,
            ),
            peer_kem_public_key=load_key_bytes(
                cfg.crypto.peer_kem_public_key_path,
                expected_length=ML_KEM_768_PUBLIC_KEY_BYTES,
            ),
            peer_sig_public_key=load_key_bytes(
                cfg.crypto.peer_sig_public_key_path,
                expected_length=ML_DSA_65_PUBLIC_KEY_BYTES,
            ),
        )
    except PQBridgeError as exc:
        err_console.print(f"[red]Key loading error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    async def _run_bridge() -> None:
        if not cfg.mqtt.enabled and not cfg.ros2.enabled:
            raise PQBridgeError(
                "At least one transport (mqtt.enabled or ros2.enabled) must be true"
            )

        buffer = StoreAndForwardBuffer(
            cfg.storage.db_path,
            max_bytes=cfg.storage.max_bytes,
            max_messages=cfg.storage.max_messages,
            overflow_policy=cfg.storage.overflow_policy,
        )
        mqtt_transport = (
            MqttBridgeTransport(cfg.mqtt, node_id=cfg.node_id) if cfg.mqtt.enabled else None
        )
        ros2_transport = (
            Ros2BridgeTransport(cfg.ros2, upstream_sink=mqtt_transport)
            if cfg.ros2.enabled
            else None
        )

        primary_transport: BaseTransport
        if mqtt_transport is not None:
            primary_transport = mqtt_transport
        else:
            assert ros2_transport is not None
            primary_transport = ros2_transport

        bridge = TelemetryBridge(
            config=cfg,
            keys=keys,
            transport=primary_transport,
            buffer=buffer,
        )
        obs_server = (
            ObservabilityServer(
                bridge,
                host=cfg.observability.host,
                port=cfg.observability.port,
            )
            if cfg.observability.enabled
            else None
        )

        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop_event.set)

        await bridge.start()
        if obs_server is not None:
            await obs_server.start()
        if mqtt_transport is not None and ros2_transport is not None:
            await ros2_transport.start(
                on_local_telemetry=bridge.handle_local_telemetry,
                on_upstream_command=bridge.handle_upstream_command,
            )

        await stop_event.wait()

        if obs_server is not None:
            await obs_server.stop()
        if mqtt_transport is not None and ros2_transport is not None:
            await ros2_transport.stop()
        await bridge.stop()

    asyncio.run(_run_bridge())


if __name__ == "__main__":
    app()
