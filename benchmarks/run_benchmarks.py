"""Real-world PQC latency, throughput, wire-overhead, CPU, and RSS benchmarks."""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import psutil
from rich.console import Console
from rich.table import Table

from pq_edge_bridge.crypto.envelope import pack_envelope, unpack_and_decrypt
from pq_edge_bridge.crypto.kem import decapsulate, encapsulate, generate_kem_keypair
from pq_edge_bridge.crypto.session import SessionManager
from pq_edge_bridge.crypto.signer import generate_signing_keypair, sign_message, verify_signature


@dataclass(slots=True)
class LatencyStats:
    """Latency percentiles and throughput summary."""

    name: str
    iterations: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    mean_ms: float
    ops_per_sec: float


@dataclass(slots=True)
class EnvelopeBenchmarkResult:
    """End-to-end envelope benchmark for a given mode and payload size."""

    mode: str
    payload_bytes: int
    wire_bytes: int
    overhead_bytes: int
    pack_stats: LatencyStats
    unpack_stats: LatencyStats
    rss_mib: float
    cpu_percent: float


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, round((pct / 100.0) * (len(sorted_vals) - 1)))
    return sorted_vals[idx]


def _summarize(name: str, samples_ns: list[int]) -> LatencyStats:
    samples_ms = sorted(s / 1_000_000.0 for s in samples_ns)
    total_sec = sum(samples_ns) / 1_000_000_000.0
    ops_sec = len(samples_ns) / total_sec if total_sec > 0 else 0.0
    return LatencyStats(
        name=name,
        iterations=len(samples_ns),
        p50_ms=round(_percentile(samples_ms, 50.0), 4),
        p95_ms=round(_percentile(samples_ms, 95.0), 4),
        p99_ms=round(_percentile(samples_ms, 99.0), 4),
        mean_ms=round(statistics.fmean(samples_ms), 4),
        ops_per_sec=round(ops_sec, 1),
    )


def bench_primitives(iterations: int) -> list[LatencyStats]:
    """Benchmark raw ML-KEM-768 and ML-DSA-65 operations."""
    kem_kp = generate_kem_keypair()
    sig_kp = generate_signing_keypair()
    sample_msg = os.urandom(256)

    kem_gen_ns: list[int] = []
    kem_enc_ns: list[int] = []
    kem_dec_ns: list[int] = []
    sig_gen_ns: list[int] = []
    sig_sign_ns: list[int] = []
    sig_ver_ns: list[int] = []

    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        _ = generate_kem_keypair()
        kem_gen_ns.append(time.perf_counter_ns() - t0)

        t0 = time.perf_counter_ns()
        ct, _ = encapsulate(kem_kp.public_key)
        kem_enc_ns.append(time.perf_counter_ns() - t0)

        t0 = time.perf_counter_ns()
        _ = decapsulate(kem_kp.secret_key, ct)
        kem_dec_ns.append(time.perf_counter_ns() - t0)

        t0 = time.perf_counter_ns()
        _ = generate_signing_keypair()
        sig_gen_ns.append(time.perf_counter_ns() - t0)

        t0 = time.perf_counter_ns()
        sig = sign_message(sig_kp.secret_key, sample_msg)
        sig_sign_ns.append(time.perf_counter_ns() - t0)

        t0 = time.perf_counter_ns()
        verify_signature(sig_kp.public_key, sample_msg, sig)
        sig_ver_ns.append(time.perf_counter_ns() - t0)

    return [
        _summarize("ML-KEM-768 KeyGen", kem_gen_ns),
        _summarize("ML-KEM-768 Encaps", kem_enc_ns),
        _summarize("ML-KEM-768 Decaps", kem_dec_ns),
        _summarize("ML-DSA-65 KeyGen", sig_gen_ns),
        _summarize("ML-DSA-65 Sign", sig_sign_ns),
        _summarize("ML-DSA-65 Verify", sig_ver_ns),
    ]


def bench_envelope(
    *,
    session_mode: bool,
    payload_bytes: int,
    iterations: int,
    proc: psutil.Process,
) -> EnvelopeBenchmarkResult:
    """Benchmark end-to-end envelope pack & unpack for a given mode and payload size."""
    edge_sig = generate_signing_keypair()
    cloud_kem = generate_kem_keypair()
    payload = os.urandom(payload_bytes)

    sender_session = (
        SessionManager(max_messages=1000, max_age_seconds=600.0) if session_mode else None
    )
    receiver_session = (
        SessionManager(max_messages=1000, max_age_seconds=600.0) if session_mode else None
    )

    pack_ns: list[int] = []
    unpack_ns: list[int] = []
    wire_sizes: list[int] = []

    cpu_before = proc.cpu_times()
    wall_before = time.perf_counter()

    for i in range(iterations):
        t0 = time.perf_counter_ns()
        env = pack_envelope(
            payload=payload,
            sender_id="bench-edge-01",
            topic="telemetry/imu",
            peer_kem_public_key=cloud_kem.public_key,
            local_sig_secret_key=edge_sig.secret_key,
            sequence=None if session_mode else i,
            session_manager=sender_session,
        )
        pack_ns.append(time.perf_counter_ns() - t0)
        wire_sizes.append(len(env))

        t0 = time.perf_counter_ns()
        _ = unpack_and_decrypt(
            env,
            local_kem_secret_key=cloud_kem.secret_key,
            peer_sig_public_key=edge_sig.public_key,
            session_manager=receiver_session,
        )
        unpack_ns.append(time.perf_counter_ns() - t0)

    wall_elapsed = max(1e-9, time.perf_counter() - wall_before)
    cpu_after = proc.cpu_times()
    cpu_used = (cpu_after.user - cpu_before.user) + (cpu_after.system - cpu_before.system)
    cpu_pct = round((cpu_used / wall_elapsed) * 100.0, 1)
    rss_mib = round(proc.memory_info().rss / (1024 * 1024), 2)

    avg_wire = round(statistics.fmean(wire_sizes))
    mode_label = "Session-Reuse (1000 msgs)" if session_mode else "Full Per-Message KEM"
    return EnvelopeBenchmarkResult(
        mode=mode_label,
        payload_bytes=payload_bytes,
        wire_bytes=avg_wire,
        overhead_bytes=avg_wire - payload_bytes,
        pack_stats=_summarize(f"Pack ({mode_label})", pack_ns),
        unpack_stats=_summarize(f"Unpack ({mode_label})", unpack_ns),
        rss_mib=rss_mib,
        cpu_percent=cpu_pct,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run pq-edge-bridge PQC benchmarks.")
    parser.add_argument("--iterations", type=int, default=200, help="Iterations per benchmark.")
    parser.add_argument("--json-out", type=Path, default=None, help="Optional JSON output path.")
    args = parser.parse_args()

    console = Console()
    proc = psutil.Process(os.getpid())

    console.print(
        f"[bold cyan]pq-edge-bridge Benchmark Suite[/bold cyan] | "
        f"arch={platform.machine()} | python={platform.python_version()} | "
        f"iterations={args.iterations}"
    )

    prim_results = bench_primitives(args.iterations)
    prim_table = Table(title="Cryptographic Primitive Latency")
    prim_table.add_column("Operation", style="cyan")
    prim_table.add_column("p50 (ms)", justify="right")
    prim_table.add_column("p95 (ms)", justify="right")
    prim_table.add_column("p99 (ms)", justify="right")
    prim_table.add_column("Throughput (ops/s)", justify="right", style="green")
    for r in prim_results:
        prim_table.add_row(
            r.name,
            f"{r.p50_ms:.4f}",
            f"{r.p95_ms:.4f}",
            f"{r.p99_ms:.4f}",
            f"{r.ops_per_sec:.1f}",
        )
    console.print(prim_table)

    env_results: list[EnvelopeBenchmarkResult] = []
    for payload_sz in (128, 1024, 16384):
        for session_mode in (False, True):
            env_results.append(
                bench_envelope(
                    session_mode=session_mode,
                    payload_bytes=payload_sz,
                    iterations=args.iterations,
                    proc=proc,
                )
            )

    env_table = Table(title="End-to-End Envelope Performance & Overhead")
    env_table.add_column("Mode", style="cyan")
    env_table.add_column("Payload", justify="right")
    env_table.add_column("Wire", justify="right")
    env_table.add_column("Overhead", justify="right")
    env_table.add_column("Pack p50/p99 (ms)", justify="right")
    env_table.add_column("Unpack p50/p99 (ms)", justify="right")
    env_table.add_column("RSS (MiB)", justify="right")
    env_table.add_column("CPU %", justify="right")
    for er in env_results:
        env_table.add_row(
            er.mode,
            f"{er.payload_bytes} B",
            f"{er.wire_bytes} B",
            f"+{er.overhead_bytes} B",
            f"{er.pack_stats.p50_ms:.3f} / {er.pack_stats.p99_ms:.3f}",
            f"{er.unpack_stats.p50_ms:.3f} / {er.unpack_stats.p99_ms:.3f}",
            f"{er.rss_mib:.2f}",
            f"{er.cpu_percent:.1f}%",
        )
    console.print(env_table)

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "platform": {
                "machine": platform.machine(),
                "system": platform.system(),
                "python": platform.python_version(),
            },
            "primitives": [asdict(r) for r in prim_results],
            "envelopes": [asdict(r) for r in env_results],
        }
        args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"[green]Wrote JSON benchmark report to {args.json_out}[/green]")


if __name__ == "__main__":
    main()
