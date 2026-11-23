"""Unit tests for the SQLite WAL-mode FIFO store-and-forward buffer."""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

import pytest

from pq_edge_bridge.exceptions import BufferFullError
from pq_edge_bridge.storage.buffer import StoreAndForwardBuffer

if TYPE_CHECKING:
    from pathlib import Path


def test_buffer_wal_mode_fifo_and_persistence(tmp_path: Path) -> None:
    db_path = tmp_path / "buffer.db"
    with StoreAndForwardBuffer(db_path) as buf:
        with sqlite3.connect(db_path) as conn:
            mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert str(mode).lower() == "wal"

        id1 = buf.enqueue("t/1", b"payload-1")
        id2 = buf.enqueue("t/2", b"payload-2")
        id3 = buf.enqueue("t/3", b"payload-3")
        assert id1 < id2 < id3

        batch = buf.peek_batch(limit=2)
        assert [m.payload for m in batch] == [b"payload-1", b"payload-2"]

        # Peek is non-destructive until ack()
        assert buf.stats().message_count == 3
        assert buf.ack([id1, id2]) == 2
        assert buf.stats().message_count == 1

    # Reopen and verify remaining message persisted
    with StoreAndForwardBuffer(db_path) as buf2:
        rem = buf2.peek_batch(limit=10)
        assert len(rem) == 1
        assert rem[0].id == id3
        assert rem[0].topic == "t/3"
        assert rem[0].payload == b"payload-3"


def test_buffer_quotas_drop_oldest_and_reject_new(tmp_path: Path) -> None:
    db_drop = tmp_path / "drop.db"
    with StoreAndForwardBuffer(
        db_drop, max_messages=3, max_bytes=1024, overflow_policy="drop_oldest"
    ) as buf:
        for i in range(5):
            buf.enqueue("t/a", f"m-{i}".encode())
        items = buf.peek_batch(limit=10)
        assert [m.payload for m in items] == [b"m-2", b"m-3", b"m-4"]

    db_reject = tmp_path / "reject.db"
    with StoreAndForwardBuffer(
        db_reject, max_messages=2, max_bytes=20, overflow_policy="reject_new"
    ) as buf:
        buf.enqueue("t/b", b"12345678")
        buf.enqueue("t/b", b"12345678")
        with pytest.raises(BufferFullError):
            buf.enqueue("t/b", b"12345678")


@pytest.mark.asyncio
async def test_buffer_async_operations(tmp_path: Path) -> None:
    buf = StoreAndForwardBuffer(tmp_path / "async.db")
    try:
        mid = await buf.aenqueue("telemetry/imu", b"abc")
        batch = await buf.apeek_batch(limit=5)
        assert len(batch) == 1
        assert batch[0].id == mid
        stats = await buf.astats()
        assert stats.message_count == 1
        assert stats.total_bytes == 3
        assert await buf.aack([mid]) == 1
        assert (await buf.astats()).message_count == 0
    finally:
        await buf.aclose()
