"""SQLite WAL-mode FIFO store-and-forward buffer for offline telemetry resilience."""

from __future__ import annotations

import asyncio
import contextlib
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from pq_edge_bridge.exceptions import BufferFullError, StorageError

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(frozen=True, slots=True)
class BufferedMessage:
    """A single persisted outbound envelope awaiting upstream acknowledgment."""

    id: int
    topic: str
    payload: bytes
    created_at_ns: int


@dataclass(frozen=True, slots=True)
class BufferStats:
    """Current occupancy statistics for the store-and-forward buffer."""

    message_count: int
    total_bytes: int
    oldest_created_at_ns: int | None
    newest_created_at_ns: int | None


class StoreAndForwardBuffer:
    """Thread-safe, WAL-mode SQLite FIFO queue with atomic dequeue-on-ack and disk quotas."""

    def __init__(
        self,
        db_path: Path | str,
        *,
        max_bytes: int = 64 * 1024 * 1024,
        max_messages: int = 100_000,
        overflow_policy: Literal["drop_oldest", "reject_new"] = "drop_oldest",
    ) -> None:
        if max_bytes < 1:
            raise ValueError("max_bytes must be >= 1")
        if max_messages < 1:
            raise ValueError("max_messages must be >= 1")
        if overflow_policy not in ("drop_oldest", "reject_new"):
            raise ValueError(f"Unsupported overflow_policy: {overflow_policy}")

        self._db_path = Path(db_path)
        self._max_bytes = max_bytes
        self._max_messages = max_messages
        self._overflow_policy = overflow_policy
        self._lock = threading.RLock()

        if str(self._db_path) != ":memory:":
            self._db_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            self._conn = sqlite3.connect(
                str(self._db_path),
                check_same_thread=False,
                isolation_level=None,
            )
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute("PRAGMA busy_timeout=5000;")
            self._conn.execute("PRAGMA temp_store=MEMORY;")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS outbound_buffer (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    topic TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    payload_bytes INTEGER NOT NULL,
                    created_at_ns INTEGER NOT NULL
                );
                """
            )
        except sqlite3.Error as exc:
            raise StorageError(
                f"Failed to initialize SQLite buffer at {self._db_path}: {exc}"
            ) from exc

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            self._conn.close()

    def __enter__(self) -> StoreAndForwardBuffer:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _current_usage(self) -> tuple[int, int]:
        row = self._conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0) FROM outbound_buffer;"
        ).fetchone()
        assert row is not None
        return int(row[0]), int(row[1])

    def enqueue(self, topic: str, payload: bytes, *, created_at_ns: int | None = None) -> int:
        """Persist a message at the tail of the FIFO queue, enforcing disk/count quotas."""
        payload_len = len(payload)
        if payload_len > self._max_bytes:
            raise BufferFullError(
                f"Single message size ({payload_len} B) exceeds max_bytes ({self._max_bytes} B)"
            )

        ts_ns = time.time_ns() if created_at_ns is None else created_at_ns
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE;")
                count, total_bytes = self._current_usage()

                if self._overflow_policy == "reject_new":
                    exceeds_msgs = count + 1 > self._max_messages
                    exceeds_bytes = total_bytes + payload_len > self._max_bytes
                    if exceeds_msgs or exceeds_bytes:
                        self._conn.execute("ROLLBACK;")
                        raise BufferFullError(
                            f"Buffer quota reached (count={count}/{self._max_messages}, "
                            f"bytes={total_bytes}/{self._max_bytes})"
                        )
                else:
                    # drop_oldest until the new message fits within both quotas
                    while (
                        count > 0
                        and (
                            count + 1 > self._max_messages
                            or total_bytes + payload_len > self._max_bytes
                        )
                    ):
                        oldest = self._conn.execute(
                            "SELECT id, payload_bytes FROM outbound_buffer ORDER BY id ASC LIMIT 1;"
                        ).fetchone()
                        if oldest is None:
                            break
                        oldest_id, oldest_bytes = int(oldest[0]), int(oldest[1])
                        self._conn.execute(
                            "DELETE FROM outbound_buffer WHERE id = ?;", (oldest_id,)
                        )
                        count -= 1
                        total_bytes -= oldest_bytes

                cur = self._conn.execute(
                    """
                    INSERT INTO outbound_buffer (topic, payload, payload_bytes, created_at_ns)
                    VALUES (?, ?, ?, ?);
                    """,
                    (topic, payload, payload_len, ts_ns),
                )
                self._conn.execute("COMMIT;")
                assert cur.lastrowid is not None
                return int(cur.lastrowid)
            except BufferFullError:
                raise
            except sqlite3.Error as exc:
                with contextlib.suppress(sqlite3.Error):
                    self._conn.execute("ROLLBACK;")
                raise StorageError(f"Failed to enqueue message: {exc}") from exc

    def peek_batch(self, limit: int = 32) -> list[BufferedMessage]:
        """Return up to ``limit`` oldest messages in strict FIFO order without removing them."""
        if limit < 1:
            return []
        with self._lock:
            try:
                rows = self._conn.execute(
                    """
                    SELECT id, topic, payload, created_at_ns
                    FROM outbound_buffer
                    ORDER BY id ASC
                    LIMIT ?;
                    """,
                    (limit,),
                ).fetchall()
            except sqlite3.Error as exc:
                raise StorageError(f"Failed to peek batch: {exc}") from exc

        return [
            BufferedMessage(
                id=int(row[0]),
                topic=str(row[1]),
                payload=bytes(row[2]),
                created_at_ns=int(row[3]),
            )
            for row in rows
        ]

    def ack(self, message_ids: Sequence[int]) -> int:
        """Atomically delete acknowledged message IDs from the buffer."""
        ids = [int(mid) for mid in message_ids]
        if not ids:
            return 0
        placeholders = ",".join("?" for _ in ids)
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE;")
                cur = self._conn.execute(
                    f"DELETE FROM outbound_buffer WHERE id IN ({placeholders});",
                    ids,
                )
                self._conn.execute("COMMIT;")
                return cur.rowcount
            except sqlite3.Error as exc:
                with contextlib.suppress(sqlite3.Error):
                    self._conn.execute("ROLLBACK;")
                raise StorageError(f"Failed to acknowledge messages: {exc}") from exc

    def stats(self) -> BufferStats:
        """Return current message count, total payload bytes, and timestamp bounds."""
        with self._lock:
            try:
                row = self._conn.execute(
                    """
                    SELECT
                        COUNT(*),
                        COALESCE(SUM(payload_bytes), 0),
                        MIN(created_at_ns),
                        MAX(created_at_ns)
                    FROM outbound_buffer;
                    """
                ).fetchone()
            except sqlite3.Error as exc:
                raise StorageError(f"Failed to query buffer stats: {exc}") from exc
        assert row is not None
        return BufferStats(
            message_count=int(row[0]),
            total_bytes=int(row[1]),
            oldest_created_at_ns=int(row[2]) if row[2] is not None else None,
            newest_created_at_ns=int(row[3]) if row[3] is not None else None,
        )

    # Async non-blocking wrappers for the asyncio bridge loop

    async def aenqueue(
        self, topic: str, payload: bytes, *, created_at_ns: int | None = None
    ) -> int:
        """Async wrapper around :meth:`enqueue`."""
        return await asyncio.to_thread(
            self.enqueue, topic, payload, created_at_ns=created_at_ns
        )

    async def apeek_batch(self, limit: int = 32) -> list[BufferedMessage]:
        """Async wrapper around :meth:`peek_batch`."""
        return await asyncio.to_thread(self.peek_batch, limit)

    async def aack(self, message_ids: Sequence[int]) -> int:
        """Async wrapper around :meth:`ack`."""
        return await asyncio.to_thread(self.ack, message_ids)

    async def astats(self) -> BufferStats:
        """Async wrapper around :meth:`stats`."""
        return await asyncio.to_thread(self.stats)

    async def aclose(self) -> None:
        """Async wrapper around :meth:`close`."""
        await asyncio.to_thread(self.close)
