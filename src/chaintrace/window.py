"""Compare two reads of the same process."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from chaintrace.clients import apply_client
from chaintrace.models import Connection, Observation
from chaintrace.procfs import ProcError, read_pid


@dataclass(frozen=True)
class Sample:
    seconds: int
    cpu_percent: float
    rss_delta: int
    opened: int
    closed: int


def compare(before: Observation, after: Observation, seconds: int) -> Sample:
    cpu_percent = (after.cpu_seconds - before.cpu_seconds) / seconds * 100
    opened, closed = _connection_delta(before.connections, after.connections)
    return Sample(
        seconds=seconds,
        cpu_percent=round(cpu_percent, 1),
        rss_delta=after.rss_bytes - before.rss_bytes,
        opened=opened,
        closed=closed,
    )


def read_window(
    proc: Path,
    pid: int,
    seconds: int,
    client: str | None,
    pause=time.sleep,
) -> tuple[Observation, Sample]:
    if seconds < 1 or seconds > 300:
        raise ProcError("window must be from 1 to 300")
    before = apply_client(read_pid(proc, pid), client)
    pause(seconds)
    try:
        after = apply_client(read_pid(proc, pid), client)
    except ProcError as exc:
        raise ProcError(f"pid {pid} exited during the window") from exc
    return after, compare(before, after, seconds)


def _connection_delta(before: tuple[Connection, ...], after: tuple[Connection, ...]) -> tuple[int, int]:
    first = Counter(_key(item) for item in before)
    second = Counter(_key(item) for item in after)
    opened = sum((second - first).values())
    closed = sum((first - second).values())
    return opened, closed


def _key(conn: Connection) -> tuple[str, str, str]:
    return (conn.protocol, conn.local, conn.remote)
