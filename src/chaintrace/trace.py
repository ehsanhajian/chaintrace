"""Read a kernel trace from probe text or JSON lines."""

from __future__ import annotations

import json
from pathlib import Path

from chaintrace.clients import Client, recognize
from chaintrace.models import Connection, Event, Observation, OpenFile
from chaintrace.net import RawSocket, connection_from_raw, format_endpoint, split_endpoint
from chaintrace.procfs import is_sensitive

_KINDS = {"exec", "connect", "open", "chmod"}


class TraceError(ValueError):
    """The trace file could not be read."""


def read_trace(path: Path) -> Observation:
    text = Path(path).read_text()
    body = [line.strip() for line in text.splitlines() if line.strip()]
    if not body:
        raise TraceError(f"{path} is empty")
    if body[0].startswith("{"):
        events = tuple(_json_event(line, index) for index, line in enumerate(body, start=1))
    else:
        events = tuple(_probe_events(body))
    if not events:
        raise TraceError(f"{path} has no events")
    return observe_events(events)


def observe_events(events: tuple[Event, ...]) -> Observation:
    first = events[0]
    client = recognize(first.comm, "")
    files: list[OpenFile] = []
    connections: list[Connection] = []
    seen_paths: set[str] = set()
    for event in events:
        if event.kind == "open" and event.path and event.path not in seen_paths:
            seen_paths.add(event.path)
            files.append(OpenFile(event.path, is_sensitive(event.path), event.comm))
        elif event.kind == "connect" and event.remote:
            connections.append(_connection(event.remote, client))
    files.sort(key=lambda item: (item.path, item.comm))
    connections.sort(key=lambda item: (item.kind, item.remote))
    return Observation(
        pid=first.pid,
        comm=first.comm,
        client=client.name,
        exe="",
        state="traced",
        rss_bytes=0,
        cpu_seconds=0.0,
        ppid=0,
        cmdline=(),
        files=tuple(files),
        connections=tuple(connections),
        children=(),
        events=events,
    )


def _connection(remote: str, client: Client) -> Connection:
    try:
        ip, port = split_endpoint(remote)
    except ValueError as exc:
        raise TraceError(f"bad connect destination {remote}") from exc
    raw = RawSocket("tcp", "0.0.0.0", 0, ip, port, "ESTABLISHED", "")
    labeled = connection_from_raw(raw, client)
    return Connection("tcp", "-", labeled.remote, "ESTABLISHED", labeled.kind)


def _json_event(line: str, index: int) -> Event:
    try:
        item = json.loads(line)
    except json.JSONDecodeError as exc:
        raise TraceError(f"line {index} is not json") from exc
    kind = str(item.get("kind", ""))
    if kind not in _KINDS:
        raise TraceError(f"line {index} has an unknown kind")
    return Event(
        kind=kind,
        pid=int(item.get("pid", 0)),
        comm=str(item.get("comm", "")),
        path=str(item.get("path", "")),
        remote=str(item.get("remote", "")),
        mode=str(item.get("mode", "")),
    )


def _probe_events(lines: list[str]) -> list[Event]:
    events: list[Event] = []
    for index, line in enumerate(lines, start=1):
        parts = line.split()
        if not parts or parts[0] not in _KINDS:
            continue
        if len(parts) < 4:
            raise TraceError(f"line {index} is incomplete")
        kind, pid_text, comm, *rest = parts
        try:
            pid = int(pid_text)
        except ValueError as exc:
            raise TraceError(f"line {index} has a bad pid") from exc
        if kind == "connect":
            if len(rest) != 2:
                raise TraceError(f"line {index} is a bad connect")
            try:
                remote = format_endpoint(rest[0], int(rest[1]))
            except ValueError as exc:
                raise TraceError(f"line {index} is a bad connect") from exc
            events.append(Event(kind, pid, comm, remote=remote))
        elif kind == "chmod":
            events.append(Event(kind, pid, comm, path=" ".join(rest[:-1]), mode=rest[-1]))
        else:
            events.append(Event(kind, pid, comm, path=" ".join(rest)))
    return events
