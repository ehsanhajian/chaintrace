"""Process snapshot and findings."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OpenFile:
    path: str
    sensitive: bool
    comm: str


@dataclass(frozen=True)
class Connection:
    protocol: str
    local: str
    remote: str
    state: str
    kind: str


@dataclass(frozen=True)
class Child:
    pid: int
    comm: str
    exe: str


@dataclass(frozen=True)
class Event:
    kind: str
    pid: int
    comm: str
    path: str = ""
    remote: str = ""
    mode: str = ""


@dataclass(frozen=True)
class Observation:
    pid: int
    comm: str
    client: str
    exe: str
    state: str
    rss_bytes: int
    cpu_seconds: float
    ppid: int
    cmdline: tuple[str, ...]
    files: tuple[OpenFile, ...]
    connections: tuple[Connection, ...]
    children: tuple[Child, ...]
    events: tuple[Event, ...] = ()


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    message: str
