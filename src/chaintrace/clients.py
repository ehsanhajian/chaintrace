"""Client profiles shipped with the package."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

from chaintrace.models import Observation


class ClientError(ValueError):
    """The named client is not in the catalog."""


@dataclass(frozen=True)
class Client:
    name: str
    comms: frozenset[str]
    p2p_ports: frozenset[int]
    remote_ports: frozenset[int]
    loopback_ports: frozenset[int]

    @property
    def profiled(self) -> bool:
        return self.name != "unknown"


@lru_cache(maxsize=1)
def catalog() -> tuple[Client, ...]:
    raw = json.loads(files("chaintrace").joinpath("clients.json").read_text())
    clients = []
    for name, item in raw.items():
        clients.append(
            Client(
                name=name,
                comms=frozenset(item.get("comms", [])),
                p2p_ports=frozenset(item.get("p2p_ports", [])),
                remote_ports=frozenset(item.get("remote_ports", [])),
                loopback_ports=frozenset(item.get("loopback_ports", [])),
            )
        )
    return tuple(clients)


def client_named(name: str) -> Client:
    for client in catalog():
        if client.name == name:
            return client
    known = ", ".join(client.name for client in catalog())
    raise ClientError(f"unknown client {name}. known clients: {known}")


def _basename(exe: str) -> str:
    name = Path(exe).name
    suffix = " (deleted)"
    if name.endswith(suffix):
        return name[: -len(suffix)]
    return name


def recognize(comm: str, exe: str) -> Client:
    """Match the executable name first, then the process name."""
    base = _basename(exe)
    if base:
        for client in catalog():
            if base in client.comms:
                return client
    for client in catalog():
        if comm in client.comms:
            return client
    return Client("unknown", frozenset({comm} if comm else set()), frozenset(), frozenset(), frozenset())


def resolve(comm: str, exe: str, override: str | None) -> Client:
    if override:
        return client_named(override)
    return recognize(comm, exe)


def apply_client(obs: Observation, override: str | None) -> Observation:
    client = resolve(obs.comm, obs.exe, override)
    if client.name == obs.client and override is None:
        return obs
    from chaintrace.net import classify_connection

    connections = tuple(
        classify_connection(conn, client) for conn in obs.connections
    )
    return Observation(
        pid=obs.pid,
        comm=obs.comm,
        client=client.name,
        exe=obs.exe,
        state=obs.state,
        rss_bytes=obs.rss_bytes,
        cpu_seconds=obs.cpu_seconds,
        ppid=obs.ppid,
        cmdline=obs.cmdline,
        files=obs.files,
        connections=connections,
        children=obs.children,
        events=obs.events,
    )
