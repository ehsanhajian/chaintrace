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
    allowed_hosts: frozenset[str] = frozenset()

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


def load_profile(path: Path) -> Client:
    """Read one client profile from a local JSON file."""
    file = Path(path)
    if not file.is_file():
        raise ClientError(f"profile {file} is not a file")
    try:
        raw = json.loads(file.read_text())
    except json.JSONDecodeError as exc:
        raise ClientError(f"profile {file} is not json") from exc
    if not isinstance(raw, dict):
        raise ClientError(f"profile {file} must be an object")
    comm = raw.get("comm")
    if not isinstance(comm, str) or not comm or "/" in comm or " " in comm:
        raise ClientError("profile comm must be a process name")
    return Client(
        name=comm,
        comms=frozenset({comm}),
        p2p_ports=_ports(raw.get("p2p_ports", []), "p2p_ports"),
        remote_ports=frozenset(),
        loopback_ports=_ports(raw.get("loopback_ports", []), "loopback_ports"),
        allowed_hosts=_hosts(raw.get("allowed_hosts", [])),
    )


def matches(client: Client, comm: str, exe: str) -> bool:
    base = _basename(exe)
    if base and base in client.comms:
        return True
    return comm in client.comms


def resolve(comm: str, exe: str, override: str | None, profile: Client | None = None) -> Client:
    if profile is not None and matches(profile, comm, exe):
        return profile
    if override:
        return client_named(override)
    return recognize(comm, exe)


def active_profile(profile: Client | None, obs: Observation) -> Client | None:
    if profile is not None and matches(profile, obs.comm, obs.exe):
        return profile
    return None


def apply_client(obs: Observation, override: str | None, profile: Client | None = None) -> Observation:
    client = resolve(obs.comm, obs.exe, override, profile)
    if client is not profile and override is None and client.name == obs.client:
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


def _ports(value: object, label: str) -> frozenset[int]:
    if not isinstance(value, list):
        raise ClientError(f"profile {label} must be a list of ports")
    ports: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or not 1 <= item <= 65535:
            raise ClientError(f"profile {label} has a bad port")
        ports.append(item)
    return frozenset(ports)


def _hosts(value: object) -> frozenset[str]:
    from chaintrace.net import NetError, host_key

    if not isinstance(value, list):
        raise ClientError("profile allowed_hosts must be a list of addresses")
    hosts: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ClientError("profile allowed_hosts must be a list of addresses")
        try:
            hosts.append(host_key(item))
        except NetError as exc:
            raise ClientError(f"profile allowed host {item} is not an address") from exc
    return frozenset(hosts)
