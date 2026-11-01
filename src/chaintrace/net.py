"""Parse /proc socket tables and classify a destination."""

from __future__ import annotations

import socket
from dataclasses import dataclass

from chaintrace.clients import Client
from chaintrace.models import Connection

METADATA_HOSTS = frozenset({"169.254.169.254", "169.254.170.2", "fd00:ec2::254"})
SUSPICIOUS_PORTS = frozenset({22, 23, 25, 445, 3389, 4444, 1337, 31337})

_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


class NetError(ValueError):
    """A socket address could not be parsed."""


@dataclass(frozen=True)
class RawSocket:
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    inode: str


def parse_proc_net(text: str, protocol: str) -> tuple[RawSocket, ...]:
    """Parse `/proc/net/tcp` or the udp, tcp6, and udp6 tables.

    The inode is the 10th column. See proc(5).
    """
    found: list[RawSocket] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 10 or ":" not in parts[1] or ":" not in parts[2]:
            continue
        try:
            local_ip, local_port = _address(parts[1])
            remote_ip, remote_port = _address(parts[2])
        except NetError:
            continue
        found.append(
            RawSocket(
                protocol=protocol,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                state=_STATES.get(parts[3].upper(), parts[3]),
                inode=parts[9],
            )
        )
    return tuple(found)


def _address(field: str) -> tuple[str, int]:
    hex_ip, _, hex_port = field.partition(":")
    if not hex_port:
        raise NetError(f"bad socket address {field}")
    return _ip(hex_ip), int(hex_port, 16)


def _ip(hex_ip: str) -> str:
    if len(hex_ip) == 8:
        raw = bytes.fromhex(hex_ip)
        return ".".join(str(b) for b in raw[::-1])
    if len(hex_ip) == 32:
        raw = bytes.fromhex(hex_ip)
        words = [raw[i : i + 4][::-1] for i in range(0, 16, 4)]
        return socket.inet_ntop(socket.AF_INET6, b"".join(words))
    raise NetError(f"bad ip length {len(hex_ip)}")


def format_endpoint(ip: str, port: int) -> str:
    if ":" in ip:
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


def split_endpoint(endpoint: str) -> tuple[str, int]:
    if endpoint.startswith("["):
        host, _, port = endpoint[1:].rpartition("]:")
        return host, int(port)
    host, _, port = endpoint.rpartition(":")
    if not host or not port:
        raise NetError(f"bad endpoint {endpoint}")
    return host, int(port)


def is_loopback(ip: str) -> bool:
    if ip == "::1":
        return True
    return ip.startswith("127.")


def is_unspecified(ip: str) -> bool:
    return ip in {"0.0.0.0", "::"}


def is_metadata(ip: str) -> bool:
    return ip in METADATA_HOSTS


def classify(raw: RawSocket, client: Client) -> str:
    listening = raw.state == "LISTEN" or raw.remote_port == 0
    if listening:
        return "listen"
    if is_metadata(raw.remote_ip):
        return "metadata"
    if is_loopback(raw.remote_ip):
        return "local"
    if not client.profiled:
        return "remote"
    if raw.remote_port in client.p2p_ports or raw.local_port in client.p2p_ports:
        return "peer"
    if raw.remote_port in client.remote_ports:
        return "expected"
    return "unknown"


def connection_from_raw(raw: RawSocket, client: Client) -> Connection:
    return Connection(
        protocol=raw.protocol,
        local=format_endpoint(raw.local_ip, raw.local_port),
        remote=format_endpoint(raw.remote_ip, raw.remote_port),
        state=raw.state,
        kind=classify(raw, client),
    )


def classify_connection(conn: Connection, client: Client) -> Connection:
    """Re-label a connection after the operator names the client."""
    if conn.local == "-":
        local_ip, local_port = "0.0.0.0", 0
    else:
        local_ip, local_port = split_endpoint(conn.local)
    remote_ip, remote_port = split_endpoint(conn.remote)
    raw = RawSocket(
        protocol=conn.protocol,
        local_ip=local_ip,
        local_port=local_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
        state=conn.state,
        inode="",
    )
    kind = classify(raw, client)
    if kind == conn.kind:
        return conn
    return Connection(conn.protocol, conn.local, conn.remote, conn.state, kind)


def suspicious_port(conn: Connection) -> bool:
    if conn.kind in {"listen", "local"}:
        return False
    try:
        remote_ip, remote_port = split_endpoint(conn.remote)
    except NetError:
        return False
    if is_loopback(remote_ip):
        return False
    return remote_port in SUSPICIOUS_PORTS
