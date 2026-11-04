"""Findings from a process snapshot or a kernel trace."""

from __future__ import annotations

from pathlib import Path

from chaintrace.baseline import Baseline
from chaintrace.clients import Client, ClientError, client_named
from chaintrace.models import Finding, Observation
from chaintrace.net import is_loopback, split_endpoint, suspicious_port

UNKNOWN_LIMIT = 5
SHELLS = frozenset(
    {
        "bash",
        "sh",
        "dash",
        "ash",
        "zsh",
        "ksh",
        "curl",
        "wget",
        "nc",
        "ncat",
        "socat",
        "python",
        "python3",
        "perl",
        "ruby",
    }
)
_PERSISTENCE = (
    "/etc/ld.so.preload",
    "/etc/crontab",
    "/etc/cron",
    "/var/spool/cron",
    "/etc/sudoers",
    "/etc/systemd/system",
    "/etc/rc.local",
)
_RANK = {"critical": 0, "warning": 1, "info": 2}


def evaluate(
    obs: Observation,
    baseline: Baseline | None = None,
    client: Client | None = None,
    unit_exe: str | None = None,
) -> list[Finding]:
    client = _profile(obs) if client is None else client
    found: list[Finding] = []
    if "(deleted)" in obs.exe:
        found.append(Finding("warning", "deleted-binary", obs.exe))
    if unit_exe and _running_exe(obs.exe) != unit_exe:
        found.append(Finding("warning", "unit-binary", f"unit {unit_exe} running {obs.exe or 'unknown'}"))
    if baseline and obs.exe and baseline.exe and obs.exe != baseline.exe:
        found.append(Finding("warning", "binary-changed", f"was {baseline.exe} now {obs.exe}"))
    for child in obs.children:
        if child.comm in SHELLS:
            found.append(Finding("critical", "shell-child", f"pid {child.pid} {child.comm}"))
    for event in obs.events:
        if event.kind == "exec":
            finding = _exec(event.path, client, obs.comm)
            if finding is not None:
                found.append(finding)
        elif event.kind == "chmod":
            found.append(_chmod(event.path, event.mode))
    for item in obs.files:
        if _persistence(item.path):
            found.append(Finding("critical", "persistence", item.path))
        elif item.sensitive:
            severity = "info" if item.comm == obs.comm or item.comm in client.comms else "warning"
            found.append(Finding(severity, "sensitive-file", item.path))
    unknown: set[str] = set()
    for conn in obs.connections:
        if conn.kind == "metadata":
            found.append(Finding("critical", "metadata-destination", conn.remote))
        elif suspicious_port(conn):
            found.append(Finding("warning", "suspicious-port", conn.remote))
        elif conn.kind == "unknown":
            unknown.add(conn.remote)
            if baseline and conn.remote not in baseline.unknown:
                found.append(Finding("warning", "new-destination", conn.remote))
            elif baseline is None:
                found.append(Finding("info", "unknown-destination", conn.remote))
        elif conn.kind == "listen":
            found.extend(_listen(conn.local, client, baseline))
    if len(unknown) >= UNKNOWN_LIMIT:
        found.append(Finding("warning", "traffic-anomaly", f"{len(unknown)} unknown destinations"))
    unique = list(dict.fromkeys(found))
    unique.sort(key=lambda item: (_RANK[item.severity], item.rule, item.message))
    return unique


def exit_code(findings: list[Finding]) -> int:
    if any(item.severity == "critical" for item in findings):
        return 2
    if any(item.severity == "warning" for item in findings):
        return 1
    return 0


def _profile(obs: Observation) -> Client:
    if obs.client == "unknown":
        return Client("unknown", frozenset({obs.comm}), frozenset(), frozenset(), frozenset())
    try:
        return client_named(obs.client)
    except ClientError:
        return Client("unknown", frozenset({obs.comm}), frozenset(), frozenset(), frozenset())


def _running_exe(exe: str) -> str:
    suffix = " (deleted)"
    if exe.endswith(suffix):
        return exe[: -len(suffix)]
    return exe


def _exec(path: str, client: Client, comm: str) -> Finding | None:
    name = Path(path).name
    if name in SHELLS:
        return Finding("critical", "unexpected-exec", path)
    if name and name not in client.comms and name != comm:
        return Finding("warning", "unexpected-exec", path)
    return None


def _chmod(path: str, mode: str) -> Finding:
    severity = "critical" if _other_writable(mode) else "warning"
    return Finding(severity, "permission-change", f"{path} mode {mode}")


def _listen(local: str, client: Client, baseline: Baseline | None) -> list[Finding]:
    found: list[Finding] = []
    try:
        ip, port = split_endpoint(local)
    except ValueError:
        return found
    if port in client.loopback_ports and not is_loopback(ip):
        found.append(Finding("warning", "exposed-port", local))
    if baseline and local not in baseline.listen:
        found.append(Finding("warning", "new-listener", local))
    return found


def _persistence(path: str) -> bool:
    if "/.ssh/authorized_keys" in path:
        return True
    for prefix in _PERSISTENCE:
        if path == prefix or path.startswith(prefix + "/") or path.startswith(prefix + "."):
            return True
    return False


def _other_writable(mode: str) -> bool:
    try:
        value = int(mode, 8) if mode.startswith("0") and len(mode) > 1 else int(mode, 10)
    except ValueError:
        return False
    return bool(value & 0o002)
