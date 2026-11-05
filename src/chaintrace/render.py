"""Text, JSON, and markdown for one observation."""

from __future__ import annotations

import json

from chaintrace.models import Finding, KeyOpen, Observation
from chaintrace.rules import worst_severity
from chaintrace.window import Sample

_KIND_ORDER = {
    "listen": 0,
    "local": 1,
    "peer": 2,
    "expected": 3,
    "remote": 4,
    "unknown": 5,
    "metadata": 6,
}


def render_status(obs: Observation, sample: Sample | None = None) -> str:
    lines = [f"client {obs.client}", f"pid {obs.pid}", f"comm {obs.comm}"]
    if obs.exe:
        lines.append(f"exe {obs.exe}")
    if obs.state != "traced":
        lines.append(f"state {obs.state}")
        lines.append(f"rss {obs.rss_bytes}")
        lines.append(f"cpu {obs.cpu_seconds:.1f}s")
        if sample is not None:
            lines.append(f"cpu_percent {sample.cpu_percent:.1f}")
            lines.append(f"rss_delta {_signed(sample.rss_delta)}")
            lines.append(f"connections_opened {sample.opened}")
            lines.append(f"connections_closed {sample.closed}")
        lines.append(f"ppid {obs.ppid}")
        if obs.cmdline:
            lines.append("cmdline " + " ".join(obs.cmdline))
        if obs.children:
            for child in obs.children:
                lines.append(f"child {child.pid} {child.comm} {child.exe or 'unknown'}")
        else:
            lines.append("child none")
    for event in obs.events:
        if event.kind == "exec":
            lines.append(f"exec {event.path}")
        elif event.kind == "chmod":
            lines.append(f"chmod {event.path} {event.mode}")
    if obs.files:
        for item in obs.files:
            mark = " sensitive" if item.sensitive else ""
            lines.append(f"file {item.path} {item.comm}{mark}")
    else:
        lines.append("file none")
    if obs.connections:
        ordered = sorted(obs.connections, key=lambda item: (_KIND_ORDER.get(item.kind, 9), item.local, item.remote))
        for conn in ordered:
            if conn.kind == "listen" or conn.remote.endswith(":0"):
                lines.append(f"{conn.kind} {conn.local} {conn.protocol}")
            elif conn.local == "-":
                lines.append(f"{conn.kind} {conn.remote} {conn.protocol}")
            else:
                lines.append(f"{conn.kind} {conn.local} {conn.remote} {conn.protocol}")
    else:
        lines.append("connection none")
    return "\n".join(lines) + "\n"


def render_findings(findings: list[Finding]) -> str:
    if not findings:
        return "ok\n"
    lines = [f"{item.severity} {item.rule} {item.message}" for item in findings]
    if all(item.severity == "info" for item in findings):
        lines.append("ok")
    return "\n".join(lines) + "\n"


def render_check(obs: Observation, findings: list[Finding]) -> str:
    return render_status(obs) + "\n" + render_findings(findings)


def render_brief(obs: Observation, findings: list[Finding]) -> str:
    return f"client {obs.client} pid {obs.pid} {worst_severity(findings)}\n"


def render_keys(obs: Observation, opens: tuple[KeyOpen, ...], findings: list[Finding]) -> str:
    lines = [f"pid {obs.pid}", f"comm {obs.comm}"]
    if opens:
        lines.extend(f"key {item.pid} {item.comm} {item.path}" for item in opens)
    else:
        lines.append("key none")
    return "\n".join(lines) + "\n\n" + render_findings(findings)


def render_keys_json(obs: Observation, opens: tuple[KeyOpen, ...], findings: list[Finding]) -> str:
    body = {
        "pid": obs.pid,
        "comm": obs.comm,
        "client": obs.client,
        "keys": [{"pid": item.pid, "comm": item.comm, "path": item.path} for item in opens],
        "findings": [
            {"severity": item.severity, "rule": item.rule, "message": item.message} for item in findings
        ],
    }
    return json.dumps(body, indent=2) + "\n"


def render_report(obs: Observation, findings: list[Finding]) -> str:
    return (
        "# ChainTrace\n\n"
        "What this node is doing internally.\n\n"
        "## Status\n\n"
        "```\n"
        f"{render_status(obs)}"
        "```\n\n"
        "## Findings\n\n"
        "```\n"
        f"{render_findings(findings)}"
        "```\n"
    )


def _signed(value: int) -> str:
    if value > 0:
        return f"+{value}"
    return str(value)


def render_json(obs: Observation, findings: list[Finding] | None = None, sample: Sample | None = None) -> str:
    body: dict[str, object] = {
        "client": obs.client,
        "pid": obs.pid,
        "comm": obs.comm,
        "exe": obs.exe,
        "state": obs.state,
        "rss_bytes": obs.rss_bytes,
        "cpu_seconds": obs.cpu_seconds,
        "ppid": obs.ppid,
        "cmdline": list(obs.cmdline),
        "children": [{"pid": child.pid, "comm": child.comm, "exe": child.exe} for child in obs.children],
        "files": [{"path": item.path, "comm": item.comm, "sensitive": item.sensitive} for item in obs.files],
        "connections": [
            {
                "kind": conn.kind,
                "local": conn.local,
                "remote": conn.remote,
                "protocol": conn.protocol,
                "state": conn.state,
            }
            for conn in obs.connections
        ],
    }
    if sample is not None:
        body["window"] = {
            "seconds": sample.seconds,
            "cpu_percent": sample.cpu_percent,
            "rss_delta": sample.rss_delta,
            "connections_opened": sample.opened,
            "connections_closed": sample.closed,
        }
    if findings is not None:
        body["findings"] = [
            {"severity": item.severity, "rule": item.rule, "message": item.message} for item in findings
        ]
    return json.dumps(body, indent=2) + "\n"
