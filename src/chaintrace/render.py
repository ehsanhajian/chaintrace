"""Text, JSON, and markdown for one observation."""

from __future__ import annotations

import json

from chaintrace.models import Finding, Observation

_KIND_ORDER = {
    "listen": 0,
    "local": 1,
    "peer": 2,
    "expected": 3,
    "remote": 4,
    "unknown": 5,
    "metadata": 6,
}


def render_status(obs: Observation) -> str:
    lines = [f"client {obs.client}", f"pid {obs.pid}", f"comm {obs.comm}"]
    if obs.exe:
        lines.append(f"exe {obs.exe}")
    if obs.state != "traced":
        lines.append(f"state {obs.state}")
        lines.append(f"rss {obs.rss_bytes}")
        lines.append(f"cpu {obs.cpu_seconds:.1f}s")
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


def render_json(obs: Observation, findings: list[Finding] | None = None) -> str:
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
    if findings is not None:
        body["findings"] = [
            {"severity": item.severity, "rule": item.rule, "message": item.message} for item in findings
        ]
    return json.dumps(body, indent=2) + "\n"
