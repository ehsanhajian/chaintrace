"""Read a systemd unit with systemctl show. The unit is never started or edited."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

_NAME = re.compile(r"^[A-Za-z0-9:@_.-]+$")
_SHOW = (
    "--property=LoadState",
    "--property=MainPID",
    "--property=ExecStart",
    "--no-pager",
)


class UnitError(ValueError):
    """The systemd unit could not be read."""


@dataclass(frozen=True)
class Unit:
    name: str
    pid: int
    exe: str


def read_unit(name: str, runner=None) -> Unit:
    if not name or name.startswith("-") or _NAME.fullmatch(name) is None:
        raise UnitError(f"bad unit name {name}")
    command = ["systemctl", "show", name, *_SHOW]
    try:
        completed = (runner or subprocess.run)(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError as exc:
        raise UnitError("systemctl is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise UnitError("systemctl did not answer") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise UnitError(detail or f"unit {name} was not found")
    props = _properties(completed.stdout)
    state = props.get("LoadState", "")
    if state != "loaded":
        if state in {"", "not-found"}:
            raise UnitError(f"unit {name} was not found")
        raise UnitError(f"unit {name} is {state}")
    exe = _exec_start(props.get("ExecStart", ""))
    if not exe:
        raise UnitError(f"unit {name} has no ExecStart")
    try:
        pid = int(props.get("MainPID", "0") or "0")
    except ValueError as exc:
        raise UnitError(f"unit {name} has no running process") from exc
    return Unit(name, pid, exe)


def _properties(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            found[key] = value
    return found


def _exec_start(value: str) -> str:
    marker = "path="
    start = value.find(marker)
    if start < 0:
        return ""
    rest = value[start + len(marker) :]
    for separator in (" ;", ";"):
        end = rest.find(separator)
        if end >= 0:
            return rest[:end].strip()
    return rest.strip()
