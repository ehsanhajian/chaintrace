"""Remember the binary, the listeners, and the unknown destinations."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from chaintrace.models import Observation


class BaselineError(ValueError):
    """The baseline file could not be read."""


@dataclass(frozen=True)
class Baseline:
    client: str
    exe: str
    unknown: frozenset[str]
    listen: frozenset[str]


_DATA_FLAGS = ("--datadir", "--data-dir", "--data-path", "--dataDir")


def datadir(cmdline: tuple[str, ...]) -> str:
    for index, arg in enumerate(cmdline):
        for flag in _DATA_FLAGS:
            if arg == flag and index + 1 < len(cmdline):
                return cmdline[index + 1]
            prefix = flag + "="
            if arg.startswith(prefix) and arg != prefix:
                return arg[len(prefix) :]
    return ""


def baseline_key(obs: Observation) -> str:
    name = obs.comm if obs.client == "unknown" else obs.client
    data = datadir(obs.cmdline)
    if data:
        return f"{name} {data}"
    return f"{name} {obs.pid}"


def _legacy_key(key: str) -> str:
    name, separator, rest = key.partition(" ")
    if separator and rest:
        return name
    return key


def home_file() -> Path:
    override = os.environ.get("CHAINTRACE_HOME")
    root = Path(override) if override else Path.home() / ".chaintrace"
    return root / "baseline.json"


def capture(obs: Observation) -> Baseline:
    return Baseline(
        client=baseline_key(obs),
        exe=obs.exe,
        unknown=frozenset(conn.remote for conn in obs.connections if conn.kind == "unknown"),
        listen=frozenset(conn.local for conn in obs.connections if conn.kind == "listen"),
    )


def load(path: Path, client: str) -> Baseline | None:
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise BaselineError(f"{path} is not a baseline file") from exc
    item = raw.get(client)
    chosen = client
    if not isinstance(item, dict):
        chosen = _legacy_key(client)
        item = raw.get(chosen) if chosen != client else None
    if not isinstance(item, dict):
        return None
    return Baseline(
        client=chosen,
        exe=str(item.get("exe", "")),
        unknown=frozenset(item.get("unknown", [])),
        listen=frozenset(item.get("listen", [])),
    )


def save(path: Path, baseline: Baseline) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    data: dict[str, object] = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise BaselineError(f"{path} is not a baseline file") from exc
        if isinstance(loaded, dict):
            data = loaded
    data[baseline.client] = {
        "exe": baseline.exe,
        "unknown": sorted(baseline.unknown),
        "listen": sorted(baseline.listen),
    }
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)
