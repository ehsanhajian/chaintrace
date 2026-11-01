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


def baseline_key(obs: Observation) -> str:
    return obs.comm if obs.client == "unknown" else obs.client


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
    if not isinstance(item, dict):
        return None
    return Baseline(
        client=client,
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
