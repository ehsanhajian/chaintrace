"""Read a /proc-shaped directory. File contents are never opened."""

from __future__ import annotations

import os
from pathlib import Path

from chaintrace.clients import recognize
from chaintrace.models import Child, Connection, Observation, OpenFile
from chaintrace.net import RawSocket, connection_from_raw, parse_proc_net
from chaintrace.redact import redact_argv

_TABLES = ("tcp", "tcp6", "udp", "udp6")
_STATE_WORDS = {
    "R": "running",
    "S": "sleeping",
    "D": "disk",
    "Z": "zombie",
    "T": "stopped",
    "t": "tracing",
    "I": "idle",
    "X": "dead",
}
_SENSITIVE = (
    "jwtsecret",
    "jwt.hex",
    "keystore",
    "utc--",
    "nodekey",
    "validator_keys",
    "mnemonic",
)


class ProcError(ValueError):
    """The process table could not be read."""


def is_sensitive(path: str) -> bool:
    lowered = path.lower()
    return any(marker in lowered for marker in _SENSITIVE)


def read_pid(proc_root: Path, pid: int) -> Observation:
    root = Path(proc_root)
    base = root / str(pid)
    if not base.is_dir():
        raise ProcError(f"pid {pid} is not in {root}")
    comm = _read_comm(base)
    exe = _read_exe(base)
    cmdline = redact_argv(_read_cmdline(base))
    letter, ppid, utime, stime, rss_pages = _read_stat(base / "stat")
    client = recognize(comm, exe)
    files = _open_files(base, comm)
    inodes = _socket_inodes(base)
    raw = _sockets(root, pid, inodes)
    connections = tuple(connection_from_raw(item, client) for item in raw)
    children = _children(root, pid)
    for child in children:
        child_base = root / str(child.pid)
        files.extend(_open_files(child_base, child.comm))
    files.sort(key=lambda item: (item.path, item.comm))
    ordered = tuple(sorted(connections, key=lambda item: (item.kind, item.local, item.remote)))
    return Observation(
        pid=pid,
        comm=comm,
        client=client.name,
        exe=exe,
        state=_STATE_WORDS.get(letter, letter),
        rss_bytes=rss_pages * _page_size(),
        cpu_seconds=round((utime + stime) / _clk_tck(), 3),
        ppid=ppid,
        cmdline=cmdline,
        files=tuple(files),
        connections=ordered,
        children=tuple(children),
    )


def find_pids(proc_root: Path, name: str) -> list[int]:
    root = Path(proc_root)
    if not root.is_dir():
        raise ProcError(f"{root} is not a process table")
    matches: list[int] = []
    for entry in root.iterdir():
        if not entry.name.isdigit() or not entry.is_dir():
            continue
        try:
            comm = _read_comm(entry)
            exe = _read_exe(entry)
        except ProcError:
            continue
        if comm == name or Path(exe).name == name:
            matches.append(int(entry.name))
    return sorted(matches)


def _read_comm(base: Path) -> str:
    path = base / "comm"
    try:
        return path.read_text().strip()
    except OSError as exc:
        raise ProcError(f"cannot read {path}") from exc


def _read_exe(base: Path) -> str:
    link = base / "exe"
    if not link.is_symlink() and not link.exists():
        return ""
    try:
        return os.readlink(link)
    except OSError as exc:
        raise ProcError(f"cannot read {link}") from exc


def _read_cmdline(base: Path) -> list[str]:
    path = base / "cmdline"
    if not path.is_file():
        return []
    raw = path.read_bytes().split(b"\0")
    return [part.decode("utf-8", "replace") for part in raw if part]


def _read_stat(path: Path) -> tuple[str, int, int, int, int]:
    if not path.is_file():
        raise ProcError(f"cannot read {path}")
    text = path.read_text()
    end = text.rfind(")")
    if end < 0:
        raise ProcError(f"bad stat line in {path}")
    rest = text[end + 1 :].split()
    if len(rest) < 22:
        raise ProcError(f"short stat line in {path}")
    return rest[0], int(rest[1]), int(rest[11]), int(rest[12]), int(rest[21])


def _open_files(base: Path, comm: str) -> list[OpenFile]:
    fd_dir = base / "fd"
    if not fd_dir.is_dir():
        return []
    found: list[OpenFile] = []
    for fd in fd_dir.iterdir():
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        if not target.startswith("/"):
            continue
        found.append(OpenFile(target, is_sensitive(target), comm))
    return found


def _socket_inodes(base: Path) -> set[str]:
    fd_dir = base / "fd"
    inodes: set[str] = set()
    if not fd_dir.is_dir():
        return inodes
    for fd in fd_dir.iterdir():
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            inodes.add(target[len("socket:[") : -1])
    return inodes


def _sockets(root: Path, pid: int, inodes: set[str]) -> list[RawSocket]:
    if not inodes:
        return []
    found: list[RawSocket] = []
    seen: set[str] = set()
    for table in _TABLES:
        protocol = "udp" if table.startswith("udp") else "tcp"
        for path in (root / str(pid) / "net" / table, root / "net" / table):
            if not path.is_file():
                continue
            for raw in parse_proc_net(path.read_text(), protocol):
                if raw.inode in inodes and raw.inode not in seen:
                    seen.add(raw.inode)
                    found.append(raw)
            break
    return found


def _children(root: Path, pid: int) -> list[Child]:
    children: list[Child] = []
    for entry in root.iterdir():
        if not entry.name.isdigit() or int(entry.name) == pid or not entry.is_dir():
            continue
        stat = entry / "stat"
        if not stat.is_file():
            continue
        try:
            _letter, ppid, *_rest = _read_stat(stat)
            comm = _read_comm(entry)
            exe = _read_exe(entry)
        except ProcError:
            continue
        if ppid == pid:
            children.append(Child(int(entry.name), comm, exe))
    children.sort(key=lambda child: child.pid)
    return children


def _page_size() -> int:
    try:
        return os.sysconf("SC_PAGE_SIZE") or 4096
    except (ValueError, OSError):
        return 4096


def _clk_tck() -> int:
    try:
        return os.sysconf("SC_CLK_TCK") or 100
    except (ValueError, OSError):
        return 100
