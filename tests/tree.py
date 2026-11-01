"""Build a /proc-shaped tree for tests."""

from __future__ import annotations

from pathlib import Path


def stat_line(
    pid: int,
    comm: str,
    ppid: int,
    *,
    state: str = "S",
    utime: int = 100,
    stime: int = 50,
    rss: int = 10,
) -> str:
    rest = ["0"] * 22
    rest[0] = state
    rest[1] = str(ppid)
    rest[11] = str(utime)
    rest[12] = str(stime)
    rest[21] = str(rss)
    return f"{pid} ({comm}) " + " ".join(rest) + "\n"


def add_process(
    root: Path,
    pid: int,
    comm: str,
    ppid: int,
    exe: str,
    cmdline: list[str],
    links: dict[int, str],
) -> None:
    base = root / str(pid)
    base.mkdir(parents=True)
    (base / "comm").write_text(comm + "\n")
    (base / "stat").write_text(stat_line(pid, comm, ppid))
    (base / "cmdline").write_bytes(b"\0".join(part.encode() for part in cmdline) + b"\0")
    (base / "exe").symlink_to(exe)
    fd_dir = base / "fd"
    fd_dir.mkdir()
    for name, target in links.items():
        (fd_dir / str(name)).symlink_to(target)


def ipv4_field(ip: str, port: int) -> str:
    parts = [int(piece) for piece in ip.split(".")]
    hex_ip = "".join(f"{piece:02X}" for piece in reversed(parts))
    return f"{hex_ip}:{port:04X}"


def socket_line(
    local_ip: str,
    local_port: int,
    remote_ip: str,
    remote_port: int,
    state: str,
    inode: int,
) -> str:
    local = ipv4_field(local_ip, local_port)
    remote = ipv4_field(remote_ip, remote_port)
    return (
        f" 0: {local} {remote} {state} 00000000:00000000 "
        f"00:00000000 00000000 0 0 {inode} 1 0000000000000000 100 0 0 10 0\n"
    )
