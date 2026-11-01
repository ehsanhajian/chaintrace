import os
from pathlib import Path

from chaintrace.procfs import find_pids, read_pid

from tests.tree import add_process, socket_line


def _node(root: Path, secret: Path) -> None:
    secret.write_text("do-not-print-this-secret\n")
    add_process(
        root,
        4242,
        "geth",
        1,
        "/usr/bin/geth",
        ["/usr/bin/geth", "--datadir", "/var/lib/geth", "--authrpc.jwtsecret", "/var/lib/geth/jwtsecret", "--password", "hunter2"],
        {
            3: "socket:[1001]",
            4: "socket:[1002]",
            5: "socket:[1003]",
            6: "socket:[1004]",
            7: "/var/lib/geth/jwtsecret",
            8: str(secret),
        },
    )
    lines = [
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        socket_line("0.0.0.0", 30303, "0.0.0.0", 0, "0A", 1001),
        socket_line("127.0.0.1", 8551, "0.0.0.0", 0, "0A", 1002),
        socket_line("10.1.2.3", 30303, "18.1.2.3", 51234, "01", 1003),
        socket_line("10.1.2.3", 41000, "127.0.0.1", 8551, "01", 1004),
    ]
    net = root / "net"
    net.mkdir()
    (net / "tcp").write_text("".join(lines))


def test_snapshot_describes_the_node(tmp_path: Path) -> None:
    secret = tmp_path / "secret-file"
    root = tmp_path / "proc"
    root.mkdir()
    _node(root, secret)
    obs = read_pid(root, 4242)
    assert obs.client == "geth"
    assert obs.exe == "/usr/bin/geth"
    assert obs.ppid == 1
    assert obs.rss_bytes == 10 * (os.sysconf("SC_PAGE_SIZE") or 4096)
    assert "[redacted]" in obs.cmdline
    assert "hunter2" not in obs.cmdline
    assert "/var/lib/geth/jwtsecret" in obs.cmdline
    kinds = {conn.kind for conn in obs.connections}
    assert kinds == {"listen", "peer", "local"}
    rendered = " ".join(item.path for item in obs.files)
    assert "jwtsecret" in rendered
    assert "do-not-print-this-secret" not in rendered
    assert secret.read_text().strip() == "do-not-print-this-secret"


def test_shell_child_and_name_lookup(tmp_path: Path) -> None:
    root = tmp_path / "proc"
    root.mkdir()
    add_process(root, 7, "geth", 1, "/usr/bin/geth", ["geth"], {})
    add_process(root, 8, "bash", 7, "/bin/bash", ["bash"], {})
    add_process(root, 9, "geth", 1, "/usr/local/bin/geth", ["geth"], {})
    obs = read_pid(root, 7)
    assert [child.comm for child in obs.children] == ["bash"]
    assert find_pids(root, "geth") == [7, 9]
    assert find_pids(root, "bash") == [8]
