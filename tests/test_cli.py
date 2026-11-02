import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from chaintrace import __version__

ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str, home: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    env["CHAINTRACE_HOME"] = str(home or Path("/tmp/chaintrace-empty"))
    return subprocess.run(
        [sys.executable, "-m", "chaintrace", *args],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
    )


def test_version() -> None:
    result = _run("--version")
    assert result.returncode == 0
    assert result.stdout.strip() == f"chaintrace {__version__}"


def test_example_node_is_ok() -> None:
    result = _run("check", "--proc", "examples/geth", "--pid", "4242", "--no-baseline")
    assert result.returncode == 0, result.stderr + result.stdout
    assert "client geth" in result.stdout
    assert "peer " in result.stdout
    assert "local " in result.stdout
    assert "listen " in result.stdout
    assert "jwtsecret" in result.stdout
    assert "[redacted]" in result.stdout
    assert "hunter2" not in result.stdout
    assert result.stdout.strip().endswith("ok")


def test_example_trace_is_critical() -> None:
    result = _run("check", "--trace", "examples/compromise.trace", "--no-baseline")
    assert result.returncode == 2
    assert "critical metadata-destination" in result.stdout
    assert "critical unexpected-exec" in result.stdout
    assert "critical persistence" in result.stdout
    assert "critical permission-change" in result.stdout


def test_json_and_report_and_baseline(tmp_path: Path) -> None:
    home = tmp_path / "home"
    checked = _run("check", "--proc", "examples/geth", "--pid", "4242", "--json", "--no-baseline")
    body = json.loads(checked.stdout)
    assert body["client"] == "geth"
    assert body["findings"]

    output = tmp_path / "report.md"
    report = _run("report", "--proc", "examples/geth", "--pid", "4242", "--output", str(output), "--no-baseline", home=home)
    assert report.returncode == 0
    assert "What this node is doing internally." in output.read_text()

    saved = _run("baseline", "--proc", "examples/geth", "--pid", "4242", home=home)
    assert saved.returncode == 0
    path = home / "baseline.json"
    assert "geth" in json.loads(path.read_text())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_missing_process_and_watch(tmp_path: Path) -> None:
    missing = _run("status", "--proc", "examples/geth", "--pid", "999")
    assert missing.returncode == 3
    assert "pid 999" in missing.stderr
    env_path = tmp_path / "bin"
    env_path.mkdir()
    watched = subprocess.run(
        [sys.executable, "-m", "chaintrace", "watch", "--pid", "4242"],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src"), "PATH": str(env_path)},
    )
    assert watched.returncode == 3
    assert "bpftrace" in watched.stderr


def test_client_override(tmp_path: Path) -> None:
    from tests.tree import add_process, socket_line

    root = tmp_path / "proc"
    root.mkdir()
    add_process(root, 3, "java", 1, "/usr/bin/java", ["java"], {4: "socket:[8]"})
    net = root / "net"
    net.mkdir()
    (net / "tcp").write_text(socket_line("10.0.0.1", 9000, "18.1.2.3", 40000, "01", 8))
    plain = _run("check", "--proc", str(root), "--pid", "3", "--no-baseline")
    named = _run("check", "--proc", str(root), "--pid", "3", "--client", "teku", "--no-baseline")
    assert "remote " in plain.stdout
    assert "peer " in named.stdout
    assert named.stdout.startswith("client teku\n")


def test_status_without_window_prints_totals_only() -> None:
    result = _run("status", "--proc", "examples/geth", "--pid", "4242")
    assert result.returncode == 0
    assert "rss " in result.stdout
    assert "cpu " in result.stdout
    assert "cpu_percent" not in result.stdout
    assert "connections_opened" not in result.stdout


def test_status_window_reports_no_change_on_a_static_table() -> None:
    result = _run("status", "--proc", "examples/geth", "--pid", "4242", "--window", "1", "--json")
    assert result.returncode == 0, result.stderr
    body = json.loads(result.stdout)
    assert body["rss_bytes"] > 0
    assert body["window"] == {
        "seconds": 1,
        "cpu_percent": 0.0,
        "rss_delta": 0,
        "connections_opened": 0,
        "connections_closed": 0,
    }


def test_status_window_rejects_zero() -> None:
    result = _run("status", "--proc", "examples/geth", "--pid", "4242", "--window", "0")
    assert result.returncode == 3
    assert "window" in result.stderr
