import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from chaintrace import __version__

ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str, home: Path | None = None, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("CHAINTRACE_ALERT_URL", None)
    env["PYTHONPATH"] = str(ROOT / "src")
    env["CHAINTRACE_HOME"] = str(home or Path("/tmp/chaintrace-empty"))
    if env_extra:
        env.update(env_extra)
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


def test_profile_is_used_before_the_catalog(tmp_path: Path) -> None:
    from tests.tree import add_process, socket_line

    root = tmp_path / "proc"
    root.mkdir()
    add_process(
        root,
        8,
        "mev-boost",
        1,
        "/usr/bin/mev-boost",
        ["mev-boost"],
        {4: "socket:[40]", 5: "socket:[41]", 6: "socket:[42]", 7: "socket:[43]"},
    )
    net = root / "net"
    net.mkdir()
    (net / "tcp").write_text(
        socket_line("10.0.0.1", 41000, "203.0.113.8", 443, "01", 40)
        + socket_line("10.0.0.1", 41001, "198.51.100.9", 443, "01", 41)
        + socket_line("10.0.0.1", 30303, "198.51.100.10", 40000, "01", 42)
        + socket_line("0.0.0.0", 8545, "0.0.0.0", 0, "0A", 43)
    )
    plain = _run("check", "--proc", str(root), "--pid", "8", "--no-baseline")
    assert "expected 10.0.0.1:41000 203.0.113.8:443 tcp" in plain.stdout
    assert "expected 10.0.0.1:41001 198.51.100.9:443 tcp" in plain.stdout
    assert "exposed-port" not in plain.stdout

    profile = tmp_path / "mev.json"
    profile.write_text(
        json.dumps(
            {
                "comm": "mev-boost",
                "p2p_ports": [30303],
                "loopback_ports": [8545],
                "allowed_hosts": ["203.0.113.8", "[2001:db8::1]"],
            }
        )
    )
    checked = _run("check", "--proc", str(root), "--pid", "8", "--profile", str(profile), "--no-baseline")
    assert checked.returncode == 1, checked.stdout + checked.stderr
    assert "client mev-boost" in checked.stdout
    assert "expected 10.0.0.1:41000 203.0.113.8:443 tcp" in checked.stdout
    assert "unknown 10.0.0.1:41001 198.51.100.9:443 tcp" in checked.stdout
    assert "peer 10.0.0.1:30303 198.51.100.10:40000 tcp" in checked.stdout
    assert "warning exposed-port 0.0.0.0:8545" in checked.stdout
    assert "unknown-destination 198.51.100.9:443" in checked.stdout
    assert "unknown-destination 203.0.113.8:443" not in checked.stdout
    assert "unknown-destination 198.51.100.10:40000" not in checked.stdout

    catalog = _run("check", "--proc", "examples/geth", "--pid", "4242", "--profile", str(profile), "--no-baseline")
    assert catalog.returncode == 0, catalog.stdout + catalog.stderr
    assert "client geth" in catalog.stdout

    both = _run("check", "--proc", str(root), "--pid", "8", "--client", "teku", "--profile", str(profile), "--no-baseline")
    assert both.returncode == 3
    assert "profile" in both.stderr

    missing = _run("check", "--proc", str(root), "--pid", "8", "--profile", str(tmp_path / "missing.json"), "--no-baseline")
    assert missing.returncode == 3
    assert "not a file" in missing.stderr

    named = tmp_path / "name.json"
    named.write_text('{"p2p_ports": [1], "allowed_hosts": ["relay.example"]}')
    bad = _run("check", "--proc", str(root), "--pid", "8", "--profile", str(named), "--no-baseline")
    assert bad.returncode == 3
    assert "comm" in bad.stderr


def test_example_profile_marks_an_allowed_address() -> None:
    saved = _run("check", "--proc", "examples/geth", "--pid", "4242", "--profile", "examples/geth.json", "--no-baseline")
    assert saved.returncode == 0, saved.stderr + saved.stdout
    assert "client geth" in saved.stdout
    assert "peer " in saved.stdout

    traced = _run("check", "--trace", "examples/allow.trace", "--profile", "examples/geth.json", "--no-baseline")
    assert traced.returncode == 0, traced.stderr + traced.stdout
    assert "expected 203.0.113.10:443 tcp" in traced.stdout
    assert "unknown 198.51.100.9:443 tcp" in traced.stdout
    assert "unknown-destination 198.51.100.9:443" in traced.stdout
    assert "unknown-destination 203.0.113.10:443" not in traced.stdout


def test_unit_warns_when_the_running_binary_differs(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "systemctl"
    script.write_text(
        "\n".join(
            [
                "#!/bin/sh",
                'if [ "$1" != show ]; then echo "refusing $1" >&2; exit 2; fi',
                'case "$2" in',
                "  other.service)",
                "    echo LoadState=loaded",
                "    echo MainPID=4242",
                "    echo 'ExecStart={ path=/tmp/other-geth ; argv[]=/tmp/other-geth ; }'",
                "    ;;",
                "  stopped.service)",
                "    echo LoadState=loaded",
                "    echo MainPID=0",
                "    echo 'ExecStart={ path=/usr/bin/geth ; argv[]=/usr/bin/geth ; }'",
                "    ;;",
                "  *)",
                "    echo LoadState=not-found",
                "    echo MainPID=0",
                "    echo ExecStart=",
                "    ;;",
                "esac",
                "exit 0",
                "",
            ]
        )
    )
    script.chmod(0o755)
    env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"}
    differ = _run("check", "--proc", "examples/geth", "--unit", "other.service", "--no-baseline", env_extra=env)
    assert differ.returncode == 1, differ.stderr + differ.stdout
    assert "warning unit-binary unit /tmp/other-geth running /usr/bin/geth" in differ.stdout
    missing = _run("check", "--proc", "examples/geth", "--unit", "missing.service", "--no-baseline", env_extra=env)
    assert missing.returncode == 3
    assert "unit missing.service was not found" in missing.stderr
    stopped = _run("check", "--proc", "examples/geth", "--unit", "stopped.service", "--no-baseline", env_extra=env)
    assert stopped.returncode == 3
    assert "is not running" in stopped.stderr


def test_example_unit_matches_the_saved_geth() -> None:
    env = {"PATH": f"{ROOT / 'examples'}{os.pathsep}{os.environ.get('PATH', '')}"}
    result = _run("check", "--proc", "examples/geth", "--unit", "geth.service", "--no-baseline", env_extra=env)
    assert result.returncode == 0, result.stderr + result.stdout
    assert "client geth" in result.stdout
    assert "unit-binary" not in result.stdout


def test_example_keys_warns_for_the_other_process() -> None:
    result = _run("keys", "--proc", "examples/geth", "--pid", "4242")
    assert result.returncode == 1, result.stderr + result.stdout
    assert "key 4242 geth /var/lib/geth/jwtsecret" in result.stdout
    assert "key 77 python /var/lib/geth/keystore/UTC--example" in result.stdout
    assert "warning sensitive-file pid 77 python /var/lib/geth/keystore/UTC--example" in result.stdout
    assert "warning sensitive-file pid 4242" not in result.stdout
    body = json.loads(_run("keys", "--proc", "examples/geth", "--pid", "4242", "--json").stdout)
    assert body["pid"] == 4242
    assert [item["path"] for item in body["keys"]] == [
        "/var/lib/geth/jwtsecret",
        "/var/lib/geth/keystore/UTC--example",
    ]
    assert "contents" not in body
    missing = _run("keys", "--proc", "examples/geth", "--pid", "999")
    assert missing.returncode == 3
    assert "pid 999" in missing.stderr


def test_status_window_rejects_zero() -> None:
    result = _run("status", "--proc", "examples/geth", "--pid", "4242", "--window", "0")
    assert result.returncode == 3
    assert "window" in result.stderr


def test_alert_posts_check_json_and_a_refused_connection_exits_3() -> None:
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    received: list[bytes] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            received.append(self.rfile.read(length))
            status = 500 if self.path == "/fail" else 204
            self.send_response(status)
            self.end_headers()

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    port = server.server_address[1]
    try:
        posted = _run(
            "check",
            "--proc",
            "examples/geth",
            "--pid",
            "4242",
            "--json",
            "--no-baseline",
            "--alert-url",
            f"http://127.0.0.1:{port}/alert",
        )
        via_env = _run(
            "check",
            "--trace",
            "examples/allow.trace",
            "--json",
            "--no-baseline",
            env_extra={"CHAINTRACE_ALERT_URL": f"http://127.0.0.1:{port}/alert"},
        )
        failed = _run(
            "check",
            "--proc",
            "examples/geth",
            "--pid",
            "4242",
            "--no-baseline",
            "--alert-url",
            f"http://127.0.0.1:{port}/fail",
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert posted.returncode == 0, posted.stderr + posted.stdout
    assert "sensitive-file" in posted.stdout
    assert received[0].decode() == posted.stdout
    body = json.loads(received[0])
    assert body["client"] == "geth"
    assert body["findings"][0]["rule"] == "sensitive-file"
    assert "contents" not in body
    assert "hunter2" not in received[0].decode()

    assert via_env.returncode == 0, via_env.stderr
    assert json.loads(received[1])["findings"][0]["rule"] == "unknown-destination"

    assert failed.returncode == 3
    assert "client geth" in failed.stdout
    assert "sensitive-file" in failed.stdout
    assert "alert" in failed.stderr

    held = socket.socket()
    held.bind(("127.0.0.1", 0))
    closed = held.getsockname()[1]
    held.close()
    refused = _run(
        "check",
        "--proc",
        "examples/geth",
        "--pid",
        "4242",
        "--no-baseline",
        "--alert-url",
        f"http://127.0.0.1:{closed}/alert",
    )
    assert refused.returncode == 3
    assert "client geth" in refused.stdout
    assert "sensitive-file" in refused.stdout
    assert f"alert http://127.0.0.1:{closed}/alert failed" in refused.stderr
