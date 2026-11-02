import json
from pathlib import Path

from chaintrace.probe import render_probe
from chaintrace.redact import redact_argv
from chaintrace.render import render_check
from chaintrace.rules import evaluate
from chaintrace.trace import read_trace

ROOT = Path(__file__).resolve().parents[1]


def test_redact_password_and_keep_jwt_path() -> None:
    argv = redact_argv(
        [
            "geth",
            "--password",
            "hunter2",
            "--password=/run/secrets/pass",
            "--authrpc.jwtsecret",
            "/var/lib/geth/jwtsecret",
            "--mnemonic=abandon abandon",
        ]
    )
    assert argv[2] == "[redacted]"
    assert argv[3] == "--password=/run/secrets/pass"
    assert "/var/lib/geth/jwtsecret" in argv
    assert "[redacted]" in argv[-1]
    assert "abandon" not in argv[-1]


def test_probe_text_and_jsonl(tmp_path: Path) -> None:
    probe = tmp_path / "probe.txt"
    probe.write_text((ROOT / "examples/compromise.trace").read_text())
    obs = read_trace(probe)
    assert obs.client == "geth"
    assert obs.state == "traced"
    assert any(event.path == "/bin/bash" for event in obs.events)
    assert any(conn.kind == "metadata" for conn in obs.connections)
    assert any(item.path == "/var/lib/geth/jwtsecret" and item.sensitive for item in obs.files)

    raw = tmp_path / "events.jsonl"
    raw.write_text(
        "\n".join(
            [
                json.dumps({"kind": "connect", "pid": 3, "comm": "lighthouse", "remote": "10.0.0.5:9000"}),
                json.dumps({"kind": "chmod", "pid": 3, "comm": "lighthouse", "path": "/usr/bin/lighthouse", "mode": "0644"}),
            ]
        )
        + "\n"
    )
    traced = read_trace(raw)
    assert traced.client == "lighthouse"
    assert traced.connections[0].kind == "peer"
    assert traced.events[1].mode == "0644"


def test_probe_follows_children_of_one_pid() -> None:
    script = render_probe(4242, 10)
    assert "@follow[4242] = 1;" in script
    assert "tracepoint:sched:sched_process_fork" in script
    assert "@follow[args->child_pid] = 1;" in script
    assert script.count("/@follow[pid]/") == 5
    assert "pid == 4242" not in script
    assert "interval:s:10" in script
    assert "clear(@follow);" in script
    assert "__PID__" not in script


def test_check_reports_a_child_connect_and_open(tmp_path: Path) -> None:
    path = tmp_path / "child.trace"
    path.write_text(
        "\n".join(
            [
                "chaintrace probe",
                "exec 4242 geth /bin/bash",
                "connect 5001 bash 203.0.113.9 443",
                "open 5001 bash /tmp/dropped",
                "",
            ]
        )
    )
    obs = read_trace(path)
    text = render_check(obs, evaluate(obs))
    assert any(event.pid == 5001 and event.kind == "connect" for event in obs.events)
    assert any(event.pid == 5001 and event.kind == "open" for event in obs.events)
    assert "203.0.113.9:443" in text
    assert "/tmp/dropped" in text
    assert "bash" in text
