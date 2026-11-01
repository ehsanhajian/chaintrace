import json
from pathlib import Path

from chaintrace.probe import render_probe
from chaintrace.redact import redact_argv
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


def test_probe_script_is_limited_to_one_pid() -> None:
    script = render_probe(4242, 10)
    assert "pid == 4242" in script
    assert "interval:s:10" in script
    assert "__PID__" not in script
    assert "sys_enter_execve" in script
    assert "sys_enter_connect" in script
    assert "sys_enter_openat" in script
    assert "sys_enter_fchmodat" in script
