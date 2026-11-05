import json
from pathlib import Path

from chaintrace.baseline import baseline_key, capture, load, save
from chaintrace.models import Observation

from tests.tree import add_process


def _obs(pid: int, exe: str, cmdline: tuple[str, ...]) -> Observation:
    return Observation(
        pid=pid,
        comm="geth",
        client="geth",
        exe=exe,
        state="sleeping",
        rss_bytes=0,
        cpu_seconds=0.0,
        ppid=1,
        cmdline=cmdline,
        files=(),
        connections=(),
        children=(),
    )


def test_key_uses_datadir_or_pid() -> None:
    first = _obs(1, "/usr/bin/geth", ("geth", "--datadir", "/data/a"))
    second = _obs(2, "/usr/local/bin/geth", ("geth", "--datadir=/data/b"))
    teku = _obs(3, "/usr/bin/teku", ("teku", "--data-path", "/data/teku"))
    plain = _obs(9, "/usr/bin/geth", ("geth",))
    assert baseline_key(first) == "geth /data/a"
    assert baseline_key(second) == "geth /data/b"
    assert baseline_key(teku) == "geth /data/teku"
    assert baseline_key(plain) == "geth 9"


def test_two_datadirs_do_not_share_a_binary(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    first = _obs(1, "/usr/bin/geth", ("geth", "--datadir", "/data/a"))
    second = _obs(2, "/usr/local/bin/geth", ("geth", "--datadir", "/data/b"))
    save(path, capture(first))
    save(path, capture(second))
    assert load(path, baseline_key(first)).exe == "/usr/bin/geth"
    assert load(path, baseline_key(second)).exe == "/usr/local/bin/geth"


def test_old_client_key_still_loads(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"geth": {"exe": "/old/geth", "unknown": [], "listen": []}}) + "\n")
    obs = _obs(1, "/usr/bin/geth", ("geth", "--datadir", "/data/a"))
    loaded = load(path, baseline_key(obs))
    assert loaded is not None
    assert loaded.client == "geth"
    assert loaded.exe == "/old/geth"
    save(path, capture(obs))
    saved = json.loads(path.read_text())
    assert saved["geth"]["exe"] == "/old/geth"
    assert saved["geth /data/a"]["exe"] == "/usr/bin/geth"
    assert load(path, "geth /data/a").exe == "/usr/bin/geth"


def test_check_keeps_two_geth_baselines_apart(tmp_path: Path) -> None:
    from tests.test_cli import _run

    root = tmp_path / "proc"
    root.mkdir()
    add_process(root, 1, "geth", 1, "/usr/bin/geth", ["geth", "--datadir", "/data/a"], {})
    add_process(root, 2, "geth", 1, "/usr/local/bin/geth", ["geth", "--datadir", "/data/b"], {})
    home = tmp_path / "home"
    assert _run("baseline", "--proc", str(root), "--pid", "1", home=home).returncode == 0
    assert _run("baseline", "--proc", str(root), "--pid", "2", home=home).returncode == 0
    stored = json.loads((home / "baseline.json").read_text())
    assert stored["geth /data/a"]["exe"] == "/usr/bin/geth"
    assert stored["geth /data/b"]["exe"] == "/usr/local/bin/geth"
    first = _run("check", "--proc", str(root), "--pid", "1", home=home)
    second = _run("check", "--proc", str(root), "--pid", "2", home=home)
    assert first.returncode == 0, first.stdout
    assert second.returncode == 0, second.stdout
    assert "binary-changed" not in first.stdout
    assert "binary-changed" not in second.stdout
