import shutil
from pathlib import Path

import pytest

from chaintrace.models import Connection, Observation
from chaintrace.procfs import ProcError
from chaintrace.window import compare, read_window

from tests.tree import add_process


def _obs(cpu: float, rss: int, connections: tuple[Connection, ...]) -> Observation:
    return Observation(
        pid=7,
        comm="geth",
        client="geth",
        exe="/usr/bin/geth",
        state="sleeping",
        rss_bytes=rss,
        cpu_seconds=cpu,
        ppid=1,
        cmdline=(),
        files=(),
        connections=connections,
        children=(),
    )


def _conn(local: str, remote: str) -> Connection:
    return Connection("tcp", local, remote, "ESTABLISHED", "peer")


def test_compare_reports_cpu_rss_and_connection_changes() -> None:
    before = _obs(1.0, 1000, (_conn("10.0.0.1:30303", "18.0.0.1:40000"), _conn("10.0.0.1:30303", "18.0.0.2:40000")))
    after = _obs(2.0, 3000, (_conn("10.0.0.1:30303", "18.0.0.2:40000"), _conn("10.0.0.1:30303", "18.0.0.3:40000")))
    sample = compare(before, after, 5)
    assert sample.cpu_percent == 20.0
    assert sample.rss_delta == 2000
    assert sample.opened == 1
    assert sample.closed == 1


def test_process_that_exits_is_an_error(tmp_path: Path) -> None:
    root = tmp_path / "proc"
    root.mkdir()
    add_process(root, 7, "geth", 1, "/usr/bin/geth", ["geth"], {})

    def remove(_seconds: int) -> None:
        shutil.rmtree(root / "7")

    with pytest.raises(ProcError, match="pid 7 exited during the window"):
        read_window(root, 7, 1, None, pause=remove)


def test_window_outside_range_does_not_wait(tmp_path: Path) -> None:
    def pause(_seconds: int) -> None:
        raise AssertionError("slept")

    with pytest.raises(ProcError, match="window"):
        read_window(tmp_path, 1, 0, None, pause=pause)
