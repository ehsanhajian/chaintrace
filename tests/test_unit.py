import subprocess

import pytest

from chaintrace.unit import UnitError, read_unit


def test_read_unit_shows_execstart_and_does_not_change_the_unit() -> None:
    seen: list[list[str]] = []

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.append(command)
        assert kwargs["timeout"] == 5
        stdout = "\n".join(
            [
                "MainPID=4242",
                "ExecStart={ path=/usr/bin/geth ; argv[]=/usr/bin/geth --datadir /var/lib/geth ; ignore_errors=no }",
                "LoadState=loaded",
            ]
        )
        return subprocess.CompletedProcess(command, 0, stdout, "")

    unit = read_unit("geth.service", runner)
    assert seen == [
        [
            "systemctl",
            "show",
            "geth.service",
            "--property=LoadState",
            "--property=MainPID",
            "--property=ExecStart",
            "--no-pager",
        ]
    ]
    assert unit.pid == 4242
    assert unit.exe == "/usr/bin/geth"


def test_missing_unit_and_bad_name(tmp_path) -> None:
    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "LoadState=not-found\nMainPID=0\nExecStart=\n", "")

    with pytest.raises(UnitError, match="was not found"):
        read_unit("missing.service", runner)

    called = False

    def refuse(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal called
        called = True
        return subprocess.CompletedProcess(command, 0, "", "")

    with pytest.raises(UnitError, match="bad unit name"):
        read_unit("geth.service;start", refuse)
    assert called is False


def test_systemctl_missing() -> None:
    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(command[0])

    with pytest.raises(UnitError, match="not installed"):
        read_unit("geth.service", runner)
