from pathlib import Path

from chaintrace.procfs import key_opens
from chaintrace.rules import exit_code, key_findings

from tests.tree import add_process


def test_keys_walks_the_table_without_reading_file_contents(tmp_path: Path) -> None:
    root = tmp_path / "proc"
    root.mkdir()
    secret = tmp_path / "validator_keys" / "mnemonic.txt"
    secret.parent.mkdir()
    secret.write_text("do-not-print-this-secret\n")
    add_process(
        root,
        10,
        "geth",
        1,
        "/usr/bin/geth",
        ["geth"],
        {3: "/var/lib/geth/jwtsecret", 4: "/var/lib/geth/jwtsecret", 5: "/var/log/geth.log"},
    )
    add_process(root, 11, "bash", 10, "/bin/bash", ["bash"], {3: "/var/lib/geth/keystore/UTC--child"})
    add_process(root, 12, "python", 1, "/usr/bin/python", ["python"], {3: str(secret)})
    broken = root / "14"
    (broken / "fd").mkdir(parents=True)
    (broken / "fd" / "3").symlink_to("/var/lib/geth/nodekey")

    opens = key_opens(root)
    assert [(item.pid, item.comm, item.path) for item in opens] == [
        (10, "geth", "/var/lib/geth/jwtsecret"),
        (11, "bash", "/var/lib/geth/keystore/UTC--child"),
        (12, "python", str(secret)),
    ]
    findings = key_findings(10, opens)
    assert [item.message for item in findings] == [
        "pid 11 bash /var/lib/geth/keystore/UTC--child",
        f"pid 12 python {secret}",
    ]
    assert exit_code(findings) == 1
    assert exit_code(key_findings(10, opens[:1])) == 0
    rendered = " ".join(item.path for item in opens)
    assert "do-not-print-this-secret" not in rendered
    assert secret.read_text().strip() == "do-not-print-this-secret"
