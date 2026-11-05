from chaintrace.clients import recognize
from chaintrace.models import Child, Connection, Event, Finding, Observation, OpenFile
from chaintrace.rules import evaluate, exit_code, worst_severity
from chaintrace.baseline import Baseline


def _obs(**kwargs: object) -> Observation:
    base = dict(
        pid=4242,
        comm="geth",
        client="geth",
        exe="/usr/bin/geth",
        state="sleeping",
        rss_bytes=0,
        cpu_seconds=0.0,
        ppid=1,
        cmdline=(),
        files=(),
        connections=(),
        children=(),
        events=(),
    )
    base.update(kwargs)
    return Observation(**base)  # type: ignore[arg-type]


def _conn(kind: str, remote: str, local: str = "10.1.2.3:41000") -> Connection:
    return Connection("tcp", local, remote, "ESTABLISHED", kind)


def test_shell_child_metadata_and_deleted_binary() -> None:
    obs = _obs(
        exe="/usr/bin/geth (deleted)",
        children=(Child(50, "bash", "/bin/bash"),),
        connections=(_conn("metadata", "169.254.169.254:80"),),
    )
    findings = evaluate(obs)
    rules = {(item.severity, item.rule) for item in findings}
    assert ("warning", "deleted-binary") in rules
    assert ("critical", "shell-child") in rules
    assert ("critical", "metadata-destination") in rules
    assert exit_code(findings) == 2


def test_unknown_destination_is_info_until_a_baseline_exists() -> None:
    obs = _obs(connections=(_conn("unknown", "203.0.113.5:443"),))
    first = evaluate(obs)
    assert first == [first[0]]
    assert first[0].severity == "info"
    assert first[0].rule == "unknown-destination"
    assert exit_code(first) == 0
    saved = Baseline("geth", "/usr/bin/geth", frozenset(), frozenset({"0.0.0.0:30303"}))
    second = evaluate(obs, saved)
    assert [(item.severity, item.rule) for item in second] == [("warning", "new-destination")]
    assert exit_code(second) == 1


def test_exposed_port_and_binary_change() -> None:
    obs = _obs(
        exe="/usr/local/bin/geth",
        connections=(Connection("tcp", "0.0.0.0:8545", "0.0.0.0:0", "LISTEN", "listen"),),
    )
    saved = Baseline("geth", "/usr/bin/geth", frozenset(), frozenset({"0.0.0.0:30303"}))
    rules = {(item.severity, item.rule) for item in evaluate(obs, saved)}
    assert ("warning", "exposed-port") in rules
    assert ("warning", "binary-changed") in rules
    assert ("warning", "new-listener") in rules


def test_trace_compromise_indicators() -> None:
    obs = _obs(
        state="traced",
        exe="",
        events=(
            Event("exec", 4242, "geth", path="/bin/bash"),
            Event("chmod", 4242, "geth", path="/usr/bin/geth", mode="511"),
            Event("open", 4242, "bash", path="/etc/ld.so.preload"),
        ),
        files=(OpenFile("/etc/ld.so.preload", False, "bash"),),
    )
    rules = {(item.severity, item.rule) for item in evaluate(obs)}
    assert ("critical", "unexpected-exec") in rules
    assert ("critical", "permission-change") in rules
    assert ("critical", "persistence") in rules


def test_fanout_of_unknown_destinations() -> None:
    connections = tuple(_conn("unknown", f"203.0.113.{index}:443") for index in range(1, 6))
    findings = evaluate(_obs(connections=connections))
    assert any(item.rule == "traffic-anomaly" for item in findings)
    assert exit_code(findings) == 1


def test_child_holding_a_key_is_a_warning() -> None:
    obs = _obs(files=(OpenFile("/var/lib/geth/jwtsecret", True, "bash"),))
    finding = evaluate(obs)[0]
    assert finding.severity == "warning"
    assert finding.rule == "sensitive-file"


def test_node_holding_its_own_jwt_is_info() -> None:
    obs = _obs(files=(OpenFile("/var/lib/geth/jwtsecret", True, "geth"),))
    finding = evaluate(obs)[0]
    assert (finding.severity, finding.rule) == ("info", "sensitive-file")
    assert exit_code(evaluate(obs)) == 0


def test_worst_severity_picks_the_highest_rank() -> None:
    assert worst_severity([]) == "ok"
    assert worst_severity([Finding("info", "sensitive-file", "jwt")]) == "info"
    mixed = [Finding("info", "sensitive-file", "jwt"), Finding("warning", "unit-binary", "path")]
    assert worst_severity(mixed) == "warning"
    mixed.append(Finding("critical", "metadata-destination", "169.254.169.254:80"))
    assert worst_severity(mixed) == "critical"


def test_unit_binary_warns_only_when_the_path_differs() -> None:
    same = evaluate(_obs(exe="/usr/bin/geth"), unit_exe="/usr/bin/geth")
    assert same == []
    moved = evaluate(_obs(exe="/usr/bin/geth"), unit_exe="/tmp/geth")
    assert [(item.severity, item.rule, item.message) for item in moved] == [
        ("warning", "unit-binary", "unit /tmp/geth running /usr/bin/geth")
    ]
    deleted = evaluate(_obs(exe="/usr/bin/geth (deleted)"), unit_exe="/usr/bin/geth")
    assert [(item.rule) for item in deleted] == ["deleted-binary"]


def test_java_process_can_be_named_teku() -> None:
    assert recognize("java", "/usr/bin/java").name == "unknown"
    assert recognize("nimbus_beacon_n", "").name == "nimbus"
    assert recognize("beacon-chain", "").name == "prysm"
