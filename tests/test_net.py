import socket

from chaintrace.clients import Client, ClientError, client_named, load_profile
from chaintrace.net import RawSocket, classify, format_endpoint, parse_proc_net

from tests.tree import ipv4_field, socket_line


def test_ipv4_matches_proc_order() -> None:
    text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    text += socket_line("127.0.0.1", 8551, "0.0.0.0", 0, "0A", 1002)
    text += socket_line("10.1.2.3", 30303, "18.1.2.3", 51234, "01", 1003)
    parsed = parse_proc_net(text, "tcp")
    assert parsed[0].local_ip == "127.0.0.1"
    assert parsed[0].local_port == 8551
    assert parsed[0].state == "LISTEN"
    assert parsed[0].inode == "1002"
    assert parsed[1].remote_ip == "18.1.2.3"
    assert parsed[1].remote_port == 51234
    assert parsed[1].state == "ESTABLISHED"
    assert ipv4_field("10.0.0.8", 80).endswith(":0050")


def test_ipv6_loopback() -> None:
    packed = socket.inet_pton(socket.AF_INET6, "::1")
    words = [packed[index : index + 4][::-1] for index in range(0, 16, 4)]
    hex_ip = b"".join(words).hex().upper()
    line = (
        f" 0: {hex_ip}:2167 {'0' * 32}:0000 01 00000000:00000000 "
        "00:00000000 00000000 0 0 9 1 0 100 0 0 10 0"
    )
    parsed = parse_proc_net(line, "tcp")
    assert parsed[0].local_ip == "::1"
    assert parsed[0].local_port == 8551
    assert format_endpoint(parsed[0].local_ip, parsed[0].local_port) == "[::1]:8551"


def test_profiled_destinations() -> None:
    geth = client_named("geth")
    assert classify(RawSocket("tcp", "0.0.0.0", 30303, "0.0.0.0", 0, "LISTEN", "1"), geth) == "listen"
    assert classify(RawSocket("tcp", "10.1.2.3", 41000, "127.0.0.1", 8551, "ESTABLISHED", "2"), geth) == "local"
    assert classify(RawSocket("tcp", "10.1.2.3", 30303, "18.1.2.3", 51234, "ESTABLISHED", "3"), geth) == "peer"
    assert classify(RawSocket("tcp", "10.1.2.3", 41001, "203.0.113.5", 443, "ESTABLISHED", "4"), geth) == "unknown"
    meta = RawSocket("tcp", "10.1.2.3", 41002, "169.254.169.254", 80, "ESTABLISHED", "5")
    assert classify(meta, geth) == "metadata"


def test_unprofiled_public_connection_is_remote() -> None:
    plain = Client("unknown", frozenset({"java"}), frozenset(), frozenset(), frozenset())
    raw = RawSocket("tcp", "10.0.0.1", 9000, "18.1.2.3", 40000, "ESTABLISHED", "1")
    assert classify(raw, plain) == "remote"
    assert classify(raw, client_named("teku")) == "peer"
    relay = RawSocket("tcp", "10.0.0.1", 41000, "203.0.113.8", 443, "ESTABLISHED", "2")
    assert classify(relay, client_named("mev-boost")) == "expected"


def test_allowed_host_is_expected_and_other_destinations_stay_unknown() -> None:
    profile = Client(
        "geth",
        frozenset({"geth"}),
        frozenset({30303}),
        frozenset(),
        frozenset({8545}),
        frozenset({"203.0.113.8", "2001:db8::1"}),
    )
    allowed = RawSocket("tcp", "10.0.0.1", 41000, "203.0.113.8", 443, "ESTABLISHED", "1")
    other = RawSocket("tcp", "10.0.0.1", 41001, "198.51.100.9", 443, "ESTABLISHED", "2")
    peer = RawSocket("tcp", "10.0.0.1", 30303, "198.51.100.10", 40000, "ESTABLISHED", "3")
    v6 = RawSocket("tcp", "2001:db8::2", 41002, "2001:db8:0:0:0:0:0:1", 443, "ESTABLISHED", "4")
    assert classify(allowed, profile) == "expected"
    assert classify(other, profile) == "unknown"
    assert classify(peer, profile) == "peer"
    assert classify(v6, profile) == "expected"


def test_profile_file_rejects_a_name(tmp_path) -> None:
    path = tmp_path / "node.json"
    path.write_text('{"comm": "geth", "allowed_hosts": ["relay.example"]}')
    try:
        load_profile(path)
    except ClientError as exc:
        assert "not an address" in str(exc)
    else:
        raise AssertionError("a host name must be rejected")
