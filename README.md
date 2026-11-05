# ChainTrace

ChainTrace answers one question: **what is my node doing internally?**

It reads the process, the files it has open, and the connections it holds. When you ask, it also attaches a short read-only kernel probe. A finding is printed when that behavior does not belong on a node.

It does not stop the process, read a file, open a connection, or store a key.

ValidatorPulse raises an alert. ChainDiff decides whether an upgrade is safe. chainlog-ai explains a failure from the logs. ChainTrace is the view of the process itself.

## Install

```bash
pip install chaintrace
```

Python 3.11 or newer. The package is published from a GitHub release to [PyPI](https://pypi.org/project/chaintrace/).

```bash
chaintrace --version
```

## Which command

| Question | Command |
| --- | --- |
| What is this process doing? | `status --pid` or `status --name` |
| What changed over a few seconds? | `status --window 5` |
| Is any of that suspicious? | `check` |
| Who else has a key path open? | `keys --pid` |
| What should the next check compare against? | `baseline` |
| Can I keep the answer? | `report` |
| What did the kernel see for a few seconds? | `watch --pid` |

`status` and `check` read a process table. That is `/proc` on the node. `status --window 5` reads it twice, five seconds apart, and adds the CPU percent, the RSS change, and how many connections opened or closed. A process that exits during that wait is an error. One sample, without `--window`, still prints the totals. `watch` needs `bpftrace` and root. It traces the pid you name and any process that pid starts, including a shell, until `--seconds` elapses. A process that was already running stays out of the trace. The probe prints `exec`, `connect`, `open`, and `chmod`. A connect line carries an IPv4 or IPv6 address and a port, with no name lookup.

## Examples

A saved process table and a saved trace are in `examples/`. Neither needs root.

```bash
chaintrace status --proc examples/geth --pid 4242
chaintrace status --proc examples/geth --pid 4242 --window 5
chaintrace check --proc examples/geth --pid 4242
chaintrace check --proc examples/geth --name geth --brief
chaintrace keys --proc examples/geth --pid 4242
chaintrace check --proc examples/geth --pid 4242 --profile examples/geth.json
chaintrace check --trace examples/allow.trace --profile examples/geth.json
PATH="examples:$PATH" chaintrace check --proc examples/geth --unit geth.service
chaintrace check --trace examples/compromise.trace
```

`--window 5` reads that process twice. On a saved table the rates stay at zero. On a live node the same command adds the CPU percent, the RSS change, and how many connections opened or closed:

```text
cpu_percent 12.0
rss_delta +4096
connections_opened 1
connections_closed 0
```

On the node:

```bash
chaintrace status --name geth --window 5
chaintrace check --name lighthouse
chaintrace check --name geth --brief
chaintrace check --unit geth.service
chaintrace check --pid 4242 --client teku
chaintrace baseline --name geth
chaintrace report --name geth
chaintrace watch --pid 4242 --seconds 10 > /tmp/node.trace
chaintrace check --trace /tmp/node.trace
```

`--client` selects a profile when the process name is generic, such as `java` for Teku. `--profile FILE` reads a JSON file on this machine. When the process comm matches `comm` in that file, `check` uses those peer ports, loopback ports, and allowed addresses before the built-in catalog. A destination that is not a peer and not on that list is `unknown`. An allowed address is `expected`.

The sample is `examples/geth.json`. On the saved geth process, `18.1.2.3` stays `peer` because the local port is 30303. `examples/allow.trace` is the allowlist check: `203.0.113.10` is `expected`, and `198.51.100.9` is `unknown`.

```json
{
  "comm": "geth",
  "p2p_ports": [30303],
  "loopback_ports": [8545, 8551],
  "allowed_hosts": ["18.1.2.3", "203.0.113.10"]
}
```

`--json` prints one document. `report` writes `chaintrace-report.md`.

A password-style argument is printed as `[redacted]`. A path, including a JWT file path, stays visible. File contents are never read.

## What a connection means

| Line | Meaning |
| --- | --- |
| `listen` | The process is waiting on this address. |
| `local` | The other end is on this machine, such as the engine API. |
| `peer` | The local or remote port is a peer port for this client. |
| `expected` | The remote port is normal for this client, such as a builder relay on 443, or the address is an allowed host in `--profile`. |
| `remote` | The process has no profile, so the destination is shown and not judged. |
| `unknown` | This profiled client connected somewhere that is not a peer, a loopback address, or an expected port. |
| `metadata` | The destination is a cloud metadata address. |

Profiles cover the execution, consensus, and builder clients these tools already talk about: Geth, Reth, Nethermind, Erigon, Besu, Lighthouse, Prysm, Teku, Nimbus, Lodestar, MEV-boost, op-node, and op-geth. Any other process is still listed. Its public connections are `remote` rather than `unknown`.

## Findings

Exit 0 means there is no warning or critical finding. An `info` line still exits 0. Exit 1 means a warning. Exit 2 means a critical finding. Exit 3 means the process, the trace, or the systemd unit could not be read, or an alert POST failed.

`check --brief` prints one journal line: the client, the pid, and the worst severity (`ok`, `info`, `warning`, or `critical`). The multi-line report stays the default, and the exit code stays the same. On the saved geth process the line is `client geth pid 4242 info`.

`examples/chaintrace-check.timer` runs `chaintrace check --name geth --brief` through `examples/chaintrace-check.service`. The units are examples. ChainTrace does not install them.

`check --unit geth.service` reads `ExecStart` with `systemctl show` and warns when the running executable is a different path. A missing unit exits 3. The command does not start, stop, or edit the unit. On this machine, `examples/systemctl` answers for the saved geth process when it is first on `PATH`.

`keys --pid` walks the process table and lists every open keystore, JWT, node key, or mnemonic path. The pid you named is listed with its own paths. Any other process that has one open is a `sensitive-file` warning. File contents stay unread. On the saved table, pid 77 is another process holding a keystore path:

```text
key 4242 geth /var/lib/geth/jwtsecret
key 77 python /var/lib/geth/keystore/UTC--example
warning sensitive-file pid 77 python /var/lib/geth/keystore/UTC--example
```

`check --alert-url` POSTs the same JSON as `check --json` after the findings are printed. `CHAINTRACE_ALERT_URL` does that for one run. With neither set, check sends nothing. A refused connection still prints the findings and exits 3. The document has paths and addresses, and no file contents.

| Finding | Severity | When |
| --- | --- | --- |
| `sensitive-file` | info, or warning if another program has it open | A JWT, keystore, node key, or mnemonic path is open. `keys` warns for every process except the pid you named. |
| `unknown-destination` | info | An unknown destination, and no baseline has been saved. |
| `new-destination` | warning | An unknown destination that was not in the baseline. |
| `new-listener` | warning | A listen address that was not in the baseline. |
| `binary-changed` | warning | The executable path changed since the baseline. |
| `unit-binary` | warning | The running executable path is not the unit's `ExecStart`. |
| `deleted-binary` | warning | The executable path is marked deleted. |
| `exposed-port` | warning | The HTTP or engine port is listening outside loopback. |
| `suspicious-port` | warning | An outbound connection to a shell or file-share port. |
| `traffic-anomaly` | warning | Five or more distinct unknown destinations. |
| `unexpected-exec` | warning, or critical for a shell or downloader | The process executed something other than itself. |
| `permission-change` | warning, or critical if the mode is world-writable | `chmod` on a path. |
| `shell-child` | critical | A child is a shell, downloader, or interpreter. |
| `metadata-destination` | critical | A connection to a cloud metadata address. |
| `persistence` | critical | An open path under cron, systemd, sudoers, preload, or authorized keys. |

`baseline` stores the executable, the listen addresses, and the unknown destinations in `~/.chaintrace/baseline.json`, or under `CHAINTRACE_HOME`. The file is readable only by its owner. One client name has one baseline. `--no-baseline` ignores it.

## Kernel probe

`watch` writes a bpftrace program and runs it. The program is read-only: exec, connect, open, and chmod for that pid and for processes it starts, then it exits. A saved probe file is the same text `check --trace` reads. A JSON line per event works too.

A shell the node starts keeps its own pid. `check --trace` reports that child's connect and open along with the node's events. A process that was already running is not in the file.

```text
exec 4242 geth /bin/bash
connect 5001 bash 203.0.113.9 443
open 5001 bash /tmp/dropped
connect 4242 geth 169.254.169.254 80
connect 4242 geth 2001:db8::1 30303
open 4242 geth /etc/ld.so.preload
chmod 4242 geth /usr/bin/geth 511
```

Run `watch` only on a host you administer. It does not survive past `--seconds`, which is at most 300.

## What it does not do

ChainTrace does not call a node RPC, restart a client, or decide whether a release is safe. It does not start, stop, or edit a systemd unit. It does not read key material. A report can include paths and destination addresses, which is the observation.
