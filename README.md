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
| What should the next check compare against? | `baseline` |
| Can I keep the answer? | `report` |
| What did the kernel see for a few seconds? | `watch --pid` |

`status` and `check` read a process table. That is `/proc` on the node. `status --window 5` reads it twice, five seconds apart, and adds the CPU percent, the RSS change, and how many connections opened or closed. A process that exits during that wait is an error. One sample, without `--window`, still prints the totals. `watch` needs `bpftrace` and root, and it only traces the one pid you name. The probe prints `exec`, `connect`, `open`, and `chmod`. It does not follow a child after the exec, and it prints IPv4 connections. IPv6 peers still show up in `status`.

## Examples

A saved process table and a saved trace are in `examples/`. Neither needs root.

```bash
chaintrace status --proc examples/geth --pid 4242
chaintrace check --proc examples/geth --pid 4242
chaintrace check --trace examples/compromise.trace
```

On the node:

```bash
chaintrace status --name geth
chaintrace check --name lighthouse
chaintrace check --pid 4242 --client teku
chaintrace baseline --name geth
chaintrace report --name geth
chaintrace watch --pid 4242 --seconds 10 > /tmp/node.trace
chaintrace check --trace /tmp/node.trace
```

`--client` selects a profile when the process name is generic, such as `java` for Teku. `--json` prints one document. `report` writes `chaintrace-report.md`.

A password-style argument is printed as `[redacted]`. A path, including a JWT file path, stays visible. File contents are never read.

## What a connection means

| Line | Meaning |
| --- | --- |
| `listen` | The process is waiting on this address. |
| `local` | The other end is on this machine, such as the engine API. |
| `peer` | The local or remote port is a peer port for this client. |
| `expected` | The remote port is normal for this client, such as a builder relay on 443. |
| `remote` | The process has no profile, so the destination is shown and not judged. |
| `unknown` | This profiled client connected somewhere that is not a peer, a loopback address, or an expected port. |
| `metadata` | The destination is a cloud metadata address. |

Profiles cover the execution, consensus, and builder clients these tools already talk about: Geth, Reth, Nethermind, Erigon, Besu, Lighthouse, Prysm, Teku, Nimbus, Lodestar, MEV-boost, op-node, and op-geth. Any other process is still listed. Its public connections are `remote` rather than `unknown`.

## Findings

Exit 0 means there is no warning or critical finding. An `info` line still exits 0. Exit 1 means a warning. Exit 2 means a critical finding. Exit 3 means the process or the trace could not be read.

| Finding | Severity | When |
| --- | --- | --- |
| `sensitive-file` | info, or warning if another program has it open | A JWT, keystore, node key, or mnemonic path is open. |
| `unknown-destination` | info | An unknown destination, and no baseline has been saved. |
| `new-destination` | warning | An unknown destination that was not in the baseline. |
| `new-listener` | warning | A listen address that was not in the baseline. |
| `binary-changed` | warning | The executable path changed since the baseline. |
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

`watch` writes a bpftrace program and runs it. The program is read-only: exec, connect, open, and chmod for that pid, then it exits. A saved probe file is the same text `check --trace` reads. A JSON line per event works too.

```text
exec 4242 geth /bin/bash
connect 4242 geth 169.254.169.254 80
open 4242 geth /etc/ld.so.preload
chmod 4242 geth /usr/bin/geth 511
```

Run `watch` only on a host you administer. It does not survive past `--seconds`, which is at most 300.

## What it does not do

ChainTrace does not call a node RPC, restart a client, or decide whether a release is safe. It does not read key material. A report can include paths and destination addresses, which is the observation.
