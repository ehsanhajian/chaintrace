"""Command line for chaintrace."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

from chaintrace import __version__
from chaintrace.alert import AlertError, alert_url, post_json
from chaintrace.baseline import BaselineError, baseline_key, capture, home_file, load, save
from chaintrace.clients import Client, ClientError, active_profile, apply_client, load_profile
from chaintrace.models import Observation
from chaintrace.probe import render_probe, unavailable
from chaintrace.procfs import ProcError, find_pids, key_opens, read_pid
from chaintrace.render import (
    render_brief,
    render_check,
    render_json,
    render_keys,
    render_keys_json,
    render_report,
    render_status,
)
from chaintrace.rules import evaluate, exit_code, key_findings
from chaintrace.trace import TraceError, read_trace
from chaintrace.unit import Unit, UnitError, read_unit
from chaintrace.window import read_window


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.version:
        print(f"chaintrace {__version__}")
        return 0
    if not args.command:
        parser.print_help(sys.stderr)
        return 3
    try:
        return args.func(args)
    except (ProcError, TraceError, ClientError, BaselineError, AlertError, UnitError) as exc:
        print(exc, file=sys.stderr)
        return 3


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chaintrace", description="See what a blockchain node is doing.")
    parser.add_argument("--version", action="store_true")
    commands = parser.add_subparsers(dest="command")

    status = commands.add_parser("status", help="Show the process, files, and connections")
    _process_flags(status)
    status.add_argument("--window", type=int, help="Seconds between two samples of this process")
    status.set_defaults(func=cmd_status, trace=None, no_baseline=True)

    check = commands.add_parser("check", help="Report behavior that does not belong on a node")
    _process_flags(check)
    check.add_argument("--trace", type=Path)
    check.add_argument("--no-baseline", action="store_true")
    check.add_argument("--alert-url", help="POST the check JSON after printing it")
    check.add_argument("--unit", help="Compare the running executable with this systemd unit")
    check.add_argument("--brief", action="store_true", help="Print one line: client, pid, and worst severity")
    check.set_defaults(func=cmd_check)

    baseline = commands.add_parser("baseline", help="Remember this binary, its listeners, and unknown destinations")
    _process_flags(baseline)
    baseline.set_defaults(func=cmd_baseline, trace=None, no_baseline=True)

    report = commands.add_parser("report", help="Write a markdown report")
    _process_flags(report)
    report.add_argument("--trace", type=Path)
    report.add_argument("--no-baseline", action="store_true")
    report.add_argument("--output", type=Path, default=Path("chaintrace-report.md"))
    report.set_defaults(func=cmd_report)

    keys = commands.add_parser("keys", help="List processes with a keystore, JWT, node key, or mnemonic open")
    keys.add_argument("--proc", type=Path, help="Process table. Defaults to /proc")
    keys.add_argument("--pid", type=int)
    keys.add_argument("--name", help="Process name, such as geth or lighthouse")
    keys.add_argument("--json", action="store_true")
    keys.set_defaults(func=cmd_keys)

    watch = commands.add_parser("watch", help="Trace exec, connect, open, and chmod for one pid")
    watch.add_argument("--pid", type=int, required=True)
    watch.add_argument("--seconds", type=int, default=10)
    watch.set_defaults(func=cmd_watch)
    return parser


def _process_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--proc", type=Path, help="Process table. Defaults to /proc")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--name", help="Process name, such as geth or lighthouse")
    parser.add_argument("--client", help="Client profile when the process name is generic")
    parser.add_argument("--profile", type=Path, help="Local JSON profile, used before the built-in catalog")
    parser.add_argument("--json", action="store_true")


def cmd_status(args: argparse.Namespace) -> int:
    profile = _local_profile(args)
    if args.window is None:
        obs = _load(args, profile)
        print(render_json(obs) if args.json else render_status(obs), end="")
        return 0
    proc, pid = _resolve(args)
    obs, sample = read_window(proc, pid, args.window, args.client, profile)
    print(render_json(obs, sample=sample) if args.json else render_status(obs, sample), end="")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    profile = _local_profile(args)
    unit = _read_unit(args)
    obs = _load(args, profile, unit)
    findings = evaluate(obs, _stored(args, obs), active_profile(profile, obs), unit.exe if unit else None)
    document = render_json(obs, findings)
    if args.brief:
        print(render_brief(obs, findings), end="")
    else:
        print(document if args.json else render_check(obs, findings), end="")
    url = alert_url(args.alert_url)
    if url:
        post_json(url, document)
    return exit_code(findings)


def cmd_keys(args: argparse.Namespace) -> int:
    proc, pid = _resolve(args)
    obs = read_pid(proc, pid)
    opens = tuple(sorted(key_opens(proc), key=lambda item: (item.pid != pid, item.pid, item.path)))
    findings = key_findings(pid, opens)
    print(render_keys_json(obs, opens, findings) if args.json else render_keys(obs, opens, findings), end="")
    return exit_code(findings)


def cmd_baseline(args: argparse.Namespace) -> int:
    obs = _load(args, _local_profile(args))
    saved = capture(obs)
    path = home_file()
    save(path, saved)
    print(f"baseline {saved.client} {path}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    profile = _local_profile(args)
    obs = _load(args, profile)
    findings = evaluate(obs, _stored(args, obs), active_profile(profile, obs))
    args.output.write_text(render_report(obs, findings))
    print(f"report {args.output}")
    return exit_code(findings)


def cmd_watch(args: argparse.Namespace) -> int:
    try:
        script = render_probe(args.pid, args.seconds)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 3
    reason = unavailable()
    if reason:
        print(reason, file=sys.stderr)
        return 3
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "node.bt"
        path.write_text(script)
        try:
            completed = subprocess.run(["bpftrace", str(path)], check=False, timeout=args.seconds + 20)
        except subprocess.TimeoutExpired:
            print("bpftrace did not exit", file=sys.stderr)
            return 3
    return 0 if completed.returncode == 0 else 3


def _stored(args: argparse.Namespace, obs: Observation):
    if args.no_baseline:
        return None
    return load(home_file(), baseline_key(obs))


def _local_profile(args: argparse.Namespace) -> Client | None:
    path = getattr(args, "profile", None)
    if path and args.client:
        raise ClientError("pass --client or --profile, not both")
    if path is None:
        return None
    return load_profile(path)


def _read_unit(args: argparse.Namespace) -> Unit | None:
    name = getattr(args, "unit", None)
    if not name:
        return None
    return read_unit(name)


def _load(args: argparse.Namespace, profile: Client | None, unit: Unit | None = None):
    trace = getattr(args, "trace", None)
    if trace and (args.pid or args.name or unit is not None):
        raise TraceError("pass a trace or a process, not both")
    if args.pid and args.name:
        raise ProcError("pass --pid or --name, not both")
    if trace:
        return apply_client(read_trace(trace), args.client, profile)
    if unit is not None and not args.pid and not args.name:
        if unit.pid <= 0:
            raise UnitError(f"unit {unit.name} is not running")
        proc = args.proc if args.proc is not None else Path("/proc")
        if not proc.is_dir():
            raise ProcError(f"{proc} is not a process table")
        return apply_client(read_pid(proc, unit.pid), args.client, profile)
    proc, pid = _resolve(args)
    return apply_client(read_pid(proc, pid), args.client, profile)


def _resolve(args: argparse.Namespace) -> tuple[Path, int]:
    if args.pid and args.name:
        raise ProcError("pass --pid or --name, not both")
    proc = args.proc if args.proc is not None else Path("/proc")
    if not proc.is_dir():
        raise ProcError(f"{proc} is not a process table")
    if args.name:
        found = find_pids(proc, args.name)
        if not found:
            raise ProcError(f"no process named {args.name}")
        if len(found) > 1:
            listed = ", ".join(str(item) for item in found)
            raise ProcError(f"more than one {args.name}: {listed}")
        return proc, found[0]
    if args.pid is None:
        raise ProcError("pass --pid or --name")
    return proc, args.pid
