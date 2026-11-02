"""A short read-only bpftrace program for one pid and the processes it starts."""

from __future__ import annotations

import os
import shutil

_TEMPLATE = """// Read-only trace for one process and the processes it starts.
// A process that was already running is not followed.
// IPv4 connections only. IPv6 peers show up in `chaintrace status`.

BEGIN
{
  printf("chaintrace probe\\n");
  @follow[__PID__] = 1;
}

tracepoint:sched:sched_process_fork
/@follow[pid]/
{
  @follow[args->child_pid] = 1;
}

tracepoint:syscalls:sys_enter_execve
/@follow[pid]/
{
  printf("exec %d %s %s\\n", pid, comm, str(args->filename));
}

tracepoint:syscalls:sys_enter_connect
/@follow[pid]/
{
  $sa = args->uservaddr;
  if ($sa->sa_family == 2) {
    $port = ($sa->sa_data[0] << 8) | $sa->sa_data[1];
    $v4 = (struct sockaddr_in *)args->uservaddr;
    printf("connect %d %s %s %d\\n", pid, comm, ntop($v4->sin_addr.s_addr), $port);
  }
}

tracepoint:syscalls:sys_enter_openat
/@follow[pid]/
{
  printf("open %d %s %s\\n", pid, comm, str(args->filename));
}

tracepoint:syscalls:sys_enter_fchmodat
/@follow[pid]/
{
  printf("chmod %d %s %s %d\\n", pid, comm, str(args->filename), args->mode);
}

interval:s:__SECONDS__
{
  clear(@follow);
  exit();
}
"""


def render_probe(pid: int, seconds: int) -> str:
    if pid <= 0:
        raise ValueError("pid must be positive")
    if seconds < 1 or seconds > 300:
        raise ValueError("seconds must be from 1 to 300")
    return _TEMPLATE.replace("__PID__", str(pid)).replace("__SECONDS__", str(seconds))


def unavailable(seconds_ok: bool = True) -> str | None:
    if shutil.which("bpftrace") is None:
        return "bpftrace is not installed"
    try:
        euid = os.geteuid()
    except AttributeError:
        return "bpftrace needs Linux"
    if euid != 0:
        return "bpftrace needs root"
    if not seconds_ok:
        return "seconds must be from 1 to 300"
    return None
