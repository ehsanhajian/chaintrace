"""A short read-only bpftrace program for one pid."""

from __future__ import annotations

import os
import shutil

_TEMPLATE = """// Read-only trace for one process. Prints exec, connect, open, and chmod.
// IPv4 connections only. IPv6 peers show up in `chaintrace status`.

BEGIN
{
  printf("chaintrace probe\\n");
}

tracepoint:syscalls:sys_enter_execve
/pid == __PID__/
{
  printf("exec %d %s %s\\n", pid, comm, str(args->filename));
}

tracepoint:syscalls:sys_enter_connect
/pid == __PID__/
{
  $sa = args->uservaddr;
  if ($sa->sa_family == 2) {
    $port = ($sa->sa_data[0] << 8) | $sa->sa_data[1];
    $v4 = (struct sockaddr_in *)args->uservaddr;
    printf("connect %d %s %s %d\\n", pid, comm, ntop($v4->sin_addr.s_addr), $port);
  }
}

tracepoint:syscalls:sys_enter_openat
/pid == __PID__/
{
  printf("open %d %s %s\\n", pid, comm, str(args->filename));
}

tracepoint:syscalls:sys_enter_fchmodat
/pid == __PID__/
{
  printf("chmod %d %s %s %d\\n", pid, comm, str(args->filename), args->mode);
}

interval:s:__SECONDS__
{
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
