"""Hide password-style command arguments. Paths stay visible."""

from __future__ import annotations

import re

_SECRET = re.compile(r"(password|mnemonic|privkey|private-key|privatekey|secret-key)", re.I)


def redact_argv(argv: list[str]) -> tuple[str, ...]:
    redacted: list[str] = []
    hide_next = False
    for arg in argv:
        if hide_next:
            redacted.append(arg if _is_path(arg) else "[redacted]")
            hide_next = False
            continue
        name, sep, value = _split(arg)
        if sep and _is_secret(name):
            shown = value if _is_path(value) else "[redacted]"
            redacted.append(f"{name}{sep}{shown}")
            continue
        redacted.append(arg)
        if sep == "" and _is_secret(name):
            hide_next = True
    return tuple(redacted)


def _split(arg: str) -> tuple[str, str, str]:
    if "=" in arg and arg.startswith("-"):
        name, value = arg.split("=", 1)
        return name, "=", value
    return arg, "", ""


def _is_secret(name: str) -> bool:
    flag = name.lstrip("-")
    if "jwt" in flag.lower():
        return False
    return _SECRET.search(flag) is not None


def _is_path(value: str) -> bool:
    return value.startswith("/") or value.startswith("./") or value.startswith("../")
