"""POST a check document when this invocation sets a webhook."""

from __future__ import annotations

import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class AlertError(ValueError):
    """The alert could not be delivered."""


def alert_url(flag: str | None) -> str | None:
    if flag:
        return flag
    value = os.environ.get("CHAINTRACE_ALERT_URL", "").strip()
    return value or None


def post_json(url: str, body: str, opener=urlopen) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise AlertError("alert url must be http or https")
    request = Request(
        url,
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with opener(request, timeout=5) as response:
            response.read()
    except HTTPError as exc:
        exc.close()
        raise AlertError(f"alert {url} failed") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise AlertError(f"alert {url} failed") from exc
