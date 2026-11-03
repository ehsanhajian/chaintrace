from urllib.error import URLError

import pytest

from chaintrace.alert import AlertError, alert_url, post_json


def test_alert_url_is_off_until_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CHAINTRACE_ALERT_URL", raising=False)
    assert alert_url(None) is None
    monkeypatch.setenv("CHAINTRACE_ALERT_URL", "  ")
    assert alert_url(None) is None
    monkeypatch.setenv("CHAINTRACE_ALERT_URL", "http://127.0.0.1/hook")
    assert alert_url(None) == "http://127.0.0.1/hook"
    assert alert_url("http://127.0.0.1/flag") == "http://127.0.0.1/flag"


def test_post_json_rejects_a_non_http_url() -> None:
    with pytest.raises(AlertError, match="http or https"):
        post_json("file:///tmp/chaintrace.json", "{}")


def test_post_json_reports_a_refused_connection() -> None:
    def opener(request: object, timeout: int) -> object:
        raise URLError(ConnectionRefusedError(61, "Connection refused"))

    with pytest.raises(AlertError, match="failed"):
        post_json("http://127.0.0.1:9/alert", "{}", opener=opener)
