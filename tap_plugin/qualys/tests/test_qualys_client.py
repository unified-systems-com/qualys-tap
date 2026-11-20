"""The read-only transport (req-qualys-transport-1 .. -8, req-qualys-connection-2). No socket is opened:
a fake adapter answers, and the guard runs before it would be reached."""

import io
import socket
from pathlib import Path

import pytest
import requests
from requests.adapters import HTTPAdapter

from tap_plugin.qualys import client as client_module
from tap_plugin.qualys.client import (
    DETECTION_PATH,
    KNOWLEDGEBASE_PATH,
    ReadFailed,
    ReadOnlyClient,
    TransportRefused,
    check_url,
)
from tap_plugin.qualys.parse import parse_detection_page

HOST = "https://qualysapi.qg2.apps.qualys.com"
DETECTION = f"{HOST}{DETECTION_PATH}?action=list&status=New,Active,Re-Opened,Fixed&show_results=1&truncation_limit=1000"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
THROTTLED = b"<SIMPLE_RETURN><RESPONSE><CODE>1965</CODE><TEXT>rate</TEXT></RESPONSE></SIMPLE_RETURN>"


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("these tests must not open a socket")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


class FakeAdapter(HTTPAdapter):
    """Answers from a script of (status, body, headers) and records what reached it."""

    def __init__(self, *answers):
        super().__init__()
        self.answers = list(answers) or [(200, b"<ok/>", {})]
        self.seen: list[requests.PreparedRequest] = []
        self.kwargs: list[dict] = []

    def send(self, request, **kwargs):
        self.seen.append(request)
        self.kwargs.append(kwargs)
        status, body, headers = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        response = requests.Response()
        response.status_code = status
        response.raw = io.BytesIO(body)
        response.headers.update(headers)
        response.url = request.url
        response.request = request
        return response


def make(*answers, sleeps=None, **kw) -> tuple[ReadOnlyClient, FakeAdapter]:
    adapter = FakeAdapter(*answers)
    record = sleeps if sleeps is not None else []
    return ReadOnlyClient(HOST, "acme_ro", "s3cret-pw", adapter=adapter, sleep=record.append, **kw), adapter


class TestAllowed:
    def test_allowlisted_get(self) -> None:
        client, adapter = make((200, b"<x/>", {"X-RateLimit-Remaining": "299", "Set-Cookie": "s=1"}))
        response = client.get(DETECTION)
        assert response.body == b"<x/>" and response.headers == {"X-RateLimit-Remaining": "299"}
        (sent,) = adapter.seen
        assert sent.method == "GET" and sent.headers["X-Requested-With"]
        assert "s3cret-pw" not in sent.url and sent.headers["Authorization"].startswith("Basic ")
        assert adapter.kwargs[0]["verify"] is True  # allow_redirects is consumed by Session.send; its rule is tested below

    def test_knowledgebase_read(self) -> None:
        client, _ = make()
        client.get(f"{HOST}{KNOWLEDGEBASE_PATH}?action=list&details=All&ids=38170,6666666")

    def test_ca_bundle_is_the_verify_value(self) -> None:
        client, adapter = make(ca_bundle="/etc/ssl/private-ca.pem")
        client.get(DETECTION)
        assert adapter.kwargs[0]["verify"] == "/etc/ssl/private-ca.pem"

    def test_environment_is_not_trusted(self) -> None:
        client, _ = make()
        assert client._session.trust_env is False


class TestRefused:
    @pytest.mark.parametrize(
        ("url", "match"),
        [
            ("https://evil.example" + DETECTION_PATH + "?action=list", "outside the configured API host"),
            ("https://qualysapi.qg2.apps.qualys.com:444" + DETECTION_PATH + "?action=list", "outside the configured API host"),
            ("http://qualysapi.qg2.apps.qualys.com" + DETECTION_PATH + "?action=list", "https"),
            ("https://u:p@qualysapi.qg2.apps.qualys.com" + DETECTION_PATH + "?action=list", "userinfo"),
            (HOST + "/api/2.0/fo/session/?action=login", "outside the allowlist"),
            (HOST + "/api/6.0/fo/scan/?action=launch", "outside the allowlist"),
            (HOST + DETECTION_PATH + "?action=list&echo_request=1", "not allowlisted"),
            (HOST + DETECTION_PATH + "?action=delete", "wrong shape"),
            (HOST + DETECTION_PATH + "?action=list&ids=1&ids=2", "not allowlisted"),
            (HOST + DETECTION_PATH + "?action=list&id_min=1&id_min=2", "twice"),
            (HOST + DETECTION_PATH + "?action=list&ag_ids=1;DROP", "wrong shape"),
            (HOST + DETECTION_PATH + "?status=Fixed", "wrong shape"),
            (HOST + DETECTION_PATH, "action=list"),
        ],
    )
    def test_off_allowlist(self, url: str, match: str) -> None:
        client, adapter = make()
        with pytest.raises(TransportRefused, match=match):
            client.get(url)
        assert adapter.seen == []

    def test_post_through_the_session_is_refused(self) -> None:
        client, adapter = make()
        with pytest.raises(TransportRefused, match="only GET"):
            client._session.request("POST", DETECTION, data={"x": 1})
        assert adapter.seen == []

    def test_remounted_adapter_does_not_bypass(self) -> None:
        client, _ = make()
        other = FakeAdapter()
        client._session.mount("https://", other)
        with pytest.raises(TransportRefused):
            client._session.request("DELETE", DETECTION)
        with pytest.raises(TransportRefused, match="outside"):
            client._session.get("https://evil.example" + DETECTION_PATH + "?action=list", allow_redirects=False)
        assert other.seen == []

    def test_verify_override_refused(self) -> None:
        client, adapter = make()
        prepared = client._session.prepare_request(requests.Request("GET", DETECTION))
        with pytest.raises(TransportRefused, match="verification"):
            client._session.send(prepared, verify=False, allow_redirects=False)
        with pytest.raises(TransportRefused, match="proxy"):
            client._session.send(prepared, verify=True, proxies={"https": "http://p"}, allow_redirects=False)
        assert adapter.seen == []

    def test_following_redirects_refused(self) -> None:
        client, _ = make()
        with pytest.raises(TransportRefused, match="redirects"):
            client._session.get(DETECTION)  # requests' default follows redirects

    def test_a_redirect_answer_is_an_error(self) -> None:
        client, adapter = make((302, b"", {"Location": "https://evil.example/"}))
        with pytest.raises(ReadFailed, match="redirect"):
            client.get(DETECTION)
        assert len(adapter.seen) == 1


class TestThrottling:
    def test_throttle_code_waits_then_reads(self) -> None:
        sleeps: list[float] = []
        client, adapter = make((409, THROTTLED, {"X-RateLimit-ToWait-Sec": "7"}), (200, b"<x/>", {}), sleeps=sleeps)
        assert client.get(DETECTION).waits == 1 and sleeps == [7.0] and len(adapter.seen) == 2

    def test_other_409_is_an_error_without_waiting(self) -> None:
        sleeps: list[float] = []
        body = b"<SIMPLE_RETURN><RESPONSE><CODE>2003</CODE><TEXT>no permission</TEXT></RESPONSE></SIMPLE_RETURN>"
        client, _ = make((409, body, {}), sleeps=sleeps)
        with pytest.raises(ReadFailed, match="409"):
            client.get(DETECTION)
        assert sleeps == []

    def test_waits_are_bounded(self) -> None:
        client, adapter = make((409, THROTTLED, {"X-RateLimit-ToWait-Sec": "1"}))
        with pytest.raises(ReadFailed, match="retry bound"):
            client.get(DETECTION)
        assert len(adapter.seen) == client_module.MAX_RETRIES + 1


class TestBounds:
    def test_body_over_the_ceiling_is_refused(self, monkeypatch) -> None:
        monkeypatch.setattr(client_module, "MAX_PAGE_BYTES", 10)
        client, _ = make((200, b"x" * 11, {}))
        with pytest.raises(ReadFailed, match="larger"):
            client.get(DETECTION)

    def test_repr_shows_no_credential(self) -> None:
        client, _ = make()
        assert "s3cret" not in repr(client) and "acme_ro" not in repr(client)


class TestNextPage:
    def test_documented_next_page_link_passes(self) -> None:
        page = parse_detection_page((FIXTURES / "hld-ec2-assembled.xml").read_bytes())
        path, params = check_url(page.next_url, HOST)
        assert path == DETECTION_PATH and params["id_min"] == "1002"

    def test_next_page_to_another_host_refused(self) -> None:
        with pytest.raises(TransportRefused, match="outside"):
            check_url("https://qualysapi.qualys.com.evil.example" + DETECTION_PATH + "?action=list&id_min=2", HOST)
