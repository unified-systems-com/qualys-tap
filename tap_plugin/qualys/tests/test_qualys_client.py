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

    def test_falsey_streaming_body_refused(self) -> None:
        class Falsey:
            def __bool__(self) -> bool:
                return False

            def __iter__(self):
                yield b"action=delete"

        client, adapter = make()
        prepared = client._session.prepare_request(requests.Request("GET", DETECTION, data=Falsey()))
        with pytest.raises(TransportRefused, match="body"):
            client._session.send(prepared, verify=True, allow_redirects=False)
        assert adapter.seen == []

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

    @pytest.mark.parametrize("header", ["NaN", "inf", "-inf", "soon"])
    def test_malformed_wait_header_falls_back(self, header: str) -> None:
        sleeps: list[float] = []
        client, _ = make((409, THROTTLED, {"X-RateLimit-ToWait-Sec": header}), (200, b"<x/>", {}), sleeps=sleeps)
        client.get(DETECTION)
        assert sleeps == [float(client_module.DEFAULT_WAIT_SECONDS)]

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


class TestStateless:
    def test_cookies_are_neither_kept_nor_sent(self) -> None:
        import http.client

        class SetsCookie(FakeAdapter):
            def send(self, request, **kwargs):
                response = super().send(request, **kwargs)
                # Build the response as urllib3 would, so the session's cookie extraction sees Set-Cookie.
                message = http.client.HTTPMessage()
                message["Set-Cookie"] = "QualysSession=abc; Path=/; Secure"
                response.raw._original_response = type("R", (), {"msg": message, "info": lambda self: message})()
                response.headers["Set-Cookie"] = "QualysSession=abc; Path=/; Secure"
                return response

        adapter = SetsCookie((200, b"<x/>", {}))
        client = ReadOnlyClient(HOST, "acme_ro", "s3cret-pw", adapter=adapter, sleep=lambda s: None)
        client.get(DETECTION)
        client.get(DETECTION)
        assert len(client._session.cookies) == 0
        assert all("Cookie" not in sent.headers for sent in adapter.seen)

    def test_a_request_carrying_a_cookie_is_refused(self) -> None:
        client, adapter = make()
        prepared = client._session.prepare_request(requests.Request("GET", DETECTION, headers={"Cookie": "x=1"}))
        with pytest.raises(TransportRefused, match="cookie"):
            client._session.send(prepared, verify=True, allow_redirects=False)
        assert adapter.seen == []


class TestSerial:
    def test_concurrent_gets_are_serialised(self) -> None:
        import threading
        import time as _time

        class Slow(FakeAdapter):
            active = 0
            peak = 0
            guard = threading.Lock()

            def send(self, request, **kwargs):
                with self.guard:
                    Slow.active += 1
                    Slow.peak = max(Slow.peak, Slow.active)
                _time.sleep(0.05)
                try:
                    return super().send(request, **kwargs)
                finally:
                    with self.guard:
                        Slow.active -= 1

        client = ReadOnlyClient(HOST, "acme_ro", "s3cret-pw", adapter=Slow(), sleep=lambda s: None)
        threads = [threading.Thread(target=client.get, args=(DETECTION,)) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert Slow.peak == 1


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


class Raising(FakeAdapter):
    """Raises the scripted exception for an answer that is an exception, as a reset or timeout would."""

    def send(self, request, **kwargs):
        if isinstance(self.answers[0], Exception):
            self.seen.append(request)
            error = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
            raise error
        return super().send(request, **kwargs)


class _CutBody(io.BytesIO):
    def read(self, *a, **k):
        raise requests.exceptions.ChunkedEncodingError("connection broken mid-body")


CONCURRENCY = b"<SIMPLE_RETURN><RESPONSE><CODE>1960</CODE><TEXT>concurrency</TEXT></RESPONSE></SIMPLE_RETURN>"


@pytest.mark.spec("req-qualys-transport-9")
class TestTransientRetries:
    """unified-systems-com/qualys-tap#47: a transient failure is asked again, a bounded number of times."""

    @pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
    def test_a_transient_status_is_retried(self, status: int) -> None:
        sleeps: list[float] = []
        client, adapter = make((status, b"down", {}), (200, b"<x/>", {}), sleeps=sleeps)
        assert client.get(DETECTION).status == 200
        assert sleeps == [client_module.TRANSIENT_BACKOFF_SECONDS[0]] and len(adapter.seen) == 2

    def test_retries_are_bounded_and_then_fail_with_the_status(self) -> None:
        sleeps: list[float] = []
        client, adapter = make((503, b"down", {}), sleeps=sleeps)
        with pytest.raises(ReadFailed) as caught:
            client.get(DETECTION)
        assert caught.value.status == 503
        assert len(adapter.seen) == client_module.MAX_TRANSIENT_RETRIES + 1
        assert sleeps == list(client_module.TRANSIENT_BACKOFF_SECONDS)

    @pytest.mark.parametrize("status", [400, 401, 403, 404])
    def test_other_errors_are_not_retried(self, status: int) -> None:
        sleeps: list[float] = []
        client, adapter = make((status, b"no", {}), sleeps=sleeps)
        with pytest.raises(ReadFailed):
            client.get(DETECTION)
        assert sleeps == [] and len(adapter.seen) == 1

    @pytest.mark.parametrize("error", [requests.ConnectionError("reset"), requests.ReadTimeout("slow"), requests.ConnectTimeout("no route")])
    def test_a_network_error_is_retried(self, error: Exception) -> None:
        sleeps: list[float] = []
        adapter = Raising(error, (200, b"<x/>", {}))
        client = ReadOnlyClient(HOST, "acme_ro", "s3cret-pw", adapter=adapter, sleep=sleeps.append)
        assert client.get(DETECTION).body == b"<x/>" and len(sleeps) == 1

    def test_a_persistent_network_error_is_raised_as_itself(self) -> None:
        adapter = Raising(requests.ConnectionError("reset"))
        client = ReadOnlyClient(HOST, "acme_ro", "s3cret-pw", adapter=adapter, sleep=lambda s: None)
        with pytest.raises(requests.ConnectionError):
            client.get(DETECTION)
        assert len(adapter.seen) == client_module.MAX_TRANSIENT_RETRIES + 1

    def test_a_body_cut_short_is_retried_and_observed(self) -> None:
        seen = []

        class Cut(FakeAdapter):
            def send(self, request, **kwargs):
                response = super().send(request, **kwargs)
                if len(self.seen) == 1:
                    response.raw = _CutBody()
                return response

        adapter = Cut((200, b"<x/>", {}))
        client = ReadOnlyClient(HOST, "acme_ro", "s3cret-pw", adapter=adapter, sleep=lambda s: None, observer=seen.append)
        assert client.get(DETECTION).body == b"<x/>"
        assert [e.body_not_read for e in seen] == ["ChunkedEncodingError", None]

    def test_retries_off_fails_on_the_first_answer(self) -> None:
        client, adapter = make((502, b"down", {}), (200, b"<x/>", {}), retry_transient=False)
        with pytest.raises(ReadFailed):
            client.get(DETECTION)
        assert len(adapter.seen) == 1

    def test_transient_and_throttle_waits_share_one_budget(self, monkeypatch) -> None:
        monkeypatch.setattr(client_module, "MAX_WAIT_TOTAL_SECONDS", 20)
        sleeps: list[float] = []
        client, adapter = make((409, THROTTLED, {"X-RateLimit-ToWait-Sec": "10"}), (502, b"", {}), (502, b"", {}), (200, b"<x/>", {}), sleeps=sleeps)
        with pytest.raises(ReadFailed):
            client.get(DETECTION)
        assert sleeps == [10.0, 5.0] and len(adapter.seen) == 3  # the next backoff (30s) would pass the budget

    def test_a_refusal_is_never_retried(self) -> None:
        client, adapter = make((200, b"<x/>", {}))
        with pytest.raises(TransportRefused):
            client.get(f"{HOST}/api/2.0/fo/session/?action=login")
        assert adapter.seen == []


@pytest.mark.spec("req-qualys-transport-9")
class TestConcurrencyWaitFloor:
    """unified-systems-com/qualys-tap#48: a 1960 wait whose header says 0 still waits."""

    @pytest.mark.parametrize("header", ["0", "1", None])
    def test_a_1960_wait_is_at_least_the_floor(self, header: str | None) -> None:
        sleeps: list[float] = []
        headers = {} if header is None else {"X-RateLimit-ToWait-Sec": header}
        client, _ = make((409, CONCURRENCY, headers), (200, b"<x/>", {}), sleeps=sleeps)
        client.get(DETECTION)
        assert sleeps == [max(client_module.CONCURRENCY_WAIT_FLOOR_SECONDS, float(header or client_module.DEFAULT_WAIT_SECONDS))]

    def test_a_1965_wait_still_follows_its_header(self) -> None:
        sleeps: list[float] = []
        client, _ = make((409, THROTTLED, {"X-RateLimit-ToWait-Sec": "2"}), (200, b"<x/>", {}), sleeps=sleeps)
        client.get(DETECTION)
        assert sleeps == [2.0]


@pytest.mark.spec("req-qualys-transport-9")
class TestCeilingBoundsAttemptsNotWaits:
    """unified-systems-com/qualys-tap#49: the per-request ceiling is around each attempt; the waits are outside it."""

    def test_each_attempt_is_bounded_and_no_wait_is_inside(self) -> None:
        inside, events = [False], []

        def bound(attempt):
            inside[0] = True
            try:
                events.append("attempt")
                return attempt()
            finally:
                inside[0] = False

        def sleep(seconds: float) -> None:
            assert not inside[0], "a wait ran inside the ceiling"
            events.append("sleep")

        adapter = FakeAdapter((409, THROTTLED, {"X-RateLimit-ToWait-Sec": "600"}), (502, b"", {}), (200, b"<x/>", {}))
        client = ReadOnlyClient(HOST, "acme_ro", "s3cret-pw", adapter=adapter, sleep=sleep)
        assert client.get(DETECTION, bound=bound).status == 200
        assert events == ["attempt", "sleep", "attempt", "sleep", "attempt"]

    def test_an_attempt_past_the_ceiling_is_not_retried_and_its_session_is_dropped(self) -> None:
        client, adapter = make((200, b"<x/>", {}))
        before = client._session

        def timed_out(attempt):
            raise TimeoutError("past the ceiling")

        with pytest.raises(TimeoutError):
            client.get(DETECTION, bound=timed_out)
        assert adapter.seen == [] and client._session is not before
        assert client.get(DETECTION).status == 200  # the new session works, and the lock was released


@pytest.mark.spec("req-qualys-transport-9")
class TestReviewRound1:
    """PR #62 round 1 (Codex, Grok): TLS and proxy failures are not transient; a replaced session has its own pool."""

    @pytest.mark.parametrize("error", [requests.exceptions.SSLError("certificate verify failed"), requests.exceptions.ProxyError("proxy refused")])
    def test_a_tls_or_proxy_failure_is_not_retried(self, error: Exception) -> None:
        assert isinstance(error, requests.ConnectionError)  # why it needs excluding by name
        sleeps: list[float] = []
        adapter = Raising(error, (200, b"<x/>", {}))
        client = ReadOnlyClient(HOST, "acme_ro", "s3cret-pw", adapter=adapter, sleep=sleeps.append)
        with pytest.raises(type(error)):
            client.get(DETECTION)
        assert len(adapter.seen) == 1 and sleeps == []

    def test_a_replaced_session_does_not_share_the_abandoned_pool(self) -> None:
        client = ReadOnlyClient(HOST, "acme_ro", "s3cret-pw", sleep=lambda s: None)  # no injected adapter: production
        before = client._session.adapters["https://"]

        def timed_out(attempt):
            raise TimeoutError("past the ceiling")

        with pytest.raises(TimeoutError):
            client.get(DETECTION, bound=timed_out)
        assert client._session.adapters["https://"] is not before

    def test_the_collector_ceiling_is_a_timeout_error(self) -> None:
        from tap_cares.collectors import CeilingExceeded

        assert issubclass(CeilingExceeded, TimeoutError)  # so the swap runs when observe's run_with_ceiling raises it
