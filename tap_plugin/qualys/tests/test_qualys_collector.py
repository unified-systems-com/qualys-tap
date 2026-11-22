"""The live collector, end to end, against a fake adapter serving the fixture pages (X5, req-qualys-probe,
req-qualys-detection-read, req-qualys-connection).

The client is the real ReadOnlyClient with its guarded session; only the adapter under it is fake, so every
request in these tests went through the allowlist. No socket is opened.
"""

import io
import json
import socket
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
import tap_plugin.compliance_core.models  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models  # noqa: F401 — trigger model registration
import tap_plugin.qualys.models  # noqa: F401 — trigger model registration
from requests.adapters import HTTPAdapter

from tap_cares.collectors.config import CollectorConfig
from tap_grid.grift.importer import grift_import
from tap_plugin.qualys import live
from tap_plugin.qualys.client import DETECTION_PATH, KNOWLEDGEBASE_PATH, ReadOnlyClient
from tap_plugin.qualys.collectors import qualys_collector
from tap_plugin.qualys.collectors.qualys_collector import QualysCollector, QualysCollectorError
from tap_plugin.qualys.decompose import COMPLETE, WINDOW
from tap_plugin.qualys.identity import subscription_key
from tap_plugin.qualys.models import QualysDetection, QualysHost, QualysScanRun, QualysSubscription

FIXTURES = Path(__file__).resolve().parent / "fixtures"
HOST = "https://qualysapi.qg2.apps.qualys.com"
KEY = subscription_key(HOST, "acme-prod")
PASSWORD = "".join(["live", "-", "test", "-", "pw"])


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _without_warning(body: bytes) -> bytes:
    start, end = body.index(b"<WARNING>"), body.index(b"</WARNING>") + len(b"</WARNING>")
    return body[:start] + body[end:]


class Router(HTTPAdapter):
    """Answers by path and parameters, and records every request that reached it."""

    def __init__(self, **overrides: Any) -> None:
        super().__init__()
        self.seen: list[requests.PreparedRequest] = []
        self.overrides = overrides

    def answer(self, request: requests.PreparedRequest) -> tuple[int, bytes, dict[str, str]]:
        parts = urlsplit(request.url)
        query = parse_qs(parts.query)
        headers = {"X-RateLimit-Remaining": "299", "X-RateLimit-Limit": "300"}
        if parts.path == DETECTION_PATH:
            if query.get("truncation_limit") == ["1"]:
                return self.overrides.get("probe", (200, _without_warning(_fixture("hld-ec2-assembled.xml")), headers))
            if "id_min" in query:
                return self.overrides.get("page2", (200, _fixture("hld-documented.xml"), headers))
            return self.overrides.get("page1", (200, _fixture("hld-ec2-assembled.xml"), headers))
        if parts.path == KNOWLEDGEBASE_PATH:
            if "kb" in self.overrides:
                return self.overrides["kb"](query)
            return 200, _fixture("kb-documented.xml"), headers
        return 404, b"", {}

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        self.seen.append(request)
        status, body, headers = self.answer(request)
        response = requests.Response()
        response.status_code = status
        response.raw = io.BytesIO(body)
        response.headers.update(headers)
        response.url = request.url
        response.request = request
        return response


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*a: Any, **k: Any) -> None:
        raise AssertionError("these tests must not open a socket")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def write(scope: dict[str, list[int]] | None = None) -> None:
        data: dict[str, Any] = {"api_host": HOST, "subscription": "acme-prod", "username": "acme_ro", "password": PASSWORD}
        if scope:
            data["scope"] = scope
        (tmp_path / "acme.secret.json").write_text(json.dumps({"scope": "qualys", "key": "acme", "kind": "qualys_api_credential", "description": "test", "data": data}))

    monkeypatch.setattr(qualys_collector.secrets_root, "resolve", lambda: tmp_path)
    write()
    return write


def _collector(monkeypatch: pytest.MonkeyPatch, router: Router) -> QualysCollector:
    def factory(api_host: str, username: str, password: str, *, ca_bundle: str | None = None) -> ReadOnlyClient:
        return ReadOnlyClient(api_host, username, password, ca_bundle=ca_bundle, adapter=router, sleep=lambda s: None)

    monkeypatch.setattr(qualys_collector, "client_factory", factory)
    collector = QualysCollector(CollectorConfig(uuid.uuid4(), uuid.uuid4()))

    def submit(doc: dict[str, Any]) -> Any:
        imported = grift_import(doc)
        assert not imported.errors, imported.errors
        return imported

    monkeypatch.setattr(collector, "submit_grift", submit)
    return collector


def _codes(collector: QualysCollector, level: str) -> list[str]:
    return [e.get("message_code") for e in collector.results[level]]


def _run_row() -> QualysScanRun:
    return QualysScanRun.objects.filter(subscription_key=KEY).order_by("-started_at").first()


@pytest.mark.django_db
class TestFirstRun:
    def test_complete_read_lands_and_advances_the_watermark(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        router = Router()
        _collector(monkeypatch, router).run()
        assert set(QualysHost.objects.filter(subscription_key=KEY).values_list("host_id", flat=True)) == {"1001", "524323"}
        assert QualysDetection.objects.filter(subscription_key=KEY).count() == 5
        run = _run_row()
        assert (run.source, run.read_kind, run.page_count) == ("api", COMPLETE, 2)
        assert run.probe["detection_api_version"] == "6.0" and run.probe["limits"]["X-RateLimit-Remaining"] == "299"
        sub = QualysSubscription.objects.get(subscription_key=KEY)
        assert sub.watermark == run.started_at and sub.last_complete_read_at == run.read_at

    def test_probe_first_then_pages_then_knowledge_base(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        router = Router()
        _collector(monkeypatch, router).run()
        kinds = []
        for request in router.seen:
            parts = urlsplit(request.url)
            query = parse_qs(parts.query)
            kinds.append("probe" if query.get("truncation_limit") == ["1"] else "kb" if parts.path == KNOWLEDGEBASE_PATH else "page")
        assert kinds == ["probe", "page", "page", "kb"]

    def test_every_request_is_an_allowlisted_get_with_all_statuses(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        router = Router()
        _collector(monkeypatch, router).run()
        for request in router.seen:
            assert request.method == "GET" and request.body is None and "Cookie" not in request.headers
            assert PASSWORD not in request.url
            query = parse_qs(urlsplit(request.url).query)
            if urlsplit(request.url).path == DETECTION_PATH:
                # Every detection page, the onward ones included: each is rebuilt from the run's own parameters.
                assert query["status"] == ["New,Active,Re-Opened,Fixed"]
                assert query["include_ignored"] == ["1"] and query["include_disabled"] == ["1"]

    def test_tag_scope_is_sent_and_recorded(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        secrets({"tag_ids": [7, 3]})
        router = Router()
        _collector(monkeypatch, router).run()
        for request in router.seen:
            if urlsplit(request.url).path == DETECTION_PATH:
                query = parse_qs(urlsplit(request.url).query)
                assert (query["use_tags"], query["tag_set_by"], query["tag_include_selector"], query["tag_set_include"]) == (["1"], ["id"], ["any"], ["3,7"])
        assert _run_row().applied_filter == {"tag_ids": [3, 7]}
        assert QualysSubscription.objects.get(subscription_key=KEY).standing_scope == {"tag_ids": [3, 7]}


@pytest.mark.django_db
class TestSecondRun:
    def test_window_from_the_watermark_less_the_overlap(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        _collector(monkeypatch, Router()).run()
        watermark = QualysSubscription.objects.get(subscription_key=KEY).watermark
        router = Router()
        _collector(monkeypatch, router).run()
        sent = parse_qs(urlsplit(router.seen[1].url).query)["vm_processed_after"][0]
        assert sent == (watermark - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        run = _run_row()
        assert run.read_kind == WINDOW and run.window_start is not None and run.applied_filter["vm_processed_after"] == sent

    def test_a_week_after_the_last_complete_read_it_is_complete_again(self) -> None:
        now = datetime(2026, 11, 30, tzinfo=UTC)
        held = {"watermark": "2026-11-29T00:00:00+00:00", "last_complete_read_at": "2026-11-22T23:00:00+00:00", "standing_scope": {}}
        assert live.plan(held, {}, now).read_kind == COMPLETE
        held["last_complete_read_at"] = "2026-11-24T00:00:00+00:00"
        assert live.plan(held, {}, now).read_kind == WINDOW

    def test_a_changed_scope_is_complete_again(self) -> None:
        held = {"watermark": "2026-11-29T00:00:00+00:00", "last_complete_read_at": "2026-11-29T00:00:00+00:00", "standing_scope": {"tag_ids": [1]}}
        assert live.plan(held, {"tag_ids": [2]}, datetime(2026, 11, 30, tzinfo=UTC)).read_kind == COMPLETE


@pytest.mark.django_db
class TestWatermarkHeld:
    def test_a_failed_page_keeps_what_was_read_and_holds_the_watermark(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        collector = _collector(monkeypatch, Router(page2=(500, b"oops", {})))
        collector.run()
        assert "WALK_INCOMPLETE" in _codes(collector, "warn")
        assert QualysHost.objects.filter(subscription_key=KEY, host_id="1001").exists()
        assert QualysSubscription.objects.get(subscription_key=KEY).watermark is None
        run = _run_row()
        assert run.read_kind != COMPLETE and {"scope": "detection page 2", "reason": "not read: ReadFailed"} in run.scopes_not_read

    def test_a_window_run_whose_first_page_fails_holds_the_watermark(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        # No page read at all, so no next-page link to betray the gap: only the walk's own record holds the mark.
        _collector(monkeypatch, Router()).run()
        watermark = QualysSubscription.objects.get(subscription_key=KEY).watermark
        _collector(monkeypatch, Router(page1=(502, b"", {}))).run()
        assert _run_row().read_kind == WINDOW
        assert QualysSubscription.objects.get(subscription_key=KEY).watermark == watermark

    def test_a_walk_stopped_by_the_page_ceiling_holds_the_watermark(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(live, "MAX_DETECTION_PAGES", 1)
        _collector(monkeypatch, Router()).run()
        assert QualysSubscription.objects.get(subscription_key=KEY).watermark is None
        assert "TRUNCATED" in [w["code"] for w in _run_row().warnings]

    def test_an_unkeyable_detection_holds_the_watermark(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        bad = _fixture("hld-documented.xml").replace(b"<UNIQUE_VULN_ID>3978355</UNIQUE_VULN_ID>", b"<UNIQUE_VULN_ID>" + b"x" * 300 + b"</UNIQUE_VULN_ID>")
        _collector(monkeypatch, Router(page2=(200, bad, {}))).run()
        assert QualysSubscription.objects.get(subscription_key=KEY).watermark is None


@pytest.mark.django_db
class TestProbe:
    @pytest.mark.parametrize("answer", [(401, b"<SIMPLE_RETURN/>", {}), (200, b"<SIMPLE_RETURN><RESPONSE><CODE>2000</CODE></RESPONSE></SIMPLE_RETURN>", {}), (400, b"bad scope", {})])
    def test_a_failed_probe_writes_nothing(self, secrets, monkeypatch: pytest.MonkeyPatch, answer) -> None:
        router = Router(probe=answer)
        collector = _collector(monkeypatch, router)
        with pytest.raises(QualysCollectorError):
            collector.run()
        assert "PROBE_FAILED" in _codes(collector, "error") and len(router.seen) == 1
        assert not QualysSubscription.objects.exists() and not QualysScanRun.objects.exists()
        assert PASSWORD not in json.dumps(collector.results)

    def test_end_of_support_text_is_recorded(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        eos = _without_warning(_fixture("hld-ec2-assembled.xml")).replace(
            b"</RESPONSE>", b"<WARNING><CODE>1990</CODE><TEXT>API v6.0 reaches end of support on 2027-12-31.</TEXT></WARNING></RESPONSE>")
        _collector(monkeypatch, Router(probe=(200, eos, {}))).run()
        (warning,) = [w for w in _run_row().warnings if w["code"] == "API_VERSION_EOS"]
        assert "end of support" in warning["detail"]


@pytest.mark.django_db
class TestReviewRound1:
    def test_a_probe_timeout_fails_only_its_subscription(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        def slow(call, what):
            raise TimeoutError(f"{what} did not finish within its ceiling")

        monkeypatch.setattr(qualys_collector, "_bounded", slow)
        collector = _collector(monkeypatch, Router())
        with pytest.raises(QualysCollectorError):
            collector.run()
        assert "PROBE_FAILED" in _codes(collector, "error") and not QualysScanRun.objects.exists()

    def test_one_subscription_failing_does_not_stop_the_next(self, secrets, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        second = {"api_host": "https://qualysapi.qg3.apps.qualys.com", "subscription": "other", "username": "u", "password": PASSWORD}
        (tmp_path / "zzz.secret.json").write_text(json.dumps({"scope": "qualys", "key": "zzz", "kind": "qualys_api_credential", "description": "t", "data": second}))
        real = live.read
        calls: list[str] = []

        def flaky(client, *a, **k):
            calls.append(client.root)
            if client.root.endswith("qg2.apps.qualys.com"):
                raise RuntimeError("boom " + PASSWORD)
            return real(client, *a, **k)

        monkeypatch.setattr(live, "read", flaky)
        collector = _collector(monkeypatch, Router())
        collector.run()
        assert len(calls) == 2 and "SUBSCRIPTION_FAILED" in _codes(collector, "error")
        assert QualysSubscription.objects.filter(subscription_label="other").exists()
        assert not QualysSubscription.objects.filter(subscription_key=KEY).exists()
        assert PASSWORD not in json.dumps(collector.results)

    def test_an_onward_link_with_no_id_min_stops_the_walk(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        page = _fixture("hld-ec2-assembled.xml").replace(b"&id_min=1002", b"&something=else")
        router = Router(page1=(200, page, {}))
        _collector(monkeypatch, router).run()
        assert not [r for r in router.seen if "something" in r.url]  # the link itself is never followed
        assert QualysSubscription.objects.get(subscription_key=KEY).watermark is None
        assert "TRUNCATED" in [w["code"] for w in _run_row().warnings]

    def test_the_probe_limits_are_kept_beside_the_last(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        probe = (200, _without_warning(_fixture("hld-ec2-assembled.xml")), {"X-RateLimit-Remaining": "300"})
        _collector(monkeypatch, Router(probe=probe)).run()
        recorded = _run_row().probe
        assert recorded["limits"]["X-RateLimit-Remaining"] == "300" and recorded["last_limits"]["X-RateLimit-Remaining"] == "299"

    def test_a_failed_complete_walk_records_no_complete_read(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        _collector(monkeypatch, Router(page2=(500, b"", {}))).run()
        assert QualysSubscription.objects.get(subscription_key=KEY).last_complete_read_at is None


@pytest.mark.django_db
class TestKnowledgeBase:
    def test_a_cut_short_chunk_is_followed_to_its_end(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        asked: list[dict[str, list[str]]] = []
        body = _fixture("kb-documented.xml")
        cut = body.replace(b"</RESPONSE>", f"<WARNING><CODE>1980</CODE><TEXT>more</TEXT><URL><![CDATA[{HOST}{KNOWLEDGEBASE_PATH}?action=list&details=All&ids=38170]]></URL></WARNING></RESPONSE>".encode())

        def kb(query: dict[str, list[str]]) -> tuple[int, bytes, dict[str, str]]:
            asked.append(query)
            return 200, (cut if len(asked) == 1 else body), {}

        _collector(monkeypatch, Router(kb=kb)).run()
        # The cut page returned 6666666; the second request re-asks every other QID by id, not by Qualys's link.
        assert len(asked) == 2 and asked[1]["ids"] == ["11827,38170,45038,82054"] and "details" in asked[1]

    def test_a_cut_page_that_moves_nothing_forward_is_incomplete(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        from tap_plugin.qualys.models import QualysQid

        empty = (f"<KNOWLEDGE_BASE_VULN_LIST_OUTPUT><RESPONSE><DATETIME>2026-11-20T18:00:00Z</DATETIME><WARNING><CODE>1980</CODE><TEXT>more</TEXT>"
                 f"<URL><![CDATA[{HOST}{KNOWLEDGEBASE_PATH}?action=list&ids=1]]></URL></WARNING></RESPONSE></KNOWLEDGE_BASE_VULN_LIST_OUTPUT>").encode()
        asked: list[Any] = []
        _collector(monkeypatch, Router(kb=lambda q: (asked.append(q), (200, empty, {}))[1])).run()
        assert len(asked) == 1  # not asked again for the same page
        assert set(QualysQid.objects.filter(subscription_key=KEY).values_list("kb_returned", flat=True)) == {None}

    def test_a_failed_chunk_leaves_its_qids_unobserved_not_absent(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        from tap_plugin.qualys.models import QualysQid

        _collector(monkeypatch, Router(kb=lambda q: (503, b"", {}))).run()
        assert set(QualysQid.objects.filter(subscription_key=KEY).values_list("kb_returned", flat=True)) == {None}


@pytest.mark.django_db
class TestCredentials:
    def test_no_credential_fails_the_run(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(qualys_collector.secrets_root, "resolve", lambda: tmp_path)
        collector = _collector(monkeypatch, Router())
        with pytest.raises(QualysCollectorError):
            collector.run()
        assert "NO_CREDENTIAL" in _codes(collector, "error")

    def test_a_refused_envelope_leaks_nothing_into_the_run(self, secrets, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        bad = {"api_host": "http://not-https.example", "subscription": "bad", "username": "u" + PASSWORD, "password": PASSWORD, "ca_bundle": PASSWORD}
        (tmp_path / "bad.secret.json").write_text(json.dumps({"scope": "qualys", "key": "bad", "kind": "qualys_" + PASSWORD, "description": "t", "data": bad}))
        (tmp_path / "broken.secret.json").write_text('{"scope": "qualys", "data": {"password": "' + PASSWORD)
        collector = _collector(monkeypatch, Router())
        collector.run()
        assert _codes(collector, "warn").count("CREDENTIAL_REFUSED") == 2
        assert PASSWORD not in json.dumps(collector.results) and PASSWORD not in collector.summary

    def test_a_probe_failure_records_no_response_text(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        odd = b"<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><DATETIME>x</DATETIME><HOST_LIST><HOST><DETECTION_LIST><DETECTION><QID>1</QID><TYPE>" + PASSWORD.encode() + b"</TYPE></DETECTION></DETECTION_LIST></HOST></HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"
        collector = _collector(monkeypatch, Router(probe=(200, odd, {})))
        with pytest.raises(QualysCollectorError):
            collector.run()
        assert PASSWORD not in json.dumps(collector.results)
        assert "not a detection document" in json.dumps(collector.results)

    def test_self_test_reports_configuration(self, secrets) -> None:
        assert QualysCollector.self_test().summary == "A credential is configured."


@pytest.mark.django_db
def test_a_live_run_lands_what_qualys_load_lands_for_the_same_pages(secrets, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The live path and the file path are one decomposition: the same pages give the same graph."""
    from django.core.management import call_command

    from tap_grid.models import Edge, Entity
    from tap_plugin.qualys.tests.test_qualys_load import make_archive

    def snapshot(label: str) -> tuple[Any, ...]:
        key = subscription_key(HOST, label)
        hosts = sorted(QualysHost.objects.filter(subscription_key=key).values_list("host_id", "state"))
        detections = sorted(QualysDetection.objects.filter(subscription_key=key).values_list("host_id", "qid", "unique_vuln_id", "state", "parse_state"))
        ids = set(QualysHost.objects.filter(subscription_key=key).values_list("entity_id", flat=True)) | set(
            QualysDetection.objects.filter(subscription_key=key).values_list("entity_id", flat=True))
        touching = sorted(Edge.objects.filter(from_entity_id__in=ids).values_list("edge_type", flat=True))
        return hosts, detections, touching

    _collector(monkeypatch, Router()).run()
    live_graph = snapshot("acme-prod")
    before = Entity.objects.count()
    archive = make_archive(tmp_path, pages=[_fixture("hld-ec2-assembled.xml"), _fixture("hld-documented.xml")])
    call_command("qualys_load", str(archive), subscription="acme-file", stdout=io.StringIO())
    assert Entity.objects.count() > before
    assert snapshot("acme-file") == live_graph


class Breaking(Router):
    """A Router whose chosen request raises a network error instead of answering, as a reset or timeout would."""

    def __init__(self, where: str, error: Exception, **overrides: Any) -> None:
        super().__init__(**overrides)
        self.where, self.error = where, error

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        parts = urlsplit(request.url)
        query = parse_qs(parts.query)
        hit = {
            "probe": parts.path == DETECTION_PATH and query.get("truncation_limit") == ["1"],
            "page2": parts.path == DETECTION_PATH and "id_min" in query,
            "kb": parts.path == KNOWLEDGEBASE_PATH,
        }[self.where]
        if hit:
            self.seen.append(request)
            raise self.error
        return super().send(request, **kwargs)


@pytest.mark.django_db
class TestNetworkErrorsKeepWhatWasRead:
    """unified-systems-com/qualys-tap#46: a network error is a failed page, not a failed subscription."""

    @pytest.mark.parametrize("error", [requests.ConnectionError("reset"), requests.ReadTimeout("slow"), requests.exceptions.ChunkedEncodingError("cut")])
    def test_a_network_error_mid_walk_keeps_the_pages_read(self, secrets, monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
        collector = _collector(monkeypatch, Breaking("page2", error))
        collector.run()
        assert "SUBSCRIPTION_FAILED" not in _codes(collector, "error")
        assert "WALK_INCOMPLETE" in _codes(collector, "warn")
        assert QualysHost.objects.filter(subscription_key=KEY, host_id="1001").exists()
        assert QualysSubscription.objects.get(subscription_key=KEY).watermark is None
        assert {"scope": "detection page 2", "reason": f"not read: {type(error).__name__}"} in _run_row().scopes_not_read

    def test_a_network_error_in_the_knowledge_base_leaves_qids_unobserved(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        from tap_plugin.qualys.models import QualysQid

        collector = _collector(monkeypatch, Breaking("kb", requests.ConnectionError("reset")))
        collector.run()
        assert "SUBSCRIPTION_FAILED" not in _codes(collector, "error")
        assert set(QualysQid.objects.filter(subscription_key=KEY).values_list("kb_returned", flat=True)) == {None}

    def test_a_network_error_on_the_probe_is_a_failed_probe(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        collector = _collector(monkeypatch, Breaking("probe", requests.ConnectionError("reset by 203.0.113.9")))
        with pytest.raises(QualysCollectorError):
            collector.run()
        assert "PROBE_FAILED" in _codes(collector, "error") and "SUBSCRIPTION_FAILED" not in _codes(collector, "error")
        assert "203.0.113.9" not in json.dumps(collector.results)  # a fixed message, never the exception's text
        assert not QualysScanRun.objects.exists()


@pytest.mark.django_db
class TestQdsAsReturned:
    """unified-systems-com/qualys-tap#50 (the factors are asked for) and #51 (the severity attribute is kept)."""

    def test_every_detection_read_asks_for_the_factors(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        router = Router()
        _collector(monkeypatch, router).run()
        detection_reads = [r for r in router.seen if urlsplit(r.url).path == DETECTION_PATH]
        assert len(detection_reads) >= 3  # probe, page 1, page 2
        assert all(parse_qs(urlsplit(r.url).query).get("show_qds_factors") == ["1"] for r in detection_reads)

    def test_the_qds_severity_is_stored_beside_the_score(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        _collector(monkeypatch, Router()).run()
        row = QualysDetection.objects.get(subscription_key=KEY, host_id="1001", qid="6666666", unique_vuln_id="7000001")
        assert (row.qds, row.qds_severity) == ("57", "MEDIUM")
        assert row.qds_factors
        absent = QualysDetection.objects.filter(subscription_key=KEY, qds__isnull=True)
        assert absent.exists() and not absent.exclude(qds_severity__isnull=True).exists()  # no QDS, no severity: null
