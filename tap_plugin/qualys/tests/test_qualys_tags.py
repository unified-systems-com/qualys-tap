"""The subscription's tags (req-qualys-tags), the one POST read that lists them (req-qualys-transport-8), and the
per-source switches (req-qualys-sources).

The tag-search fixtures are synthetic, built from Qualys's documented response shape: no captured response
exists yet. The client is the real ReadOnlyClient with its guarded session; only the adapter under it is fake.
"""

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
import tap_plugin.compliance_core.models  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models  # noqa: F401 — trigger model registration
import tap_plugin.qualys.models  # noqa: F401 — trigger model registration
from tap_plugin.qualys import live
from tap_plugin.qualys.client import (
    DETECTION_PATH,
    KNOWLEDGEBASE_PATH,
    TAG_SEARCH_PATH,
    ReadOnlyClient,
    TransportRefused,
    tag_search_body,
)
from tap_plugin.qualys.collectors import qualys_collector
from tap_plugin.qualys.credential import CredentialError, credential_from_envelope
from tap_plugin.qualys.models import QualysHost, QualysQid, QualysScanRun, QualysSubscription, QualysTag
from tap_plugin.qualys.parse import PageRefused, parse_tag_page
from tap_plugin.qualys.read_kind import NARROWER
from tap_plugin.qualys.tests.test_qualys_client import HOST as CLIENT_HOST
from tap_plugin.qualys.tests.test_qualys_client import make
from tap_plugin.qualys.tests.test_qualys_collector import (  # noqa: F401
    HOST,
    KEY,
    PASSWORD,
    Router,
    _collector,
    _fixture,
    no_sockets,
)

from tap_grid.dimension_names import view
from tap_grid.event_time import TIME_DIMENSION
from tap_grid.models import Edge

TAGS = CLIENT_HOST + TAG_SEARCH_PATH


def _page(*tags: str, more: str | None = "false", last: str | None = None, code: str = "SUCCESS") -> bytes:
    head = f"<responseCode>{code}</responseCode><count>{len(tags)}</count>"
    if more is not None:
        head += f"<hasMoreRecords>{more}</hasMoreRecords>"
    if last is not None:
        head += f"<lastId>{last}</lastId>"
    return f"<ServiceResponse>{head}<data>{''.join(tags)}</data></ServiceResponse>".encode()


def _tag(tag_id: str, name: str = "t", children: str | None = "<children><list/></children>") -> str:
    return f"<Tag><id>{tag_id}</id><name>{name}</name>{children or ''}</Tag>"


@pytest.fixture
def secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def write(sources: dict[str, bool] | None = None) -> None:
        data: dict[str, Any] = {"api_host": HOST, "subscription": "acme-prod", "username": "acme_ro", "password": PASSWORD}
        if sources is not None:
            data["sources"] = sources
        (tmp_path / "acme.secret.json").write_text(json.dumps({"scope": "qualys", "key": "acme", "kind": "qualys_api_credential", "description": "test", "data": data}))

    monkeypatch.setattr(qualys_collector.secrets_root, "resolve", lambda: tmp_path)
    write()
    return write


def _paths(router: Router) -> list[str]:
    return [urlsplit(r.url).path for r in router.seen]


def _run_row() -> QualysScanRun:
    return QualysScanRun.objects.filter(subscription_key=KEY).order_by("-started_at").first()


def _edges(slug: str) -> set[tuple[str, str]]:
    names = {}
    for tag in QualysTag.objects.filter(subscription_key=KEY):
        names[tag.entity_id] = tag.tag_id
    for sub in QualysSubscription.objects.filter(subscription_key=KEY):
        names[sub.entity_id] = "sub"
    return {(names.get(e.from_entity_id, "?"), names.get(e.to_entity_id, "?")) for e in Edge.objects.filter(edge_type=slug) if e.from_entity_id in names}


class TestTheOnePost:
    """req-qualys-transport-8: the tag search is the only POST, and its body can carry nothing but paging."""

    @pytest.mark.spec("req-qualys-transport-8")
    def test_the_tag_search_is_sent_as_its_template(self) -> None:
        client, adapter = make((200, _page(_tag("1")), {}))
        client.search_tags(None)
        client.search_tags("42")
        first, second = adapter.seen
        assert first.method == second.method == "POST" and urlsplit(first.url).path == TAG_SEARCH_PATH and not urlsplit(first.url).query
        assert first.body == b"<ServiceRequest><preferences><limitResults>100</limitResults></preferences></ServiceRequest>"
        assert second.body == b"<ServiceRequest><preferences><startFromId>42</startFromId><limitResults>100</limitResults></preferences></ServiceRequest>"
        assert first.headers["Content-Type"] == "text/xml" and first.headers["X-Requested-With"]

    @pytest.mark.spec("req-qualys-transport-8")
    @pytest.mark.parametrize(
        ("method", "url", "body", "match"),
        [
            ("POST", TAGS, b"<ServiceRequest><filters><Criteria field=\"name\" operator=\"EQUALS\">x</Criteria></filters></ServiceRequest>", "wrong shape"),
            ("POST", TAGS, b"<ServiceRequest><data><Tag><name>x</name></Tag></data></ServiceRequest>", "wrong shape"),
            ("POST", TAGS + "?action=list", tag_search_body(None), "no query"),
            ("POST", CLIENT_HOST + "/qps/rest/2.0/create/am/tag", tag_search_body(None), "only GET"),
            ("POST", CLIENT_HOST + "/qps/rest/2.0/update/am/tag/1", tag_search_body(None), "only GET"),
            ("POST", CLIENT_HOST + DETECTION_PATH, tag_search_body(None), "only GET"),
            ("POST", "https://evil.example" + TAG_SEARCH_PATH, tag_search_body(None), "outside"),
            ("GET", TAGS, None, "outside the allowlist"),
            ("PUT", TAGS, tag_search_body(None), "only GET"),
        ],
    )
    def test_anything_else_is_refused_unsent(self, method: str, url: str, body: bytes | None, match: str) -> None:
        client, adapter = make()
        with pytest.raises(TransportRefused, match=match):
            client._session.request(method, url, data=body, headers={"Content-Type": "text/xml"}, allow_redirects=False)
        assert adapter.seen == []

    @pytest.mark.spec("req-qualys-transport-8")
    def test_wrong_content_type_and_anonymous_are_refused(self) -> None:
        client, adapter = make()
        with pytest.raises(TransportRefused, match="text/xml"):
            client._session.request("POST", TAGS, data=tag_search_body(None), headers={"Content-Type": "application/json"}, allow_redirects=False)
        anonymous = ReadOnlyClient.anonymous(CLIENT_HOST, adapter=adapter)
        with pytest.raises(TransportRefused, match="anonymous"):
            anonymous.search_tags(None)
        with pytest.raises(TransportRefused, match="digits"):
            tag_search_body("1</startFromId><filters>")
        assert adapter.seen == []

    @pytest.mark.spec("req-qualys-transport-8")
    def test_the_post_list_is_the_spec_row(self) -> None:
        from tap_plugin.qualys import client as client_module

        assert set(client_module.POST_READS) == {TAG_SEARCH_PATH, client_module.HOST_ASSET_SEARCH_PATH}


class TestTagPage:
    @pytest.mark.spec("req-qualys-tags-1")
    def test_fixture_page_reads_as_returned(self) -> None:
        page = parse_tag_page(_fixture("tags-synthetic-1.xml"))
        assert (page.has_more, page.last_id, page.count) == (True, "102", "3")
        production = page.tags[0]
        assert production["tag_id"] == "100" and production["name"] == "Production" and production["rule_type"] == "GROOVY"
        assert production["rule_text"] == 'asset.installedSoftwares.contains { it.name == "nginx" }'
        assert production["created_datetime"] == "2024-03-01T10:00:00Z" and production["child_tag_ids"] == ["101", "102"]
        assert page.tags[2]["rule_type"] is None and page.tags[2]["child_tag_ids"] == []

    @pytest.mark.spec("req-qualys-tags-1")
    def test_a_children_list_not_returned_is_unobserved(self) -> None:
        page = parse_tag_page(_page(_tag("7", children=None)))
        assert page.tags[0]["child_tag_ids"] is None

    @pytest.mark.spec("req-qualys-tags-2")
    @pytest.mark.parametrize(
        ("body", "match"),
        [
            (_page(_tag("1"), code="INVALID_CREDENTIALS"), "INVALID_CREDENTIALS"),
            (_page(_tag("1"), code="<b>x</b>"), "unreadable code"),
            (b"<ServiceResponse><responseCode>SUCCESS</responseCode><count>2</count></ServiceResponse>", "no data"),
            (b"<HOST_LIST_VM_DETECTION_OUTPUT/>", "expected ServiceResponse"),
            (b"", "empty"),
            (b'<!DOCTYPE x [<!ENTITY a "b">]><ServiceResponse/>', "refused XML construct"),
        ],
    )
    def test_anything_but_success_is_refused(self, body: bytes, match: str) -> None:
        with pytest.raises(PageRefused, match=match):
            parse_tag_page(body)

    def test_a_page_that_does_not_say_whether_more_follow(self) -> None:
        assert parse_tag_page(_page(_tag("1"), more=None)).has_more is None


def _walk(*answers: tuple[int, bytes, dict[str, str]]) -> tuple[live.TagRead, list[requests.PreparedRequest]]:
    client, adapter = make(*answers)
    got = live.read_tags(client, bounded=lambda attempt, what: attempt(), time_left=lambda: 3600.0)
    return got, adapter.seen


@pytest.mark.spec("req-qualys-tags-2")
class TestTheWalk:
    def test_pages_by_id_until_qualys_says_no_more_and_skips_a_repeat(self) -> None:
        got, seen = _walk((200, _fixture("tags-synthetic-1.xml"), {}), (200, _fixture("tags-synthetic-2.xml"), {}))
        assert got.complete and got.pages == 2 and [t["tag_id"] for t in got.tags] == ["100", "101", "102", "205"]
        assert b"<startFromId>102</startFromId>" in seen[1].body

    def test_an_exclusive_start_reads_the_same(self) -> None:
        got, _ = _walk((200, _page(_tag("1"), _tag("2"), more="true", last="2"), {}), (200, _page(_tag("3")), {}))
        assert got.complete and [t["tag_id"] for t in got.tags] == ["1", "2", "3"]

    @pytest.mark.parametrize(
        ("second", "detail"),
        [
            (_page(_tag("3"), more=None), "did not say"),
            (_page(_tag("2"), more="true", last="2"), "moved nothing forward"),
            (_page(_tag("1"), _tag("5")), "below its start"),
        ],
    )
    def test_a_walk_that_cannot_prove_its_end_is_incomplete(self, second: bytes, detail: str) -> None:
        got, _ = _walk((200, _page(_tag("2"), more="true", last="2"), {}), (200, second, {}))
        assert not got.complete and detail in got.warnings[-1]["detail"]

    def test_a_page_not_read_is_listed_and_keeps_what_was_read(self) -> None:
        got, _ = _walk((200, _page(_tag("2"), more="true", last="2"), {}), (403, b"<x/>", {}))
        assert not got.complete and [t["tag_id"] for t in got.tags] == ["2"]
        assert got.not_read == [{"scope": "tag page 2", "reason": "not read: ReadFailed"}]

    def test_a_tag_without_a_usable_id_makes_the_list_incomplete(self) -> None:
        got, _ = _walk((200, _page(_tag("x"), _tag("4")), {}))
        assert not got.complete and got.unkeyable == 1 and [t["tag_id"] for t in got.tags] == ["4"]


@pytest.mark.django_db
class TestTagsOnTheGrid:
    @pytest.mark.spec("req-qualys-tags-1")
    def test_every_tag_lands_with_its_subscription_and_children(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        _collector(monkeypatch, Router()).run()
        tags = {t.tag_id: t for t in QualysTag.objects.filter(subscription_key=KEY)}
        assert set(tags) == {"100", "101", "102", "205"}
        assert tags["100"].name == "Production" and tags["100"].state == "current" and tags["205"].criticality_score == "3"
        assert tags["100"].entity.name == "Production"
        assert _edges("TAG_OF_SUBSCRIPTION__qualys") == {(t, "sub") for t in tags}
        assert _edges("LISTS_CHILD_TAG__qualys") == {("100", "101"), ("100", "102")}
        assert view(tags["100"].entity.dimensions)["qualys.area"] == "tagging"
        assert _run_row().counters["tags"] == 4

    @pytest.mark.spec("req-qualys-tags-1")
    def test_a_tags_event_time_is_its_creation(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        _collector(monkeypatch, Router()).run()
        production = QualysTag.objects.get(subscription_key=KEY, tag_id="100").entity
        # A moment: start and end are the same instant (core's req-grid-entity-event-time).
        assert production.event_start.isoformat() == production.event_end.isoformat() == "2024-03-01T10:00:00+00:00"
        assert production.event_precision == "second"
        assert view(production.dimensions).get(TIME_DIMENSION) == "created"
        assert QualysTag.objects.get(subscription_key=KEY, tag_id="205").entity.event_start is None

    @pytest.mark.spec("req-qualys-tags-3")
    def test_a_rename_is_the_same_node(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        _collector(monkeypatch, Router()).run()
        before = QualysTag.objects.get(subscription_key=KEY, tag_id="101").entity_id
        renamed = _fixture("tags-synthetic-1.xml").replace(b"<name>Databases</name>\n      <created>", b"<name>Data Stores</name>\n      <created>")
        _collector(monkeypatch, Router(tags1=(200, renamed, {}))).run()
        after = QualysTag.objects.get(subscription_key=KEY, tag_id="101")
        assert after.entity_id == before and after.name == "Data Stores"

    @pytest.mark.spec("req-qualys-tags-4")
    def test_a_complete_list_withdraws_a_tag_it_lacks_and_an_incomplete_one_does_not(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        _collector(monkeypatch, Router()).run()
        without_205 = _fixture("tags-synthetic-2.xml").replace(b"<id>205</id>", b"<id>206</id>")
        _collector(monkeypatch, Router(tags2=(200, without_205, {}))).run()
        gone = QualysTag.objects.get(subscription_key=KEY, tag_id="205")
        assert gone.state == "withdrawn" and gone.withdrawn_in_run == _run_row().run_id and gone.name == "critical_3"
        _collector(monkeypatch, Router(tags2=(500, b"", {}))).run()
        assert QualysTag.objects.get(subscription_key=KEY, tag_id="206").state == "current"
        run = _run_row()
        assert run.counters.get("tags_withdrawn") is None and {"scope": "tag page 2", "reason": "not read: ReadFailed"} in run.scopes_not_read

    @pytest.mark.spec("req-qualys-tags-2")
    def test_a_failed_tag_read_does_not_touch_the_detection_read(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        collector = _collector(monkeypatch, Router(tags1=(401, b"", {})))
        collector.run()
        assert QualysHost.objects.filter(subscription_key=KEY).count() == 2
        assert not QualysTag.objects.filter(subscription_key=KEY).exists()
        assert QualysSubscription.objects.get(subscription_key=KEY).watermark is not None
        assert "TAGS_INCOMPLETE" in [e.get("message_code") for e in collector.results["warn"]]


@pytest.mark.django_db
@pytest.mark.spec("req-qualys-sources-1")
class TestSourceSwitches:
    def test_every_source_is_on_by_default(self) -> None:
        envelope = type("E", (), {"qualified": "qualys:acme", "scope": "qualys", "kind": "qualys_api_credential", "data": {
            "api_host": HOST, "subscription": "acme-prod", "username": "u", "password": "p"}})()
        # Every source on, except host assets, which need Asset Management's Read Asset permission too.
        assert credential_from_envelope(envelope).sources == {"detections": True, "knowledgebase": True, "tags": True, "host_assets": False}

    def test_every_source_off_is_refused(self) -> None:
        envelope = type("E", (), {"qualified": "qualys:acme", "scope": "qualys", "kind": "qualys_api_credential", "data": {
            "api_host": HOST, "subscription": "acme-prod", "username": "u", "password": "p",
            "sources": {"detections": False, "knowledgebase": False, "tags": False}}})()
        with pytest.raises(CredentialError, match="nothing to read"):
            credential_from_envelope(envelope)

    def test_tags_off_sends_no_post(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        secrets({"tags": False})
        router = Router()
        _collector(monkeypatch, router).run()
        assert TAG_SEARCH_PATH not in _paths(router) and all(r.method == "GET" for r in router.seen)
        assert {"scope": "tags", "reason": "switched off"} in _run_row().scopes_not_read
        assert not QualysTag.objects.exists()

    @pytest.mark.spec("req-qualys-sources-2")
    def test_detections_off_reads_the_probe_only_and_changes_no_host(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        _collector(monkeypatch, Router()).run()
        watermark = QualysSubscription.objects.get(subscription_key=KEY).watermark
        secrets({"detections": False})
        router = Router()
        _collector(monkeypatch, router).run()
        detection_requests = [r for r in router.seen if urlsplit(r.url).path == DETECTION_PATH]
        assert len(detection_requests) == 1 and parse_qs(urlsplit(detection_requests[0].url).query)["truncation_limit"] == ["1"]
        assert KNOWLEDGEBASE_PATH not in _paths(router)
        run = _run_row()
        assert run.read_kind == NARROWER and {"scope": "detections", "reason": "switched off"} in run.scopes_not_read
        assert QualysSubscription.objects.get(subscription_key=KEY).watermark == watermark
        assert set(QualysHost.objects.filter(subscription_key=KEY).values_list("state", flat=True)) == {"current"}
        assert QualysTag.objects.filter(subscription_key=KEY).count() == 4

    @pytest.mark.spec("req-qualys-sources-3")
    def test_knowledgebase_off_leaves_new_qids_unobserved(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        secrets({"knowledgebase": False})
        router = Router()
        _collector(monkeypatch, router).run()
        assert KNOWLEDGEBASE_PATH not in _paths(router)
        qids = QualysQid.objects.filter(subscription_key=KEY)
        assert qids.exists() and set(qids.values_list("kb_returned", flat=True)) == {None}
        assert {"scope": "knowledgebase", "reason": "switched off"} in _run_row().scopes_not_read
