"""Host inventory from the Asset Management host asset search (req-qualys-host-assets), the second POST read
(req-qualys-transport-8). The fixture is synthetic, built from Qualys's documented response shape.
"""

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
import requests
import tap_plugin.aws_core.models  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models  # noqa: F401 — trigger model registration
import tap_plugin.qualys.models  # noqa: F401 — trigger model registration
from django.apps import apps
from tap_plugin.qualys import live
from tap_plugin.qualys.client import HOST_ASSET_SEARCH_PATH, TransportRefused, host_asset_search_body
from tap_plugin.qualys.collectors import qualys_collector
from tap_plugin.qualys.models import QualysHost, QualysScanRun
from tap_plugin.qualys.parse import PageRefused, parse_host_asset_page
from tap_plugin.qualys.tests.test_qualys_aws import _page as aws_page
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

from tap_grid.models import Edge, Entity

ASSETS = CLIENT_HOST + HOST_ASSET_SEARCH_PATH


class AssetRouter(Router):
    def answer(self, request: requests.PreparedRequest) -> tuple[int, bytes, dict[str, str]]:
        if urlsplit(request.url).path == HOST_ASSET_SEARCH_PATH and request.method == "POST":
            return self.overrides.get("assets", (200, _fixture("host-assets-synthetic.xml"), {}))
        return super().answer(request)


@pytest.fixture
def secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def write(sources: dict[str, bool] | None = None, integrations: dict[str, bool] | None = None) -> None:
        data: dict[str, Any] = {"api_host": HOST, "subscription": "acme-prod", "username": "acme_ro", "password": PASSWORD,
                                "sources": {"tags": False, **({"host_assets": True} if sources is None else sources)}}
        if integrations is not None:
            data["integrations"] = integrations
        (tmp_path / "acme.secret.json").write_text(json.dumps({"scope": "qualys", "key": "acme", "kind": "qualys_api_credential", "description": "test", "data": data}))

    monkeypatch.setattr(qualys_collector.secrets_root, "resolve", lambda: tmp_path)
    write()
    return write


class TestTheSecondPost:
    @pytest.mark.spec("req-qualys-transport-8")
    def test_the_body_is_its_template(self) -> None:
        client, adapter = make((200, _fixture("host-assets-synthetic.xml"), {}))
        client.search_host_assets(["1001", "524323"], None)
        (sent,) = adapter.seen
        assert sent.method == "POST" and urlsplit(sent.url).path == HOST_ASSET_SEARCH_PATH and sent.headers["Content-Type"] == "text/xml"
        assert sent.body == (b"<ServiceRequest><preferences><limitResults>100</limitResults></preferences>"
                             b'<filters><Criteria field="qwebHostId" operator="IN">1001,524323</Criteria></filters></ServiceRequest>')

    @pytest.mark.spec("req-qualys-transport-8")
    @pytest.mark.parametrize(
        "body",
        [
            b'<ServiceRequest><preferences><limitResults>100</limitResults></preferences><filters><Criteria field="name" operator="CONTAINS">x</Criteria></filters></ServiceRequest>',
            b'<ServiceRequest><preferences><limitResults>100</limitResults></preferences><filters><Criteria field="qwebHostId" operator="IN">1;DROP</Criteria></filters></ServiceRequest>',
            b"<ServiceRequest><preferences><limitResults>100</limitResults></preferences></ServiceRequest>",
            b'<ServiceRequest><data><HostAsset><name>x</name></HostAsset></data></ServiceRequest>',
        ],
    )
    def test_any_other_body_is_refused_unsent(self, body: bytes) -> None:
        client, adapter = make()
        with pytest.raises(TransportRefused, match="wrong shape"):
            client._session.request("POST", ASSETS, data=body, headers={"Content-Type": "text/xml"}, allow_redirects=False)
        assert adapter.seen == []

    def test_the_builder_refuses_what_the_template_would(self) -> None:
        with pytest.raises(TransportRefused, match="1 to 100"):
            host_asset_search_body([str(i) for i in range(101)], None)
        with pytest.raises(TransportRefused, match="1 to 100"):
            host_asset_search_body(["1,2"], None)
        with pytest.raises(TransportRefused, match="1 to 100"):
            host_asset_search_body([], None)


class TestThePage:
    @pytest.mark.spec("req-qualys-host-assets-1")
    def test_inventory_as_returned_and_unread_lists_are_null(self) -> None:
        page = parse_host_asset_page(_fixture("host-assets-synthetic.xml"))
        first, second = page.assets
        assert (first["host_asset_id"], first["qweb_host_id"]) == ("7727721", "1001")
        assert first["interfaces"][0] == {"interface_id": "eni-09f901fe", "interface_name": "eth0", "mac_address": "0e:1a:2b:3c:4d:5e",
                                          "address": "10.0.1.15", "gateway_address": "10.0.1.1", "hostname": "ip-10-0-1-15", "type": "PRIVATE"}
        assert first["open_ports"][1] == {"port": "443", "protocol": "TCP", "service_id": None, "service_name": None}
        assert first["software"] == [{"name": "openssl", "version": "1.0.2k-19.el7"}]
        assert second["open_ports"] == [] and second["interfaces"] is None and second["software"] is None

    def test_a_wrapper_without_its_list_is_not_returned_never_empty(self) -> None:
        body = (b"<ServiceResponse><responseCode>SUCCESS</responseCode><count>1</count><hasMoreRecords>false</hasMoreRecords><data>"
                b"<HostAsset><id>1</id><qwebHostId>1001</qwebHostId><networkInterface/><openPort><list/></openPort></HostAsset></data></ServiceResponse>")
        (asset,) = parse_host_asset_page(body).assets
        assert asset["interfaces"] is None and asset["open_ports"] == [] and asset["software"] is None

    def test_anything_but_success_is_refused(self) -> None:
        with pytest.raises(PageRefused, match="NOT_AUTHORIZED"):
            parse_host_asset_page(b"<ServiceResponse><responseCode>NOT_AUTHORIZED</responseCode></ServiceResponse>")


@pytest.mark.django_db
class TestOnTheGrid:
    @pytest.mark.spec("req-qualys-host-assets-1")
    def test_each_hosts_inventory_lands_on_it(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        router = AssetRouter()
        _collector(monkeypatch, router).run()
        host = QualysHost.objects.get(subscription_key=KEY, host_id="1001")
        assert host.host_asset_id == "7727721" and host.interfaces[0]["interface_id"] == "eni-09f901fe"
        assert [p["port"] for p in host.open_ports] == ["22", "443"] and host.software == [{"name": "openssl", "version": "1.0.2k-19.el7"}]
        other = QualysHost.objects.get(subscription_key=KEY, host_id="524323")
        assert other.open_ports == [] and other.interfaces is None  # observed-empty versus not returned
        assert QualysScanRun.objects.get(subscription_key=KEY).counters["host_assets_read"] == 2

    @pytest.mark.spec("req-qualys-host-assets-2")
    def test_a_run_that_reads_none_keeps_what_was_held(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        _collector(monkeypatch, AssetRouter()).run()
        secrets(sources={"host_assets": False})
        router = AssetRouter()
        _collector(monkeypatch, router).run()
        assert HOST_ASSET_SEARCH_PATH not in [urlsplit(r.url).path for r in router.seen]
        assert QualysHost.objects.get(subscription_key=KEY, host_id="1001").software == [{"name": "openssl", "version": "1.0.2k-19.el7"}]
        run = QualysScanRun.objects.filter(subscription_key=KEY).order_by("-started_at").first()
        assert {"scope": "host_assets", "reason": "switched off"} in run.scopes_not_read

    @pytest.mark.spec("req-qualys-host-assets-2")
    def test_a_refused_search_is_listed_and_keeps_the_detection_read(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        _collector(monkeypatch, AssetRouter(assets=(403, b"<x/>", {}))).run()
        run = QualysScanRun.objects.get(subscription_key=KEY)
        assert {"scope": "host asset group 1 page 1", "reason": "not read: ReadFailed"} in run.scopes_not_read
        assert QualysHost.objects.filter(subscription_key=KEY).count() == 2 and QualysHost.objects.get(subscription_key=KEY, host_id="1001").interfaces is None

    @pytest.mark.spec("req-qualys-host-assets-3")
    def test_with_the_aws_integration_an_eni_is_minted_and_attached(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        secrets(integrations={"aws": True})
        _collector(monkeypatch, AssetRouter(page1=(200, aws_page(), {}))).run()
        eni = apps.get_model("aws_core", "Ec2NetworkInterface").objects.get(ec2_network_interface_id="eni-09f901fe")
        names = {e.id: e.name for e in Entity.objects.all()}
        attached = {(names[e.from_entity_id], names[e.to_entity_id]) for e in Edge.objects.filter(edge_type="ATTACHED_TO_INSTANCE__aws_core")}
        assert attached == {("eni-09f901fe", "i-0abc123def4567890")} and eni.name == "eni-09f901fe"


class TestTheWalk:
    def test_ids_go_in_groups_of_one_hundred(self) -> None:
        client, adapter = make((200, b"<ServiceResponse><responseCode>SUCCESS</responseCode><count>0</count><hasMoreRecords>false</hasMoreRecords></ServiceResponse>", {}))
        got = live.read_host_assets(client, [str(i) for i in range(1, 251)], bounded=lambda attempt, what: attempt(), time_left=lambda: 3600.0)
        assert got.complete and len(adapter.seen) == 3 and adapter.seen[2].body.count(b",") == 49

    def test_a_walk_stopped_at_the_page_ceiling_is_never_complete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(live, "MAX_TAG_PAGES", 2)
        pages = [(200, f"<ServiceResponse><responseCode>SUCCESS</responseCode><count>1</count><hasMoreRecords>true</hasMoreRecords><lastId>{n}</lastId>"
                        f"<data><HostAsset><id>{n}</id><qwebHostId>1</qwebHostId></HostAsset></data></ServiceResponse>".encode(), {}) for n in (10, 20)]
        client, _ = make(*pages)
        got = live.read_host_assets(client, ["1"], bounded=lambda attempt, what: attempt(), time_left=lambda: 3600.0)
        assert not got.complete and got.warnings[-1]["code"] == "TRUNCATED"

    def test_the_run_ceiling_lists_every_unfinished_group(self) -> None:
        client, adapter = make()
        got = live.read_host_assets(client, [str(i) for i in range(1, 151)], bounded=lambda attempt, what: attempt(), time_left=lambda: 0.0)
        assert not got.complete and adapter.seen == []
        assert [n["scope"] for n in got.not_read] == ["host asset group 1", "host asset group 2"]


@pytest.mark.django_db
class TestWithoutDetections:
    def test_host_assets_without_detections_is_not_read_never_empty(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        secrets(sources={"host_assets": True, "detections": False})
        router = AssetRouter()
        _collector(monkeypatch, router).run()
        assert HOST_ASSET_SEARCH_PATH not in [urlsplit(r.url).path for r in router.seen]
        run = QualysScanRun.objects.get(subscription_key=KEY)
        assert any(s["scope"] == "host_assets" and "detections are switched off" in s["reason"] for s in run.scopes_not_read)

