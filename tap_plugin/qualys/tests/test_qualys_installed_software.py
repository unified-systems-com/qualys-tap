"""Installed software on the shared computing_core host (req-qualys-installed-software).

The Qualys host 1001 in the assembled fixture is an Ubuntu EC2 instance, so its packages are ``deb``. The asset
records are synthetic, in the documented shape of the host asset search.
"""

import json
from pathlib import Path
from typing import Any

import pytest
import tap_plugin.aws_core.models  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models  # noqa: F401 — trigger model registration
import tap_plugin.qualys.models  # noqa: F401 — trigger model registration
from tap_plugin.qualys import shared_host
from tap_plugin.qualys.collectors import qualys_collector
from tap_plugin.qualys.models import QualysHost, QualysScanRun
from tap_plugin.qualys.tests.test_qualys_aws import _page as aws_page
from tap_plugin.qualys.tests.test_qualys_collector import HOST, KEY, PASSWORD, _collector, no_sockets  # noqa: F401
from tap_plugin.qualys.tests.test_qualys_host_assets import AssetRouter

from tap_grid.models import Edge, Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_node

INSTANCE = "i-0abc123def4567890"


def _assets(software: str) -> bytes:
    return (b"<ServiceResponse><responseCode>SUCCESS</responseCode><count>1</count><hasMoreRecords>false</hasMoreRecords><data>"
            b"<HostAsset><id>7727721</id><qwebHostId>1001</qwebHostId>" + software.encode() + b"</HostAsset></data></ServiceResponse>")


SOFTWARE = ("<software><list>"
            "<HostAssetSoftware><name>openssl</name><version>3.0.2-0ubuntu1.15</version></HostAssetSoftware>"
            "<HostAssetSoftware><name>bash</name><version>5.1-6ubuntu1</version></HostAssetSoftware>"
            "<HostAssetSoftware><name>tzdata</name><version>1:2024a-0ubuntu0.22.04</version></HostAssetSoftware>"
            "</list></software>")


@pytest.fixture
def secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data: dict[str, Any] = {"api_host": HOST, "subscription": "acme-prod", "username": "acme_ro", "password": PASSWORD,
                            "sources": {"tags": False, "host_assets": True}}
    (tmp_path / "acme.secret.json").write_text(json.dumps({"scope": "qualys", "key": "acme", "kind": "qualys_api_credential", "description": "test", "data": data}))
    monkeypatch.setattr(qualys_collector.secrets_root, "resolve", lambda: tmp_path)


def _router(software: str = SOFTWARE) -> AssetRouter:
    return AssetRouter(page1=(200, aws_page(), {}), assets=(200, _assets(software), {}))


def _host_model() -> Any:
    return get_model_class(shared_host.HOST_TYPE)


def _installs() -> set[tuple[str, str]]:
    names = {e.id: e.name for e in Entity.objects.all()}
    return {(names[e.from_entity_id], names[e.to_entity_id]) for e in Edge.objects.filter(edge_type=shared_host.INSTALLS_PACKAGE)}


class TestHostKey:
    @pytest.mark.spec("req-qualys-installed-software-1")
    def test_an_ec2_host_is_its_instance_under_the_aws_ec2_realm(self) -> None:
        host = {"cloud_provider": "AWS", "cloud_service": "EC2", "cloud_resource_id": INSTANCE}
        assert shared_host.host_key(host) == ("aws-ec2", INSTANCE)
        assert shared_host.host_key({**host, "cloud_resource_id": "i-not/hex"}) is None
        assert shared_host.host_key({"cloud_provider": "AZURE", "cloud_service": "VM", "cloud_resource_id": INSTANCE}) is None
        assert shared_host.host_key({"ip": "10.0.0.1"}) is None  # no issuer's id: no shared host

    def test_the_ecosystem_comes_from_the_os_and_never_from_a_guess(self) -> None:
        software = [{"name": "openssl", "version": "3.0.2-0ubuntu1.15"}, {"name": "tzdata", "version": "1:2024a-0ubuntu0.22.04"}]
        assert shared_host.packages_of(software, "Ubuntu 22.04.4 LTS") == [("deb", "openssl", "3.0.2-0ubuntu1.15")]  # an epoch is ambiguous
        assert shared_host.packages_of(software, "Windows Server 2019") == []


@pytest.mark.django_db
class TestOnTheGrid:
    @pytest.mark.spec("req-qualys-installed-software-1")
    def test_the_instance_is_a_shared_host_that_installs_its_packages(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        _collector(monkeypatch, _router()).run()
        host = _host_model().objects.get(realm="aws-ec2", stable_id=INSTANCE)
        assert host.kind is None  # key fields only: the shared-fact rule
        assert _installs() == {(INSTANCE, "openssl 3.0.2-0ubuntu1.15"), (INSTANCE, "bash 5.1-6ubuntu1")}
        package = get_model_class("computing_core__package").objects.get(name="openssl")
        assert (package.ecosystem, package.version) == ("deb", "3.0.2-0ubuntu1.15")
        qualys = QualysHost.objects.get(subscription_key=KEY, host_id="1001")
        assert Edge.objects.filter(edge_type=shared_host.TRACKS_HOST, from_entity_id=qualys.entity_id, to_entity_id=host.entity_id).exists()
        counters = QualysScanRun.objects.get(subscription_key=KEY).counters
        assert counters["shared_hosts_created"] == 1 and counters["installs"] == 2

    @pytest.mark.spec("req-qualys-installed-software-2")
    def test_a_host_another_plugin_holds_is_linked_and_never_rewritten(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        assert create_node(shared_host.HOST_TYPE, {"realm": "aws-ec2", "stable_id": INSTANCE, "name": "web-1", "kind": "virtual_machine"}).success
        _collector(monkeypatch, _router()).run()
        host = _host_model().objects.get(realm="aws-ec2", stable_id=INSTANCE)
        assert (host.name, host.kind) == ("web-1", "virtual_machine")
        assert _installs() == {("web-1", "openssl 3.0.2-0ubuntu1.15"), ("web-1", "bash 5.1-6ubuntu1")}
        assert "shared_hosts_created" not in QualysScanRun.objects.get(subscription_key=KEY).counters

    @pytest.mark.spec("req-qualys-installed-software-2")
    def test_no_software_read_means_no_shared_host_and_no_installs(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        _collector(monkeypatch, _router(software="")).run()
        assert not _host_model().objects.filter(stable_id=INSTANCE).exists() and not _installs()

    @pytest.mark.spec("req-qualys-installed-software-3")
    def test_the_installs_claim_is_never_complete_on_a_shared_host(self) -> None:
        _, edges, claims, _ = shared_host.build([{**_BASE, "os": "Ubuntu 22.04"}], _ASSETS, _NoGrid())
        assert [c["read"] for c in claims] == ["partial"] and claims[0]["direction"] == "outbound"
        _, edges, claims, _ = shared_host.build([{**_BASE, "os": "Windows Server 2019"}], _ASSETS, _NoGrid())
        assert claims[0]["read"] == "partial" and not [e for e in edges if e["edge"]["edge_type"] == shared_host.INSTALLS_PACKAGE]

    @pytest.mark.spec("req-qualys-installed-software-1")
    def test_two_qualys_hosts_on_one_instance_are_both_linked_and_both_counted(self) -> None:
        other = {**_BASE, "host_id": "1002", "os": "Ubuntu 22.04"}
        assets = {**_ASSETS, "1002": {"software": [{"name": "curl", "version": "7.81.0-1ubuntu1.15"}]}}
        _, edges, claims, _ = shared_host.build([{**_BASE, "os": "Ubuntu 22.04"}, other], assets, _NoGrid())
        assert {e["edge"]["from_ref"] for e in edges if e["edge"]["edge_type"] == shared_host.TRACKS_HOST} == {"h1001", "h1002"}
        assert sorted(e["edge"]["to_key"]["key"]["name"] for e in edges if e["edge"]["edge_type"] == shared_host.INSTALLS_PACKAGE) == ["bash", "curl"]
        assert len(claims) == 1  # one scope per shared host (req-grid-reconcile-edge-authority-4)


class _NoGrid:
    def held_keys(self, entity_type: str, keys: Any) -> set[Any]:
        return set()

    def held_packages(self, keys: Any) -> set[Any]:
        return set()

    def default_dimensions(self, entity_type: str) -> dict[str, str]:
        return {}


_BASE = {"cloud_provider": "AWS", "cloud_service": "EC2", "cloud_resource_id": INSTANCE, "host_id": "1001"}
_ASSETS = {"1001": {"software": [{"name": "bash", "version": "5.1-6ubuntu1"}]}}

@pytest.mark.django_db
class TestAHeldHostAtAnyBound:
    @pytest.mark.spec("req-qualys-installed-software-2")
    def test_every_install_is_written_once_and_the_claim_proposes_nothing(self, secrets) -> None:
        from tap_plugin.qualys.decompose import documents

        assert create_node(shared_host.HOST_TYPE, {"realm": "aws-ec2", "stable_id": INSTANCE, "name": "web-1"}).success
        captured: dict[str, Any] = {}

        def capture(result: Any, run: Any) -> None:
            captured["result"], captured["run"] = result, run

        import tap_plugin.qualys.collectors.qualys_collector as qc

        original = qc.documents
        router = _router()
        collector = None

        def spy(result: Any, run: Any, **kw: Any) -> Any:
            capture(result, run)
            return original(result, run, **kw)

        import pytest as _pytest

        mp = _pytest.MonkeyPatch()
        mp.setattr(qc, "documents", spy)
        try:
            collector = _collector(mp, router)
            collector.run()
        finally:
            mp.undo()
        for bound in (1, 2, 3, 50):
            docs = documents(captured["result"], captured["run"], max_keys=bound)
            batches = [d["batches"][0] for d in docs]
            claims = [c for b in batches for c in b.get("edge_cases", {}).get("authority", []) if c["edge_type"] == shared_host.INSTALLS_PACKAGE]
            installs = [e for b in batches for e in b["edges"] if e["edge"]["edge_type"] == shared_host.INSTALLS_PACKAGE]
            assert [c["read"] for c in claims] == ["partial"], bound
            assert sorted(e["edge"]["to_key"]["key"]["name"] for e in installs) == ["bash", "openssl"], bound
            first_install = min(i for i, b in enumerate(batches) for e in b["edges"] if e["edge"]["edge_type"] == shared_host.INSTALLS_PACKAGE)
            last_package = max(i for i, b in enumerate(batches) for n in b["nodes"] if n["entity"]["entity_type"] == "computing_core__package")
            assert first_install > last_package, bound  # after the packages it names, never in the opening

