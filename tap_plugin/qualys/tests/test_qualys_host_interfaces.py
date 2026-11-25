"""Network interfaces on the shared computing_core host (req-qualys-installed-software-4).

Host 1001 in the assembled fixture is an EC2 instance. The asset records are synthetic, in the documented shape
of the host asset search.
"""

import json
from pathlib import Path
from typing import Any

import pytest
import tap_plugin.aws_core.models  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models  # noqa: F401 — trigger model registration
import tap_plugin.qualys.models  # noqa: F401 — trigger model registration
from tap_grid.models import Edge, Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_node
from tap_plugin.computing_core import key_dimensions

from tap_plugin.qualys import shared_host
from tap_plugin.qualys.collectors import qualys_collector
from tap_plugin.qualys.tests.test_qualys_aws import _page as aws_page
from tap_plugin.qualys.tests.test_qualys_collector import HOST, PASSWORD, _collector, no_sockets  # noqa: F401
from tap_plugin.qualys.tests.test_qualys_host_assets import AssetRouter

INSTANCE = "i-0abc123def4567890"
SCOPE = f"aws-ec2|{INSTANCE}"
INTERFACES = ("<networkInterface><list>"
              "<HostAssetInterface><interfaceName>ens5</interfaceName><macAddress></macAddress><address>10.0.1.25</address></HostAssetInterface>"
              "<HostAssetInterface><interfaceName>docker0</interfaceName><macAddress>02:42:AC:11:00:01</macAddress><address>172.17.0.1</address></HostAssetInterface>"
              "<HostAssetInterface><interfaceName></interfaceName><address>10.0.1.26</address></HostAssetInterface>"
              "</list></networkInterface>")


def _assets(body: str) -> bytes:
    return (b"<ServiceResponse><responseCode>SUCCESS</responseCode><count>1</count><hasMoreRecords>false</hasMoreRecords><data>"
            b"<HostAsset><id>7727721</id><qwebHostId>1001</qwebHostId>" + body.encode() + b"</HostAsset></data></ServiceResponse>")


@pytest.fixture
def secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data: dict[str, Any] = {"api_host": HOST, "subscription": "acme-prod", "username": "acme_ro", "password": PASSWORD,
                            "sources": {"tags": False, "host_assets": True}}
    (tmp_path / "acme.secret.json").write_text(json.dumps({"scope": "qualys", "key": "acme", "kind": "qualys_api_credential", "description": "test", "data": data}))
    monkeypatch.setattr(qualys_collector.secrets_root, "resolve", lambda: tmp_path)


def _run(monkeypatch: pytest.MonkeyPatch, body: str = INTERFACES) -> None:
    _collector(monkeypatch, AssetRouter(page1=(200, aws_page(), {}), assets=(200, _assets(body), {}))).run()


def _interface(name: str) -> Any:
    return get_model_class(shared_host.INTERFACE_TYPE).find_existing(**{key_dimensions.HOST_ENTRY: SCOPE, "interface_name": name})


def _contained() -> set[tuple[str, str]]:
    names = {e.id: e.name for e in Entity.objects.all()}
    return {(names[e.from_entity_id], names[e.to_entity_id]) for e in Edge.objects.filter(edge_type=shared_host.CONTAINS_INTERFACE)}


class TestTheInterfacesOfAHost:
    @pytest.mark.spec("req-qualys-installed-software-4")
    def test_named_interfaces_only_and_an_empty_mac_is_unobserved(self) -> None:
        got = shared_host.interfaces_of([{"interface_name": "ens5", "mac_address": ""},
                                          {"interface_name": "docker0", "mac_address": "02:42:AC:11:00:01"},
                                          {"interface_name": "  ", "mac_address": "02:42:ac:11:00:02"}])
        assert got == {"ens5": None, "docker0": "02:42:ac:11:00:01"}
        assert shared_host.interfaces_of(None) == {}

    def test_the_host_scope_is_the_hosts_spine_key(self) -> None:
        assert shared_host.host_scope(("aws-ec2", INSTANCE)) == SCOPE


@pytest.mark.django_db
class TestOnTheGrid:
    @pytest.mark.spec("req-qualys-installed-software-4")
    def test_the_instance_contains_its_named_interfaces(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        _run(monkeypatch)
        ens5, docker0 = _interface("ens5"), _interface("docker0")
        assert ens5 is not None and ens5.mac_address is None  # Qualys's empty MAC is unobserved
        assert docker0.mac_address == "02:42:ac:11:00:01"
        assert _contained() == {(INSTANCE, "ens5"), (INSTANCE, "docker0")}

    @pytest.mark.spec("req-qualys-installed-software-4")
    def test_an_interface_another_plugin_holds_is_linked_and_never_rewritten(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        assert create_node(shared_host.INTERFACE_TYPE, {"interface_name": "ens5", "mac_address": "0a:1b:2c:3d:4e:5f", "state": "up"},
                           dimensions={key_dimensions.HOST: SCOPE}).success
        _run(monkeypatch)
        ens5 = _interface("ens5")
        assert (ens5.mac_address, ens5.state) == ("0a:1b:2c:3d:4e:5f", "up")
        assert get_model_class(shared_host.INTERFACE_TYPE).objects.filter(interface_name="ens5").count() == 1
        assert (INSTANCE, "ens5") in _contained()

    def test_no_interfaces_read_means_none_written(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        _run(monkeypatch, body="")
        assert not get_model_class(shared_host.INTERFACE_TYPE).objects.exists()
