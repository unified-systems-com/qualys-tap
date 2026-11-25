"""Addresses and open ports on the shared computing_core host (req-qualys-host-network).

Host 1001 in the AWS fixture is an EC2 instance in vpc-0123abcd, reported at 10.0.1.15. Asset records are synthetic,
in the documented shape of the host asset search.
"""

import json
from pathlib import Path
from typing import Any

import pytest
import tap_plugin.aws_core.models  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models  # noqa: F401 — trigger model registration
import tap_plugin.qualys.models  # noqa: F401 — trigger model registration
from tap_plugin.computing_core import key_dimensions
from tap_plugin.qualys import shared_host
from tap_plugin.qualys.collectors import qualys_collector
from tap_plugin.qualys.models import QualysScanRun
from tap_plugin.qualys.tests.test_qualys_aws import _page as aws_page
from tap_plugin.qualys.tests.test_qualys_collector import HOST, KEY, PASSWORD, _collector, no_sockets  # noqa: F401
from tap_plugin.qualys.tests.test_qualys_host_assets import AssetRouter

from tap_grid.models import Edge, Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_node

BODY = ("<networkInterface><list>"
        "<HostAssetInterface><interfaceName>ens5</interfaceName><address>10.0.1.15</address></HostAssetInterface>"
        "<HostAssetInterface><interfaceName>ens5</interfaceName><address>54.210.0.7</address></HostAssetInterface>"
        "<HostAssetInterface><interfaceName>lo</interfaceName><address>127.0.0.1</address></HostAssetInterface>"
        "</list></networkInterface>"
        "<openPort><list>"
        "<HostAssetOpenPort><port>22</port><protocol>TCP</protocol></HostAssetOpenPort>"
        "<HostAssetOpenPort><port>443</port><protocol>TCP</protocol></HostAssetOpenPort>"
        "<HostAssetOpenPort><port>0</port><protocol>TCP</protocol></HostAssetOpenPort>"
        "<HostAssetOpenPort><port>53</port><protocol>ICMP</protocol></HostAssetOpenPort>"
        "</list></openPort>")
NETWORKS = {"default": "corp", "vpcs": {"vpc-0123abcd": "prod-vpc"}}


def _assets(body: str) -> bytes:
    return (b"<ServiceResponse><responseCode>SUCCESS</responseCode><count>1</count><hasMoreRecords>false</hasMoreRecords><data>"
            b"<HostAsset><id>7727721</id><qwebHostId>1001</qwebHostId>" + body.encode() + b"</HostAsset></data></ServiceResponse>")


def _secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, networks: dict[str, Any] | None) -> None:
    data: dict[str, Any] = {"api_host": HOST, "subscription": "acme-prod", "username": "acme_ro", "password": PASSWORD,
                            "sources": {"tags": False, "host_assets": True}}
    if networks is not None:
        data["networks"] = networks
    (tmp_path / "acme.secret.json").write_text(json.dumps({"scope": "qualys", "key": "acme", "kind": "qualys_api_credential", "description": "test", "data": data}))
    monkeypatch.setattr(qualys_collector.secrets_root, "resolve", lambda: tmp_path)


def _run(monkeypatch: pytest.MonkeyPatch) -> None:
    _collector(monkeypatch, AssetRouter(page1=(200, aws_page(), {}), assets=(200, _assets(BODY), {}))).run()


def _address(net: str, addr: str) -> Any:
    return get_model_class(shared_host.ADDRESS_TYPE).find_existing(**{key_dimensions.NETWORK_NAME_ENTRY: net, "address": addr})


def _pairs(edge_type: str) -> set[tuple[str, str]]:
    names = {e.id: e.name for e in Entity.objects.all()}
    return {(names[e.from_entity_id], names[e.to_entity_id]) for e in Edge.objects.filter(edge_type=edge_type)}


class TestTheRules:
    @pytest.mark.spec("req-qualys-host-network-1")
    def test_public_is_internet_and_private_takes_the_vpcs_name(self) -> None:
        assert shared_host.network_of("54.210.0.7", "vpc-0123abcd", NETWORKS) == "Internet"
        assert shared_host.network_of("10.0.1.15", "vpc-0123abcd", NETWORKS) == "prod-vpc"
        assert shared_host.network_of("10.0.1.15", "vpc-0fffffff", NETWORKS) == "corp"
        assert shared_host.network_of("10.0.1.15", None, {"default": "corp"}) == "corp"

    def test_one_spelling_per_address_and_no_host_scoped_ones(self) -> None:
        assert shared_host.canonical_address("::ffff:10.0.1.15") == "10.0.1.15"
        assert shared_host.canonical_address("127.0.0.1") is None
        assert shared_host.canonical_address("169.254.169.254") is None
        assert shared_host.canonical_address("not-an-ip") is None

    def test_ports_need_a_known_transport_and_a_real_number(self) -> None:
        got = shared_host.ports_of([{"port": "22", "protocol": "TCP"}, {"port": "0", "protocol": "TCP"},
                                    {"port": "53", "protocol": "ICMP"}, {"port": "x", "protocol": "UDP"}])
        assert got == {("tcp", 22)}


@pytest.mark.django_db
class TestOnTheGrid:
    @pytest.mark.spec("req-qualys-host-network-1")
    def test_addresses_on_their_networks_used_by_their_interface(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _secrets(tmp_path, monkeypatch, NETWORKS)
        _run(monkeypatch)
        private, public = _address("prod-vpc", "10.0.1.15"), _address("Internet", "54.210.0.7")
        assert private is not None and public is not None
        assert not get_model_class(shared_host.ADDRESS_TYPE).objects.filter(address="127.0.0.1").exists()
        assert _pairs(shared_host.USES_ADDRESS) == {("ens5", "10.0.1.15"), ("ens5", "54.210.0.7")}

    @pytest.mark.spec("req-qualys-host-network-2")
    def test_open_ports_are_available_at_the_hosts_address(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _secrets(tmp_path, monkeypatch, NETWORKS)
        _run(monkeypatch)
        ports = get_model_class(shared_host.PORT_TYPE).objects.all()
        assert sorted((p.address, p.transport, p.port_number) for p in ports) == [("10.0.1.15", "tcp", 22), ("10.0.1.15", "tcp", 443)]
        address = _address("prod-vpc", "10.0.1.15")
        by_entity = {p.entity_id: p.port_number for p in ports}
        available = Edge.objects.filter(edge_type=shared_host.AVAILABLE_AT)
        assert sorted(by_entity[e.from_entity_id] for e in available) == [22, 443]
        assert {e.to_entity_id for e in available} == {address.entity_id}

    @pytest.mark.spec("req-qualys-host-network-3")
    def test_an_address_another_plugin_holds_is_linked_and_never_rewritten(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        assert create_node(shared_host.ADDRESS_TYPE, {"address": "10.0.1.15", "name": "web-1 private"},
                           dimensions={key_dimensions.NETWORK_NAME: "prod-vpc"}).success
        _secrets(tmp_path, monkeypatch, NETWORKS)
        _run(monkeypatch)
        assert get_model_class(shared_host.ADDRESS_TYPE).objects.filter(address="10.0.1.15").count() == 1
        assert _address("prod-vpc", "10.0.1.15").name == "web-1 private"
        assert ("ens5", "web-1 private") in _pairs(shared_host.USES_ADDRESS)

    @pytest.mark.spec("req-qualys-host-network-3")
    def test_no_declared_network_writes_no_address_or_port(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _secrets(tmp_path, monkeypatch, None)
        _run(monkeypatch)
        assert not get_model_class(shared_host.ADDRESS_TYPE).objects.exists()
        assert not get_model_class(shared_host.PORT_TYPE).objects.exists()
        assert QualysScanRun.objects.get(subscription_key=KEY).counters["networks_undeclared"] == 1
        assert get_model_class(shared_host.INTERFACE_TYPE).objects.filter(interface_name="ens5").exists()  # interfaces need no network
