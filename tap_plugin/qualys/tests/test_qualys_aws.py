"""The optional AWS side (req-qualys-aws): aws_core nodes and edges minted from what Qualys reports.

The METADATA attributes added to the assembled fixture carry synthetic values under the names a live subscription
returned (field report, 2026-11-23, Q38d).
"""

import json
from pathlib import Path
from typing import Any

import pytest
import tap_plugin.aws_core.models  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models  # noqa: F401 — trigger model registration
import tap_plugin.qualys.models  # noqa: F401 — trigger model registration
from django.apps import apps
from tap_plugin.qualys import aws_mint
from tap_plugin.qualys.collectors import qualys_collector
from tap_plugin.qualys.models import QualysHost
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
from tap_grid.services import create_node

INSTANCE = "i-0abc123def4567890"
METADATA = {
    "latest/dynamic/instance-identity/document/accountId": "123456789012",
    "latest/dynamic/instance-identity/document/availabilityZone": "us-east-1a",
    "latest/dynamic/instance-identity/document/imageId": "ami-0123456789abcdef0",
    "latest/dynamic/instance-identity/document/instanceType": "t3.medium",
    "latest/dynamic/instance-identity/document/privateIp": "10.0.1.15",
    "latest/meta-data/public-ipv4": "",
    "instanceState": "running",
    "vpcId": "vpc-0123abcd",
    "subnetId": "subnet-0456efgh",
    "groupId": "sg-0aaa1111",
    "groupName": "web",
    "ownerId": "123456789012",
    "keyName": "deploy",
}
CLOUD_TAGS = [("Name", "web-1"), ("Env", "prod"), ("Owner", "")]


def _page() -> bytes:
    body = _fixture("hld-ec2-assembled.xml").decode()
    attributes = "".join(
        f"<ATTRIBUTE><NAME><![CDATA[{name}]]></NAME><LAST_STATUS>Success</LAST_STATUS><VALUE><![CDATA[{value}]]></VALUE>"
        "<LAST_SUCCESS_DATE>2026-11-22T10:00:00Z</LAST_SUCCESS_DATE></ATTRIBUTE>"
        for name, value in METADATA.items()
    )
    body = body.replace("</EC2>\n</METADATA>", f"{attributes}</EC2>\n</METADATA>", 1)
    tags = "".join(f"<CLOUD_TAG><NAME>{n}</NAME><VALUE>{v}</VALUE><LAST_SUCCESS_DATE>2026-11-20T00:00:00Z</LAST_SUCCESS_DATE></CLOUD_TAG>" for n, v in CLOUD_TAGS)
    assert body.count("</METADATA>") == 1
    return body.replace("</METADATA>", f"</METADATA>\n<CLOUD_PROVIDER_TAGS>{tags}</CLOUD_PROVIDER_TAGS>", 1).encode()


@pytest.fixture
def secrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def write(integrations: dict[str, bool] | None = None) -> None:
        data: dict[str, Any] = {"api_host": HOST, "subscription": "acme-prod", "username": "acme_ro", "password": PASSWORD,
                                "sources": {"tags": False}}
        if integrations is not None:
            data["integrations"] = integrations
        (tmp_path / "acme.secret.json").write_text(json.dumps({"scope": "qualys", "key": "acme", "kind": "qualys_api_credential", "description": "test", "data": data}))

    monkeypatch.setattr(qualys_collector.secrets_root, "resolve", lambda: tmp_path)
    write({"aws": True})
    return write


def _model(name: str) -> Any:
    return apps.get_model("aws_core", name)


def _router() -> Router:
    return Router(page1=(200, _page(), {}))


def _edge_pairs(slug: str) -> set[tuple[str, str]]:
    names = {e.id: e.name for e in Entity.objects.all()}
    return {(names.get(e.from_entity_id), names.get(e.to_entity_id)) for e in Edge.objects.filter(edge_type=slug)}


@pytest.mark.django_db
class TestMinting:
    @pytest.mark.spec("req-qualys-aws-1")
    def test_every_aws_record_qualys_reports_is_minted_with_aws_cores_edges(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        _collector(monkeypatch, _router()).run()
        instance = _model("Ec2Instance").objects.get(instance_id=INSTANCE)
        assert (instance.ami_id, instance.ec2_type, instance.private_ip, instance.state) == ("ami-0123456789abcdef0", "t3.medium", "10.0.1.15", "running")
        assert instance.tags == {"Name": "web-1", "Env": "prod", "Owner": ""}
        assert instance.public_ip is None  # reported empty, so not written
        assert _model("Vpc").objects.filter(vpc_id="vpc-0123abcd").exists()
        assert _model("Subnet").objects.get(subnet_id="subnet-0456efgh").availability_zone == "us-east-1a"
        assert _model("SecurityGroup").objects.get(group_id="sg-0aaa1111").name == "web"
        assert _model("AwsAccount").objects.filter(account_id="123456789012").exists()
        assert _model("AwsAccountRegion").objects.filter(account_id="123456789012", region_code="us-east-1").exists()
        assert _edge_pairs("PARTITIONED_INTO_SUBNET__aws_core") == {("vpc-0123abcd", "subnet-0456efgh")}
        assert _edge_pairs("RESIDES_IN_VPC__aws_core") == {("web", "vpc-0123abcd")}
        assert _edge_pairs("HOSTS_EC2_INSTANCE__aws_core") == {("123456789012/us-east-1", INSTANCE)}
        # A VPC, subnet or security group gets no account or region edge: a shared VPC is another account's.
        assert not {p for p in _edge_pairs("BELONGS_TO_ACCOUNT__aws_core") if p[0] in {"vpc-0123abcd", "subnet-0456efgh"}}
        assert not _edge_pairs("HOSTS_VPC__aws_core") and not _edge_pairs("HOSTS_SUBNET__aws_core")
        # The Qualys host links to the instance it minted.
        host = QualysHost.objects.get(subscription_key=KEY, host_id="1001")
        assert host.ec2_metadata["keyName"] == "deploy" and host.ec2_metadata["latest/meta-data/public-ipv4"] == ""
        assert host.ec2_metadata_status["vpcId"] == {"last_status": "Success", "last_success_date": "2026-11-22T10:00:00Z", "last_error_date": None, "last_error": None}
        assert host.cloud_tags == [{"name": "Name", "value": "web-1"}, {"name": "Env", "value": "prod"}, {"name": "Owner", "value": ""}]
        assert Edge.objects.filter(edge_type="TRACKS_EC2_INSTANCE__qualys", from_entity_id=host.entity_id).exists()

    @pytest.mark.spec("req-qualys-aws-2")
    def test_a_node_aws_core_holds_is_never_rewritten(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        assert create_node("aws_core__aws_ec2_instance", {"instance_id": INSTANCE, "name": "web-1 (boto)", "state": "running", "ami_id": "ami-boto"}).success
        assert create_node("aws_core__aws_vpc", {"vpc_id": "vpc-0123abcd", "name": "main", "cidr_block": "10.9.0.0/16", "tags": {"k": "v"}}).success
        _collector(monkeypatch, _router()).run()
        instance = _model("Ec2Instance").objects.get(instance_id=INSTANCE)
        assert (instance.name, instance.state, instance.ami_id, instance.tags) == ("web-1 (boto)", "running", "ami-boto", None)
        vpc = _model("Vpc").objects.get(vpc_id="vpc-0123abcd")
        assert (vpc.name, vpc.cidr_block, vpc.tags) == ("main", "10.9.0.0/16", {"k": "v"})
        # Edges between a minted node and a held one are written; between two held ones they are aws_core's.
        assert _edge_pairs("PARTITIONED_INTO_SUBNET__aws_core") == {("main", "subnet-0456efgh")}
        assert _edge_pairs("HOSTS_EC2_INSTANCE__aws_core") == {("123456789012/us-east-1", "web-1 (boto)")}
        from tap_plugin.qualys.models import QualysScanRun

        run = QualysScanRun.objects.get(subscription_key=KEY)
        assert run.counters["aws_ec2_instance_held"] == 1 and run.counters["aws_vpc_held"] == 1 and "aws_ec2_instance_created" not in run.counters

    @pytest.mark.spec("req-qualys-aws-3")
    def test_off_by_default_mints_nothing(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:
        secrets(None)
        _collector(monkeypatch, _router()).run()
        assert not _model("Vpc").objects.exists() and not _model("Ec2Instance").objects.exists()
        assert QualysHost.objects.get(subscription_key=KEY, host_id="1001").cloud_tags is not None  # read either way

    @pytest.mark.spec("req-qualys-aws-3")
    def test_without_aws_core_it_mints_nothing(self) -> None:
        class NoAws:
            def held_keys(self, entity_type: str, keys: Any) -> None:
                return None

            def default_dimensions(self, entity_type: str) -> dict[str, str]:
                return {}

        host = {"cloud_provider": "AWS", "cloud_service": "EC2", "cloud_resource_id": INSTANCE, "ec2_metadata": METADATA, "cloud_tags": None}
        got = aws_mint.mint([host], NoAws())
        assert got.absent and not got.nodes and not got.edges


class TestObserve:
    def test_only_an_aws_ec2_host_is_read(self) -> None:
        assert aws_mint.observe({"cloud_provider": "AZURE", "cloud_service": "VM", "cloud_resource_id": INSTANCE}) is None
        assert aws_mint.observe({"cloud_provider": "AWS", "cloud_service": "EC2", "cloud_resource_id": "not-an-instance"}) is None

    def test_a_malformed_value_is_left_out_not_guessed(self) -> None:
        meta = {**METADATA, "latest/dynamic/instance-identity/document/accountId": "12345", "ownerId": "x",
                "groupId": "sg-0aaa1111 sg-0bbb2222", "groupName": "web db", "vpcId": "vpc-1 vpc-2"}
        seen = aws_mint.observe({"cloud_provider": "AWS", "cloud_service": "EC2", "cloud_resource_id": INSTANCE, "ec2_metadata": meta, "cloud_tags": None})
        assert seen["account_id"] is None and seen["vpc_id"] is None and seen["tags"] is None
        # Two groups are both minted, but neither is named: the pairing of several names is not documented.
        assert seen["security_groups"] == ["sg-0aaa1111", "sg-0bbb2222"] and seen["group_names"] == {}
