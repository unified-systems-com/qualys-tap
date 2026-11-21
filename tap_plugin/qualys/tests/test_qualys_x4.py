"""X4 end to end: the fixture export archive through ``qualys_load``, as an operator would load it.

The archive is the loader tests' fixture archive (the assembled EC2 detection page and Qualys's documented
knowledge-base sample, which names CVE-2024-40780 for QID 6666666). One test per part of the target:

- a neutral finding carried by the package where the parser is sure, by the host where it is not;
- the EC2 instance aws_core holds linked, and left exactly as it was;
- the archive loaded with aws_core absent, without error.
"""

import io
from pathlib import Path

import pytest
import tap_plugin.aws_core.models  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models  # noqa: F401 — trigger model registration
import tap_plugin.qualys.models  # noqa: F401 — trigger model registration
from django.apps import apps
from django.core.management import call_command
from django.forms.models import model_to_dict

from tap_grid.models import Edge
from tap_grid.services import create_node
from tap_plugin.qualys import neutral
from tap_plugin.qualys.models import QualysHost, QualysScanRun
from tap_plugin.qualys.tests.test_qualys_load import KEY, _fixture, make_archive

INSTANCE = "i-0abc123def4567890"
CVE = "CVE-2024-40780"


def _load(path: Path) -> str:
    out = io.StringIO()
    call_command("qualys_load", str(path), subscription="acme", stdout=out)
    return out.getvalue()


def _finding():
    return apps.get_model("compliance_core", "ComplianceFinding").objects.get(source="qualys", source_key=neutral.source_key(KEY, "1001", CVE))


def _carrier_of(finding) -> int:
    (carries,) = Edge.objects.filter(edge_type=neutral.CARRIES, to_entity_id=finding.entity_id)
    return carries.from_entity_id


@pytest.mark.django_db
class TestX4:
    def test_package_carries_where_the_parser_is_sure(self, tmp_path: Path) -> None:
        assert "loaded run" in _load(make_archive(tmp_path))
        finding = _finding()
        package = apps.get_model("computing_core", "Package").objects.get(ecosystem="deb", name="webkit2gtk", version="2.44.2-1~deb12u1")
        assert finding.status == "open" and _carrier_of(finding) == package.entity_id
        assert Edge.objects.filter(edge_type=neutral.CONCERNS, from_entity_id=finding.entity_id).count() == 1

    def test_host_carries_where_the_parser_is_not(self, tmp_path: Path) -> None:
        # The same archive with the host's OS one the parser cannot place: the observation is ambiguous.
        page = _fixture("hld-ec2-assembled.xml").replace(b"Ubuntu 22.04.4 LTS", b"Some Appliance OS")
        _load(make_archive(tmp_path, pages=[page]))
        finding = _finding()
        host = QualysHost.objects.get(subscription_key=KEY, host_id="1001")
        assert _carrier_of(finding) == host.entity_id
        assert not apps.get_model("computing_core", "Package").objects.exists()

    def test_held_ec2_instance_linked_and_unchanged(self, tmp_path: Path) -> None:
        assert create_node("aws_core__aws_ec2_instance", {"instance_id": INSTANCE, "name": "web-1", "state": "running"}).success
        model = apps.get_model("aws_core", "Ec2Instance")
        before = model.objects.get(instance_id=INSTANCE)
        snapshot, version = model_to_dict(before), before.entity.version
        _load(make_archive(tmp_path))
        after = model.objects.get(instance_id=INSTANCE)
        assert model_to_dict(after) == snapshot and after.entity.version == version
        host = QualysHost.objects.get(subscription_key=KEY, host_id="1001")
        (link,) = Edge.objects.filter(edge_type="TRACKS_EC2_INSTANCE__qualys")
        assert (link.from_entity_id, link.to_entity_id) == (host.entity_id, after.entity_id)

    def test_loads_with_aws_core_absent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        real = apps.get_model

        def without_aws_core(app_label, *args, **kwargs):
            if app_label == "aws_core":
                raise LookupError("aws_core is not installed")
            return real(app_label, *args, **kwargs)

        monkeypatch.setattr(apps, "get_model", without_aws_core)
        assert "loaded run" in _load(make_archive(tmp_path))
        run = QualysScanRun.objects.get(subscription_key=KEY)
        assert "AWS_CORE_ABSENT" in [w["code"] for w in run.warnings]
        assert _finding().status == "open"
        assert not Edge.objects.filter(edge_type="TRACKS_EC2_INSTANCE__qualys").exists()
