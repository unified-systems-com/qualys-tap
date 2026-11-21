"""The EC2 link through the real importer, against an instance aws_core holds (req-qualys-ec2-link).

The instance is created through the service layer, as aws_core's collector would leave it; the run then links
the Qualys host to it and must leave every field and the revision of the instance exactly as they were.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
import tap_plugin.aws_core.models  # noqa: F401 — trigger model registration
import tap_plugin.qualys.models  # noqa: F401 — trigger model registration
from django.apps import apps
from django.forms.models import model_to_dict

from tap_grid.grift.importer import grift_import
from tap_grid.models import Edge
from tap_grid.services import create_node
from tap_plugin.qualys.decompose import COMPLETE, Run, decompose, document
from tap_plugin.qualys.models import QualysHost
from tap_plugin.qualys.parse import parse_detection_page, parse_knowledgebase_page
from tap_plugin.qualys.store import GridStore

FIXTURES = Path(__file__).resolve().parent / "fixtures"
HOST = "https://qualysapi.qg2.apps.qualys.com"
INSTANCE = "i-0abc123def4567890"


def _load() -> dict:
    at = datetime(2026, 11, 20, 18, tzinfo=UTC)
    run = Run(api_host=HOST, label="acme", source="file", read_kind=COMPLETE, started_at=at, read_at=at, applied_filter={})
    body = (FIXTURES / "hld-ec2-assembled.xml").read_bytes()
    start, end = body.index(b"<WARNING>"), body.index(b"</WARNING>") + len(b"</WARNING>")
    result = decompose(run, [parse_detection_page(body[:start] + body[end:])], [parse_knowledgebase_page((FIXTURES / "kb-documented.xml").read_bytes())], GridStore())
    imported = grift_import(document(result, run))
    assert not imported.errors, imported.errors
    return result.counters


def _instance_model():
    return apps.get_model("aws_core", "Ec2Instance")


@pytest.mark.django_db
class TestEc2LinkImported:
    def test_held_instance_linked_and_untouched(self) -> None:
        created = create_node("aws_core__aws_ec2_instance", {"instance_id": INSTANCE, "name": "web-1", "state": "running"})
        assert created.success, created
        before = _instance_model().objects.get(instance_id=INSTANCE)
        snapshot = model_to_dict(before)
        revision, history = before.entity.version, before.history.count()

        counters = _load()

        after = _instance_model().objects.get(instance_id=INSTANCE)
        assert model_to_dict(after) == snapshot
        assert (after.entity.version, after.history.count()) == (revision, history)
        host = QualysHost.objects.get(host_id="1001")
        (link,) = Edge.objects.filter(edge_type="TRACKS_EC2_INSTANCE__qualys")
        assert (link.from_entity_id, link.to_entity_id) == (host.entity_id, after.entity_id)
        assert link.properties == {"source_field": "CLOUD_RESOURCE_ID"}
        assert counters["ec2_linked"] == 1

    def test_second_run_draws_no_second_edge(self) -> None:
        assert create_node("aws_core__aws_ec2_instance", {"instance_id": INSTANCE}).success
        _load()
        _load()
        assert Edge.objects.filter(edge_type="TRACKS_EC2_INSTANCE__qualys").count() == 1

    def test_unheld_instance_creates_nothing(self) -> None:
        counters = _load()
        assert not _instance_model().objects.exists()
        assert not Edge.objects.filter(edge_type="TRACKS_EC2_INSTANCE__qualys").exists()
        assert counters["ec2_unresolved"] == 1
