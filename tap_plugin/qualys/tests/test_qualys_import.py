"""Decomposed runs imported through the real GRIFT importer and read back through the models.

The grid applies a written node as a full replacement and resolves key-addressed edges against the batch and
the live grid; these tests prove the envelopes the decomposer builds are accepted and mean what it intends.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
import tap_plugin.compliance_core.models  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models  # noqa: F401 — trigger model registration
import tap_plugin.qualys.models  # noqa: F401 — trigger model registration

from tap_grid.grift.importer import grift_import
from tap_grid.models import Edge
from tap_plugin.qualys.decompose import COMPLETE, WINDOW, Run, decompose, document
from tap_plugin.qualys.identity import subscription_key
from tap_plugin.qualys.models import QualysDetection, QualysHost, QualysQid, QualysScanRun, QualysSubscription
from tap_plugin.qualys.parse import parse_detection_page, parse_knowledgebase_page
from tap_plugin.qualys.store import GridStore, newest_read_time

FIXTURES = Path(__file__).resolve().parent / "fixtures"
HOST = "https://qualysapi.qg2.apps.qualys.com"
KEY = subscription_key(HOST, "acme")


def _load(kind: str, detection_xml: bytes, at: datetime) -> Run:
    run = Run(api_host=HOST, label="acme", source="file", read_kind=kind, started_at=at, read_at=at, applied_filter={},
              knowledgebase_asked={"6666666", "38170", "11827", "45038"})
    pages = [parse_detection_page(detection_xml)]
    kb = [parse_knowledgebase_page((FIXTURES / "kb-documented.xml").read_bytes())]
    result = decompose(run, pages, kb, GridStore())
    imported = grift_import(document(result, run))
    assert not imported.errors, imported.errors
    return run


def _assembled() -> bytes:
    """The assembled page without its next-page link, so a complete read of it is whole."""
    body = (FIXTURES / "hld-ec2-assembled.xml").read_bytes()
    start, end = body.index(b"<WARNING>"), body.index(b"</WARNING>") + len(b"</WARNING>")
    return body[:start] + body[end:]


@pytest.mark.django_db
class TestFirstRun:
    def test_nodes_land(self) -> None:
        _load(COMPLETE, _assembled(), datetime(2026, 11, 20, 18, tzinfo=UTC))
        assert QualysSubscription.objects.get(subscription_key=KEY).subscription_label == "acme"
        host = QualysHost.objects.get(subscription_key=KEY, host_id="1001")
        assert host.cloud_resource_id == "i-0abc123def4567890" and host.state == "current"
        assert QualysDetection.objects.filter(subscription_key=KEY).count() == 4
        assert QualysQid.objects.get(subscription_key=KEY, qid="6666666").kb_returned is True
        assert QualysQid.objects.get(subscription_key=KEY, qid="38170").kb_returned is False
        assert QualysScanRun.objects.get(subscription_key=KEY).read_kind == COMPLETE

    def test_edges_land(self) -> None:
        _load(COMPLETE, _assembled(), datetime(2026, 11, 20, 18, tzinfo=UTC))
        counts = {slug: Edge.objects.filter(edge_type=slug).count() for slug in ("DETECTED_ON_HOST__qualys", "ABOUT_QID__qualys", "RUN_OF_SUBSCRIPTION__qualys")}
        assert counts == {"DETECTED_ON_HOST__qualys": 4, "ABOUT_QID__qualys": 4, "RUN_OF_SUBSCRIPTION__qualys": 1}

    def test_fixed_is_resolved(self) -> None:
        _load(COMPLETE, _assembled(), datetime(2026, 11, 20, 18, tzinfo=UTC))
        fixed = QualysDetection.objects.get(subscription_key=KEY, qid="38170")
        assert (fixed.state, fixed.resolution_source) == ("resolved", "qualys_fixed")


@pytest.mark.django_db
class TestSecondRun:
    def test_reread_is_the_same_nodes(self) -> None:
        _load(COMPLETE, _assembled(), datetime(2026, 11, 20, 18, tzinfo=UTC))
        _load(COMPLETE, _assembled(), datetime(2026, 11, 21, 18, tzinfo=UTC))
        assert QualysDetection.objects.filter(subscription_key=KEY).count() == 4
        assert QualysHost.objects.filter(subscription_key=KEY).count() == 1

    def test_absent_detection_keeps_its_state_and_absent_host_is_withdrawn(self) -> None:
        _load(COMPLETE, _assembled(), datetime(2026, 11, 20, 18, tzinfo=UTC))
        # A complete read that returns only Qualys's documented sample: host 1001 and its detections are absent.
        _load(COMPLETE, (FIXTURES / "hld-documented.xml").read_bytes(), datetime(2026, 11, 21, 18, tzinfo=UTC))
        gone = QualysHost.objects.get(subscription_key=KEY, host_id="1001")
        assert gone.state == "withdrawn" and gone.cloud_resource_id == "i-0abc123def4567890"  # rewritten whole
        assert QualysDetection.objects.get(subscription_key=KEY, host_id="1001", qid="6666666").state == "open"

    def test_window_read_withdraws_nothing(self) -> None:
        _load(COMPLETE, _assembled(), datetime(2026, 11, 20, 18, tzinfo=UTC))
        _load(WINDOW, (FIXTURES / "hld-documented.xml").read_bytes(), datetime(2026, 11, 21, 18, tzinfo=UTC))
        assert QualysHost.objects.get(subscription_key=KEY, host_id="1001").state == "current"

    def test_returned_qid_is_not_wiped_by_a_later_read(self) -> None:
        _load(COMPLETE, _assembled(), datetime(2026, 11, 20, 18, tzinfo=UTC))
        title = QualysQid.objects.get(subscription_key=KEY, qid="6666666").title
        run = Run(api_host=HOST, label="acme", source="file", read_kind=WINDOW, started_at=datetime(2026, 11, 21, tzinfo=UTC),
                  read_at=datetime(2026, 11, 21, tzinfo=UTC), applied_filter={}, knowledgebase_complete=False)
        result = decompose(run, [parse_detection_page(_assembled())], [], GridStore())
        assert not grift_import(document(result, run)).errors
        assert QualysQid.objects.get(subscription_key=KEY, qid="6666666").title == title

    def test_newest_read_time(self) -> None:
        _load(COMPLETE, _assembled(), datetime(2026, 11, 20, 18, tzinfo=UTC))
        _load(WINDOW, _assembled(), datetime(2026, 11, 22, 18, tzinfo=UTC))
        assert newest_read_time(KEY) == datetime(2026, 11, 22, 18, tzinfo=UTC)
