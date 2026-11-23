"""Event time on the spine (core's req-grid-entity-event-time, tap 0.4.6): what each qualys model declares,
and what core derives from Qualys's own text once a decomposed run is imported.

Qualys sends its times as `YYYY-MM-DDTHH:MM:SSZ` text, which is one of the FHIR forms core reads, so the
typed fields are declared as returned and nothing is converted in the collector.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
import tap_plugin.compliance_core.models  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models  # noqa: F401 — trigger model registration
import tap_plugin.qualys.models  # noqa: F401 — trigger model registration

from tap_grid.dimension_names import view
from tap_grid.event_time import NO_EVENT_TIME, TIME_DIMENSION, Moment, declaration_problems
from tap_grid.grift.importer import grift_import
from tap_plugin.qualys.decompose import COMPLETE, Run, decompose, document
from tap_plugin.qualys.identity import subscription_key
from tap_plugin.qualys.models import QualysDetection, QualysHost, QualysQid, QualysScanRun, QualysSubscription
from tap_plugin.qualys.parse import parse_detection_page, parse_knowledgebase_page
from tap_plugin.qualys.store import GridStore

FIXTURES = Path(__file__).resolve().parent / "fixtures"
HOST = "https://qualysapi.qg2.apps.qualys.com"
KEY = subscription_key(HOST, "acme")
AT = datetime(2026, 11, 20, 18, tzinfo=UTC)


def _load(detection_xml: bytes) -> None:
    run = Run(api_host=HOST, label="acme", source="file", read_kind=COMPLETE, started_at=AT, read_at=AT, applied_filter={},
              knowledgebase_asked={"6666666", "38170", "11827", "45038"})
    kb = [parse_knowledgebase_page((FIXTURES / "kb-documented.xml").read_bytes())]
    result = decompose(run, [parse_detection_page(detection_xml)], kb, GridStore())
    imported = grift_import(document(result, run))
    assert not imported.errors, imported.errors


def _spine(row: object) -> tuple[object, ...]:
    """Start, end, precision and the `time` dimension's kind, as core derived them for a typed row."""
    entity = row.entity  # type: ignore[attr-defined]
    return (entity.event_start, entity.event_end, entity.event_precision, view(entity.dimensions).get(TIME_DIMENSION))


def _assembled() -> bytes:
    """The assembled page without its next-page link, so a complete read of it is whole."""
    body = (FIXTURES / "hld-ec2-assembled.xml").read_bytes()
    start, end = body.index(b"<WARNING>"), body.index(b"</WARNING>") + len(b"</WARNING>")
    return body[:start] + body[end:]


class TestDeclarations:
    def test_every_model_declares_and_core_accepts_it(self) -> None:
        expected = {
            QualysDetection: Moment(field="first_found_datetime", kind="first_seen"),
            QualysQid: Moment(field="published_datetime", kind="published"),
            QualysHost: NO_EVENT_TIME,
            QualysScanRun: NO_EVENT_TIME,
            QualysSubscription: NO_EVENT_TIME,
        }
        for model, declaration in expected.items():
            assert model.EVENT_TIME == declaration, model.__name__
            assert declaration_problems(model) == [], model.__name__


@pytest.mark.django_db
class TestDerivedFromQualysText:
    def test_a_detection_is_first_seen_at_its_first_found_time(self) -> None:
        _load(_assembled())
        detection = QualysDetection.objects.get(subscription_key=KEY, qid="38170")
        assert detection.first_found_datetime == "2026-10-01T06:00:00Z"  # the typed field keeps Qualys's text
        moment = datetime(2026, 10, 1, 6, tzinfo=UTC)
        assert _spine(detection) == (moment, moment, "second", "first_seen")

    def test_a_detection_with_no_first_found_time_has_none(self) -> None:
        _load(_assembled())
        detection = QualysDetection.objects.get(subscription_key=KEY, qid="11827")
        assert detection.first_found_datetime is None
        assert _spine(detection) == (None, None, None, None)

    def test_a_knowledge_base_record_is_published_at_its_published_time(self) -> None:
        _load(_assembled())
        moment = datetime(2024, 8, 26, 14, 8, 11, tzinfo=UTC)
        assert _spine(QualysQid.objects.get(subscription_key=KEY, qid="6666666")) == (moment, moment, "second", "published")

    def test_a_qid_the_knowledge_base_did_not_return_has_none(self) -> None:
        _load(_assembled())
        assert _spine(QualysQid.objects.get(subscription_key=KEY, qid="38170")) == (None, None, None, None)

    def test_the_types_with_no_event_time_have_none(self) -> None:
        _load(_assembled())
        for row in (QualysHost.objects.get(subscription_key=KEY, host_id="1001"),
                    QualysScanRun.objects.get(subscription_key=KEY),
                    QualysSubscription.objects.get(subscription_key=KEY)):
            assert _spine(row) == (None, None, None, None), type(row).__name__

    def test_a_malformed_time_is_kept_as_sent_and_left_off_the_spine(self) -> None:
        # Qualys's own documented sample prints FIRST_FOUND_DATETIME as 2019-1108T06:37:29Z. Core refuses it
        # (rule 12): the typed field keeps the text and the spine stays empty, rather than a guessed date.
        _load((FIXTURES / "hld-documented.xml").read_bytes())
        malformed = [d for d in QualysDetection.objects.filter(subscription_key=KEY) if d.first_found_datetime == "2019-1108T06:37:29Z"]
        assert malformed
        for detection in malformed:
            assert _spine(detection) == (None, None, None, None)
