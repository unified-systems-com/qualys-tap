"""A run written as bounded batches with the seal last (req-qualys-chunked-write; WORKAROUND for
unified-systems-com/tap#1348, where core locks every natural key of a batch until it commits).
"""

from typing import Any

import pytest
import tap_plugin.compliance_core.models  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models  # noqa: F401 — trigger model registration
import tap_plugin.qualys.models  # noqa: F401 — trigger model registration
from tap_plugin.qualys import decompose as decompose_module
from tap_plugin.qualys.collectors.qualys_collector import QualysCollectorError
from tap_plugin.qualys.decompose import Run, decompose, documents
from tap_plugin.qualys.models import QualysDetection, QualysHost, QualysQid, QualysScanRun, QualysSubscription
from tap_plugin.qualys.neutral import FINDING_TYPE
from tap_plugin.qualys.parse import parse_detection_page, parse_knowledgebase_page
from tap_plugin.qualys.read_kind import COMPLETE
from tap_plugin.qualys.store import GridStore
from tap_plugin.qualys.tests.test_qualys_collector import KEY, Router, _collector, no_sockets, secrets  # noqa: F401
from tap_plugin.qualys.tests.test_qualys_event_time import AT, FIXTURES, HOST
from tap_plugin.qualys.tests.test_qualys_event_time import KEY as FILE_KEY

from tap_grid.grift.importer import grift_import


def _decomposed() -> tuple[Any, Run]:
    """A file run over the documented pages: two hosts, their detections, QIDs, CVEs, packages and findings."""
    run = Run(api_host=HOST, label="acme", source="file", read_kind=COMPLETE, started_at=AT, read_at=AT, applied_filter={},
              knowledgebase_asked={"6666666", "38170", "11827", "45038"})
    pages = [parse_detection_page((FIXTURES / name).read_bytes()) for name in ("hld-ec2-assembled.xml", "hld-documented.xml")]
    kb = [parse_knowledgebase_page((FIXTURES / "kb-documented.xml").read_bytes())]
    return decompose(run, pages, kb, GridStore()), run


def _batch(doc: dict[str, Any]) -> dict[str, Any]:
    (batch,) = doc["batches"]
    return batch


@pytest.mark.django_db
class TestTheParts:
    @pytest.fixture
    def parts(self) -> tuple[Any, Any, list[dict[str, Any]]]:
        result, run = _decomposed()
        return result, run, documents(result, run, max_keys=6)

    @pytest.mark.spec("req-qualys-chunked-write-1")
    def test_every_node_and_edge_is_written_once_and_no_ref_leaves_its_batch(self, parts) -> None:
        result, _, docs = parts
        body = [_batch(d) for d in docs[1:-1]]
        written = [n["entity"]["ref"] for b in body for n in b["nodes"]]
        expected = [n["entity"]["ref"] for n in result.nodes if n["entity"]["ref"] not in ("sub", "run")]
        assert sorted(written) == sorted(expected) and len(written) == len(set(written))
        assert sum(len(b["edges"]) for b in body) + 1 == len(result.edges)  # the run's own edge rides with the hubs
        for batch in map(_batch, docs):
            refs = {n["entity"]["ref"] for n in batch["nodes"]}
            for e in batch["edges"]:
                for end in ("from_ref", "to_ref"):
                    if e["edge"].get(end) is not None:
                        assert e["edge"][end] in refs, (e["entity"]["ref"], end)

    @pytest.mark.spec("req-qualys-chunked-write-2")
    def test_each_body_batch_stays_inside_the_bound_unless_one_group_is_bigger(self, parts) -> None:
        _, _, docs = parts
        assert len(docs) > 4
        for batch in map(_batch, docs[1:-1]):
            size = len(batch["nodes"]) + len(batch["edges"])
            # A host and everything joined to it by ref is never split, so a batch over the bound holds one host.
            hosts = sum(1 for n in batch["nodes"] if n["entity"]["entity_type"] == QualysHost.ENTITY_TYPE)
            assert size <= 6 or hosts == 1, (size, hosts)
        assert any(len(_batch(d)["nodes"]) + len(_batch(d)["edges"]) > 6 for d in docs[1:-1])  # the exception is exercised

    @pytest.mark.spec("req-qualys-chunked-write-3")
    def test_opening_first_shared_records_next_seal_last(self, parts) -> None:
        result, run, docs = parts
        opening, seal = _batch(docs[0]), _batch(docs[-1])
        assert [n["entity"]["ref"] for n in opening["nodes"]] == ["sub", "run"] and opening["nodes"][1]["node"]["finished_at"] is None
        assert opening["nodes"][0]["node"]["watermark"] == result.subscription_held["watermark"]
        assert {n["entity"]["ref"] for n in seal["nodes"]} >= {"sub", "run"}
        # Every record an edge names by key, when this run writes it, lands in the same batch or an earlier one.
        where: dict[tuple[str, tuple[Any, ...]], int] = {}
        for number, batch in enumerate(map(_batch, docs)):
            for n in batch["nodes"]:
                for k, v in n["node"].items():
                    where.setdefault((n["entity"]["entity_type"], (k, str(v))), number)
        checked = 0
        for number, batch in enumerate(map(_batch, docs)):
            for e in batch["edges"]:
                for end in ("from_key", "to_key"):
                    named = e["edge"].get(end)
                    if not named:
                        continue
                    places = [where.get((named["entity_type"], (k, str(v)))) for k, v in named["key"].items()]
                    if all(p is not None for p in places):
                        assert max(places) <= number, (e["entity"]["ref"], end)
                        checked += 1
        assert checked > 0
        hosts_at = [i for i, d in enumerate(docs) if any(n["entity"]["entity_type"] == QualysHost.ENTITY_TYPE for n in _batch(d)["nodes"])]
        qids_at = [i for i, d in enumerate(docs) if any(n["entity"]["entity_type"] == QualysQid.ENTITY_TYPE for n in _batch(d)["nodes"])]
        assert max(qids_at) < min(hosts_at)
        # Each finding's authority claim rides with the batch holding the finding.
        for batch in map(_batch, docs[1:-1]):
            for claim in batch.get("edge_cases", {}).get("authority", []):
                assert any(n["entity"]["entity_type"] == FINDING_TYPE and all(n["node"].get(k) == v for k, v in claim["anchor"]["key"].items())
                           for n in batch["nodes"])

    @pytest.mark.spec("req-qualys-chunked-write-3")
    def test_a_later_run_never_rewrites_the_subscription_before_its_seal_and_withdraws_in_the_seal(self, parts) -> None:
        _, _, docs = parts
        for doc in docs:
            assert not grift_import(doc).errors
        run = Run(api_host=HOST, label="acme", source="file", read_kind=COMPLETE, started_at=AT, read_at=AT, applied_filter={},
                  knowledgebase_asked=set())
        later = decompose(run, [parse_detection_page((FIXTURES / "hld-documented.xml").read_bytes())], [], GridStore())
        assert later.counters.get("hosts_withdrawn")
        again = documents(later, run, max_keys=6)
        opening, seal = _batch(again[0]), _batch(again[-1])
        assert [n["entity"]["entity_type"] for n in opening["nodes"]] == [QualysScanRun.ENTITY_TYPE]
        (to_sub,) = opening["edges"]
        assert to_sub["edge"]["to_key"]["entity_type"] == QualysSubscription.ENTITY_TYPE and "to_ref" not in to_sub["edge"]
        withdrawn = [n for n in seal["nodes"] if n["node"].get("withdrawn_in_run") == run.run_id]
        assert withdrawn and all(n["node"]["state"] == "withdrawn" for n in withdrawn)
        assert not any(n["node"].get("withdrawn_in_run") == run.run_id for d in again[:-1] for n in _batch(d)["nodes"])
        for doc in again:
            assert not grift_import(doc).errors

    def test_each_batch_imports_and_the_grid_matches_one_batch(self, parts) -> None:
        _, _, docs = parts
        for doc in docs:
            assert not grift_import(doc).errors
        result, _, _ = parts
        hosts = sum(1 for n in result.nodes if n["entity"]["entity_type"] == QualysHost.ENTITY_TYPE)
        detections = sum(1 for n in result.nodes if n["entity"]["entity_type"] == QualysDetection.ENTITY_TYPE)
        assert QualysHost.objects.filter(subscription_key=FILE_KEY).count() == hosts > 0
        assert QualysDetection.objects.filter(subscription_key=FILE_KEY).count() == detections > 0
        assert QualysScanRun.objects.get(subscription_key=FILE_KEY).read_kind == result.read_kind


@pytest.mark.django_db
class TestTheCollectorWritesInParts:
    @pytest.mark.spec("req-qualys-chunked-write-1")
    def test_a_run_in_small_parts_lands_whole(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811 — the imported fixture
        monkeypatch.setattr(decompose_module, "CHUNK_KEYS", 5)
        collector = _collector(monkeypatch, Router())
        sent: list[dict[str, Any]] = []
        submit = collector.submit_grift
        monkeypatch.setattr(collector, "submit_grift", lambda doc: sent.append(doc) or submit(doc))
        collector.run()
        assert len(sent) > 4
        assert set(QualysHost.objects.filter(subscription_key=KEY).values_list("host_id", flat=True)) == {"1001", "524323"}
        assert QualysDetection.objects.filter(subscription_key=KEY).count() == 5
        run = QualysScanRun.objects.get(subscription_key=KEY)
        assert run.finished_at is not None and QualysSubscription.objects.get(subscription_key=KEY).watermark == run.started_at

    @pytest.mark.spec("req-qualys-chunked-write-4")
    def test_a_part_that_fails_keeps_what_landed_and_never_seals(self, secrets, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811 — the imported fixture
        monkeypatch.setattr(decompose_module, "CHUNK_KEYS", 5)
        collector = _collector(monkeypatch, Router())
        submit, count = collector.submit_grift, [0]

        def failing(doc: dict[str, Any]) -> Any:
            count[0] += 1
            if count[0] == 4:
                raise RuntimeError("the grid refused this part")
            return submit(doc)

        monkeypatch.setattr(collector, "submit_grift", failing)
        # The collector records the subscription that failed and ends the run as one that wrote nothing whole.
        with pytest.raises(QualysCollectorError):
            collector.run()
        run = QualysScanRun.objects.get(subscription_key=KEY)
        sub = QualysSubscription.objects.get(subscription_key=KEY)
        assert run.finished_at is None and sub.watermark is None and sub.last_complete_read_at is None
        assert sub.standing_scope is None  # the opening writes the scope as held, so a later plan reads it as new
