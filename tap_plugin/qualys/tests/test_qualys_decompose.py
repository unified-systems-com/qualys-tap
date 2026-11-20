"""Parsed pages into GRIFT nodes and edges (req-qualys-host, -detection, -qid, -states, -subscription-run).

Pure: a fake grid view stands in for what the grid holds, so no database is needed.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from tap_plugin.qualys.decompose import COMPLETE, NARROWER, WINDOW, Run, decompose, parse_time
from tap_plugin.qualys.identity import subscription_key
from tap_plugin.qualys.parse import parse_detection_page, parse_knowledgebase_page

FIXTURES = Path(__file__).resolve().parent / "fixtures"
HOST = "https://qualysapi.qg2.apps.qualys.com"
KEY = subscription_key(HOST, "acme")


class FakeGrid:
    def __init__(self, hosts: dict[str, dict[str, Any]] | None = None, qids: set[str] | None = None, sub: dict[str, Any] | None = None):
        self.hosts = hosts or {}
        self.qids = qids or set()
        self.sub = sub

    def subscription(self, key: str) -> dict[str, Any] | None:
        return self.sub

    def current_hosts(self, key: str) -> dict[str, dict[str, Any]]:
        return self.hosts

    def held_qids(self, key: str, qids) -> set[str]:
        return self.qids & set(qids)


def _run(kind: str = COMPLETE, **kw: Any) -> Run:
    return Run(api_host=HOST, label="acme", source="file", read_kind=kind, started_at=datetime(2026, 11, 20, 19, tzinfo=UTC), read_at=datetime(2026, 11, 20, 18, tzinfo=UTC), applied_filter={}, **kw)


def _pages() -> list:
    return [parse_detection_page((FIXTURES / "hld-ec2-assembled.xml").read_bytes())]


def _complete_pages() -> list:
    """The assembled page without its next-page link: a whole read, as a complete read must be."""
    body = (FIXTURES / "hld-ec2-assembled.xml").read_bytes()
    start, end = body.index(b"<WARNING>"), body.index(b"</WARNING>") + len(b"</WARNING>")
    return [parse_detection_page(body[:start] + body[end:])]


def _kb() -> list:
    return [parse_knowledgebase_page((FIXTURES / "kb-documented.xml").read_bytes())]


def _nodes(result, entity_type: str) -> list[dict[str, Any]]:
    return [n["node"] for n in result.nodes if n["entity"]["entity_type"] == entity_type]


class TestNodes:
    def test_one_node_per_type_and_detection(self) -> None:
        result = decompose(_run(), _pages(), _kb(), FakeGrid())
        assert len(_nodes(result, "qualys__qualys_subscription")) == 1
        assert len(_nodes(result, "qualys__qualys_scan_run")) == 1
        (host,) = _nodes(result, "qualys__qualys_host")
        assert host["subscription_key"] == KEY and host["host_id"] == "1001" and host["state"] == "current"
        assert host["cloud_resource_id"] == "i-0abc123def4567890" and host["last_scan_at"] == "2026-11-20T06:00:00+00:00"
        assert len(_nodes(result, "qualys__qualys_detection")) == 4

    def test_qid_in_the_detection_key(self) -> None:
        detections = _nodes(decompose(_run(), _pages(), _kb(), FakeGrid()), "qualys__qualys_detection")
        keys = {(d["qid"], d["unique_vuln_id"]) for d in detections}
        assert ("6666666", "7000001") in keys and ("45038", "7000001") in keys

    def test_values_as_returned(self) -> None:
        detections = {d["qid"]: d for d in _nodes(decompose(_run(), _pages(), _kb(), FakeGrid()), "qualys__qualys_detection")}
        assert detections["6666666"]["qds"] == "57" and detections["6666666"]["is_ignored"] == "0"
        assert detections["11827"]["is_ignored"] == "1"
        assert detections["45038"]["results"] == "" and detections["45038"]["port"] is None

    def test_parse_state_unobserved_until_parsers(self) -> None:
        for d in _nodes(decompose(_run(), _pages(), _kb(), FakeGrid()), "qualys__qualys_detection"):
            assert d["parse_state"] is None and d["package_observations"] is None


class TestResolution:
    def test_only_fixed_resolves(self) -> None:
        detections = {d["qid"]: d for d in _nodes(decompose(_run(), _pages(), _kb(), FakeGrid()), "qualys__qualys_detection")}
        assert (detections["38170"]["state"], detections["38170"]["resolution_source"]) == ("resolved", "qualys_fixed")
        assert detections["11827"]["state"] == "open"  # Re-Opened reopens
        assert detections["6666666"]["state"] == "open"

    def test_absent_detection_is_not_written(self) -> None:
        # Nothing in the batch names a detection the read did not return, so it keeps what it had.
        detections = _nodes(decompose(_run(), _pages(), _kb(), FakeGrid()), "qualys__qualys_detection")
        assert all(d["host_id"] == "1001" for d in detections)


class TestWithdrawal:
    STORED = {"subscription_key": KEY, "host_id": "2002", "ip": "10.0.9.9", "dns": None, "state": "current", "os": "Amazon Linux 2"}

    def test_complete_read_withdraws_a_host_it_did_not_see(self) -> None:
        result = decompose(_run(COMPLETE), _complete_pages(), _kb(), FakeGrid(hosts={"2002": dict(self.STORED)}))
        withdrawn = [h for h in _nodes(result, "qualys__qualys_host") if h["host_id"] == "2002"]
        assert withdrawn == [{**self.STORED, "state": "withdrawn", "withdrawn_in_run": result.nodes[-1]["node"]["run_id"]}]
        assert result.counters["hosts_withdrawn"] == 1

    def test_withdrawal_rewrites_every_stored_field(self) -> None:
        result = decompose(_run(COMPLETE), _complete_pages(), _kb(), FakeGrid(hosts={"2002": dict(self.STORED)}))
        (withdrawn,) = [h for h in _nodes(result, "qualys__qualys_host") if h["host_id"] == "2002"]
        assert withdrawn["os"] == "Amazon Linux 2"  # the grid replaces whole nodes, so nothing is dropped

    @pytest.mark.parametrize("kind", [WINDOW, NARROWER])
    def test_window_and_narrower_reads_withdraw_nothing(self, kind: str) -> None:
        result = decompose(_run(kind), _pages(), _kb(), FakeGrid(hosts={"2002": dict(self.STORED)}))
        assert not [h for h in _nodes(result, "qualys__qualys_host") if h["host_id"] == "2002"]

    def test_partly_read_page_withdraws_nothing(self) -> None:
        pages = _pages()
        pages[0].hosts[0]["detections"].append({"qid": "", "unique_vuln_id": "9"})
        held = {"last_complete_read_at": "2026-11-01T00:00:00+00:00"}
        result = decompose(_run(COMPLETE), pages, _kb(), FakeGrid(hosts={"2002": dict(self.STORED)}, sub=held))
        assert result.partly_read_pages == 1 and result.counters["detections_unkeyable"] == 1
        assert not [h for h in _nodes(result, "qualys__qualys_host") if h["host_id"] == "2002"]
        (sub,) = _nodes(result, "qualys__qualys_subscription")
        assert sub["last_complete_read_at"] == held["last_complete_read_at"]  # a partly read run is not complete

    def test_complete_label_with_a_narrower_filter_is_downgraded(self) -> None:
        run = _run(COMPLETE)
        run.applied_filter = {"tag_ids": [7]}
        result = decompose(run, _pages(), _kb(), FakeGrid(hosts={"2002": dict(self.STORED)}))
        assert not [h for h in _nodes(result, "qualys__qualys_host") if h["host_id"] == "2002"]
        (run_node,) = _nodes(result, "qualys__qualys_scan_run")
        assert run_node["read_kind"] == NARROWER and run_node["warnings"][0]["code"] == "READ_KIND_DOWNGRADED"
        from tap_plugin.qualys.decompose import document

        assert document(result, run)["batches"][0]["batch_node"]["description"].startswith("One narrower read")

    def test_truncated_complete_read_withdraws_nothing(self) -> None:
        pages = _pages()  # the assembled page ends on a next-page link
        result = decompose(_run(COMPLETE), pages, _kb(), FakeGrid(hosts={"2002": dict(self.STORED)}))
        assert not [h for h in _nodes(result, "qualys__qualys_host") if h["host_id"] == "2002"]
        (run_node,) = _nodes(result, "qualys__qualys_scan_run")
        assert {w["code"] for w in run_node["warnings"]} >= {"TRUNCATED", "READ_KIND_DOWNGRADED"}

    def test_no_pages_withdraws_nothing(self) -> None:
        result = decompose(_run(COMPLETE), [], [], FakeGrid(hosts={"2002": dict(self.STORED)}))
        assert not [h for h in _nodes(result, "qualys__qualys_host") if h["host_id"] == "2002"]

    def test_a_run_cannot_authorise_its_own_withdrawals_by_changing_scope(self) -> None:
        run = _run(COMPLETE, standing_scope={"tag_ids": [7]})
        run.applied_filter = {"tag_ids": [7]}
        grid = FakeGrid(hosts={"2002": dict(self.STORED)}, sub={"standing_scope": {"tag_ids": [1]}})
        result = decompose(run, _complete_pages(), _kb(), grid)
        assert not [h for h in _nodes(result, "qualys__qualys_host") if h["host_id"] == "2002"]
        (sub,) = _nodes(result, "qualys__qualys_subscription")
        assert sub["standing_scope"] == {"tag_ids": [7]}  # the new scope is recorded for the next read

    def test_complete_read_records_its_time(self) -> None:
        (sub,) = _nodes(decompose(_run(COMPLETE), _complete_pages(), _kb(), FakeGrid()), "qualys__qualys_subscription")
        assert sub["last_complete_read_at"] == "2026-11-20T18:00:00+00:00"


class TestKnowledgeBase:
    def test_returned_qid_carries_its_record(self) -> None:
        qids = {q["qid"]: q for q in _nodes(decompose(_run(), _pages(), _kb(), FakeGrid()), "qualys__qualys_qid")}
        assert qids["6666666"]["kb_returned"] is True and qids["6666666"]["cve_list"][0]["id"] == "CVE-2024-40780"

    def test_unreturned_qid_is_a_stub_marked_not_returned(self) -> None:
        qids = {q["qid"]: q for q in _nodes(decompose(_run(knowledgebase_asked={"6666666", "38170", "11827", "45038"}), _pages(), _kb(), FakeGrid()), "qualys__qualys_qid")}
        assert qids["38170"] == {"subscription_key": KEY, "qid": "38170", "kb_returned": False}

    def test_unreturned_qid_with_incomplete_kb_is_unknown(self) -> None:
        qids = {q["qid"]: q for q in _nodes(decompose(_run(knowledgebase_complete=False), _pages(), _kb(), FakeGrid()), "qualys__qualys_qid")}
        assert qids["38170"]["kb_returned"] is None

    def test_held_qid_is_never_overwritten_by_a_stub(self) -> None:
        result = decompose(_run(), _pages(), _kb(), FakeGrid(qids={"38170"}))
        assert "38170" not in {q["qid"] for q in _nodes(result, "qualys__qualys_qid")}


class TestDropped:
    def test_value_a_column_cannot_hold_is_null_and_listed(self) -> None:
        pages = _pages()
        pages[0].hosts[0]["detections"][0]["port"] = "9" * 40  # port holds 16 characters
        result = decompose(_run(), pages, _kb(), FakeGrid())
        detection = next(d for d in _nodes(result, "qualys__qualys_detection") if d["qid"] == "6666666")
        assert detection["port"] is None
        (run_node,) = _nodes(result, "qualys__qualys_scan_run")
        (warning,) = [w for w in run_node["warnings"] if w["code"] == "VALUE_DROPPED"]
        assert "port (longer than 16 characters)" in warning["detail"]


class TestEdgesAndRun:
    def test_detection_edges(self) -> None:
        result = decompose(_run(), _pages(), _kb(), FakeGrid())
        slugs = [e["edge"]["edge_type"] for e in result.edges]
        assert slugs.count("DETECTED_ON_HOST__qualys") == 4 and slugs.count("ABOUT_QID__qualys") == 4
        assert slugs.count("RUN_OF_SUBSCRIPTION__qualys") == 1
        about = next(e for e in result.edges if e["edge"]["edge_type"] == "ABOUT_QID__qualys")
        assert about["edge"]["to_key"]["key"]["subscription_key"] == KEY

    def test_run_records_source_kind_and_read_time(self) -> None:
        (run,) = _nodes(decompose(_run(archive_sha256="ab" * 32), _complete_pages(), _kb(), FakeGrid()), "qualys__qualys_scan_run")
        assert run["source"] == "file" and run["read_kind"] == COMPLETE and run["read_at"] == "2026-11-20T18:00:00+00:00"
        assert run["archive_sha256"] == "ab" * 32 and run["counters"]["detections"] == 4

    def test_subscription_carries_its_watermark_forward(self) -> None:
        held = {"watermark": "2026-11-19T00:00:00+00:00", "standing_scope": {"tag_ids": [1]}}
        (sub,) = _nodes(decompose(_run(WINDOW), _pages(), _kb(), FakeGrid(sub=held)), "qualys__qualys_subscription")
        assert sub["watermark"] == held["watermark"] and sub["standing_scope"] == {"tag_ids": [1]}


@pytest.mark.parametrize(
    ("raw", "parsed"),
    [("2026-11-20T06:00:00Z", "2026-11-20T06:00:00+00:00"), ("2019-1108T09:15:14Z", None), ("", None), (None, None), ("2026-11-20T06:00:00", None)],
)
def test_parse_time(raw, parsed) -> None:
    assert parse_time(raw) == parsed
