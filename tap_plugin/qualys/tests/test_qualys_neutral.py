"""The neutral finding, the shared vulnerability record and the package link (req-qualys-neutral, -package-link).

Pure tests drive ``decompose`` against a fake grid with knowledge-base records built here, so each rule is
tested by the QID-to-CVE fan-out it is about. The import tests at the end run the fixture archive's pages
through the real GRIFT importer.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import tap_plugin.compliance_core.models  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models  # noqa: F401 — trigger model registration
import tap_plugin.qualys.models  # noqa: F401 — trigger model registration
from django.apps import apps
from django.forms.models import model_to_dict

from tap_grid.grift.importer import grift_import
from tap_grid.models import Edge
from tap_grid.services import create_node
from tap_plugin.qualys import neutral
from tap_plugin.qualys.decompose import COMPLETE, WINDOW, Run, decompose, document
from tap_plugin.qualys.identity import subscription_key
from tap_plugin.qualys.parse import KnowledgeBasePage, parse_detection_page, parse_knowledgebase_page
from tap_plugin.qualys.store import GridStore
from tap_plugin.qualys.tests.test_qualys_decompose import FakeGrid

FIXTURES = Path(__file__).resolve().parent / "fixtures"
HOST = "https://qualysapi.qg2.apps.qualys.com"
KEY = subscription_key(HOST, "acme")
WEBKIT = ("deb", "webkit2gtk", "2.44.2-1~deb12u1")


def _run(kind: str = COMPLETE) -> Run:
    at = datetime(2026, 11, 20, 18, tzinfo=UTC)
    return Run(api_host=HOST, label="acme", source="file", read_kind=kind, started_at=at, read_at=at, applied_filter={})


def _body(**replace: str) -> bytes:
    body = (FIXTURES / "hld-ec2-assembled.xml").read_bytes()
    start, end = body.index(b"<WARNING>"), body.index(b"</WARNING>") + len(b"</WARNING>")
    body = body[:start] + body[end:]
    for old, new in replace.items():
        assert body.count(old.encode()) == 1, old
        body = body.replace(old.encode(), new.encode())
    return body


def _pages(**replace: str) -> list:
    return [parse_detection_page(_body(**replace))]


def _vuln(qid: str, *cves: str, v3: str | None = "7.5", v2: str | None = None) -> dict[str, Any]:
    return {
        "qid": qid,
        "title": f"QID {qid}",
        "cve_list": [{"id": c, "url": None} for c in cves],
        "cvss_v3": {"base": v3, "vector_string": "CVSS:3.1/AV:N"} if v3 is not None else None,
        "cvss_v2": {"base": v2, "vector_string": "AV:N"} if v2 is not None else None,
    }


def _kb(*vulns: dict[str, Any]) -> list[KnowledgeBasePage]:
    return [KnowledgeBasePage(response_datetime="2026-11-20T18:00:00Z", vulns=list(vulns))]


def _of(result, entity_type: str) -> list[dict[str, Any]]:
    return [n for n in result.nodes if n["entity"]["entity_type"] == entity_type]


def _edges(result, slug: str) -> list[dict[str, Any]]:
    return [e["edge"] for e in result.edges if e["edge"]["edge_type"] == slug]


class TestOnePerHostAndCve:
    def test_two_qids_naming_one_cve_make_one_finding(self) -> None:
        result = decompose(_run(), _pages(), _kb(_vuln("6666666", "CVE-2024-40780"), _vuln("11827", "CVE-2024-40780")), FakeGrid())
        (finding,) = _of(result, neutral.FINDING_TYPE)
        assert finding["node"]["source"] == "qualys"
        assert finding["node"]["source_key"] == neutral.source_key(KEY, "1001", "CVE-2024-40780")
        assert sorted(e["from_ref"] for e in _edges(result, neutral.DETAILS)) == ["d1001-11827-7000003", "d1001-6666666-7000001"]

    def test_source_key_is_a_digest_of_an_array_not_a_concatenation(self) -> None:
        # The concatenations of these two triples are equal; their keys must not be.
        assert "a" + "bc" + "d" == "ab" + "c" + "d"
        assert neutral.source_key("a", "bc", "d") != neutral.source_key("ab", "c", "d")

    def test_summary_and_first_detected(self) -> None:
        result = decompose(_run(), _pages(), _kb(_vuln("6666666", "CVE-1"), _vuln("38170", "CVE-1")), FakeGrid())
        (finding,) = _of(result, neutral.FINDING_TYPE)
        # Highest severity of the two (3 and 2); the earliest first-found time (38170's, 2026-10-01).
        assert finding["node"]["summary"] == "Qualys severity 3"
        assert finding["node"]["first_detected_at"].startswith("2026-10-01T06:00:00")
        assert finding["node"]["name"].startswith("CVE-1 on ")

    def test_no_qualys_dimension(self) -> None:
        result = decompose(_run(), _pages(), _kb(_vuln("6666666", "CVE-1")), FakeGrid())
        for node in _of(result, neutral.FINDING_TYPE) + _of(result, neutral.VULNERABILITY_TYPE):
            assert not [k for k in node["entity"]["dimensions"] if k.startswith("qualys.")]


class TestStatusFollowsFixed:
    def test_open_while_any_is_open(self) -> None:
        # 6666666 is Active and 38170 is Fixed; both name CVE-1.
        (finding,) = _of(decompose(_run(), _pages(), _kb(_vuln("6666666", "CVE-1"), _vuln("38170", "CVE-1")), FakeGrid()), neutral.FINDING_TYPE)
        assert finding["node"]["status"] == "open"

    def test_resolved_once_every_one_is_fixed(self) -> None:
        grid = FakeGrid()
        grid.findings = {neutral.source_key(KEY, "1001", "CVE-1")}
        kb = _kb(_vuln("38170", "CVE-1"), _vuln("6666666"), _vuln("11827"), _vuln("45038"))
        (finding,) = _of(decompose(_run(), _pages(), kb, grid), neutral.FINDING_TYPE)
        assert finding["node"]["status"] == "resolved"

    def test_a_fixed_detection_alone_creates_no_finding(self) -> None:
        assert _of(decompose(_run(), _pages(), _kb(_vuln("38170", "CVE-1")), FakeGrid()), neutral.FINDING_TYPE) == []

    def test_a_held_open_detection_keeps_it_open(self) -> None:
        # A window read returns 38170 Fixed; the grid still holds another detection on the host, open, naming the CVE.
        grid = FakeGrid()
        grid.detection_rows = {"1001": [{"qid": "90000", "unique_vuln_id": "1", "state": "open", "severity": "5", "first_found_datetime": None, "package_observations": None}]}
        grid.qid_rows = {"90000": {"qid": "90000", "cve_list": [{"id": "CVE-1"}], "cvss_v2": None, "cvss_v3": None}}
        (finding,) = _of(decompose(_run(WINDOW), _pages(), _kb(_vuln("38170", "CVE-1")), grid), neutral.FINDING_TYPE)
        assert finding["node"]["status"] == "open" and finding["node"]["summary"] == "Qualys severity 5"


class TestCarrier:
    def test_one_package_carries(self) -> None:
        result = decompose(_run(), _pages(), _kb(_vuln("6666666", "CVE-1")), FakeGrid())
        (carries,) = _edges(result, neutral.CARRIES)
        assert carries["from_key"] == neutral.package_ref(WEBKIT)
        (concerns,) = _edges(result, neutral.CONCERNS)
        assert concerns["to_key"]["key"] == {"vuln_id": "CVE-1"} and concerns["properties"] == {"fixed_versions": ["2.44.3-1~deb12u1"]}

    def test_two_packages_mean_the_host_carries(self) -> None:
        two = "webkit2gtk\t2.44.2-1~deb12u1\t2.44.3-1~deb12u1\nlibjavascriptcoregtk-4.1-0\t2.44.2-1~deb12u1\t2.44.3-1~deb12u1"
        result = decompose(_run(), _pages(**{"webkit2gtk\t2.44.2-1~deb12u1\t2.44.3-1~deb12u1": two}), _kb(_vuln("6666666", "CVE-1")), FakeGrid())
        (carries,) = _edges(result, neutral.CARRIES)
        assert carries["from_ref"] == "h1001" and "from_key" not in carries
        (concerns,) = _edges(result, neutral.CONCERNS)
        assert concerns["properties"] == {}  # no single package, so no single fixed version

    def test_no_package_means_the_host_carries(self) -> None:
        (carries,) = _edges(decompose(_run(), _pages(), _kb(_vuln("11827", "CVE-1")), FakeGrid()), neutral.CARRIES)
        assert carries["from_ref"] == "h1001"

    def test_one_authority_claim_per_finding(self) -> None:
        kb = _kb(_vuln("6666666", "CVE-1", "CVE-2"), _vuln("38170"), _vuln("11827"), _vuln("45038"))
        result = decompose(_run(), _pages(), kb, FakeGrid())
        assert len(result.authority) == 2
        assert {c["anchor"]["key"]["source_key"] for c in result.authority} == {neutral.source_key(KEY, "1001", c) for c in ("CVE-1", "CVE-2")}
        assert all((c["edge_type"], c["direction"], c["read"]) == (neutral.CARRIES, "inbound", "complete") for c in result.authority)
        assert document(result, _run())["batches"][0]["edge_cases"] == {"authority": result.authority}


class TestReviewRound1:
    def test_a_partly_read_run_claims_partial(self) -> None:
        # One detection with an unusable unique id: the page is partly read, so no claim may say complete.
        pages = _pages(**{"<UNIQUE_VULN_ID>7000003</UNIQUE_VULN_ID>": "<UNIQUE_VULN_ID>not-a-number-" + "x" * 300 + "</UNIQUE_VULN_ID>"})
        result = decompose(_run(), pages, _kb(_vuln("6666666", "CVE-1")), FakeGrid())
        assert result.partly_read_pages == 1 and result.authority
        assert {c["read"] for c in result.authority} == {"partial"}

    def test_a_whole_run_claims_complete(self) -> None:
        kb = _kb(_vuln("6666666", "CVE-1"), _vuln("38170"), _vuln("11827"), _vuln("45038"))
        result = decompose(_run(), _pages(), kb, FakeGrid())
        assert {c["read"] for c in result.authority} == {"complete"}

    def test_a_qid_with_no_cve_list_makes_its_host_partial(self) -> None:
        # 11827 is on the host but the knowledge base did not return it and the grid holds no list for it.
        result = decompose(_run(), _pages(), _kb(_vuln("6666666", "CVE-1")), FakeGrid())
        assert result.authority and {c["read"] for c in result.authority} == {"partial"}
        assert result.counters["hosts_with_unknown_qids"] == 1

    def test_a_held_finding_is_not_resolved_on_a_host_with_unknown_qids(self) -> None:
        # 38170 (Fixed) names CVE-1 and the finding is held; 11827 on the same host has no CVE list anywhere.
        grid = FakeGrid()
        grid.findings = {neutral.source_key(KEY, "1001", "CVE-1")}
        result = decompose(_run(), _pages(), _kb(_vuln("38170", "CVE-1")), grid)
        assert _of(result, neutral.FINDING_TYPE) == []
        assert result.counters["findings_not_resolved_unknown_qids"] == 1

    @staticmethod
    def _group(*rows: tuple[str | None, ...]) -> neutral.Group:
        grp = neutral.Group("1001", "CVE-1")
        for n, (required,) in enumerate(rows):
            observation = {"ecosystem": "deb", "name": "curl", "installed_version": "7.88.1-10", "required_version": required, "mapping_unambiguous": True}
            grp.detections.append(neutral.Detection(str(n), str(n), "open", None, None, [observation]))
        return grp

    def test_a_row_without_a_required_version_never_hides_one(self) -> None:
        assert self._group((None,), ("7.88.1-11",)).packages() == {("deb", "curl", "7.88.1-10"): "7.88.1-11"}

    def test_disagreeing_required_versions_do_not_depend_on_order(self) -> None:
        one = self._group(("7.88.1-12",), ("7.88.1-11",)).packages()
        two = self._group(("7.88.1-11",), ("7.88.1-12",)).packages()
        assert one == two == {("deb", "curl", "7.88.1-10"): "7.88.1-11"}

    def test_an_unrelated_held_cve_is_not_touched(self) -> None:
        grid = FakeGrid()
        grid.detection_rows = {"1001": [{"qid": "90000", "unique_vuln_id": "1", "state": "resolved", "severity": "5", "first_found_datetime": None, "package_observations": None}]}
        grid.qid_rows = {"90000": {"qid": "90000", "cve_list": [{"id": "CVE-B"}], "cvss_v2": None, "cvss_v3": {"base": "9.0"}}}
        result = decompose(_run(), _pages(), _kb(_vuln("6666666", "CVE-A")), grid)
        assert [n["node"]["vuln_id"] for n in _of(result, neutral.VULNERABILITY_TYPE)] == ["CVE-A"]

    def test_the_score_does_not_depend_on_order(self) -> None:
        kb_a = _kb(_vuln("6666666", "CVE-1", v3="9.1"), _vuln("11827", "CVE-1", v3="4.0"))
        kb_b = _kb(_vuln("11827", "CVE-1", v3="4.0"), _vuln("6666666", "CVE-1", v3="9.1"))
        scores = {_of(decompose(_run(), _pages(), kb, FakeGrid()), neutral.VULNERABILITY_TYPE)[0]["node"]["cvss_score"] for kb in (kb_a, kb_b)}
        assert scores == {4.0}  # the lowest-numbered QID with a score, 11827, whichever order the pages came in


class TestVulnerabilityRecord:
    def test_absent_record_created_with_the_exact_id_and_score(self) -> None:
        result = decompose(_run(), _pages(), _kb(_vuln("6666666", "CVE-2024-40780", v3="8.8", v2="6.8")), FakeGrid())
        (record,) = _of(result, neutral.VULNERABILITY_TYPE)
        assert record["node"] == {"vuln_id": "CVE-2024-40780", "cvss_score": 8.8, "cvss_version": "3", "cvss_source": "Qualys knowledge base", "cvss_vector": "CVSS:3.1/AV:N"}

    def test_v2_when_there_is_no_v3(self) -> None:
        (record,) = _of(decompose(_run(), _pages(), _kb(_vuln("6666666", "CVE-1", v3=None, v2="5.0")), FakeGrid()), neutral.VULNERABILITY_TYPE)
        assert (record["node"]["cvss_score"], record["node"]["cvss_version"]) == (5.0, "2")

    def test_an_id_over_128_characters_gets_nothing(self) -> None:
        long_id = "CVE-" + "9" * 125
        result = decompose(_run(), _pages(), _kb(_vuln("6666666", long_id)), FakeGrid())
        assert _of(result, neutral.VULNERABILITY_TYPE) == [] and _of(result, neutral.FINDING_TYPE) == []
        assert result.counters["cve_ids_too_long"] == 1

    def test_unscored_held_record_is_filled_with_its_own_dimensions(self) -> None:
        grid = FakeGrid()
        grid.vulns = {"CVE-1": {"scored": False, "dimensions": {"compliance": "vulnerability", "other.key": "kept"}}}
        (record,) = _of(decompose(_run(), _pages(), _kb(_vuln("6666666", "CVE-1")), grid), neutral.VULNERABILITY_TYPE)
        assert record["entity"]["dimensions"] == {"compliance": "vulnerability", "other.key": "kept"}
        assert record["node"]["cvss_score"] == 7.5

    def test_scored_held_record_is_not_written(self) -> None:
        grid = FakeGrid()
        grid.vulns = {"CVE-1": {"scored": True, "dimensions": {}}}
        result = decompose(_run(), _pages(), _kb(_vuln("6666666", "CVE-1")), grid)
        assert _of(result, neutral.VULNERABILITY_TYPE) == []
        assert len(_edges(result, neutral.CONCERNS)) == 1  # still concerned, by key

    def test_qid_links_each_cve_record(self) -> None:
        result = decompose(_run(), _pages(), _kb(_vuln("6666666", "CVE-1", "CVE-2")), FakeGrid())
        assert sorted((e["from_ref"], e["to_key"]["key"]["vuln_id"]) for e in _edges(result, neutral.ABOUT_VULNERABILITY)) == [("q6666666", "CVE-1"), ("q6666666", "CVE-2")]


class TestPackageLink:
    def test_unambiguous_observation_links_and_creates_with_keys_only(self) -> None:
        result = decompose(_run(), _pages(), _kb(), FakeGrid())
        (link,) = _edges(result, neutral.FOUND_IN_PACKAGE)
        assert link["from_ref"] == "d1001-6666666-7000001" and link["to_key"] == neutral.package_ref(WEBKIT)
        (package,) = _of(result, neutral.PACKAGE_TYPE)
        assert package["node"] == {"ecosystem": "deb", "name": "webkit2gtk", "version": "2.44.2-1~deb12u1"}

    def test_held_package_is_never_written(self) -> None:
        grid = FakeGrid()
        grid.packages = {WEBKIT}
        result = decompose(_run(), _pages(), _kb(), grid)
        assert _of(result, neutral.PACKAGE_TYPE) == [] and len(_edges(result, neutral.FOUND_IN_PACKAGE)) == 1

    def test_ambiguous_observation_draws_nothing(self) -> None:
        # A host whose OS the parser cannot place: the observation is stored, but nothing is linked or created.
        result = decompose(_run(), _pages(**{"Ubuntu 22.04.4 LTS": "Some Appliance OS"}), _kb(), FakeGrid())
        assert _edges(result, neutral.FOUND_IN_PACKAGE) == [] and _of(result, neutral.PACKAGE_TYPE) == []


@pytest.mark.django_db
class TestImported:
    def _load(self, kb: list[KnowledgeBasePage] | None = None) -> None:
        kb = kb if kb is not None else [parse_knowledgebase_page((FIXTURES / "kb-documented.xml").read_bytes())]
        run = _run()
        imported = grift_import(document(decompose(run, _pages(), kb, GridStore()), run))
        assert not imported.errors, imported.errors

    def test_finding_package_and_record_land(self) -> None:
        self._load()
        finding = apps.get_model("compliance_core", "ComplianceFinding").objects.get(source="qualys")
        assert finding.status == "open" and finding.source_key == neutral.source_key(KEY, "1001", "CVE-2024-40780")
        package = apps.get_model("computing_core", "Package").objects.get(ecosystem="deb", name="webkit2gtk")
        (carries,) = Edge.objects.filter(edge_type=neutral.CARRIES)
        assert (carries.from_entity_id, carries.to_entity_id) == (package.entity_id, finding.entity_id)
        record = apps.get_model("compliance_core", "ComplianceVulnerability").objects.get(vuln_id="CVE-2024-40780")
        (concerns,) = Edge.objects.filter(edge_type=neutral.CONCERNS)
        assert concerns.to_entity_id == record.entity_id
        assert Edge.objects.filter(edge_type=neutral.FOUND_IN_PACKAGE, to_entity_id=package.entity_id).count() == 1
        assert Edge.objects.filter(edge_type=neutral.DETAILS, to_entity_id=finding.entity_id).count() == 1
        assert Edge.objects.filter(edge_type=neutral.ABOUT_VULNERABILITY, to_entity_id=record.entity_id).count() == 1

    def test_a_second_run_writes_no_second_finding_or_edge(self) -> None:
        self._load()
        self._load()
        assert apps.get_model("compliance_core", "ComplianceFinding").objects.filter(source="qualys").count() == 1
        for slug in (neutral.CARRIES, neutral.CONCERNS, neutral.DETAILS, neutral.FOUND_IN_PACKAGE, neutral.ABOUT_VULNERABILITY):
            assert Edge.objects.filter(edge_type=slug).count() == 1, slug

    def test_a_scored_record_is_left_exactly_as_it_was(self) -> None:
        assert create_node("compliance_core__compliance_vulnerability", {"vuln_id": "CVE-2024-40780", "cvss_score": 9.9, "cvss_version": "3", "cvss_source": "NVD", "title": "kept"}).success
        model = apps.get_model("compliance_core", "ComplianceVulnerability")
        before = model.objects.get(vuln_id="CVE-2024-40780")
        snapshot, version = model_to_dict(before), before.entity.version
        self._load()
        after = model.objects.get(vuln_id="CVE-2024-40780")
        assert model_to_dict(after) == snapshot and after.entity.version == version

    def test_an_unscored_record_gains_the_score_and_keeps_the_rest(self) -> None:
        assert create_node("compliance_core__compliance_vulnerability", {"vuln_id": "CVE-2024-40780", "title": "kept"}).success
        kb = _kb(_vuln("6666666", "CVE-2024-40780", v3="8.8"))
        self._load(kb)
        after = apps.get_model("compliance_core", "ComplianceVulnerability").objects.get(vuln_id="CVE-2024-40780")
        assert (after.cvss_score, after.cvss_version, after.cvss_source, after.title) == (8.8, "3", "Qualys knowledge base", "kept")

    def test_a_held_package_is_left_exactly_as_it_was(self) -> None:
        assert create_node("computing_core__package", {"ecosystem": "deb", "name": "webkit2gtk", "version": "2.44.2-1~deb12u1", "purl": "pkg:deb/debian/webkit2gtk@2.44.2-1~deb12u1"}).success
        model = apps.get_model("computing_core", "Package")
        before = model.objects.get(name="webkit2gtk")
        snapshot, version = model_to_dict(before), before.entity.version
        self._load()
        after = model.objects.get(name="webkit2gtk")
        assert model_to_dict(after) == snapshot and after.entity.version == version
