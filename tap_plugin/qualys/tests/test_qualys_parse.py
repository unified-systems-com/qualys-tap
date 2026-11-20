"""Reading detection and knowledge-base pages (req-qualys-contract-extract-3, -5, req-qualys-transport-6).

Fixtures: two of Qualys's documented samples copied verbatim, and one assembled from the DTD for what the
samples do not show. None is a recording; each file's first comment says which it is.
"""

from pathlib import Path

import pytest

from tap_plugin.qualys.parse import MAX_DEPTH, PageRefused, parse_detection_page, parse_knowledgebase_page

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _read(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class TestDocumentedSamples:
    def test_detection_sample(self) -> None:
        page = parse_detection_page(_read("hld-documented.xml"))
        assert page.response_datetime == "2023-08-16T13:34:18Z"
        assert page.next_url is None
        (host,) = page.hosts
        assert host["host_id"] == "524323" and host["tracking_method"] == "IP"
        assert host["os"] == "Linux 2.4-2.6 / Embedded Device / F5 Networks Big-IP"
        (detection,) = host["detections"]
        assert detection["qid"] == "82054" and detection["unique_vuln_id"] == "3978355"
        assert detection["status"] == "New" and detection["is_ignored"] == "0"

    def test_knowledgebase_sample(self) -> None:
        page = parse_knowledgebase_page(_read("kb-documented.xml"))
        (vuln,) = page.vulns
        assert vuln["qid"] == "6666666" and vuln["severity_level"] == "3" and vuln["patchable"] == "1"
        assert vuln["cve_list"] == [{"id": "CVE-2024-40780", "url": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-40780"}]
        assert vuln["vendor_references"][0]["id"] == "webkit2gtk_Debian12"
        # The sample carries no CVSS block: unobserved, not zero.
        assert vuln["cvss_v2"] is None and vuln["cvss_v3"] is None


class TestAssembledShape:
    @pytest.fixture
    def page(self):
        return parse_detection_page(_read("hld-ec2-assembled.xml"))

    def test_cloud_fields_and_metadata(self, page) -> None:
        (host,) = page.hosts
        assert (host["cloud_provider"], host["cloud_service"], host["cloud_resource_id"]) == ("AWS", "EC2", "i-0abc123def4567890")
        assert host["ec2_metadata"] == {"latest/dynamic/instance-identity/document/region": "us-east-1"}

    def test_statuses_flags_and_qds(self, page) -> None:
        by_qid = {d["qid"]: d for d in page.hosts[0]["detections"]}
        assert by_qid["38170"]["status"] == "Fixed" and by_qid["38170"]["last_fixed_datetime"] == "2026-11-15T06:00:00Z"
        assert by_qid["11827"]["status"] == "Re-Opened" and by_qid["11827"]["is_ignored"] == "1"
        assert by_qid["6666666"]["qds"] == "57"
        assert by_qid["6666666"]["qds_factors"] == [{"name": "CVSS", "value": "8.8"}]

    def test_one_unique_vuln_id_under_two_qids(self, page) -> None:
        pairs = [(d["unique_vuln_id"], d["qid"]) for d in page.hosts[0]["detections"]]
        assert ("7000001", "6666666") in pairs and ("7000001", "45038") in pairs

    def test_results_kept_exactly(self, page) -> None:
        by_qid = {d["qid"]: d for d in page.hosts[0]["detections"]}
        assert by_qid["6666666"]["results"] == "Package\tInstalled Version\tRequired Version\nwebkit2gtk\t2.44.2-1~deb12u1\t2.44.3-1~deb12u1"

    def test_three_states(self, page) -> None:
        by_qid = {d["qid"]: d for d in page.hosts[0]["detections"]}
        assert by_qid["45038"]["results"] == ""  # present and empty
        assert by_qid["45038"]["port"] is None  # absent: unobserved
        assert page.hosts[0]["ipv6"] is None

    def test_next_page_link(self, page) -> None:
        assert page.next_url.endswith("&id_min=1002")
        assert page.warning["code"] == "1980"


class TestRefused:
    def test_wrong_root(self) -> None:
        with pytest.raises(PageRefused, match="root element"):
            parse_detection_page(_read("kb-documented.xml"))

    def test_missing_required_child(self) -> None:
        body = b"<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><DATETIME>x</DATETIME><HOST_LIST><HOST><DETECTION_LIST><DETECTION><QID>1</QID><TYPE>Info</TYPE></DETECTION></DETECTION_LIST></HOST></HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"
        with pytest.raises(PageRefused, match="HOST lacks required ID"):
            parse_detection_page(body)

    @pytest.mark.parametrize(
        ("old", "new", "missing"),
        [('<QDS severity="MEDIUM">', "<QDS>", "severity"), ('<QDS_FACTOR name="CVSS">', "<QDS_FACTOR>", "name")],
    )
    def test_missing_required_attribute(self, old: str, new: str, missing: str) -> None:
        body = _read("hld-ec2-assembled.xml").replace(old.encode(), new.encode())
        with pytest.raises(PageRefused, match=f"required attribute {missing}"):
            parse_detection_page(body)

    def test_repeated_single_child_refused(self) -> None:
        body = _read("hld-ec2-assembled.xml").replace(b"<ID>1001</ID>", b"<ID>1001</ID><ID>1002</ID>")
        with pytest.raises(PageRefused, match="repeats ID"):
            parse_detection_page(body)

    def test_entity_declaration_refused(self) -> None:
        body = b'<?xml version="1.0"?><!DOCTYPE X [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><DATETIME>&b;</DATETIME></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>'
        with pytest.raises(PageRefused, match="refused XML construct"):
            parse_detection_page(body)

    def test_external_entity_refused(self) -> None:
        body = b'<?xml version="1.0"?><!DOCTYPE X [<!ENTITY e SYSTEM "file:///etc/passwd">]><HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><DATETIME>&e;</DATETIME></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>'
        with pytest.raises(PageRefused, match="refused XML construct"):
            parse_detection_page(body)

    def test_not_well_formed(self) -> None:
        with pytest.raises(PageRefused, match="not well-formed"):
            parse_knowledgebase_page(b"<KNOWLEDGE_BASE_VULN_LIST_OUTPUT><RESPONSE>")

    def test_too_deep(self) -> None:
        body = b"<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><DATETIME>x</DATETIME>" + b"<a>" * (MAX_DEPTH + 1) + b"</a>" * (MAX_DEPTH + 1) + b"</RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>"
        with pytest.raises(PageRefused, match="deeper"):
            parse_detection_page(body)

    def test_doctype_with_external_dtd_reference_is_read(self) -> None:
        # Qualys's responses name their DTD by URL; the parser reads the page without fetching it.
        body = b'<?xml version="1.0"?><!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT SYSTEM "https://example.invalid/output.dtd"><HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><DATETIME>t</DATETIME></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>'
        assert parse_detection_page(body).hosts == []
