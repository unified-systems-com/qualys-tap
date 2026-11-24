"""Read Qualys's host detection and knowledge-base pages into plain records (req-qualys-contract-extract).

Pure: bytes in, records out, no grid and no network. XML is parsed with ``defusedxml`` (an entity
declaration or an external entity is refused), and a page is bounded by size and depth before it is
trusted (req-qualys-transport-6). Each page is checked against the committed extract: the root element,
and every child the DTD requires that this plugin reads. A page that fails is refused whole, never partly
stored (req-qualys-contract-extract-3).

Values are Qualys's text as returned. An element the page did not carry is ``None`` (unobserved); a
present, empty element is ``""``. Scalar text is stripped of surrounding whitespace, except ``RESULTS``,
which is kept exactly (req-qualys-detection-4). Nothing is converted, scaled or mapped.
"""

import io
import json
import re
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as SafeET
from defusedxml import DefusedXmlException

#: A page larger than this is refused unread (req-qualys-transport).
MAX_PAGE_BYTES = 256 << 20
#: XML nested deeper than this is refused.
MAX_DEPTH = 64
#: Elements per page, counted as they are parsed (unified-systems-com/qualys-tap#15). The byte ceiling alone
#: lets a shallow page of tiny elements allocate far more than its size suggests; this stops it while parsing.
#: A full 1,000-host page with about 150 detections a host is roughly 5 million elements.
MAX_ELEMENTS = 8_000_000

_EXTRACT = Path(__file__).resolve().parent / "contract" / "extract.json"
#: Consumed elements this plugin does not read under a given parent. The check matches children by name, so an
#: element read in one place (``LAST_SUCCESS_DATE`` under ``ATTRIBUTE``) would otherwise be required everywhere the
#: DTD requires it, and one AWS tag lacking it would refuse a whole detection page (PR #78 review).
_NOT_READ_UNDER: dict[str, frozenset[str]] = {"CLOUD_TAG": frozenset({"LAST_SUCCESS_DATE"})}


class PageRefused(ValueError):
    """A page that is not read at all: too large, too deep, not well-formed, hostile, or off-contract."""


class EmptyBody(PageRefused):
    """A page with no content at all, refused under its own name (unified-systems-com/qualys-tap#52, ruled Q30a).

    An empty answer is missing evidence, not evidence of absence: read as a page with no hosts, it would let a
    complete read withdraw every host held. So it is refused like any other page, and named so an operator can
    tell it from a malformed one.
    """


@cache
def extract() -> dict[str, Any]:
    return json.loads(_EXTRACT.read_text(encoding="utf-8"))


@dataclass
class DetectionPage:
    """One host detection page: Qualys's response time, the hosts, and the next-page link if any."""

    response_datetime: str | None
    hosts: list[dict[str, Any]]
    next_url: str | None
    warning: dict[str, str | None] | None


@dataclass
class KnowledgeBasePage:
    """One knowledge-base page: Qualys's response time and the QID records it returned."""

    response_datetime: str | None
    vulns: list[dict[str, Any]] = field(default_factory=list)
    #: The next-page link Qualys returns when it cut the list short (unified-systems-com/qualys-tap#16).
    next_url: str | None = None
    warning: dict[str, str | None] | None = None


def _load(body: bytes, document: str) -> Element:
    if len(body) > MAX_PAGE_BYTES:
        raise PageRefused(f"page larger than {MAX_PAGE_BYTES} bytes")
    if not body.strip():  # after the size check, so nothing past the ceiling is scanned or copied
        raise EmptyBody("the page is empty")
    root = _bounded_parse(body)
    spec = extract()["documents"][document]
    if root.tag != spec["root"]:
        raise PageRefused(f"root element is {root.tag}, expected {spec['root']}")
    _check(root, spec["elements"], 1)
    return root


def _bounded_parse(body: bytes) -> Element:
    """Parse incrementally, refusing past the element count or depth as the elements arrive."""
    root: Element | None = None
    depth = count = 0
    try:
        for event, element in SafeET.iterparse(io.BytesIO(body), events=("start", "end")):
            if event == "end":
                depth -= 1
                continue
            if root is None:
                root = element
            depth += 1
            count += 1
            if depth > MAX_DEPTH:
                raise PageRefused(f"XML nested deeper than {MAX_DEPTH}")
            if count > MAX_ELEMENTS:
                raise PageRefused(f"page holds more than {MAX_ELEMENTS} elements")
    except DefusedXmlException as exc:
        raise PageRefused(f"refused XML construct: {type(exc).__name__}") from exc
    except SafeET.ParseError as exc:
        raise PageRefused(f"not well-formed XML: {exc}") from exc
    if root is None:
        raise PageRefused("not well-formed XML: no element")
    return root


def _check(node: Element, elements: dict[str, Any], depth: int) -> None:
    """Depth bound, and every required child this plugin reads is present on every element it reads."""
    if depth > MAX_DEPTH:
        raise PageRefused(f"XML nested deeper than {MAX_DEPTH}")
    decl = elements.get(node.tag)
    if decl:
        present = {child.tag for child in node}
        skipped = _NOT_READ_UNDER.get(node.tag, frozenset())
        missing = [c for c in decl["required_children"] if c in elements and c not in present and c not in skipped]
        if missing:
            raise PageRefused(f"{node.tag} lacks required {', '.join(missing)}")
        tags = [child.tag for child in node]
        repeated = [c for c in decl.get("single_children", []) if c in elements and tags.count(c) > 1]
        if repeated:
            raise PageRefused(f"{node.tag} repeats {', '.join(repeated)}, which the DTD allows once")
        absent = [a for a, spec in decl["attributes"].items() if spec.get("default") == "#REQUIRED" and node.get(a) is None]
        if absent:
            raise PageRefused(f"{node.tag} lacks required attribute {', '.join(absent)}")
    for child in node:
        _check(child, elements, depth + 1)


def _text(parent: Element | None, tag: str, *, exact: bool = False) -> str | None:
    """The child's text as returned: None when the child is absent, "" when present and empty."""
    if parent is None:
        return None
    child = parent.find(tag)
    if child is None:
        return None
    text = child.text or ""
    return text if exact else text.strip()


def _cloud_tags(node: Element) -> list[dict[str, str | None]] | None:
    """The provider's own resource tags, each ``CLOUD_TAG``'s ``NAME`` and ``VALUE`` as returned.

    None when the element is absent (not returned, or ``show_cloud_tags`` not honoured), never ``[]``: the DTD
    requires at least one tag inside it, so an empty list would claim an observation nobody made.
    ``LAST_SUCCESS_DATE`` is not read: the DTD requires it, and a contract that consumed it would refuse a whole
    detection page over one tag that lacked it.
    """
    tags = node.find("CLOUD_PROVIDER_TAGS")
    if tags is None:
        return None
    return [
        {"name": _text(tag, "NAME", exact=True), "value": _text(tag, "VALUE", exact=True)}
        for tag in tags.findall("CLOUD_TAG")
    ]


def _host(node: Element) -> dict[str, Any]:
    metadata = node.find("METADATA/EC2")
    ec2 = status = None
    if metadata is not None:
        ec2, status = {}, {}
        for attribute in metadata.findall("ATTRIBUTE"):
            name = _text(attribute, "NAME")
            if name:
                ec2[name] = _text(attribute, "VALUE")
                # How Qualys last fared reading the attribute: an empty VALUE with LAST_STATUS Success is observed-empty.
                status[name] = {
                    "last_status": _text(attribute, "LAST_STATUS"),
                    "last_success_date": _text(attribute, "LAST_SUCCESS_DATE"),
                    "last_error_date": _text(attribute, "LAST_ERROR_DATE"),
                    "last_error": _text(attribute, "LAST_ERROR"),
                }
    return {
        "host_id": _text(node, "ID"),
        "asset_id": _text(node, "ASSET_ID"),
        "ip": _text(node, "IP"),
        "ipv6": _text(node, "IPV6"),
        "tracking_method": _text(node, "TRACKING_METHOD"),
        "dns": _text(node, "DNS"),
        "netbios": _text(node, "NETBIOS"),
        "os": _text(node, "OS"),
        "last_scan_datetime": _text(node, "LAST_SCAN_DATETIME"),
        "last_vm_scanned_date": _text(node, "LAST_VM_SCANNED_DATE"),
        "last_vm_auth_scanned_date": _text(node, "LAST_VM_AUTH_SCANNED_DATE"),
        "cloud_provider": _text(node, "CLOUD_PROVIDER"),
        "cloud_service": _text(node, "CLOUD_SERVICE"),
        "cloud_resource_id": _text(node, "CLOUD_RESOURCE_ID"),
        "ec2_instance_id": _text(node, "EC2_INSTANCE_ID"),
        "ec2_metadata": ec2,
        "ec2_metadata_status": status,
        "cloud_tags": _cloud_tags(node),
        "detections": [_detection(d) for d in node.findall("DETECTION_LIST/DETECTION")],
    }


def _detection(node: Element) -> dict[str, Any]:
    qds = node.find("QDS")
    factors = node.find("QDS_FACTORS")
    return {
        "unique_vuln_id": _text(node, "UNIQUE_VULN_ID"),
        "qid": _text(node, "QID"),
        "detection_type": _text(node, "TYPE"),
        "severity": _text(node, "SEVERITY"),
        "port": _text(node, "PORT"),
        "protocol": _text(node, "PROTOCOL"),
        "fqdn": _text(node, "FQDN"),
        "ssl": _text(node, "SSL"),
        "results": _text(node, "RESULTS", exact=True),
        "status": _text(node, "STATUS"),
        "first_found_datetime": _text(node, "FIRST_FOUND_DATETIME"),
        "last_found_datetime": _text(node, "LAST_FOUND_DATETIME"),
        "qds": None if qds is None else (qds.text or "").strip(),
        # The DTD declares QDS's severity attribute #REQUIRED; kept beside the score (unified-systems-com/qualys-tap#51).
        "qds_severity": None if qds is None else qds.get("severity"),
        "qds_factors": None if factors is None else [
            {"name": f.get("name"), "value": (f.text or "").strip()} for f in factors.findall("QDS_FACTOR")
        ],
        "times_found": _text(node, "TIMES_FOUND"),
        "last_test_datetime": _text(node, "LAST_TEST_DATETIME"),
        "last_update_datetime": _text(node, "LAST_UPDATE_DATETIME"),
        "last_fixed_datetime": _text(node, "LAST_FIXED_DATETIME"),
        "last_reopened_datetime": _text(node, "LAST_REOPENED_DATETIME"),
        "times_reopened": _text(node, "TIMES_REOPENED"),
        "is_ignored": _text(node, "IS_IGNORED"),
        "is_disabled": _text(node, "IS_DISABLED"),
        "last_processed_datetime": _text(node, "LAST_PROCESSED_DATETIME"),
    }


def _warning(response: Element) -> dict[str, str | None] | None:
    node = response.find("WARNING")
    if node is None:
        return None
    return {"code": _text(node, "CODE"), "text": _text(node, "TEXT"), "url": _text(node, "URL")}


def parse_detection_page(body: bytes) -> DetectionPage:
    """A host detection page as records; refused whole if it is not a contract-valid detection page."""
    root = _load(body, "detection")
    response = root.find("RESPONSE")
    if response is None:
        raise PageRefused("no RESPONSE element")
    warning = _warning(response)
    return DetectionPage(
        response_datetime=_text(response, "DATETIME"),
        hosts=[_host(h) for h in response.findall("HOST_LIST/HOST")],
        next_url=warning["url"] if warning and warning["url"] else None,
        warning=warning,
    )


def _cvss(node: Element | None) -> dict[str, Any] | None:
    if node is None:
        return None
    base = node.find("BASE")
    return {
        "base": None if base is None else (base.text or "").strip(),
        "base_source": None if base is None else base.get("source"),
        "temporal": _text(node, "TEMPORAL"),
        "vector_string": _text(node, "VECTOR_STRING"),
    }


def _references(node: Element | None, path: str) -> list[dict[str, str | None]] | None:
    if node is None:
        return None
    return [{"id": _text(r, "ID"), "url": _text(r, "URL")} for r in node.findall(path)]


def _vuln(node: Element) -> dict[str, Any]:
    return {
        "qid": _text(node, "QID"),
        "vuln_type": _text(node, "VULN_TYPE"),
        "severity_level": _text(node, "SEVERITY_LEVEL"),
        "title": _text(node, "TITLE"),
        "category": _text(node, "CATEGORY"),
        "patchable": _text(node, "PATCHABLE"),
        "published_datetime": _text(node, "PUBLISHED_DATETIME"),
        "last_service_modification_datetime": _text(node, "LAST_SERVICE_MODIFICATION_DATETIME"),
        "cvss_v2": _cvss(node.find("CVSS")),
        "cvss_v3": _cvss(node.find("CVSS_V3")),
        "vendor_references": _references(node.find("VENDOR_REFERENCE_LIST"), "VENDOR_REFERENCE"),
        "cve_list": _references(node.find("CVE_LIST"), "CVE"),
    }


def parse_knowledgebase_page(body: bytes) -> KnowledgeBasePage:
    """A knowledge-base page as records; refused whole if it is not a contract-valid knowledge-base page."""
    root = _load(body, "knowledgebase")
    response = root.find("RESPONSE")
    if response is None:
        raise PageRefused("no RESPONSE element")
    warning = _warning(response)
    return KnowledgeBasePage(
        response_datetime=_text(response, "DATETIME"),
        vulns=[_vuln(v) for v in response.findall("VULN_LIST/VULN")],
        next_url=warning["url"] if warning and warning["url"] else None,
        warning=warning,
    )


@dataclass
class TagPage:
    """One page of the tag search (req-qualys-tags): the tags, and what Qualys said about the rest.

    ``has_more`` is None when the page did not say, which the walk treats as not knowing it reached the end.
    """

    tags: list[dict[str, Any]]
    has_more: bool | None
    last_id: str | None
    count: str | None


#: The Tag fields read, by Qualys's element name, kept as returned under the model's field name.
_TAG_FIELDS = {
    "name": "name",
    "color": "color",
    "ruleType": "rule_type",
    "ruleText": "rule_text",
    "criticalityScore": "criticality_score",
    "description": "description",
    "created": "created_datetime",
    "modified": "modified_datetime",
    "parentTagId": "parent_tag_id",
}
_RESPONSE_CODE = re.compile(r"[A-Z_]{1,64}")


def _tag(node: Element) -> dict[str, Any]:
    record: dict[str, Any] = {"tag_id": _text(node, "id")}
    for element, name in _TAG_FIELDS.items():
        record[name] = _text(node, element, exact=element in ("ruleText", "description"))
    children = node.find("children")
    if children is None:
        record["child_tag_ids"] = None  # not returned: unobserved, never "no children"
    else:
        listed = children.find("list")
        simple = [] if listed is None else [c for c in listed if c.tag in ("SimpleTag", "TagSimple")]
        record["child_tag_ids"] = [_text(c, "id") for c in simple]
    return record


def parse_tag_page(body: bytes) -> TagPage:
    """A tag-search page, refused unless Qualys answered SUCCESS with a ``data`` list of tags."""
    if len(body) > MAX_PAGE_BYTES:
        raise PageRefused(f"page larger than {MAX_PAGE_BYTES} bytes")
    if not body.strip():
        raise EmptyBody("the page is empty")
    root = _bounded_parse(body)
    if root.tag != "ServiceResponse":
        raise PageRefused(f"root element is {root.tag}, expected ServiceResponse")
    code = _text(root, "responseCode")
    if code != "SUCCESS":
        # Only a code of the documented shape is named; any other text Qualys sent stays out of the run's record.
        shown = code if code is not None and _RESPONSE_CODE.fullmatch(code) else "an unreadable code"
        raise PageRefused(f"the tag search answered {shown}, not SUCCESS")
    data = root.find("data")
    if data is None and _text(root, "count") != "0":
        raise PageRefused("the tag search answered SUCCESS with no data list")
    more = _text(root, "hasMoreRecords")
    return TagPage(
        tags=[_tag(t) for t in (data if data is not None else []) if t.tag == "Tag"],
        has_more={"true": True, "false": False}.get(more or ""),
        last_id=_text(root, "lastId"),
        count=_text(root, "count"),
    )
