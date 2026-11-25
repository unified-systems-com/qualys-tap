"""Turn parsed Qualys pages into GRIFT node and edge envelopes (req-qualys-host, -detection, -qid, -states).

Nodes are named by batch-local ``ref`` and found again by the grid through each model's declared natural key,
so nothing here derives an id. Values are carried as returned; a value a column cannot hold is stored as null
and listed on the run, never cut or altered. A detection key part that cannot be held makes the detection
unkeyable: it is not stored, counted, and its page counts as partly read.

The grid applies a written node as a full replacement, so a node rewritten to change one fact re-sends every
other fact as the grid holds it (a withdrawn host), and a node the run did not read is not written at all when
the grid already holds it (a QID the knowledge base did not return this time). Grid reads come in through a
``GridView`` so :func:`decompose` stays testable without a database; only the document header (:func:`document`,
:func:`documents`) reads the grid, for the versions its format "1" header states.

Resolution follows Qualys alone: a detection is ``resolved`` exactly when Qualys reports ``Fixed`` and ``open``
otherwise; a detection absent from a read is not written, so it keeps what it had (req-qualys-states-3, -4).
A host absent from a complete read of the standing scope is rewritten ``withdrawn``; its detections are not
touched (req-qualys-states-5).

Tags come from the tag search when the run read it (req-qualys-tags). Each tag is written with an edge to its
subscription and an edge to each child the list also holds. Only a complete list withdraws a held tag it does not
contain, and only a complete list whose every children list was returned claims the child edges whole.
"""

import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import parse_qs, urlsplit

from django.db import models as dj_models
from tap_plugin.qualys import aws_mint, neutral, parsers, shared_host
from tap_plugin.qualys.identity import subscription_key as derive_subscription_key
from tap_plugin.qualys.models.detection import QualysDetection
from tap_plugin.qualys.models.host import QualysHost
from tap_plugin.qualys.models.qid import QualysQid
from tap_plugin.qualys.models.scan_run import QualysScanRun
from tap_plugin.qualys.models.subscription import QualysSubscription
from tap_plugin.qualys.models.tag import QualysTag
from tap_plugin.qualys.parse import DetectionPage, KnowledgeBasePage
from tap_plugin.qualys.read_kind import COMPLETE, NARROWER, WINDOW


def _first_host_id(page: DetectionPage) -> int | None:
    ids = [h.get("host_id") for h in page.hosts]
    return int(ids[0]) if ids and isinstance(ids[0], str) and ids[0].isdigit() else None


def _last_host_id(page: DetectionPage) -> int | None:
    ids = [h.get("host_id") for h in page.hosts]
    return int(ids[-1]) if ids and isinstance(ids[-1], str) and ids[-1].isdigit() else None


def chain_break(pages: list[DetectionPage]) -> str | None:
    """Why the pages are not one unbroken next-page chain, or None (unified-systems-com/qualys-tap#19).

    Every page but the last must link onward, and the page after it must be the one that link names: its
    first host at or above the link's ``id_min`` and above the linking page's last host. A missing link, a
    reordered pair or a repeated page breaks the chain, so the read cannot count as complete or move the
    watermark. One gap it cannot see: a page dropped cleanly from the middle, whose successor still starts
    above the link's ``id_min``, since host ids are sparse and Qualys promises no exact start.
    """
    for number, (page, following) in enumerate(zip(pages, pages[1:], strict=False), 1):
        if not page.next_url:
            return f"detection page {number} has no next-page link, yet a page follows it"
        values = parse_qs(urlsplit(page.next_url).query).get("id_min", [])
        if len(values) != 1 or not values[0].isdigit():
            return f"detection page {number} links onward with no usable id_min"
        first = _first_host_id(following)
        last = _last_host_id(page)
        if first is None:
            return f"detection page {number + 1} has no host id to check against the link"
        if first < int(values[0]) or (last is not None and first <= last):
            return f"detection page {number + 1} is not the page detection page {number} links to"
    return None


#: Host fields parsed to UTC beside the string Qualys sent (req-qualys-host).
_PARSED_TIMES = {
    "last_scan_datetime": "last_scan_at",
    "last_vm_scanned_date": "last_vm_scanned_at",
    "last_vm_auth_scanned_date": "last_vm_auth_scanned_at",
}
_DETECTION_KEY = ("host_id", "qid", "unique_vuln_id")
EC2_INSTANCE_TYPE = "aws_core__aws_ec2_instance"


class GridView(Protocol):
    """What the run needs to know about what the grid already holds for one subscription."""

    def subscription(self, key: str) -> dict[str, Any] | None: ...

    def current_hosts(self, key: str) -> dict[str, dict[str, Any]]:
        """Every host of the subscription not withdrawn, by host id, with its stored fields."""
        ...

    def held_qids(self, key: str, qids: Iterable[str]) -> set[str]: ...

    def current_tags(self, key: str) -> dict[str, dict[str, Any]]:
        """Every tag of the subscription not withdrawn, by tag id, with its stored fields."""
        ...

    def qid_records(self, key: str, qids: Iterable[str]) -> dict[str, dict[str, Any]]:
        """The held QIDs' ``cve_list``, ``cvss_v2`` and ``cvss_v3``, for QIDs the knowledge base did not return this run."""
        ...

    def host_detections(self, key: str, host_ids: Iterable[str]) -> dict[str, list[dict[str, Any]]]:
        """Every detection the grid holds on these hosts, with what the neutral rules read of it."""
        ...

    def vulnerabilities(self, vuln_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        """Held shared records by exact id: ``{"scored": bool, "dimensions": {...}}``."""
        ...

    def held_packages(self, keys: Iterable[tuple[str, str, str]]) -> set[tuple[str, str, str]]: ...

    def held_findings(self, source_keys: Iterable[str]) -> set[str]:
        """Which of these neutral finding source keys the grid holds for source ``qualys``."""
        ...

    def default_dimensions(self, entity_type: str) -> dict[str, str]: ...

    def held_keys(self, entity_type: str, keys: Iterable[tuple[str, ...]]) -> set[tuple[str, ...]] | None:
        """Of these natural keys of an aws_core type, those the grid holds; None when aws_core is not installed."""
        ...

    def has_edge_type(self, slug: str) -> bool:
        """Whether the installed plugins define this edge type."""
        ...

    def ec2_instances(self, instance_ids: Iterable[str]) -> set[str] | None:
        """Of these ids, those ``aws_core`` holds as an EC2 instance's ``instance_id``; None without ``aws_core``."""
        ...


@dataclass
class Run:
    """The facts about one collection that are not in its pages."""

    api_host: str
    label: str
    source: str
    read_kind: str
    started_at: datetime
    read_at: datetime | None
    applied_filter: dict[str, Any]
    standing_scope: dict[str, Any] | None = None
    knowledgebase_asked: set[str] | None = None
    knowledgebase_complete: bool = True
    archive_sha256: str | None = None
    export_created_at: str | None = None
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    # A live run's own facts (req-qualys-probe, req-qualys-detection-read); a file run leaves them unset.
    probe: dict[str, Any] | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    #: Whether the run followed every next-page link to the end, within its ceilings. None for a file run,
    #: which never advances the live watermark (req-qualys-file-import).
    walk_complete: bool | None = None
    extra_warnings: list[dict[str, str]] = field(default_factory=list)
    detection_pages_not_read: list[dict[str, str]] = field(default_factory=list)
    #: The tags the tag search returned; None when the run did not read tags (switched off, or a file run).
    tags: list[dict[str, Any]] | None = None
    #: Whether that list is the whole list: every page read to Qualys's last, and every tag keyable.
    tags_complete: bool = False
    tags_not_read: list[dict[str, str]] = field(default_factory=list)
    #: Each read host's asset record by Qualys host id (req-qualys-host-assets); None when the run read none.
    host_assets: dict[str, dict[str, Any]] | None = None
    host_assets_not_read: list[dict[str, str]] = field(default_factory=list)
    #: Whether the envelope turned the AWS integration on (req-qualys-aws): mint absent aws_core nodes.
    aws: bool = False
    #: The envelope's declared networks (req-qualys-host-network): ``{"default": name, "vpcs": {vpc id: name}}`` or None.
    networks: dict[str, Any] | None = None
    #: The sources the envelope switched off (req-qualys-sources), each listed on the run as not read.
    switched_off: list[str] = field(default_factory=list)


@dataclass
class Result:
    """The batch's nodes and edges, and what the run counted and could not carry."""

    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=dict)
    authority: list[dict[str, Any]] = field(default_factory=list)
    watermark_advanced: bool = False
    dropped: list[dict[str, str]] = field(default_factory=list)
    scopes_not_read: list[dict[str, str]] = field(default_factory=list)
    partly_read_pages: int = 0
    read_kind: str = ""  # the kind the run was treated as, after any downgrade
    #: Whether the grid held the subscription before this run; the opening batch writes it only when it did not.
    subscription_existed: bool = False
    #: The subscription's fields as the grid held them before this run, for the opening batch of a new subscription.
    subscription_held: dict[str, Any] = field(default_factory=dict)

    def count(self, name: str, n: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + n


def _fit(model: type[dj_models.Model], name: str, value: Any) -> tuple[Any, str | None]:
    """The value if the column can hold it, else None with the reason."""
    if value is None:
        return None, None
    column = model._meta.get_field(name)
    limit = getattr(column, "max_length", None)
    if limit is not None and isinstance(value, str) and len(value) > limit:
        return None, f"longer than {limit} characters"
    return value, None


def _carry(model: type[dj_models.Model], record: dict[str, Any], names: Iterable[str], result: Result, where: str) -> dict[str, Any]:
    out = {}
    for name in names:
        value, problem = _fit(model, name, record.get(name))
        if problem:
            result.dropped.append({"where": where, "field": name, "reason": problem})
        out[name] = value
    return out


def parse_time(value: str | None) -> str | None:
    """An ISO-8601 UTC timestamp as Qualys sends it, normalised; None when absent or not a timestamp."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC).isoformat()


def envelope(ref: str, model: type[dj_models.Model], name: str, fields: dict[str, Any]) -> dict[str, Any]:
    return {
        "entity": {"ref": ref, "entity_type": model.ENTITY_TYPE, "name": (name or model.ENTITY_NAME)[:255], "dimensions": dict(model.DEFAULT_DIMENSIONS)},
        "node": fields,
    }


def edge(ref: str, slug: str, from_ref: str, to_ref: str) -> dict[str, Any]:
    return {"entity": {"ref": ref, "entity_type": "edge", "name": slug, "dimensions": {}}, "edge": {"from_ref": from_ref, "to_ref": to_ref, "edge_type": slug, "properties": {}}}


def edge_to_key(ref: str, slug: str, from_ref: str, entity_type: str, key: dict[str, str]) -> dict[str, Any]:
    return {"entity": {"ref": ref, "entity_type": "edge", "name": slug, "dimensions": {}}, "edge": {"from_ref": from_ref, "to_key": {"entity_type": entity_type, "key": key}, "edge_type": slug, "properties": {}}}


_HOST_FIELDS = (
    "asset_id", "ip", "ipv6", "tracking_method", "dns", "netbios", "os", "last_scan_datetime", "last_vm_scanned_date",
    "last_vm_auth_scanned_date", "cloud_provider", "cloud_service", "cloud_resource_id", "ec2_instance_id",
)
_DETECTION_FIELDS = (
    "detection_type", "port", "protocol", "fqdn", "ssl", "status", "severity", "first_found_datetime", "last_found_datetime",
    "last_fixed_datetime", "last_reopened_datetime", "times_found", "times_reopened", "last_test_datetime",
    "last_update_datetime", "last_processed_datetime", "is_ignored", "is_disabled", "qds", "qds_severity", "results",
)
_QID_FIELDS = (
    "vuln_type", "severity_level", "title", "category", "patchable", "published_datetime",
    "last_service_modification_datetime",
)


_TAG_FIELDS = (
    "name", "color", "rule_type", "rule_text", "criticality_score", "description", "created_datetime", "modified_datetime",
    "parent_tag_id",
)
TAG_OF_SUBSCRIPTION = "TAG_OF_SUBSCRIPTION__qualys"
LISTS_CHILD_TAG = "LISTS_CHILD_TAG__qualys"


def _tags(key: str, run: Run, grid: GridView, result: Result) -> None:
    """The subscription's tags, their subscription and child edges, and the withdrawal of a held tag a complete list lacks."""
    listed: dict[str, dict[str, Any]] = {}
    for tag in run.tags or []:
        tag_id = tag.get("tag_id")
        if not (_keyable(tag_id, QualysTag, "tag_id") and tag_id.isdigit()):
            result.count("tags_unkeyable")
            continue
        if tag_id in listed:
            continue
        fields = {"subscription_key": key, "tag_id": tag_id, **_carry(QualysTag, tag, _TAG_FIELDS, result, f"tag {tag_id}")}
        children = tag.get("child_tag_ids")
        fields["child_tag_ids"] = list(children) if children is not None else None
        fields["state"] = "current"
        fields["withdrawn_in_run"] = None
        listed[tag_id] = fields
        result.nodes.append(envelope(f"t{tag_id}", QualysTag, fields.get("name") or f"tag {tag_id}", fields))
        result.edges.append(edge(f"e-tag-{tag_id}", TAG_OF_SUBSCRIPTION, f"t{tag_id}", "sub"))
    result.count("tags", len(listed))
    for tag_id, fields in listed.items():
        for child in fields["child_tag_ids"] or []:
            if isinstance(child, str) and child in listed and child != tag_id:
                result.edges.append(edge(f"e-child-{tag_id}-{child}", LISTS_CHILD_TAG, f"t{tag_id}", f"t{child}"))
                result.count("tag_children")
            else:
                result.count("tag_children_not_listed")
    if not run.tags_complete or result.counters.get("tags_unkeyable"):
        return
    # A complete list states each tag's whole set of parents only when every tag's children list came back: a tag
    # whose list was not returned could be a parent nothing here shows. Otherwise the claims say partial.
    parents_known = all(fields["child_tag_ids"] is not None for fields in listed.values())
    for tag_id in sorted(listed, key=int):
        result.authority.append({
            "edge_type": LISTS_CHILD_TAG,
            "anchor": {"entity_type": QualysTag.ENTITY_TYPE, "key": {"subscription_key": key, "tag_id": tag_id}},
            "direction": "inbound",
            "read": "complete" if parents_known else "partial",
        })
    for tag_id, stored in sorted(grid.current_tags(key).items()):
        if tag_id in listed:
            continue
        rewritten = {**stored, "state": "withdrawn", "withdrawn_in_run": run.run_id}
        result.nodes.append(envelope(f"tw{tag_id}", QualysTag, stored.get("name") or f"tag {tag_id}", rewritten))
        result.count("tags_withdrawn")


_INVENTORY = ("host_asset_id", "interfaces", "open_ports", "software")


def _inventory(key: str, run: Run, grid: GridView, result: Result, seen_hosts: set[str]) -> None:
    """Each written host's inventory from this run's host asset search, else as the grid holds it (req-qualys-host-assets).

    A host node is written whole, so a host this run did not read an asset record for keeps what an earlier read
    gave: not read is never "none".
    """
    assets = run.host_assets or {}
    need_held = [h for h in seen_hosts if h not in assets]
    held = grid.current_hosts(key) if need_held else {}
    for node in result.nodes:
        if node["entity"]["entity_type"] != QualysHost.ENTITY_TYPE or node["node"].get("host_id") not in seen_hosts:
            continue
        host_id = node["node"]["host_id"]
        source = assets.get(host_id)
        if source is not None:
            result.count("host_assets_read")
        source = source if source is not None else held.get(host_id, {})
        for name in _INVENTORY:
            node["node"][name] = source.get(name)


def _host_node(ref: str, key: str, record: dict[str, Any], result: Result) -> dict[str, Any]:
    where = f"host {record['host_id']}"
    fields = {"subscription_key": key, "host_id": record["host_id"], **_carry(QualysHost, record, _HOST_FIELDS, result, where)}
    for raw, parsed in _PARSED_TIMES.items():
        fields[parsed] = parse_time(fields[raw])
    fields["ec2_metadata"] = record.get("ec2_metadata")
    fields["ec2_metadata_status"] = record.get("ec2_metadata_status")
    fields["cloud_tags"] = record.get("cloud_tags")  # CLOUD_TAG NAME and VALUE as returned; None when not returned
    fields["state"] = "current"
    fields["withdrawn_in_run"] = None
    return envelope(ref, QualysHost, fields.get("dns") or fields.get("ip") or f"host {record['host_id']}", fields)


def _detection_node(ref: str, key: str, host_id: str, os_name: Any, record: dict[str, Any], result: Result) -> dict[str, Any]:
    where = f"detection {host_id}/{record['qid']}/{record['unique_vuln_id']}"
    fields = {"subscription_key": key, "host_id": host_id, "qid": record["qid"], "unique_vuln_id": record["unique_vuln_id"]}
    fields.update(_carry(QualysDetection, record, _DETECTION_FIELDS, result, where))
    fields["qds_factors"] = record.get("qds_factors")
    fixed = record.get("status") == "Fixed"
    fields["state"] = "resolved" if fixed else "open"
    fields["resolution_source"] = "qualys_fixed" if fixed else None
    # Exactly one parse state per detection (req-qualys-parsers-1); the result text itself is stored unchanged.
    parsed = parsers.parse({"qid": record["qid"], "results": record.get("results"), "os": os_name})
    fields["parse_state"] = parsed.state
    fields["parser_version"] = parsed.parser_version
    fields["package_observations"] = [o.as_dict() for o in parsed.observations] if parsed.state == parsers.PARSED else None
    result.count(f"parse_{parsed.state}")
    return envelope(ref, QualysDetection, f"QID {record['qid']} on host {host_id}", fields)


def _qid_node(ref: str, key: str, vuln: dict[str, Any], result: Result) -> dict[str, Any]:
    fields = {"subscription_key": key, "qid": vuln["qid"], "kb_returned": True}
    fields.update(_carry(QualysQid, vuln, _QID_FIELDS, result, f"qid {vuln['qid']}"))
    fields["cvss_v2"] = vuln.get("cvss_v2")
    fields["cvss_v3"] = vuln.get("cvss_v3")
    fields["cvss_v4"] = None
    fields["vendor_references"] = vuln.get("vendor_references")
    fields["cve_list"] = vuln.get("cve_list")
    title = fields.get("title")
    return envelope(ref, QualysQid, f"QID {vuln['qid']}: {title}" if title else f"QID {vuln['qid']}", fields)


#: How many dropped values one warning names before it summarises the rest.
_DROPPED_LISTED = 20


def _dropped_warnings(dropped: list[dict[str, str]]) -> list[dict[str, str]]:
    """One VALUE_DROPPED warning naming each value stored as null because its column could not hold it."""
    if not dropped:
        return []
    named = "; ".join(f"{d['where']}: {d['field']} ({d['reason']})" for d in dropped[:_DROPPED_LISTED])
    more = f"; and {len(dropped) - _DROPPED_LISTED} more" if len(dropped) > _DROPPED_LISTED else ""
    return [{"code": "VALUE_DROPPED", "detail": f"{len(dropped)} value(s) stored as null: {named}{more}"}]


def _keyable(value: Any, model: type[dj_models.Model], name: str) -> bool:
    return isinstance(value, str) and value != "" and _fit(model, name, value)[1] is None


def _neutral(key: str, grid: GridView, result: Result, run_detections: dict[str, list[neutral.Detection]], host_names: dict[str, str], vulns: dict[str, dict[str, Any]]) -> None:
    """The neutral findings, the shared vulnerability records and the package links (req-qualys-neutral, -package-link, -qid).

    A finding is computed over every detection the host has, not only this run's: a window read returns only
    what changed, and a finding is open while ANY detection naming its CVE on that host is open. This run's
    detections replace the held ones they rewrite. A finding is written only where this run read one of its
    detections, and created only while one is open; once written it is kept, so it can become resolved.
    """
    held_by_host = grid.host_detections(key, run_detections)
    for host_id in run_detections:
        merged = {(d.qid, d.unique_vuln_id): d for d in run_detections[host_id]}
        for row in held_by_host.get(host_id, []):
            merged.setdefault((row["qid"], row["unique_vuln_id"]), neutral.Detection(
                row["qid"], row["unique_vuln_id"], row["state"], row.get("severity"), row.get("first_found_datetime"), row.get("package_observations")))
        run_detections[host_id] = list(merged.values())
    # Every QID the merged detections name, held ones included: a held open detection keeps its finding open.
    named = {d.qid for dets in run_detections.values() for d in dets}
    records = {qid: vulns[qid] for qid in named if qid in vulns}
    records.update(grid.qid_records(key, named - set(records)))
    cves_by_qid = {qid: neutral.cve_ids(record.get("cve_list")) for qid, record in records.items()}
    # A host with a detection whose QID has no CVE list on record (not returned, or a stub) cannot be grouped
    # whole: that detection may name a CVE a finding on the host is about. Its claims say partial.
    unknown = {qid for qid in named if records.get(qid, {}).get("cve_list") is None}
    hosts_unsure = {h for h, dets in run_detections.items() if any(d.qid in unknown for d in dets)}
    if hosts_unsure:
        result.count("hosts_with_unknown_qids", len(hosts_unsure))
    for cves in cves_by_qid.values():
        for cve in cves:
            if not neutral.usable_vuln_id(cve):
                result.count("cve_ids_too_long")
    groups = [g for g in neutral.group(run_detections, cves_by_qid) if g.read_this_run]
    held_findings = grid.held_findings(neutral.source_key(key, g.host_id, g.cve) for g in groups)
    groups = [g for g in groups if g.open or neutral.source_key(key, g.host_id, g.cve) in held_findings]
    # Fail closed: on a host with a detection of unknown CVEs, a finding is never moved to resolved, because that
    # detection may name its CVE and be open. Open findings are still written; the next whole read settles the rest.
    unsettled = [g for g in groups if not g.open and g.host_id in hosts_unsure]
    if unsettled:
        result.count("findings_not_resolved_unknown_qids", len(unsettled))
        groups = [g for g in groups if g not in unsettled]

    # The shared vulnerability records: every CVE a QID returned this run names, and every CVE a written finding
    # concerns; a held detection's CVE that no written finding concerns is not touched. Where several QIDs name one
    # CVE, the score comes from the lowest-numbered QID that has one, so the result never depends on read order.
    in_scope = {cve for qid in cves_by_qid if qid in vulns for cve in cves_by_qid[qid]} | {g.cve for g in groups}
    scores: dict[str, dict[str, Any]] = {cve: {} for cve in in_scope if neutral.usable_vuln_id(cve)}
    for qid in sorted(cves_by_qid, key=int):
        for cve in cves_by_qid[qid]:
            if cve in scores and not scores[cve]:
                scores[cve] = neutral.cvss_of(records[qid])
    held = grid.vulnerabilities(scores)
    defaults = grid.default_dimensions(neutral.VULNERABILITY_TYPE)
    for cve in sorted(scores):
        if cve not in held:
            result.nodes.append(neutral.vulnerability_node(f"v:{cve}", cve, defaults, scores[cve]))
            result.count("vulnerabilities_created")
        elif not held[cve]["scored"] and scores[cve]:
            # WORKAROUND(unified-systems-com/tap#1172): read, then write. A score another source writes between
            # this read and the import is replaced; tap has no write that yields to a held value.
            result.nodes.append(neutral.vulnerability_node(f"v:{cve}", cve, held[cve]["dimensions"], scores[cve]))
            result.count("vulnerabilities_scored")
    for qid in sorted(q for q in cves_by_qid if q in vulns):
        for cve in cves_by_qid[qid]:
            if neutral.usable_vuln_id(cve):
                result.edges.append(edge_to_key(f"e-cve-{qid}-{cve}", neutral.ABOUT_VULNERABILITY, f"q{qid}", neutral.VULNERABILITY_TYPE, {"vuln_id": cve}))

    # Packages: a link from each detection read this run to each package a parser was sure of, and every
    # package a link or a carrier names created with its key fields where the grid holds none.
    wanted: set[tuple[str, str, str]] = set()
    for dets in run_detections.values():
        for d in dets:
            if d.ref is None:
                continue
            for o in d.package_observations or []:
                if o.get("mapping_unambiguous") is True and neutral.package_key(o) is None:
                    result.count("package_keys_too_long")
            for package in {k for o in d.package_observations or [] if (k := neutral.package_key(o))}:
                wanted.add(package)
                result.edges.append(edge_to_key(f"e-pkg-{d.ref}-{len(result.edges)}", neutral.FOUND_IN_PACKAGE, d.ref, neutral.PACKAGE_TYPE, neutral.package_ref(package)["key"]))
                result.count("package_links")
    wanted.update(c for g in groups if (c := g.carrier()) is not None)
    package_dims = grid.default_dimensions(neutral.PACKAGE_TYPE)
    for package in sorted(wanted - grid.held_packages(wanted)):
        result.nodes.append(neutral.package_node(f"p:{'/'.join(package)}", package, package_dims))
        result.count("packages_created")

    # The findings, their edges, and one authority claim each so a changed carrier leaves exactly one edge. A run
    # that skipped an entry, or met a host twice, cannot say it saw every detection behind a finding, so its claims
    # say partial and propose no removal (req-grid-reconcile-edge-authority: only complete licenses one).
    finding_dims = grid.default_dimensions(neutral.FINDING_TYPE)
    whole = not result.partly_read_pages and not result.counters.get("hosts_repeated") and not result.counters.get("detections_unkeyable")
    for grp in groups:
        ref = f"n:{grp.host_id}:{grp.cve}"
        first = min((t for d in grp.detections if (t := parse_time(d.first_found_datetime))), default=None)
        result.nodes.append(neutral.finding_node(ref, key, host_names.get(grp.host_id, f"host {grp.host_id}"), grp, finding_dims, first))
        for d in grp.detections:
            if d.ref is not None:
                result.edges.append(edge(f"e-det-{d.ref}-{grp.cve}", neutral.DETAILS, d.ref, ref))
        carrier = grp.carrier()
        if carrier is None:
            carries = edge(f"e-car-{ref}", neutral.CARRIES, f"h{grp.host_id}", ref)
        else:
            carries = {"entity": {"ref": f"e-car-{ref}", "entity_type": "edge", "name": neutral.CARRIES, "dimensions": {}},
                       "edge": {"from_key": neutral.package_ref(carrier), "to_ref": ref, "edge_type": neutral.CARRIES, "properties": {}}}
        result.edges.append(carries)
        concerns = edge_to_key(f"e-con-{ref}", neutral.CONCERNS, ref, neutral.VULNERABILITY_TYPE, {"vuln_id": grp.cve})
        required = grp.packages().get(carrier) if carrier is not None else None
        if required:
            concerns["edge"]["properties"] = {"fixed_versions": [required]}
        result.edges.append(concerns)
        result.authority.append(neutral.authority_claim(key, grp.host_id, grp.cve, complete=whole and grp.host_id not in hosts_unsure))
        result.count("neutral_findings")
        result.count("neutral_findings_open" if grp.open else "neutral_findings_resolved")
def _want_ec2(host_ref: str, host: dict[str, Any], wanted: dict[str, str], result: Result) -> None:
    """Note a host's EC2 instance id when Qualys says it is one (req-qualys-ec2-link-1, -5).

    Only ``CLOUD_RESOURCE_ID`` with provider AWS and service EC2 links. ``EC2_INSTANCE_ID`` is deprecated and
    also carries Azure ids, so a host that has only it is counted unresolved and never linked.
    """
    resource = host.get("cloud_resource_id")
    if host.get("cloud_provider") == "AWS" and host.get("cloud_service") == "EC2" and resource:
        wanted[host_ref] = resource
    elif host.get("ec2_instance_id") and not (host.get("cloud_provider") or host.get("cloud_service") or resource):
        # Only the deprecated field, with no cloud fields to say what the host is: counted, never linked. A host
        # whose cloud fields name another provider or service is not an EC2 host and is not counted at all.
        result.count("ec2_unresolved")
        result.count("ec2_unresolved_deprecated_field")


def _link_ec2(wanted: dict[str, str], grid: GridView, result: Result, minted: set[str] | None = None) -> list[dict[str, str]]:
    """``TRACKS_EC2_INSTANCE__qualys`` to each instance ``aws_core`` holds or this run mints (-2, -3, -4; req-qualys-aws)."""
    if not wanted:
        return []
    held = grid.ec2_instances(set(wanted.values()))
    if held is not None and minted:
        held = held | minted
    if held is None:
        return [{"code": "AWS_CORE_ABSENT", "detail": f"aws_core is not installed; {len(wanted)} EC2 host(s) not looked up"}]
    for host_ref, instance_id in sorted(wanted.items()):
        if instance_id in held:
            link = edge_to_key(f"e-ec2-{host_ref}", "TRACKS_EC2_INSTANCE__qualys", host_ref, EC2_INSTANCE_TYPE, {"instance_id": instance_id})
            link["edge"]["properties"] = {"source_field": "CLOUD_RESOURCE_ID"}
            result.edges.append(link)
            result.count("ec2_linked")
        else:
            result.count("ec2_unresolved")
    missing = sum(1 for instance_id in wanted.values() if instance_id not in held)
    return [{"code": "EC2_UNRESOLVED", "detail": f"{missing} EC2 host(s) name an instance aws_core does not hold"}] if missing else []


def decompose(run: Run, pages: list[DetectionPage], kb_pages: list[KnowledgeBasePage], grid: GridView) -> Result:
    """Every node and edge one run writes, from its pages and what the grid already holds."""
    result = Result()
    key = derive_subscription_key(run.api_host, run.label)
    warnings: list[dict[str, str]] = []

    # The subscription and the run.
    stored = grid.subscription(key)
    held = stored or {}
    # The scope a complete read is judged against is the one the grid already holds. A run that brings a
    # new standing scope records it, but the first read under a changed scope withdraws nothing
    # (req-qualys-states), so a run can never authorise its own withdrawals by changing the scope.
    held_scope = held.get("standing_scope") or {}
    scope_changed = stored is not None and run.standing_scope is not None and (run.standing_scope or {}) != held_scope
    standing = held_scope if stored is not None else (run.standing_scope or {})
    read_kind = run.read_kind
    if read_kind == COMPLETE:
        reason = None
        if scope_changed:
            reason = "the standing scope changed in this run"
        elif (run.applied_filter or {}) != standing:
            reason = "labelled complete, but its filter is not the standing scope"
        elif not pages:
            reason = "labelled complete, but it read no detection page"
        elif pages[-1].next_url:
            reason = "labelled complete, but its last page links to a next page that was not read"
            warnings.append({"code": "TRUNCATED", "detail": "the last detection page carries a next-page link"})
        elif (gap := chain_break(pages)) is not None:
            reason = "labelled complete, but its pages do not form one unbroken chain"
            warnings.append({"code": "TRUNCATED", "detail": gap})
        if reason:
            read_kind = NARROWER
            warnings.append({"code": "READ_KIND_DOWNGRADED", "detail": reason})
    sub_fields = {
        **{k: v for k, v in held.items() if k in QualysSubscription.FIELD_CRUD_SCHEMA},
        "api_host": run.api_host,
        "subscription_label": run.label,
        "subscription_key": key,
        "standing_scope": run.standing_scope if run.standing_scope is not None else held.get("standing_scope"),
        "watermark": held.get("watermark"),
        "last_complete_read_at": held.get("last_complete_read_at"),  # set below, once the read proves complete
        "detection_api_version": "6.0",
        "knowledgebase_api_version": "4.0",
    }
    result.read_kind = read_kind
    # What the opening batch writes: the subscription as it was, so a run whose seal never lands moves nothing
    # a later plan reads (the watermark, the last complete read, the standing scope).
    result.subscription_existed = stored is not None
    result.subscription_held = {
        **sub_fields,
        "standing_scope": held.get("standing_scope") if stored is not None else None,
    }
    sub_node = envelope("sub", QualysSubscription, run.label, sub_fields)
    result.nodes.append(sub_node)

    # Hosts and detections.
    seen_hosts: set[str] = set()
    ec2_wanted: dict[str, str] = {}
    seen_detections: set[tuple[str, str, str]] = set()
    run_detections: dict[str, list[neutral.Detection]] = {}
    host_names: dict[str, str] = {}
    qids_named: set[str] = set()
    for number, page in enumerate(pages):
        partly = False
        for host in page.hosts:
            host_id = host.get("host_id")
            if not _keyable(host_id, QualysHost, "host_id") or not host_id.isdigit():
                result.count("hosts_unkeyable")
                partly = True
                continue
            host_ref = f"h{host_id}"
            if host_id in seen_hosts:
                result.count("hosts_repeated")
            else:
                seen_hosts.add(host_id)
                result.nodes.append(_host_node(host_ref, key, host, result))
                host_names[host_id] = result.nodes[-1]["entity"]["name"]
                _want_ec2(host_ref, host, ec2_wanted, result)
            for detection in host["detections"]:
                parts = (host_id, detection.get("qid"), detection.get("unique_vuln_id"))
                if not (_keyable(parts[1], QualysDetection, "qid") and parts[1].isdigit() and _keyable(parts[2], QualysDetection, "unique_vuln_id")):
                    result.count("detections_unkeyable")
                    partly = True
                    continue
                if parts in seen_detections:
                    result.count("detections_repeated")
                    continue
                seen_detections.add(parts)
                ref = "d" + "-".join(parts)
                result.nodes.append(_detection_node(ref, key, host_id, host.get("os"), detection, result))
                written = result.nodes[-1]["node"]
                run_detections.setdefault(host_id, []).append(neutral.Detection(
                    parts[1], parts[2], written["state"], written.get("severity"), written.get("first_found_datetime"), written["package_observations"], ref))
                result.edges.append(edge(f"e-on-{ref}", "DETECTED_ON_HOST__qualys", ref, host_ref))
                result.edges.append(edge_to_key(f"e-qid-{ref}", "ABOUT_QID__qualys", ref, QualysQid.ENTITY_TYPE, {"subscription_key": key, "qid": parts[1]}))
                qids_named.add(parts[1])
                result.count("detections_resolved" if detection.get("status") == "Fixed" else "detections_open")
        if partly:
            result.partly_read_pages += 1
            result.scopes_not_read.append({"scope": f"detection page {number + 1}", "reason": "partly read: an entry had no usable key"})
    result.count("hosts", len(seen_hosts))
    result.count("detections", len(seen_detections))
    _inventory(key, run, grid, result, seen_hosts)
    if run.host_assets:
        host_nodes, host_edges, host_claims, host_counts = shared_host.build((h for page in pages for h in page.hosts), run.host_assets, grid, run.networks)
        result.nodes.extend(host_nodes)
        result.edges.extend(host_edges)
        result.authority.extend(host_claims)
        for name, n in host_counts.items():
            result.count(name, n)
    minted: set[str] | None = None
    if run.aws:
        aws = aws_mint.mint((h for page in pages for h in page.hosts), grid, run.host_assets or {})
        if not aws.absent:
            # Shared records: written before the hosts whose EC2 link names an instance by key.
            result.nodes.extend(aws.nodes)
            result.edges.extend(aws.edges)
            for name, n in aws.counters.items():
                result.count(name, n)
            minted = aws.instances
    warnings.extend(_link_ec2(ec2_wanted, grid, result, minted))

    # Knowledge-base records. A QID not returned is written as a stub only where the grid holds none, so a
    # record an earlier read filled is never wiped by a read that did not return it.
    returned: set[str] = set()
    for page in kb_pages:
        for vuln in page.vulns:
            qid = vuln.get("qid")
            if not (_keyable(qid, QualysQid, "qid") and qid.isdigit()) or qid in returned:
                continue
            returned.add(qid)
            result.nodes.append(_qid_node(f"q{qid}", key, vuln, result))
    missing = qids_named - returned
    held_qids = grid.held_qids(key, missing)
    for qid in sorted(missing - held_qids):
        asked = run.knowledgebase_asked is None or qid in run.knowledgebase_asked
        kb_returned = False if (asked and run.knowledgebase_complete) else None
        result.nodes.append(envelope(f"q{qid}", QualysQid, f"QID {qid}", {"subscription_key": key, "qid": qid, "kb_returned": kb_returned}))
    if missing:
        result.scopes_not_read.extend({"scope": f"qid {q}", "reason": "not returned by the knowledge base"} for q in sorted(missing))
    result.count("qids", len(returned))
    result.count("qids_not_returned", len(missing))

    _neutral(key, grid, result, run_detections, host_names, {v["qid"]: v for page in kb_pages for v in page.vulns if v.get("qid") in returned})

    if run.tags is not None:
        _tags(key, run, grid, result)

    # Withdrawal, and the record of a complete read: only a complete read with nothing partly read counts.
    # A complete read with no read time cannot say when the data was read, so it records no complete read and
    # withdraws nothing; a live run sets read_at to its own start, a file run to Qualys's response time.
    fully_complete = read_kind == COMPLETE and not result.partly_read_pages and run.read_at is not None and run.walk_complete is not False
    if fully_complete:
        sub_node["node"]["last_complete_read_at"] = run.read_at.isoformat()
        for host_id, stored in sorted(grid.current_hosts(key).items()):
            if host_id in seen_hosts:
                continue
            rewritten = {**stored, "state": "withdrawn", "withdrawn_in_run": run.run_id}
            result.nodes.append(envelope(f"w{host_id}", QualysHost, stored.get("dns") or stored.get("ip") or f"host {host_id}", rewritten))
            result.count("hosts_withdrawn")

    # The watermark: a live run's start, only after a run whose every detection page was read and validated
    # (req-qualys-detection-read-3). A failed, truncated, ceiling-stopped or partly read run leaves it as it was.
    clean = (
        run.walk_complete is True
        and read_kind in (COMPLETE, WINDOW)
        and not result.partly_read_pages
        and not run.detection_pages_not_read
        and not (pages and pages[-1].next_url)
        and chain_break(pages) is None
    )
    if clean:
        sub_node["node"]["watermark"] = run.started_at.isoformat()
        result.watermark_advanced = True

    # The run itself, last, so its counters are complete.
    run_fields = {
        "subscription_key": key,
        "run_id": run.run_id,
        "source": run.source,
        "started_at": run.started_at.isoformat(),
        "finished_at": None,
        "read_at": run.read_at.isoformat() if run.read_at else None,
        "read_kind": read_kind,
        "applied_filter": run.applied_filter,
        "window_start": run.window_start.isoformat() if run.window_start else None,
        "window_end": run.window_end.isoformat() if run.window_end else None,
        "page_count": len(pages),
        "probe": run.probe,
        "counters": dict(result.counters),
        "warnings": warnings + run.extra_warnings + _dropped_warnings(result.dropped),
        "scopes_not_read": (
            [{"scope": name, "reason": "switched off"} for name in run.switched_off]
            + run.detection_pages_not_read
            + result.scopes_not_read
            + run.tags_not_read
            + run.host_assets_not_read
        ),
        "archive_sha256": run.archive_sha256,
        "export_created_at": parse_time(run.export_created_at),
    }
    result.nodes.append(envelope("run", QualysScanRun, f"run {run.run_id}", run_fields))
    result.edges.append(edge("e-run", "RUN_OF_SUBSCRIPTION__qualys", "run", "sub"))
    return result


def document(result: Result, run: Run) -> dict[str, Any]:
    """The GRIFT document for one run: a single batch holding every node and edge it writes.

    A big run cannot be written this way: core locks every natural key of a batch until it commits
    (unified-systems-com/tap#1348). The collector and the file load write :func:`documents` instead.
    """
    return _document(run, f"Qualys {run.source} read", f"One {result.read_kind or run.read_kind} read of Qualys subscription {run.label}, from {run.source}.",
                     {"run_id": run.run_id, "counters": result.counters}, result.nodes, result.edges, result.authority)


def _document(run: Run, name: str, description: str, data: dict[str, Any], nodes: list[dict[str, Any]], edges: list[dict[str, Any]],
              authority: list[dict[str, Any]]) -> dict[str, Any]:
    from tap_grid.grift.upgrade import build_header

    doc: dict[str, Any] = {
        "_reserved": {},
        "batches": [{
            "batch_entity": {"entity_id": str(uuid.uuid4()), "entity_type": "batch", "name": name, "dimensions": {}},
            "batch_node": {
                "source": "tap_plugin.qualys",
                "name": name,
                "description": description,
                "description_json": {"format": "tap.qualys.run-v0", "data": data},
            },
            "nodes": nodes,
            "edges": edges,
            **({"edge_cases": {"authority": authority}} if authority else {}),
        }],
    }
    # GRIFT format "1": core states the spine and every type the batch carries at the versions this grid records,
    # read once the batch is complete (tap 0.5.0 refuses a format "0" document by default).
    return {"metadata": build_header(doc), **doc}


#: Identity keys per batch of a chunked write: each node and each edge is about one advisory lock, held until
#: the batch commits, and Postgres's default lock table is about 6,400 slots for every connection together.
#: A single host whose own records exceed it is written alone, over the bound (req-qualys-chunked-write-2).
CHUNK_KEYS = 2000
_HUBS = ("sub", "run")
_SHARED_TYPES = frozenset({QualysQid.ENTITY_TYPE, neutral.VULNERABILITY_TYPE, neutral.PACKAGE_TYPE}) | aws_mint.TYPES


def documents(result: Result, run: Run, *, max_keys: int | None = None) -> list[dict[str, Any]]:
    """The run as a sequence of GRIFT documents, one batch each, each its own transaction (req-qualys-chunked-write).

    WORKAROUND(unified-systems-com/tap#1348): core locks every natural key of a batch until it commits, so a
    big run written as one batch exhausts Postgres's lock table. In order:

    1. the opening: the run, not yet finished, and the subscription only when the grid does not hold it yet, so an
       opening never rewrites a subscription's watermark, last complete read or standing scope;
    2. the shared records later batches point at by key (QIDs, vulnerability records, packages);
    3. everything else in bounded chunks, each a whole group of nodes joined by batch-local refs, so a host,
       its detections, its findings and their authority claims land together, and so do a tag and its children;
    4. the seal: the subscription with its new watermark and last complete read, the withdrawals, and the run.

    The edges that name the subscription by ref outside the opening and the seal name it by key instead. A batch
    that fails stops the write: what committed stays, and the seal, the one batch that moves the watermark or
    withdraws anything, is never written.
    """
    max_keys = CHUNK_KEYS if max_keys is None else max_keys
    hub_nodes = {n["entity"]["ref"]: n for n in result.nodes if n["entity"]["ref"] in _HUBS}
    sub, the_run = hub_nodes["sub"], hub_nodes["run"]
    sub_key = {"api_host": sub["node"]["api_host"], "subscription_label": sub["node"]["subscription_label"]}
    withdrawn = [n for n in result.nodes if n["entity"]["ref"] not in _HUBS and n["node"].get("withdrawn_in_run") == run.run_id]
    withdrawn_refs = {n["entity"]["ref"] for n in withdrawn}
    seal_refs = set(_HUBS) | withdrawn_refs
    body = [n for n in result.nodes if n["entity"]["ref"] not in _HUBS and n["entity"]["ref"] not in withdrawn_refs]

    # Group nodes joined by batch-local refs; a ref is meaningful only inside the batch that holds it.
    parent = {n["entity"]["ref"]: n["entity"]["ref"] for n in body}

    def find(ref: str) -> str:
        while parent[ref] != ref:
            parent[ref] = parent[parent[ref]]
            ref = parent[ref]
        return ref

    hub_edges: list[dict[str, Any]] = []
    seal_edges: list[dict[str, Any]] = []
    keyed_only: list[dict[str, Any]] = []
    grouped_edges: list[tuple[str, dict[str, Any]]] = []
    for e in result.edges:
        ends = [r for r in (e["edge"].get("from_ref"), e["edge"].get("to_ref")) if r is not None]
        if any(r in withdrawn_refs for r in ends):
            # A withdrawn node is written by the seal alone, so an edge naming it by ref rides there too.
            if any(r not in seal_refs for r in ends):
                raise ValueError(f"edge {e['entity']['ref']} joins a withdrawn node to a body node by ref")
            seal_edges.append(e)
            continue
        inner = [r for r in ends if r not in _HUBS]
        if not ends:
            # Both ends named by key: nothing batch-local joins it, so it rides with the body batches, after the
            # shared records it may name (never in the opening, before they exist).
            keyed_only.append(e)
            continue
        if not inner:
            hub_edges.append(e)
            continue
        if any(r in _HUBS for r in ends):
            if e["edge"].get("to_ref") != "sub":
                raise ValueError(f"edge {e['entity']['ref']} names a hub other than the subscription by ref")
            e = {**e, "edge": {k: v for k, v in e["edge"].items() if k != "to_ref"} | {"to_key": {"entity_type": QualysSubscription.ENTITY_TYPE, "key": sub_key}}}
        for other in inner[1:]:
            a, b = find(inner[0]), find(other)
            if a != b:
                parent[b] = a
        grouped_edges.append((inner[0], e))

    groups: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for n in body:
        groups.setdefault(find(n["entity"]["ref"]), {"nodes": [], "edges": []})["nodes"].append(n)
    for ref, e in grouped_edges:
        groups[find(ref)]["edges"].append(e)
    # Vulnerability records and packages before the QIDs, whose CVE edges name them by key.
    rest_extra = [{"nodes": [], "edges": [e]} for e in keyed_only]
    shared = sorted((g for g in groups.values() if all(n["entity"]["entity_type"] in _SHARED_TYPES for n in g["nodes"])),
                    key=lambda g: any(n["entity"]["entity_type"] == QualysQid.ENTITY_TYPE for n in g["nodes"]))
    rest = [g for g in groups.values() if not all(n["entity"]["entity_type"] in _SHARED_TYPES for n in g["nodes"])]

    chunks: list[dict[str, list[dict[str, Any]]]] = []
    for kind in (shared, rest + rest_extra):
        current: dict[str, list[dict[str, Any]]] = {"nodes": [], "edges": []}
        for g in kind:
            size = len(g["nodes"]) + len(g["edges"])
            if (current["nodes"] or current["edges"]) and len(current["nodes"]) + len(current["edges"]) + size > max_keys:
                chunks.append(current)
                current = {"nodes": [], "edges": []}
            current["nodes"].extend(g["nodes"])
            current["edges"].extend(g["edges"])
        if current["nodes"] or current["edges"]:
            chunks.append(current)

    # Each authority claim rides with the batch holding its anchor, whose edges are the claim's asserted set. A
    # claim whose anchor no batch holds would assert nothing, so it is sent partial, which proposes nothing.
    claims: list[list[dict[str, Any]]] = [[] for _ in chunks]
    seal_claims: list[dict[str, Any]] = []
    index: dict[tuple[str, tuple[Any, ...]], int] = {}
    names_by_type: dict[str, tuple[str, ...]] = {}
    for claim in result.authority:
        names_by_type.setdefault(claim["anchor"]["entity_type"], tuple(sorted(claim["anchor"]["key"])))
    for number, chunk in enumerate(chunks):
        for n in chunk["nodes"]:
            names = names_by_type.get(n["entity"]["entity_type"])
            if names is not None:
                index[(n["entity"]["entity_type"], tuple(n["node"].get(k) for k in names))] = number
    for claim in result.authority:
        anchor = claim["anchor"]
        at = index.get((anchor["entity_type"], tuple(anchor["key"].get(k) for k in names_by_type[anchor["entity_type"]])))
        if at is None:
            seal_claims.append({**claim, "read": "partial"})
        else:
            claims[at].append(claim)

    opening_run = {**the_run, "node": {**the_run["node"], "finished_at": None}}
    if result.subscription_existed:
        # The subscription is not rewritten by the opening: a held value written back here could undo a newer
        # seal if two writers ever overlapped. The run names it by key instead.
        opening_nodes = [opening_run]
        opening_edges = [
            {**e, "edge": {k: v for k, v in e["edge"].items() if k != "to_ref"} | {"to_key": {"entity_type": QualysSubscription.ENTITY_TYPE, "key": sub_key}}}
            for e in hub_edges
        ]
    else:
        opening_nodes = [{**sub, "node": result.subscription_held}, opening_run]
        opening_edges = hub_edges
    total = len(chunks) + 2
    data = {"run_id": run.run_id, "counters": result.counters}
    out = [_document(run, f"Qualys {run.source} read, part 1 of {total} (opening)", f"The opening of a {result.read_kind or run.read_kind} read of Qualys subscription {run.label}: the subscription as held, and the run, not yet finished.",
                     {**data, "part": 1, "parts": total}, opening_nodes, opening_edges, [])]
    for number, chunk in enumerate(chunks):
        out.append(_document(run, f"Qualys {run.source} read, part {number + 2} of {total}", f"Part {number + 2} of a read of Qualys subscription {run.label}.",
                             {**data, "part": number + 2, "parts": total}, chunk["nodes"], chunk["edges"], claims[number]))
    out.append(_document(run, f"Qualys {run.source} read, part {total} of {total} (seal)", f"The seal of a {result.read_kind or run.read_kind} read of Qualys subscription {run.label}: the watermark, the withdrawals and the finished run.",
                         {**data, "part": total, "parts": total}, [sub, *withdrawn, the_run], hub_edges + seal_edges, seal_claims))
    return out
