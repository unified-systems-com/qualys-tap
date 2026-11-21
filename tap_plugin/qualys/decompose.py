"""Turn parsed Qualys pages into GRIFT node and edge envelopes (req-qualys-host, -detection, -qid, -states).

Nodes are named by batch-local ``ref`` and found again by the grid through each model's declared natural key,
so nothing here derives an id. Values are carried as returned; a value a column cannot hold is stored as null
and listed on the run, never cut or altered. A detection key part that cannot be held makes the detection
unkeyable: it is not stored, counted, and its page counts as partly read.

The grid applies a written node as a full replacement, so a node rewritten to change one fact re-sends every
other fact as the grid holds it (a withdrawn host), and a node the run did not read is not written at all when
the grid already holds it (a QID the knowledge base did not return this time). Grid reads come in through a
``GridView`` so this module stays testable without a database.

Resolution follows Qualys alone: a detection is ``resolved`` exactly when Qualys reports ``Fixed`` and ``open``
otherwise; a detection absent from a read is not written, so it keeps what it had (req-qualys-states-3, -4).
A host absent from a complete read of the standing scope is rewritten ``withdrawn``; its detections are not
touched (req-qualys-states-5).
"""

import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from django.db import models as dj_models

from tap_plugin.qualys.identity import subscription_key as derive_subscription_key
from tap_plugin.qualys.models.detection import QualysDetection
from tap_plugin.qualys.models.host import QualysHost
from tap_plugin.qualys.models.qid import QualysQid
from tap_plugin.qualys.models.scan_run import QualysScanRun
from tap_plugin.qualys.models.subscription import QualysSubscription
from tap_plugin.qualys import neutral, parsers
from tap_plugin.qualys.parse import DetectionPage, KnowledgeBasePage

COMPLETE = "complete"
WINDOW = "window"
NARROWER = "narrower"

#: Host fields parsed to UTC beside the string Qualys sent (req-qualys-host).
_PARSED_TIMES = {
    "last_scan_datetime": "last_scan_at",
    "last_vm_scanned_date": "last_vm_scanned_at",
    "last_vm_auth_scanned_date": "last_vm_auth_scanned_at",
}
_DETECTION_KEY = ("host_id", "qid", "unique_vuln_id")


class GridView(Protocol):
    """What the run needs to know about what the grid already holds for one subscription."""

    def subscription(self, key: str) -> dict[str, Any] | None: ...

    def current_hosts(self, key: str) -> dict[str, dict[str, Any]]:
        """Every host of the subscription not withdrawn, by host id, with its stored fields."""
        ...

    def held_qids(self, key: str, qids: Iterable[str]) -> set[str]: ...

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


@dataclass
class Result:
    """The batch's nodes and edges, and what the run counted and could not carry."""

    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=dict)
    authority: list[dict[str, Any]] = field(default_factory=list)
    dropped: list[dict[str, str]] = field(default_factory=list)
    scopes_not_read: list[dict[str, str]] = field(default_factory=list)
    partly_read_pages: int = 0
    read_kind: str = ""  # the kind the run was treated as, after any downgrade

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
    "last_update_datetime", "last_processed_datetime", "is_ignored", "is_disabled", "qds", "results",
)
_QID_FIELDS = (
    "vuln_type", "severity_level", "title", "category", "patchable", "published_datetime",
    "last_service_modification_datetime",
)


def _host_node(ref: str, key: str, record: dict[str, Any], result: Result) -> dict[str, Any]:
    where = f"host {record['host_id']}"
    fields = {"subscription_key": key, "host_id": record["host_id"], **_carry(QualysHost, record, _HOST_FIELDS, result, where)}
    for raw, parsed in _PARSED_TIMES.items():
        fields[parsed] = parse_time(fields[raw])
    fields["ec2_metadata"] = record.get("ec2_metadata")
    fields["cloud_tags"] = None  # CLOUD_PROVIDER_TAGS has no documented shape yet (ledger cloud-provider-tags-shape)
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
    sub_node = envelope("sub", QualysSubscription, run.label, sub_fields)
    result.nodes.append(sub_node)

    # Hosts and detections.
    seen_hosts: set[str] = set()
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

    # Withdrawal, and the record of a complete read: only a complete read with nothing partly read counts.
    # A complete read with no read time cannot say when the data was read, so it records no complete read and
    # withdraws nothing; a live run sets read_at to its own start, a file run to Qualys's response time.
    fully_complete = read_kind == COMPLETE and not result.partly_read_pages and run.read_at is not None
    if fully_complete:
        sub_node["node"]["last_complete_read_at"] = run.read_at.isoformat()
        for host_id, stored in sorted(grid.current_hosts(key).items()):
            if host_id in seen_hosts:
                continue
            rewritten = {**stored, "state": "withdrawn", "withdrawn_in_run": run.run_id}
            result.nodes.append(envelope(f"w{host_id}", QualysHost, stored.get("dns") or stored.get("ip") or f"host {host_id}", rewritten))
            result.count("hosts_withdrawn")

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
        "window_start": None,
        "window_end": None,
        "page_count": len(pages),
        "probe": None,
        "counters": dict(result.counters),
        "warnings": warnings + _dropped_warnings(result.dropped),
        "scopes_not_read": result.scopes_not_read,
        "archive_sha256": run.archive_sha256,
        "export_created_at": parse_time(run.export_created_at),
    }
    result.nodes.append(envelope("run", QualysScanRun, f"run {run.run_id}", run_fields))
    result.edges.append(edge("e-run", "RUN_OF_SUBSCRIPTION__qualys", "run", "sub"))
    return result


def document(result: Result, run: Run) -> dict[str, Any]:
    """The GRIFT document for one run: a single batch holding every node and edge it writes."""
    return {
        "metadata": {"grift_version": "0"},
        "_reserved": {},
        "batches": [{
            "batch_entity": {"entity_id": str(uuid.uuid4()), "entity_type": "batch", "name": f"Qualys {run.source} read", "dimensions": {}},
            "batch_node": {
                "source": "tap_plugin.qualys",
                "name": f"Qualys {run.source} read",
                "description": f"One {result.read_kind or run.read_kind} read of Qualys subscription {run.label}, from {run.source}.",
                "description_json": {"format": "tap.qualys.run-v0", "data": {"run_id": run.run_id, "counters": result.counters}},
            },
            "nodes": result.nodes,
            "edges": result.edges,
            **({"edge_cases": {"authority": result.authority}} if result.authority else {}),
        }],
    }
