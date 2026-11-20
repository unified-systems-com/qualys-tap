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
EC2_INSTANCE_TYPE = "aws_core__aws_ec2_instance"


class GridView(Protocol):
    """What the run needs to know about what the grid already holds for one subscription."""

    def subscription(self, key: str) -> dict[str, Any] | None: ...

    def current_hosts(self, key: str) -> dict[str, dict[str, Any]]:
        """Every host of the subscription not withdrawn, by host id, with its stored fields."""
        ...

    def held_qids(self, key: str, qids: Iterable[str]) -> set[str]: ...

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


@dataclass
class Result:
    """The batch's nodes and edges, and what the run counted and could not carry."""

    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=dict)
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


def _detection_node(ref: str, key: str, host_id: str, record: dict[str, Any], result: Result) -> dict[str, Any]:
    where = f"detection {host_id}/{record['qid']}/{record['unique_vuln_id']}"
    fields = {"subscription_key": key, "host_id": host_id, "qid": record["qid"], "unique_vuln_id": record["unique_vuln_id"]}
    fields.update(_carry(QualysDetection, record, _DETECTION_FIELDS, result, where))
    fields["qds_factors"] = record.get("qds_factors")
    fixed = record.get("status") == "Fixed"
    fields["state"] = "resolved" if fixed else "open"
    fields["resolution_source"] = "qualys_fixed" if fixed else None
    # Packages come with the parsers (the next target); until then the parse state is unobserved, never "no package".
    fields["parse_state"] = None
    fields["parser_version"] = None
    fields["package_observations"] = None
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


def _link_ec2(wanted: dict[str, str], grid: GridView, result: Result) -> list[dict[str, str]]:
    """``TRACKS_EC2_INSTANCE__qualys`` to each instance ``aws_core`` holds; the instance is never written (-2, -3, -4)."""
    if not wanted:
        return []
    held = grid.ec2_instances(set(wanted.values()))
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
    ec2_wanted: dict[str, str] = {}
    seen_detections: set[tuple[str, str, str]] = set()
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
                result.nodes.append(_detection_node(ref, key, host_id, detection, result))
                result.edges.append(edge(f"e-on-{ref}", "DETECTED_ON_HOST__qualys", ref, host_ref))
                result.edges.append(edge_to_key(f"e-qid-{ref}", "ABOUT_QID__qualys", ref, QualysQid.ENTITY_TYPE, {"subscription_key": key, "qid": parts[1]}))
                qids_named.add(parts[1])
                result.count("detections_resolved" if detection.get("status") == "Fixed" else "detections_open")
        if partly:
            result.partly_read_pages += 1
            result.scopes_not_read.append({"scope": f"detection page {number + 1}", "reason": "partly read: an entry had no usable key"})
    result.count("hosts", len(seen_hosts))
    result.count("detections", len(seen_detections))
    warnings.extend(_link_ec2(ec2_wanted, grid, result))

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
        }],
    }
