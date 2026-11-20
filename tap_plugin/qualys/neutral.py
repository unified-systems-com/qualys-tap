"""The neutral finding beside Qualys's own records (req-qualys-neutral, req-qualys-package-link).

A page that shows vulnerabilities from every scanner reads compliance_core's types, not each scanner's: a
component carries a finding, and the finding concerns a shared vulnerability record. Qualys's QID fans out to
CVEs, so the unit is the host and the CVE, as for Tenable: two QIDs naming one CVE on one host make one
neutral finding, detailed by both detections.

Pure: the detections, the CVE lists and what the grid holds come in; GRIFT fragments go out. No grid is read
here, so the rules can be tested without a database.
"""

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

SOURCE = "qualys"
FINDING_TYPE = "compliance_core__compliance_finding"
VULNERABILITY_TYPE = "compliance_core__compliance_vulnerability"
PACKAGE_TYPE = "computing_core__package"
CARRIES = "CARRIES_COMPLIANCE_FINDING__compliance_core"
CONCERNS = "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core"
DETAILS = "DETAILS_COMPLIANCE_FINDING__qualys"
ABOUT_VULNERABILITY = "ABOUT_VULNERABILITY__qualys"
FOUND_IN_PACKAGE = "FOUND_IN_PACKAGE__qualys"
CVSS_SOURCE = "Qualys knowledge base"

MAX_VULN_ID = 128
_MAX_NAME = 255
_MAX_SUMMARY = 500


def source_key(subscription_key: str, host_id: str, cve_id: str) -> str:
    """The SHA-256 of the compact JSON array ``[subscription_key, host_id, cve_id]``, never of a concatenation."""
    return hashlib.sha256(json.dumps([subscription_key, host_id, cve_id], separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def finding_key(subscription_key: str, host_id: str, cve_id: str) -> dict[str, str]:
    return {"source": SOURCE, "source_key": source_key(subscription_key, host_id, cve_id)}


def usable_vuln_id(vuln_id: Any) -> bool:
    return isinstance(vuln_id, str) and 0 < len(vuln_id) <= MAX_VULN_ID


def cve_ids(cve_list: Any) -> list[str]:
    """The CVE ids a QID's CVE list names, in order, once each; an entry with no id is skipped."""
    out: list[str] = []
    for entry in cve_list or []:
        cve = entry.get("id") if isinstance(entry, dict) else None
        if isinstance(cve, str) and cve and cve not in out:
            out.append(cve)
    return out


def cvss_of(vuln: dict[str, Any]) -> dict[str, Any]:
    """The QID's CVSS base score, v3 before v2, with its vector and version; nothing when it has none.

    A score that is not a number from 0 to 10 is no score.
    """
    for version, label in (("cvss_v3", "3"), ("cvss_v2", "2")):
        block = vuln.get(version)
        if not isinstance(block, dict):
            continue
        base = block.get("base")
        try:
            score = float(base) if isinstance(base, (str, int, float)) and not isinstance(base, bool) else -1.0
        except ValueError:
            continue
        if 0 <= score <= 10:
            out: dict[str, Any] = {"cvss_score": score, "cvss_version": label, "cvss_source": CVSS_SOURCE}
            vector = block.get("vector_string")
            if isinstance(vector, str) and vector:
                out["cvss_vector"] = vector
            return out
    return {}


def package_key(observation: dict[str, Any]) -> tuple[str, str, str] | None:
    """The computing_core package an observation names, only where the parser was sure (req-qualys-package-link-1)."""
    if observation.get("mapping_unambiguous") is not True:
        return None
    parts = (observation.get("ecosystem"), observation.get("name"), observation.get("installed_version"))
    if not all(isinstance(p, str) and p for p in parts):
        return None
    return parts  # type: ignore[return-value]


def package_ref(key: tuple[str, str, str]) -> dict[str, Any]:
    return {"entity_type": PACKAGE_TYPE, "key": {"ecosystem": key[0], "name": key[1], "version": key[2]}}


@dataclass
class Detection:
    """What the neutral rules need of one detection, from this run or as the grid holds it."""

    qid: str
    unique_vuln_id: str
    state: str
    severity: str | None
    first_found_datetime: str | None
    package_observations: list[dict[str, Any]] | None
    ref: str | None = None  # the batch ref when this run wrote it; None for a held detection not read this run


@dataclass
class Group:
    """Every detection on one host whose QID names one CVE."""

    host_id: str
    cve: str
    detections: list[Detection] = field(default_factory=list)

    @property
    def open(self) -> bool:
        return any(d.state == "open" for d in self.detections)

    @property
    def read_this_run(self) -> bool:
        return any(d.ref is not None for d in self.detections)

    def packages(self) -> dict[tuple[str, str, str], str | None]:
        """The packages parsers were sure of across the group, each with the required version a row gave."""
        out: dict[tuple[str, str, str], str | None] = {}
        for detection in self.detections:
            for observation in detection.package_observations or []:
                key = package_key(observation)
                if key is not None:
                    required = observation.get("required_version")
                    out.setdefault(key, required if isinstance(required, str) and required else None)
        return out

    def carrier(self) -> tuple[str, str, str] | None:
        """The one package carrying the finding; None means the host carries it (ruled Q7b, req-qualys-neutral-3).

        Several packages carry no single answer, so none is chosen.
        """
        packages = self.packages()
        return next(iter(packages)) if len(packages) == 1 else None


def group(detections_by_host: dict[str, list[Detection]], cves_by_qid: dict[str, list[str]]) -> list[Group]:
    """The (host, CVE) groups, in a stable order; a CVE id the record cannot hold makes none (-4)."""
    groups: dict[tuple[str, str], Group] = {}
    for host_id in sorted(detections_by_host):
        for detection in detections_by_host[host_id]:
            for cve in cves_by_qid.get(detection.qid, []):
                if usable_vuln_id(cve):
                    groups.setdefault((host_id, cve), Group(host_id, cve)).detections.append(detection)
    return [groups[k] for k in sorted(groups)]


def _severity(detections: Iterable[Detection]) -> int | None:
    levels = [int(d.severity) for d in detections if isinstance(d.severity, str) and d.severity.isdigit()]
    return max(levels) if levels else None


def finding_node(ref: str, subscription_key: str, host_name: str, grp: Group, dimensions: dict[str, str], first_detected_at: str | None) -> dict[str, Any]:
    """The neutral finding for one host and CVE. ``dimensions`` are compliance_core's defaults: no ``qualys.*`` (-6)."""
    name = f"{grp.cve} on {host_name}"[:_MAX_NAME]
    severity = _severity(grp.detections)
    node: dict[str, Any] = {
        **finding_key(subscription_key, grp.host_id, grp.cve),
        "name": name,
        "summary": (f"Qualys severity {severity}" if severity is not None else "")[:_MAX_SUMMARY],
        "status": "open" if grp.open else "resolved",
        # Left out where Qualys gave no first-found time, so a stored value is kept.
        **({"first_detected_at": first_detected_at} if first_detected_at else {}),
    }
    return {"entity": {"ref": ref, "entity_type": FINDING_TYPE, "name": name, "dimensions": dict(dimensions)}, "node": node}


def vulnerability_node(ref: str, vuln_id: str, dimensions: dict[str, Any], scores: dict[str, Any]) -> dict[str, Any]:
    """The shared record: its id, and Qualys's score where it has none (-4, -5).

    ``dimensions`` are the type's defaults for a record being created and the record's own, as the grid holds
    them, for a record being given a score: a fill sends the held ones back unchanged.
    """
    return {"entity": {"ref": ref, "entity_type": VULNERABILITY_TYPE, "name": vuln_id, "dimensions": dict(dimensions)}, "node": {"vuln_id": vuln_id, **scores}}


def package_node(ref: str, key: tuple[str, str, str], dimensions: dict[str, str]) -> dict[str, Any]:
    """An absent package, created with its key fields and no others (ruled Q8b, req-qualys-package-link-2)."""
    return {
        # The envelope name is the package's own name field: the importer refuses one that differs from the payload.
        "entity": {"ref": ref, "entity_type": PACKAGE_TYPE, "name": key[1], "dimensions": dict(dimensions)},
        "node": {"ecosystem": key[0], "name": key[1], "version": key[2]},
    }


def authority_claim(subscription_key: str, host_id: str, cve_id: str, *, complete: bool = True) -> dict[str, Any]:
    """This run's statement that the carrier it sends is the finding's whole set of carriers (req-qualys-neutral-3).

    ``complete`` false (a run that skipped an entry) makes the claim ``partial``, which proposes no removal.
    """
    return {
        "edge_type": CARRIES,
        "anchor": {"entity_type": FINDING_TYPE, "key": finding_key(subscription_key, host_id, cve_id)},
        "direction": "inbound",
        "read": "complete" if complete else "partial",
    }
