"""Qualys detection — Qualys's assertion that a QID was found on a host."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

_STR_OR_NULL = {"type": ["string", "null"]}
#: The four parse states (req-qualys-parsers-1).
PARSE_STATES = ("parsed", "no_parser", "parser_failed", "not_applicable")


class QualysDetection(BaseModel):
    """One detection: a QID found on a host, with its history and result text as Qualys returns them.

    Keyed by subscription, host id, QID and unique vulnerability id: Qualys documents that one
    UNIQUE_VULN_ID can be shared by a vulnerability and an information-gathered finding, so the QID is
    part of the key, and the host id is there so the key rests only on facts this node carries
    (req-qualys-detection-1, -2). Port, protocol and SSL are properties. ``state`` follows Qualys's own
    STATUS: resolved exactly when Qualys reports Fixed, and absence never resolves (req-qualys-states-3).
    The CVE fan-out lives on the QID, never here (req-qualys-qid-2).

    Spec: specs/spec-qualys-v0.md (req-qualys-detection, req-qualys-states, req-qualys-parsers).
    """

    ENTITY_TYPE: ClassVar[str] = "qualys__qualys_detection"
    ENTITY_NAME: ClassVar[str] = "Qualys Detection"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "Qualys's assertion that a QID was found on a host: its status, history, severity, QDS and full "
        "result text as returned, with the packages a parser read from that text."
    )
    ENTITY_ICON: ClassVar[str] = "qualys-detection"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"qualys.area": "finding"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("subscription_key", "host_id", "qid", "unique_vuln_id")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "qualys__qualys_host"}], "edges": [{"type": "DETECTED_ON_HOST__qualys"}]},
        {"nodes": [{"type": "qualys__qualys_qid"}], "edges": [{"type": "ABOUT_QID__qualys"}]},
        {"nodes": [{"type": "qualys__qualys_scan_run"}], "edges": [{"type": "LAST_SEEN_IN_RUN__qualys"}]},
        {"nodes": [{"type": "computing_core__package"}], "edges": [{"type": "FOUND_IN_PACKAGE__qualys"}]},
        {
            "nodes": [{"type": "compliance_core__compliance_finding"}],
            "edges": [{"type": "DETAILS_COMPLIANCE_FINDING__qualys"}],
        },
    ]
    # Nothing points at a detection in v0.
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "subscription_key": {"type": "string", "minLength": 1},
        "host_id": {"type": "string", "minLength": 1, "pattern": "^[0-9]+$"},
        "qid": {"type": "string", "minLength": 1, "pattern": "^[0-9]+$"},
        "unique_vuln_id": {"type": "string", "minLength": 1},
        "detection_type": _STR_OR_NULL,
        "port": _STR_OR_NULL,
        "protocol": _STR_OR_NULL,
        "fqdn": _STR_OR_NULL,
        "ssl": _STR_OR_NULL,
        "status": _STR_OR_NULL,
        "severity": _STR_OR_NULL,
        "first_found_datetime": _STR_OR_NULL,
        "last_found_datetime": _STR_OR_NULL,
        "last_fixed_datetime": _STR_OR_NULL,
        "last_reopened_datetime": _STR_OR_NULL,
        "times_found": _STR_OR_NULL,
        "times_reopened": _STR_OR_NULL,
        "last_test_datetime": _STR_OR_NULL,
        "last_update_datetime": _STR_OR_NULL,
        "last_processed_datetime": _STR_OR_NULL,
        "is_ignored": _STR_OR_NULL,
        "is_disabled": _STR_OR_NULL,
        "qds": _STR_OR_NULL,
        "qds_severity": _STR_OR_NULL,
        "qds_factors": {"type": ["array", "null"], "items": {"type": "object"}},
        "results": _STR_OR_NULL,
        "state": {"type": ["string", "null"], "enum": ["open", "resolved", None]},
        "resolution_source": {"type": ["string", "null"], "enum": ["qualys_fixed", None]},
        "parse_state": {"type": ["string", "null"], "enum": [*PARSE_STATES, None]},
        "parser_version": _STR_OR_NULL,
        "package_observations": {"type": ["array", "null"], "items": {"type": "object"}},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema} for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["subscription_key", "host_id", "qid", "unique_vuln_id"]

    subscription_key = models.CharField(max_length=512, db_index=True, help_text="The subscription that reported this detection.")
    host_id = models.CharField(max_length=32, help_text="Qualys's host ID the detection is on, as returned.")
    qid = models.CharField(max_length=16, help_text="The QID detected, as returned.")
    unique_vuln_id = models.CharField(max_length=32, help_text="UNIQUE_VULN_ID as returned; unique only together with the QID.")
    detection_type = models.CharField(
        max_length=32, null=True, blank=True, default=None, help_text="TYPE as returned (Confirmed, Potential, Info)."
    )
    port = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="PORT as returned.")
    protocol = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="PROTOCOL as returned.")
    fqdn = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="FQDN as returned.")
    ssl = models.CharField(max_length=8, null=True, blank=True, default=None, help_text="SSL as returned.")
    status = models.CharField(
        max_length=16, null=True, blank=True, default=None, help_text="STATUS exactly as returned: New, Active, Re-Opened or Fixed."
    )
    severity = models.CharField(max_length=8, null=True, blank=True, default=None, help_text="SEVERITY as returned; no scale applied.")
    first_found_datetime = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="FIRST_FOUND_DATETIME as returned.")
    last_found_datetime = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="LAST_FOUND_DATETIME as returned.")
    last_fixed_datetime = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="LAST_FIXED_DATETIME as returned.")
    last_reopened_datetime = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="LAST_REOPENED_DATETIME as returned."
    )
    times_found = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="TIMES_FOUND as returned.")
    times_reopened = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="TIMES_REOPENED as returned.")
    last_test_datetime = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="LAST_TEST_DATETIME as returned.")
    last_update_datetime = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="LAST_UPDATE_DATETIME as returned."
    )
    last_processed_datetime = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="LAST_PROCESSED_DATETIME as returned."
    )
    is_ignored = models.CharField(max_length=8, null=True, blank=True, default=None, help_text="IS_IGNORED as returned; stored, not acted on.")
    is_disabled = models.CharField(max_length=8, null=True, blank=True, default=None, help_text="IS_DISABLED as returned; stored, not acted on.")
    qds = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="QDS (Qualys Detection Score) as returned.")
    qds_severity = models.CharField(
        max_length=16, null=True, blank=True, default=None, help_text="The QDS element's severity attribute (for example HIGH), as returned."
    )
    qds_factors = models.JSONField(null=True, blank=True, default=None, help_text="QDS_FACTORS as returned, one object per factor.")
    results = models.TextField(
        null=True, blank=True, default=None, help_text="RESULTS in full, as returned; in no key, digest or index (req-qualys-detection-4)."
    )
    state = models.CharField(
        max_length=16, null=True, blank=True, default=None, help_text="open, or resolved exactly when Qualys reports Fixed (req-qualys-states-3)."
    )
    resolution_source = models.CharField(
        max_length=16, null=True, blank=True, default=None, help_text="qualys_fixed when resolved; null while open."
    )
    parse_state = models.CharField(
        max_length=16, null=True, blank=True, default=None, help_text="parsed, no_parser, parser_failed or not_applicable (req-qualys-parsers-1)."
    )
    parser_version = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="<module>/<version> of the parser that read RESULTS; null when none did."
    )
    package_observations = models.JSONField(
        null=True, blank=True, default=None, help_text="What the parser read from RESULTS, each with its evidence line; [] when parsed and empty."
    )

    class Meta(BaseModel.Meta):
        db_table = "qualys_detection"

    def get_name(self) -> str:
        return f"QID {self.qid} on host {self.host_id}" if self.qid and self.host_id else ""

    def __str__(self) -> str:
        return self.get_name()
