"""Qualys scan run — one collection of one subscription, live or from an export archive."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.event_time import NO_EVENT_TIME, NoEventTime
from tap_grid.models import BaseModel

_STR_OR_NULL = {"type": ["string", "null"]}
_INT_OR_NULL = {"type": ["integer", "null"], "minimum": 0}
_SCOPES_NOT_READ = {
    "type": ["array", "null"],
    "items": {
        "type": "object",
        "required": ["scope", "reason"],
        "additionalProperties": False,
        "properties": {"scope": {"type": "string"}, "reason": {"type": "string"}},
    },
}
#: The warning codes a run can carry, defined once in the spec's table (req-qualys-subscription-run-3).
WARNING_CODES = (
    "API_VERSION_EOS",
    "CONTRACT_DRIFT",
    "THROTTLED",
    "TRUNCATED",
    "EC2_UNRESOLVED",
    "AWS_CORE_ABSENT",
    "VALUE_DROPPED",
    "READ_KIND_DOWNGRADED",
)
_WARNINGS = {
    "type": ["array", "null"],
    "items": {
        "type": "object",
        "required": ["code"],
        "additionalProperties": False,
        "properties": {"code": {"enum": list(WARNING_CODES)}, "detail": {"type": "string"}},
    },
}


class QualysScanRun(BaseModel):
    """One collection of one subscription: where it read from, what it asked for and what it did not read.

    A detection is judged against the run that last read it, so the run records its source (the API or an
    export archive), the probe results, the read kind and filter, the pages read and what was not read with
    the reason. Not read is never clean (req-qualys-states).

    Spec: specs/spec-qualys-v0.md (req-qualys-subscription-run, req-qualys-probe, req-qualys-detection-read,
    req-qualys-file-import).
    """

    ENTITY_TYPE: ClassVar[str] = "qualys__qualys_scan_run"
    ENTITY_NAME: ClassVar[str] = "Qualys Scan Run"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "One collection of one Qualys subscription, from the API or an export archive: what it read, how it "
        "was filtered, what it did not read and the warnings it raised."
    )
    ENTITY_ICON: ClassVar[str] = "qualys-scan-run"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"qualys.area": "run"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("subscription_key", "run_id")
    # Event time (req-grid-entity-event-time): none. A run is a collection, and its times are the
    # collector's own clock: collection time, which is never declared (rule 13) and has its own place
    # (req-grid-entity-collection-time).
    EVENT_TIME: ClassVar[NoEventTime] = NO_EVENT_TIME

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "qualys__qualys_subscription"}], "edges": [{"type": "RUN_OF_SUBSCRIPTION__qualys"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [{"type": "qualys__qualys_host"}, {"type": "qualys__qualys_detection"}],
            "edges": [{"type": "LAST_SEEN_IN_RUN__qualys"}],
        },
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "subscription_key": {"type": "string", "minLength": 1},
        "run_id": {"type": "string", "minLength": 1},
        "source": {"enum": ["api", "file"]},
        "started_at": _STR_OR_NULL,
        "finished_at": _STR_OR_NULL,
        "read_at": _STR_OR_NULL,
        "read_kind": {"type": ["string", "null"], "enum": ["complete", "window", "narrower", None]},
        "applied_filter": {"type": ["object", "null"]},
        "window_start": _STR_OR_NULL,
        "window_end": _STR_OR_NULL,
        "page_count": _INT_OR_NULL,
        "probe": {"type": ["object", "null"]},
        "counters": {"type": ["object", "null"]},
        "warnings": _WARNINGS,
        "scopes_not_read": _SCOPES_NOT_READ,
        "archive_sha256": {"type": ["string", "null"], "pattern": "^[0-9a-f]{64}$"},
        "export_created_at": _STR_OR_NULL,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema} for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["subscription_key", "run_id", "source"]

    subscription_key = models.CharField(max_length=512, db_index=True, help_text="The subscription this run read.")
    run_id = models.CharField(max_length=64, help_text="Identity within the subscription: an id the collector mints once per run.")
    source = models.CharField(max_length=8, help_text="Where the data came from: api (a live read) or file (an export archive).")
    started_at = models.DateTimeField(null=True, blank=True, default=None, help_text="When the run began; null when unobserved.")
    finished_at = models.DateTimeField(null=True, blank=True, default=None, help_text="When the run ended; null while unfinished.")
    read_at = models.DateTimeField(
        null=True,
        blank=True,
        default=None,
        help_text="When the data was read from Qualys: the start of a live run, or for a file run the earliest RESPONSE/DATETIME on its pages, never the manifest's time (req-qualys-file-import-4).",
    )
    read_kind = models.CharField(
        max_length=16,
        null=True,
        blank=True,
        default=None,
        help_text="complete (no window, standing scope only), window (vm_processed_after) or narrower (a scope narrower than the standing one).",
    )
    applied_filter = models.JSONField(
        null=True, blank=True, default=None, help_text="The canonical filter exactly as sent; {} for none, null when unobserved."
    )
    window_start = models.DateTimeField(null=True, blank=True, default=None, help_text="vm_processed_after as sent; null for a complete read.")
    window_end = models.DateTimeField(null=True, blank=True, default=None, help_text="The end of the window, the run's start; null for a complete read.")
    page_count = models.IntegerField(null=True, blank=True, default=None, help_text="Detection pages read; null when unobserved.")
    probe = models.JSONField(
        null=True,
        blank=True,
        default=None,
        help_text="The probe's results: API versions and the rate-limit and concurrency headers as returned (req-qualys-probe).",
    )
    counters = models.JSONField(
        null=True,
        blank=True,
        default=None,
        help_text="What the run counted: hosts, detections, QIDs, neutral findings, packages, EC2 links found and unresolved.",
    )
    warnings = models.JSONField(
        null=True, blank=True, default=None, help_text="Warning codes from the spec's table, each with a bounded detail; [] when none."
    )
    scopes_not_read = models.JSONField(
        null=True, blank=True, default=None, help_text="What this run could not read, each with the reason; [] when nothing was missed."
    )
    archive_sha256 = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="SHA-256 of the export archive a file run loaded; null for a live run."
    )
    export_created_at = models.DateTimeField(
        null=True, blank=True, default=None, help_text="The export manifest's created_at, the read time of a file run; null for a live run."
    )

    class Meta(BaseModel.Meta):
        db_table = "qualys_scan_run"

    def get_name(self) -> str:
        return f"run {self.run_id}" if self.run_id else ""

    def __str__(self) -> str:
        return self.get_name()
