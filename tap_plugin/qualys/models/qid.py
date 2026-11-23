"""Qualys QID — the knowledge-base record behind a QID."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.event_time import Moment
from tap_grid.models import BaseModel

_STR_OR_NULL = {"type": ["string", "null"]}
_OBJ_OR_NULL = {"type": ["object", "null"]}


class QualysQid(BaseModel):
    """What a QID means, from Qualys's knowledge base: title, severity, scores and the CVEs it names.

    The CVE fan-out lives here so detections do not carry it: one ``ABOUT_VULNERABILITY__qualys`` edge per
    CVE goes from the QID, never from a detection (req-qualys-qid-2). A QID the knowledge base did not
    return is held with its id and ``kb_returned`` false, and recorded as not read on the run (req-qualys-qid-4). Reference data,
    so it carries no ``state``.

    Spec: specs/spec-qualys-v0.md (req-qualys-qid).
    """

    ENTITY_TYPE: ClassVar[str] = "qualys__qualys_qid"
    ENTITY_NAME: ClassVar[str] = "Qualys QID"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "The Qualys knowledge-base record behind a QID: its title, severity, CVSS scores and vectors, vendor "
        "references and the CVEs it names, as returned."
    )
    ENTITY_ICON: ClassVar[str] = "qualys-qid"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"qualys.area": "knowledge"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("subscription_key", "qid")
    # Event time (req-grid-entity-event-time): when Qualys published the knowledge-base record, as the
    # text it returned. LAST_SERVICE_MODIFICATION_DATETIME is the source editing its own record and is
    # not declared while a time for the thing exists (rule 13).
    EVENT_TIME: ClassVar[Moment] = Moment(field="published_datetime", kind="published")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {
            "nodes": [{"type": "compliance_core__compliance_vulnerability"}],
            "edges": [{"type": "ABOUT_VULNERABILITY__qualys"}],
        },
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "qualys__qualys_detection"}], "edges": [{"type": "ABOUT_QID__qualys"}]},
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "subscription_key": {"type": "string", "minLength": 1},
        "qid": {"type": "string", "minLength": 1, "pattern": "^[0-9]+$"},
        "kb_returned": {"type": ["boolean", "null"]},
        "vuln_type": _STR_OR_NULL,
        "severity_level": _STR_OR_NULL,
        "title": _STR_OR_NULL,
        "category": _STR_OR_NULL,
        "patchable": _STR_OR_NULL,
        "published_datetime": _STR_OR_NULL,
        "last_service_modification_datetime": _STR_OR_NULL,
        "cvss_v2": _OBJ_OR_NULL,
        "cvss_v3": _OBJ_OR_NULL,
        "cvss_v4": _OBJ_OR_NULL,
        "vendor_references": {"type": ["array", "null"], "items": {"type": "object"}},
        "cve_list": {
            "type": ["array", "null"],
            "items": {
                "type": "object",
                "required": ["id"],
                "properties": {"id": {"type": "string", "minLength": 1}, "url": {"type": ["string", "null"]}},
            },
        },
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema} for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["subscription_key", "qid"]

    subscription_key = models.CharField(max_length=512, db_index=True, help_text="The subscription whose knowledge base returned this record.")
    qid = models.CharField(max_length=16, help_text="The QID, as returned.")
    kb_returned = models.BooleanField(
        null=True,
        blank=True,
        default=None,
        help_text="True once the knowledge base returned this record; false when it was asked and did not; null before any read (req-qualys-qid-4).",
    )
    vuln_type = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="VULN_TYPE as returned.")
    severity_level = models.CharField(max_length=8, null=True, blank=True, default=None, help_text="SEVERITY_LEVEL as returned; no scale applied.")
    title = models.TextField(null=True, blank=True, default=None, help_text="TITLE as returned.")
    category = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="CATEGORY as returned.")
    patchable = models.CharField(max_length=8, null=True, blank=True, default=None, help_text="PATCHABLE as returned.")
    published_datetime = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="PUBLISHED_DATETIME as returned.")
    last_service_modification_datetime = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="LAST_SERVICE_MODIFICATION_DATETIME as returned."
    )
    cvss_v2 = models.JSONField(null=True, blank=True, default=None, help_text="The CVSS element as returned (base score, vector and the rest).")
    cvss_v3 = models.JSONField(null=True, blank=True, default=None, help_text="The CVSS_V3 element as returned.")
    cvss_v4 = models.JSONField(
        null=True, blank=True, default=None, help_text="The CVSS v4 element as returned, where knowledge base 4.0 carries it."
    )
    vendor_references = models.JSONField(
        null=True, blank=True, default=None, help_text="VENDOR_REFERENCE_LIST as returned, one object per reference."
    )
    cve_list = models.JSONField(
        null=True, blank=True, default=None, help_text="CVE_LIST as returned: each CVE's id and URL; [] when the QID names none."
    )

    class Meta(BaseModel.Meta):
        db_table = "qualys_qid"

    def get_name(self) -> str:
        if not self.qid:
            return ""
        return f"QID {self.qid}: {self.title}" if self.title else f"QID {self.qid}"

    def __str__(self) -> str:
        return self.get_name()
