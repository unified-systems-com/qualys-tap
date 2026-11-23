"""Qualys host — a machine as Qualys tracks it, by agent or by address."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.event_time import NO_EVENT_TIME, NoEventTime
from tap_grid.models import BaseModel

_STR_OR_NULL = {"type": ["string", "null"]}


class QualysHost(BaseModel):
    """A host as Qualys tracks it: Qualys's view of a machine, not the machine itself.

    Agent-tracked and scanner-tracked hosts are one type, told apart by ``tracking_method``
    (req-qualys-host-3). The EC2 instance belongs to ``aws_core``; this node links to it by exact
    ``CLOUD_RESOURCE_ID`` and never writes it (req-qualys-ec2-link). Every field is Qualys's value as
    returned; each timestamp is kept as the string Qualys sent beside its parsed UTC value.

    Spec: specs/spec-qualys-v0.md (req-qualys-host, req-qualys-states).
    """

    ENTITY_TYPE: ClassVar[str] = "qualys__qualys_host"
    ENTITY_NAME: ClassVar[str] = "Qualys Host"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "A machine as Qualys tracks it, by Cloud Agent or by address: its Qualys ids, addresses, OS, scan "
        "times and cloud fields as returned, linked to the EC2 instance it is."
    )
    ENTITY_ICON: ClassVar[str] = "qualys-host"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"qualys.area": "observation"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("subscription_key", "host_id")
    # Event time (req-grid-entity-event-time): none. The host's times are when Qualys last scanned it,
    # which are last-seen times and stay typed fields (rule 14); the read carries no time for when the
    # host came to exist, which rule 8 would declare.
    EVENT_TIME: ClassVar[NoEventTime] = NO_EVENT_TIME

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "aws_core__aws_ec2_instance"}], "edges": [{"type": "TRACKS_EC2_INSTANCE__qualys"}]},
        {"nodes": [{"type": "qualys__qualys_scan_run"}], "edges": [{"type": "LAST_SEEN_IN_RUN__qualys"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "qualys__qualys_detection"}], "edges": [{"type": "DETECTED_ON_HOST__qualys"}]},
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "subscription_key": {"type": "string", "minLength": 1},
        "host_id": {"type": "string", "minLength": 1, "pattern": "^[0-9]+$"},
        "asset_id": _STR_OR_NULL,
        "ip": _STR_OR_NULL,
        "ipv6": _STR_OR_NULL,
        "tracking_method": _STR_OR_NULL,
        "dns": _STR_OR_NULL,
        "netbios": _STR_OR_NULL,
        "os": _STR_OR_NULL,
        "last_scan_datetime": _STR_OR_NULL,
        "last_scan_at": _STR_OR_NULL,
        "last_vm_scanned_date": _STR_OR_NULL,
        "last_vm_scanned_at": _STR_OR_NULL,
        "last_vm_auth_scanned_date": _STR_OR_NULL,
        "last_vm_auth_scanned_at": _STR_OR_NULL,
        "cloud_provider": _STR_OR_NULL,
        "cloud_service": _STR_OR_NULL,
        "cloud_resource_id": _STR_OR_NULL,
        "ec2_instance_id": _STR_OR_NULL,
        "ec2_metadata": {"type": ["object", "null"], "additionalProperties": {"type": ["string", "null"]}},
        "cloud_tags": {"type": ["array", "null"], "items": {"type": "object"}},
        "state": {"type": ["string", "null"], "enum": ["current", "withdrawn", None]},
        "withdrawn_in_run": _STR_OR_NULL,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema} for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["subscription_key", "host_id"]

    subscription_key = models.CharField(max_length=512, db_index=True, help_text="The subscription that reported this host.")
    host_id = models.CharField(max_length=32, help_text="Qualys's host ID, as returned.")
    asset_id = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="Qualys's ASSET_ID, as returned.")
    ip = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="IP as returned.")
    ipv6 = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="IPV6 as returned.")
    tracking_method = models.CharField(
        max_length=32, null=True, blank=True, default=None, help_text="TRACKING_METHOD as returned (for example IP, DNS, AGENT, EC2)."
    )
    dns = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="DNS as returned.")
    netbios = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="NETBIOS as returned.")
    os = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="OS as returned.")
    last_scan_datetime = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="LAST_SCAN_DATETIME as returned."
    )
    last_scan_at = models.DateTimeField(null=True, blank=True, default=None, help_text="LAST_SCAN_DATETIME parsed to UTC.")
    last_vm_scanned_date = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="LAST_VM_SCANNED_DATE as returned."
    )
    last_vm_scanned_at = models.DateTimeField(null=True, blank=True, default=None, help_text="LAST_VM_SCANNED_DATE parsed to UTC.")
    last_vm_auth_scanned_date = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="LAST_VM_AUTH_SCANNED_DATE as returned."
    )
    last_vm_auth_scanned_at = models.DateTimeField(
        null=True, blank=True, default=None, help_text="LAST_VM_AUTH_SCANNED_DATE parsed to UTC."
    )
    cloud_provider = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="CLOUD_PROVIDER as returned.")
    cloud_service = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="CLOUD_SERVICE as returned.")
    cloud_resource_id = models.CharField(
        max_length=255, null=True, blank=True, default=None, db_index=True, help_text="CLOUD_RESOURCE_ID as returned; the EC2 instance id for AWS."
    )
    ec2_instance_id = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        default=None,
        help_text="The deprecated EC2_INSTANCE_ID as returned; it can carry Azure ids too, so it never links alone.",
    )
    ec2_metadata = models.JSONField(
        null=True,
        blank=True,
        default=None,
        help_text="The METADATA/EC2 attributes as name to value, from host_metadata=ec2; null when not returned.",
    )
    cloud_tags = models.JSONField(
        null=True, blank=True, default=None, help_text="The CLOUD_TAGS as returned, from show_cloud_tags=1; [] when none."
    )
    state = models.CharField(
        max_length=16,
        null=True,
        blank=True,
        default=None,
        help_text="current, or withdrawn once a complete read of the standing scope no longer reports it (req-qualys-states-5).",
    )
    withdrawn_in_run = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="The run_id that saw the host gone; null while current."
    )

    class Meta(BaseModel.Meta):
        db_table = "qualys_host"

    def get_name(self) -> str:
        return self.dns or self.ip or self.cloud_resource_id or (f"host {self.host_id}" if self.host_id else "")

    def __str__(self) -> str:
        return self.get_name()
