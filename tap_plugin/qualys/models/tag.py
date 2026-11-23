"""Qualys tag — one asset tag of the subscription, from the Asset Management and Tagging tag search."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.event_time import Moment
from tap_grid.models import BaseModel

_STR_OR_NULL = {"type": ["string", "null"]}


class QualysTag(BaseModel):
    """An asset tag as Qualys holds it: the platform's one tagging system, which VMDR and Global AssetView share.

    Keyed by Qualys's tag id, never its name, because a tag is renamed in place: a rename is this node's history,
    not a new tag. Every field is Qualys's value as returned. A tag a complete list no longer contains is marked
    ``withdrawn`` and nothing else changes, the way a host is (req-qualys-tags-4).

    Spec: specs/spec-qualys-v0.md (req-qualys-tags).
    """

    ENTITY_TYPE: ClassVar[str] = "qualys__qualys_tag"
    ENTITY_NAME: ClassVar[str] = "Qualys Tag"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "An asset tag of a Qualys subscription, as the tag search returns it: its id, name, colour, rule and "
        "criticality, linked to its subscription and to its child tags."
    )
    ENTITY_ICON: ClassVar[str] = "qualys-tag"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"qualys.area": "tagging"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("subscription_key", "tag_id")
    # Event time (req-grid-entity-event-time): the tag's creation, as Qualys records it. ``modified`` is when it
    # last changed, which is not an end, so it stays a typed field.
    EVENT_TIME: ClassVar[Moment] = Moment(field="created_datetime", kind="created")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "qualys__qualys_subscription"}], "edges": [{"type": "TAG_OF_SUBSCRIPTION__qualys"}]},
        {"nodes": [{"type": "qualys__qualys_tag"}], "edges": [{"type": "LISTS_CHILD_TAG__qualys"}]},
    ]
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "qualys__qualys_tag"}], "edges": [{"type": "LISTS_CHILD_TAG__qualys"}]},
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "subscription_key": {"type": "string", "minLength": 1},
        "tag_id": {"type": "string", "minLength": 1, "pattern": "^[0-9]+$"},
        "name": _STR_OR_NULL,
        "color": _STR_OR_NULL,
        "rule_type": _STR_OR_NULL,
        "rule_text": _STR_OR_NULL,
        "criticality_score": _STR_OR_NULL,
        "description": _STR_OR_NULL,
        "created_datetime": _STR_OR_NULL,
        "modified_datetime": _STR_OR_NULL,
        "parent_tag_id": _STR_OR_NULL,
        "child_tag_ids": {"type": ["array", "null"], "items": {"type": ["string", "null"]}},
        "state": {"type": ["string", "null"], "enum": ["current", "withdrawn", None]},
        "withdrawn_in_run": _STR_OR_NULL,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema} for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["subscription_key", "tag_id"]

    subscription_key = models.CharField(max_length=512, db_index=True, help_text="The subscription whose tag search returned this tag.")
    tag_id = models.CharField(max_length=32, help_text="Qualys's tag id, as returned.")
    name = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="The tag's name as returned; it changes when the tag is renamed.")
    color = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="color as returned, such as #FF0000.")
    rule_type = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="ruleType as returned (for example GROOVY, NAME_CONTAINS); null for a static tag."
    )
    rule_text = models.TextField(null=True, blank=True, default=None, help_text="ruleText as returned, unchanged.")
    criticality_score = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="criticalityScore as returned; no scale applied.")
    description = models.TextField(null=True, blank=True, default=None, help_text="description as returned, unchanged.")
    created_datetime = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="created as returned.")
    modified_datetime = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="modified as returned.")
    parent_tag_id = models.CharField(
        max_length=32, null=True, blank=True, default=None, help_text="parentTagId as returned; null when the search did not return one."
    )
    child_tag_ids = models.JSONField(
        null=True, blank=True, default=None, help_text="The ids in the tag's children list as returned; [] for none, null when the list was not returned."
    )
    state = models.CharField(
        max_length=16, null=True, blank=True, default=None, help_text="current, or withdrawn once a complete tag list no longer contains it (req-qualys-tags-4)."
    )
    withdrawn_in_run = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="The run_id whose complete list no longer had the tag; null while current."
    )

    class Meta(BaseModel.Meta):
        db_table = "qualys_tag"

    def get_name(self) -> str:
        return self.name or (f"tag {self.tag_id}" if self.tag_id else "")

    def __str__(self) -> str:
        return self.get_name()
