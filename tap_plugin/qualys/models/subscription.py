"""Qualys subscription — one Qualys subscription the collector reads, as an operator envelope names it."""

from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models

from tap_grid.models import BaseModel
from tap_plugin.qualys.identity import InvalidApiHost, canonical_api_host, subscription_key

_STR_OR_NULL = {"type": ["string", "null"]}


class QualysSubscription(BaseModel):
    """One Qualys subscription: the platform API host and the operator's label for it.

    Qualys is a shared service, so many subscriptions answer on one API host and the host alone cannot
    identify one; the operator's label is the other half of the key (req-qualys-connection). The
    ``subscription_key`` column is the compact JSON array ``[api_host, subscription_label]``, which every
    other Qualys type keys on, so no two (host, label) pairs encode alike. The watermark and standing
    scope live here because the next run needs them (req-qualys-detection-read, req-qualys-states).

    Spec: specs/spec-qualys-v0.md (req-qualys-subscription-run).
    """

    ENTITY_TYPE: ClassVar[str] = "qualys__qualys_subscription"
    ENTITY_NAME: ClassVar[str] = "Qualys Subscription"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "One Qualys subscription the collector reads: its platform API host, the operator's label, the "
        "standing scope and the watermark of the last clean read."
    )
    ENTITY_ICON: ClassVar[str] = "qualys-subscription"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"qualys.area": "run"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("api_host", "subscription_label")

    # Nothing goes out from a subscription in v0; runs point at it.
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "qualys__qualys_scan_run"}], "edges": [{"type": "RUN_OF_SUBSCRIPTION__qualys"}]},
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "api_host": {"type": "string", "minLength": 1, "pattern": "^https://[a-z0-9.-]+(:[0-9]+)?$"},
        "subscription_label": {"type": "string", "minLength": 1},
        "subscription_key": {"type": "string", "minLength": 1},
        "standing_scope": {"type": ["object", "null"]},
        "watermark": _STR_OR_NULL,
        "last_complete_read_at": _STR_OR_NULL,
        "detection_api_version": _STR_OR_NULL,
        "knowledgebase_api_version": _STR_OR_NULL,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema} for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["api_host", "subscription_label", "subscription_key"]

    api_host = models.CharField(
        max_length=255, db_index=True, help_text="The platform API root, canonical: https, lower-cased host, no path."
    )
    subscription_label = models.CharField(
        max_length=128, help_text="The operator's label for the subscription, from the envelope (req-qualys-connection)."
    )
    subscription_key = models.CharField(
        max_length=512,
        db_index=True,
        help_text="The compact JSON array [api_host, subscription_label]; the key every other Qualys type carries.",
    )
    standing_scope = models.JSONField(
        null=True,
        blank=True,
        default=None,
        help_text="The envelope's scope filter (asset group or tag ids) every read is made with; {} when none, null when unobserved.",
    )
    watermark = models.DateTimeField(
        null=True,
        blank=True,
        default=None,
        help_text="Start time of the last run whose every page was read and validated; the next window read starts here.",
    )
    last_complete_read_at = models.DateTimeField(
        null=True, blank=True, default=None, help_text="When the last complete read of the standing scope ran; null before one."
    )
    detection_api_version = models.CharField(
        max_length=8, null=True, blank=True, default=None, help_text="The host detection API version last read."
    )
    knowledgebase_api_version = models.CharField(
        max_length=8, null=True, blank=True, default=None, help_text="The knowledge base API version last read."
    )

    class Meta(BaseModel.Meta):
        db_table = "qualys_subscription"

    def validate(self) -> None:
        """The stored keys must be the ones derived from the host and the label.

        Every other Qualys type keys on ``subscription_key``, so a subscription whose stored key named a
        different (host, label) pair would strand them. The host must already be canonical, and the key
        must equal ``identity.subscription_key(api_host, subscription_label)``.
        """
        try:
            canonical = canonical_api_host(self.api_host)
        except InvalidApiHost as exc:
            raise ValidationError({"api_host": [str(exc)]}) from exc
        if canonical != self.api_host:
            raise ValidationError({"api_host": [f"api_host must be canonical: {canonical}"]})
        expected = subscription_key(self.api_host, self.subscription_label)
        if self.subscription_key != expected:
            raise ValidationError({"subscription_key": [f"subscription_key must be {expected}"]})

    def get_name(self) -> str:
        return self.subscription_label or ""

    def __str__(self) -> str:
        return self.get_name()
