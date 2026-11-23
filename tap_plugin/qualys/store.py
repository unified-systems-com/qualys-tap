"""What the grid already holds for one subscription: the reads a run makes before it writes.

All reads go through the models' default managers, which exclude tombstoned rows and are guarded to a bound
actor (a collector task or the load command binds one).
"""

import contextlib
from collections.abc import Iterable, Iterator
from typing import Any

from django.apps import apps
from django.db import connection, transaction
from django.forms.models import model_to_dict

from tap_grid.dimension_names import view
from tap_plugin.qualys.models.detection import QualysDetection

from tap_plugin.qualys.models.host import QualysHost
from tap_plugin.qualys.models.qid import QualysQid
from tap_plugin.qualys.models.scan_run import QualysScanRun
from tap_plugin.qualys.models.subscription import QualysSubscription
from tap_plugin.qualys.models.tag import QualysTag

_HOST_PAYLOAD = [f.name for f in QualysHost._meta.concrete_fields if f.name in QualysHost.FIELD_CRUD_SCHEMA]
_TAG_PAYLOAD = [f.name for f in QualysTag._meta.concrete_fields if f.name in QualysTag.FIELD_CRUD_SCHEMA]
_SUB_PAYLOAD = [f.name for f in QualysSubscription._meta.concrete_fields if f.name in QualysSubscription.FIELD_CRUD_SCHEMA]


def _payload(row: Any, names: list[str]) -> dict[str, Any]:
    """A row's writable fields as a GRIFT payload: datetimes as ISO strings, everything else as stored."""
    out = {}
    for name, value in model_to_dict(row, fields=names).items():
        out[name] = value.isoformat() if hasattr(value, "isoformat") else value
    return out


class GridStore:
    """The ``decompose.GridView`` over the live grid."""

    def subscription(self, key: str) -> dict[str, Any] | None:
        row = QualysSubscription.objects.filter(subscription_key=key).first()
        return _payload(row, _SUB_PAYLOAD) if row else None

    def current_hosts(self, key: str) -> dict[str, dict[str, Any]]:
        rows = QualysHost.objects.filter(subscription_key=key).exclude(state="withdrawn")
        return {row.host_id: _payload(row, _HOST_PAYLOAD) for row in rows}

    def current_tags(self, key: str) -> dict[str, dict[str, Any]]:
        rows = QualysTag.objects.filter(subscription_key=key).exclude(state="withdrawn")
        return {row.tag_id: _payload(row, _TAG_PAYLOAD) for row in rows}

    def held_qids(self, key: str, qids: Iterable[str]) -> set[str]:
        qids = list(qids)
        if not qids:
            return set()
        return set(QualysQid.objects.filter(subscription_key=key, qid__in=qids).values_list("qid", flat=True))

    def qid_records(self, key: str, qids: Iterable[str]) -> dict[str, dict[str, Any]]:
        qids = list(qids)
        if not qids:
            return {}
        rows = QualysQid.objects.filter(subscription_key=key, qid__in=qids).values("qid", "cve_list", "cvss_v2", "cvss_v3")
        return {row["qid"]: row for row in rows}

    def host_detections(self, key: str, host_ids: Iterable[str]) -> dict[str, list[dict[str, Any]]]:
        host_ids = list(host_ids)
        if not host_ids:
            return {}
        out: dict[str, list[dict[str, Any]]] = {}
        fields = ("host_id", "qid", "unique_vuln_id", "state", "severity", "first_found_datetime", "package_observations")
        for row in QualysDetection.objects.filter(subscription_key=key, host_id__in=host_ids).values(*fields):
            out.setdefault(row["host_id"], []).append(row)
        return out

    def vulnerabilities(self, vuln_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        """Held shared records by exact id; no alias is resolved and no case folded."""
        ids = list(vuln_ids)
        if not ids:
            return {}
        model = apps.get_model("compliance_core", "ComplianceVulnerability")
        rows = model.objects.filter(vuln_id__in=ids).select_related("entity")
        return {row.vuln_id: {"scored": row.cvss_score is not None, "dimensions": dict(view(row.entity.dimensions))} for row in rows}

    def held_packages(self, keys: Iterable[tuple[str, str, str]]) -> set[tuple[str, str, str]]:
        keys = set(keys)
        if not keys:
            return set()
        model = apps.get_model("computing_core", "Package")
        names = {k[1] for k in keys}
        rows = model.objects.filter(name__in=names).values_list("ecosystem", "name", "version")
        return {row for row in rows if row in keys}

    def held_findings(self, source_keys: Iterable[str]) -> set[str]:
        keys = list(source_keys)
        if not keys:
            return set()
        model = apps.get_model("compliance_core", "ComplianceFinding")
        return set(model.objects.filter(source="qualys", source_key__in=keys).values_list("source_key", flat=True))

    def default_dimensions(self, entity_type: str) -> dict[str, str]:
        from tap_grid.registry import get_model_class

        return dict(get_model_class(entity_type).DEFAULT_DIMENSIONS)
    def ec2_instances(self, instance_ids: Iterable[str]) -> set[str] | None:
        """Of these ids, those aws_core holds by exact ``instance_id``; None when aws_core is not installed.

        Read only: this plugin never writes an EC2 instance (req-qualys-ec2-link-2). The model is resolved
        through the app registry, so nothing here imports aws_core where it is absent.
        """
        try:
            instance = apps.get_model("aws_core", "Ec2Instance")
        except LookupError:
            return None
        ids = list(instance_ids)
        if not ids:
            return set()
        return set(instance.objects.filter(instance_id__in=ids).values_list("instance_id", flat=True))


def newest_read_time(key: str) -> Any:
    """The latest read time any run of the subscription recorded, file or live; None before any run.

    A run's ``read_at`` is Qualys's own response time for a file run and the run's start for a live one; the
    manifest's ``created_at`` is never used (req-qualys-file-import-4).
    """
    row = QualysScanRun.objects.filter(subscription_key=key, read_at__isnull=False).order_by("-read_at").first()
    return row.read_at if row else None


@contextlib.contextmanager
def hold_subscription(key: str) -> Iterator[None]:
    """One transaction holding a per-subscription advisory lock across a run's grid reads and its import.

    The file load and the live collector take the same lock, so two writes to one subscription never both read
    the held state before either writes.
    """
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", [f"qualys-load:{key}"])
        yield
