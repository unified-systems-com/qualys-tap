"""What the grid already holds for one subscription: the reads a run makes before it writes.

All reads go through the models' default managers, which exclude tombstoned rows and are guarded to a bound
actor (a collector task or the load command binds one).
"""

from collections.abc import Iterable
from typing import Any

from django.apps import apps
from django.forms.models import model_to_dict

from tap_plugin.qualys.models.host import QualysHost
from tap_plugin.qualys.models.qid import QualysQid
from tap_plugin.qualys.models.scan_run import QualysScanRun
from tap_plugin.qualys.models.subscription import QualysSubscription

_HOST_PAYLOAD = [f.name for f in QualysHost._meta.concrete_fields if f.name in QualysHost.FIELD_CRUD_SCHEMA]
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

    def held_qids(self, key: str, qids: Iterable[str]) -> set[str]:
        qids = list(qids)
        if not qids:
            return set()
        return set(QualysQid.objects.filter(subscription_key=key, qid__in=qids).values_list("qid", flat=True))

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
