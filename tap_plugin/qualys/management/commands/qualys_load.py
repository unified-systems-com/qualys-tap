"""``manage.py qualys_load <archive.tgz> --subscription <label>`` (req-qualys-file-import).

Loads an export archive from ``tools/qualys-export`` onto the grid as the collector program actor. Prints what
was written, or why nothing was. An archive is accepted or refused whole.
"""

from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from tap_auth.actors import COLLECTOR, acting_as, get_builtin_actor
from tap_grid.grift.importer import grift_import
from tap_plugin.qualys.load import LoadRefused, load_archive
from tap_plugin.qualys.models import QualysScanRun
from tap_plugin.qualys.store import GridStore, newest_read_time


def _already_loaded(key: str, sha256: str) -> bool:
    return QualysScanRun.objects.filter(subscription_key=key, archive_sha256=sha256).exists()


class Command(BaseCommand):
    help = "Load a Qualys export archive (from tools/qualys-export) onto the grid."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("archive", type=Path, help="The qualys-export-<time>.tgz file.")
        parser.add_argument(
            "--subscription",
            required=True,
            help="Your label for the Qualys subscription the archive came from; use the same label as its envelope, if any.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        path: Path = options["archive"]
        if not path.is_file():
            raise CommandError(f"{path} is not a file")
        label = options["subscription"].strip()
        if not label:
            raise CommandError("--subscription must not be empty")
        with acting_as(get_builtin_actor(COLLECTOR)):
            try:
                loaded = load_archive(
                    path,
                    label,
                    grid=GridStore(),
                    already_loaded=_already_loaded,
                    newest_read_time=newest_read_time,
                    importer=grift_import,
                )
            except LoadRefused as exc:
                raise CommandError(f"refused, nothing written: {exc}") from exc
        counters = ", ".join(f"{k} {v}" for k, v in sorted(loaded.counters.items()))
        self.stdout.write(self.style.SUCCESS(f"loaded run {loaded.run_id} into {loaded.subscription_key}: {counters}"))
        for warning in loaded.warnings:
            self.stdout.write(self.style.WARNING(f"{warning['code']}: {warning.get('detail', '')}"))
