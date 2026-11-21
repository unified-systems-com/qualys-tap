"""Load an export archive onto the grid (req-qualys-file-import).

The archive goes through the same contract check, parser, decomposer and GRIFT import a live read uses. What
is particular to a file:

- Trust: the archive is not authenticated; loading it is an operator act the operator vouches for (ruled
  2026-11-20, Q12c). It is still bounded and contract-checked (``archive``, ``parse``), and the run records
  its SHA-256. An archive already loaded, by that digest, is refused.
- Read time: the earliest ``RESPONSE/DATETIME`` Qualys stamped on its detection pages, never the manifest's
  ``created_at``. A read time in the future, or older than the subscription's newest recorded read, is refused
  with no override (``-4``).
- Scope: the manifest's scope becomes the run's filter. The run is labelled complete, and the decomposer
  treats it as narrower unless that filter equals the standing scope exactly (``-6``), so withdrawal is decided
  in one place.
- Drift: any DTD the archive carries is reduced and compared with the committed extract; a consumed
  difference is recorded as ``CONTRACT_DRIFT`` (req-qualys-drift-ci-4).
"""

import contextlib
import json
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from tap_plugin.qualys.archive import Archive, ArchiveRefused, open_archive, read_snapshot
from tap_plugin.qualys.contract.reduce import ReduceError, reduce
from tap_plugin.qualys.decompose import COMPLETE, Run, decompose, document, parse_time
from tap_plugin.qualys.identity import canonical_api_host, subscription_key
from tap_plugin.qualys.parse import PageRefused, extract, parse_detection_page, parse_knowledgebase_page

#: Clock skew allowed between Qualys's response time and the loading host.
_SKEW = timedelta(minutes=5)
_DTD_DOCUMENT = {"hld-output.dtd": "detection", "kb.dtd": "knowledgebase"}


class LoadRefused(ValueError):
    """An archive that writes nothing: the message says why."""


@dataclass
class Loaded:
    """What a load wrote."""

    subscription_key: str
    run_id: str
    counters: dict[str, int]
    warnings: list[dict[str, str]] = field(default_factory=list)


def _filter(scope: dict[str, Any] | None) -> dict[str, Any]:
    """The manifest's scope as the run's applied filter, in the standing scope's own shape where it can be."""
    if not scope:
        return {}
    kind, values = scope["kind"], scope["values"]
    if kind in ("asset_group_ids", "tag_ids"):
        try:
            ids = sorted(int(v) for v in values)
        except (TypeError, ValueError) as exc:
            raise LoadRefused(f"export.json {kind} holds a non-numeric id") from exc
        if kind == "tag_ids" and scope.get("tag_match") != "any":
            return {kind: ids, "tag_match": scope.get("tag_match")}
        return {kind: ids}
    return {kind: list(values), **({"tag_match": scope["tag_match"]} if "tag_match" in scope else {})}


def _drift(dtds: dict[str, str]) -> list[dict[str, str]]:
    """CONTRACT_DRIFT for each served DTD whose consumed elements differ from the committed extract."""
    warnings = []
    consumed = json.loads((Path(__file__).resolve().parent / "contract" / "consumed.json").read_text(encoding="utf-8"))
    for name, text in sorted(dtds.items()):
        doc = _DTD_DOCUMENT[name]
        spec = consumed["documents"][doc]
        try:
            served = reduce(text, spec["elements"], spec.get("named_not_declared"))
        except ReduceError as exc:
            warnings.append({"code": "CONTRACT_DRIFT", "detail": f"{name}: {str(exc)[:300]}"})
            continue
        committed = extract()["documents"][doc]["elements"]
        changed = sorted(e for e in committed if {k: v for k, v in served.get(e, {}).items()} != committed[e])
        if changed:
            warnings.append({"code": "CONTRACT_DRIFT", "detail": f"{name}: consumed element(s) differ: {', '.join(changed[:20])}"})
    return warnings


def load_archive(
    path: Path,
    label: str,
    *,
    grid: Any,
    already_loaded: Any,
    newest_read_time: Any,
    importer: Any,
    serialize: Callable[[str], AbstractContextManager[Any]] = lambda key: contextlib.nullcontext(),
    now: datetime | None = None,
) -> Loaded:
    """Check, parse and import one archive; refuse it whole, writing nothing, if any check fails.

    ``grid`` is the decomposer's view of what the grid holds; ``already_loaded(key, sha256)`` and
    ``newest_read_time(key)`` read past runs; ``importer(document)`` performs the GRIFT import; ``serialize(key)``
    holds the subscription for the checks and the import together, so two loads of one subscription cannot both
    pass the duplicate and staleness checks before either writes. They are passed in so the command binds them
    to the live grid and tests can drive the same path.
    """
    now = now or datetime.now(UTC)
    try:
        archive: Archive = open_archive(read_snapshot(path))
    except ArchiveRefused as exc:
        raise LoadRefused(str(exc)) from exc
    sha256 = archive.sha256
    try:
        api_host = canonical_api_host(archive.manifest["api_host"])
    except ValueError as exc:
        raise LoadRefused(f"export.json api_host is not a canonical https host: {exc}") from exc
    key = subscription_key(api_host, label)
    with serialize(key):
        return _load_held(archive, api_host, label, key, sha256, now, grid=grid, already_loaded=already_loaded, newest_read_time=newest_read_time, importer=importer)


def _load_held(archive: Archive, api_host: str, label: str, key: str, sha256: str, now: datetime, *, grid: Any, already_loaded: Any, newest_read_time: Any, importer: Any) -> Loaded:
    """The checks and the import, run while the subscription is held."""
    if already_loaded(key, sha256):
        raise LoadRefused("this archive has already been loaded into this subscription")

    try:
        pages = [parse_detection_page(body) for body in archive.detection_pages]
    except PageRefused as exc:
        raise LoadRefused(f"a detection page is off-contract: {exc}") from exc
    kb_pages = []
    kb_complete = archive.manifest["knowledgebase_complete"]
    for body in archive.knowledgebase_files:
        try:
            kb_pages.append(parse_knowledgebase_page(body))
        except PageRefused:
            kb_complete = False  # recorded through the QIDs it leaves not returned; the detections still load
            continue
        if kb_pages[-1].next_url:
            # A chunk Qualys cut short: the export script does not follow the link (#16), so a QID asked of it and
            # not returned may simply be on the page not read. It is unobserved, not absent.
            kb_complete = False

    stamps = [parse_time(p.response_datetime) for p in pages]
    if any(s is None for s in stamps):
        raise LoadRefused("a detection page carries no usable RESPONSE/DATETIME")
    times = [datetime.fromisoformat(s) for s in stamps]
    if max(times) > now + _SKEW:
        raise LoadRefused("the archive's read time is in the future")  # any page, not only the earliest
    read_at = min(times)
    newest = newest_read_time(key)
    if newest is not None and read_at < newest:
        raise LoadRefused("the archive is older than the subscription's newest recorded read")

    run = Run(
        api_host=api_host,
        label=label,
        source="file",
        read_kind=COMPLETE,
        started_at=now,
        read_at=read_at,
        applied_filter=_filter(archive.manifest.get("scope")),
        knowledgebase_asked=archive.qids_asked or None,
        knowledgebase_complete=kb_complete,
        archive_sha256=sha256,
        export_created_at=archive.manifest.get("created_at"),
    )
    result = decompose(run, pages, kb_pages, grid)
    drift = _drift(archive.dtds)
    run_node = next(n for n in result.nodes if n["entity"]["entity_type"] == "qualys__qualys_scan_run")
    run_node["node"]["warnings"] = drift + run_node["node"]["warnings"]
    run_node["node"]["finished_at"] = now.isoformat()
    outcome = importer(document(result, run))
    errors = getattr(outcome, "errors", None)
    if errors:
        raise LoadRefused(f"the grid refused the batch: {str(errors)[:500]}")
    return Loaded(subscription_key=key, run_id=run.run_id, counters=result.counters, warnings=run_node["node"]["warnings"])
