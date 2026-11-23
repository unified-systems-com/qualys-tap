"""The Qualys collector: every configured subscription, read live, decomposed and written as one batch each.

For each envelope in scope ``qualys`` (req-qualys-connection): plan the read from what the grid holds, read it
through the read-only transport (:mod:`tap_plugin.qualys.live`), then, holding the subscription, decompose and
submit. The network read takes no database lock; the lock covers only the grid reads decompose makes and the
import, and is the same one ``qualys_load`` takes, so a file load and a live run never interleave. The import is
several batches, each its own transaction, with the seal last (req-qualys-chunked-write).

A subscription that cannot be read fails alone: its probe failing writes nothing for it and is recorded; the
run fails only when no subscription could be written.
"""

from datetime import UTC, datetime
from typing import Any, ClassVar

from tap import secrets_root
from tap_cares.collectors import CeilingExceeded, CollectorBase, run_with_ceiling
from tap_cares.collectors.readiness import CollectorReadinessStatus, CollectorSelfTestResult, check_fail, check_pass

from tap_plugin.qualys import live
from tap_plugin.qualys.client import ReadOnlyClient, Response
from tap_plugin.qualys.credential import Credential, discover
from tap_plugin.qualys.decompose import Run, decompose, documents
from tap_plugin.qualys.store import GridStore, hold_subscription, newest_read_time

_SITE_RUN_STARTED = "7e3c"
_SITE_CREDENTIAL_REFUSED = "283e"
_SITE_NO_CREDENTIAL = "ea25"
_SITE_PROBE_FAILED = "e4b3"
_SITE_SUBSCRIPTION_WRITTEN = "b191"
_SITE_NEWER_READ = "858b"
_SITE_NOTHING_WRITTEN = "49c6"
_SITE_RUN_FINISHED = "1107"
_SITE_WALK_INCOMPLETE = "6a6b"
_SITE_SUBSCRIPTION_FAILED = "6a7a"

#: Tests replace this to serve recorded responses; the default is the real transport.
client_factory = ReadOnlyClient


def _discover() -> tuple[list[Credential], list[Any]]:
    root = secrets_root.resolve()
    return discover(root) if root is not None else ([], [])


class QualysCollectorError(Exception):
    """The run could write nothing. The message names subscriptions by ``qualys:<key>``, never a value."""


def _bounded(call: Any, what: str) -> Response:
    try:
        return run_with_ceiling(call, live.READ_CEILING_SECONDS, name=f"qualys-{what}")
    except CeilingExceeded as exc:
        raise TimeoutError(f"{what} did not finish within its ceiling") from exc


class QualysCollector(CollectorBase):
    """Read host detections and their knowledge-base records from every configured Qualys subscription."""

    # No reconcile verdicts yet: withdrawal is a host state the read itself decides (req-qualys-states-5).
    RECONCILE_BUDGET_DEFAULT: ClassVar[int] = 0

    @classmethod
    def self_test(cls) -> CollectorSelfTestResult:
        """Whether a usable credential exists. Reads no subscription."""
        usable, refused = _discover()
        context = {"usable": [c.qualified for c in usable], "refused": [e.qualified for e in refused]}
        if usable:
            return CollectorSelfTestResult.from_checks(
                [check_pass("CREDENTIAL_PRESENT", f"{len(usable)} usable credential(s); {len(refused)} refused.", context=context)],
                summary="A credential is configured.",
            )
        return CollectorSelfTestResult.from_checks(
            [check_fail("NO_CREDENTIAL", "No usable credential in scope qualys.", readiness_status=CollectorReadinessStatus.UNCONFIGURED, context=context)],
            summary="No credential is configured.",
        )

    def run(self) -> None:
        self.record_info(_SITE_RUN_STARTED, "RUN_STARTED", "Qualys collection started.")
        self.declare_no_surfaces()
        usable, refused = _discover()
        for error in refused:
            self.record_warn(_SITE_CREDENTIAL_REFUSED, "CREDENTIAL_REFUSED", str(error), message_data={"credential": error.qualified})
        if not usable:
            self.record_error(_SITE_NO_CREDENTIAL, "NO_CREDENTIAL", "No usable credential in scope qualys; nothing was read or written.")
            raise QualysCollectorError("no usable credential")
        written: list[str] = []
        for credential in usable:
            try:
                line = self._collect(credential)
            except Exception as exc:  # noqa: BLE001 — one subscription's failure must not stop the others
                # The type only: an exception's text may carry what a response said, and nothing it carries is checked.
                self.record_error(_SITE_SUBSCRIPTION_FAILED, "SUBSCRIPTION_FAILED", f"{credential.qualified}: the read failed ({type(exc).__name__}); nothing more was written for it.", message_data={"credential": credential.qualified})
                continue
            if line:
                written.append(line)
        if not written:
            self.summary = "No subscription could be written."
            self.record_error(_SITE_NOTHING_WRITTEN, "NOTHING_WRITTEN", self.summary)
            raise QualysCollectorError(self.summary)
        self.summary = "; ".join(written)
        self.record_info(_SITE_RUN_FINISHED, "RUN_FINISHED", self.summary)

    def _collect(self, credential: Credential) -> str | None:
        started = datetime.now(UTC)
        grid = GridStore()
        the_plan = live.plan(grid.subscription(credential.key), credential.standing_scope, started)
        username, password = credential.basic
        client = client_factory(credential.api_host, username, password, ca_bundle=credential.ca_bundle)
        try:
            got = live.read(client, credential.standing_scope, the_plan, bounded=_bounded)
        except live.ProbeFailed as exc:
            self.record_error(_SITE_PROBE_FAILED, "PROBE_FAILED", f"{credential.qualified}: {exc}; nothing was written for it.", message_data={"credential": credential.qualified})
            return None
        if not got.walk_complete:
            self.record_warn(_SITE_WALK_INCOMPLETE, "WALK_INCOMPLETE", f"{credential.qualified}: the detection walk did not reach its end; what was read is written and the watermark stays.", message_data={"credential": credential.qualified})
        run = Run(
            api_host=credential.api_host,
            label=credential.label,
            source="api",
            read_kind=got.read_kind,
            started_at=started,
            read_at=started,
            applied_filter=got.applied_filter,
            standing_scope=credential.standing_scope,
            knowledgebase_asked=got.knowledgebase_asked,
            knowledgebase_complete=got.knowledgebase_complete,
            probe={**got.probe, "requests": got.requests},
            window_start=got.window_start,
            window_end=started if got.window_start is not None else None,
            walk_complete=got.walk_complete,
            extra_warnings=got.warnings,
            detection_pages_not_read=got.detection_pages_not_read,
        )
        with hold_subscription(credential.key):
            newest = newest_read_time(credential.key)
            if newest is not None and newest > started:
                # A file load or another run recorded a newer read while this one was reading: writing this older
                # read now could reopen what that read showed fixed.
                self.record_warn(_SITE_NEWER_READ, "NEWER_READ_HELD", f"{credential.qualified}: a newer read landed during this run; nothing was written for it.", message_data={"credential": credential.qualified})
                return None
            result = decompose(run, got.pages, got.kb_pages, GridStore())
            run_node = next(n for n in result.nodes if n["entity"]["ref"] == "run")
            run_node["node"]["finished_at"] = datetime.now(UTC).isoformat()
            # A rejected batch raises (the abort default), so a later batch, and the seal above all, is never sent.
            for doc in documents(result, run):
                self.submit_grift(doc)
        line = (f"{credential.qualified}: {result.read_kind} read, {len(got.pages)} page(s), {result.counters.get('hosts', 0)} host(s), "
                f"{result.counters.get('detections', 0)} detection(s), {result.counters.get('neutral_findings', 0)} neutral finding(s); "
                f"watermark {'advanced' if result.watermark_advanced else 'held'}")
        self.record_info(_SITE_SUBSCRIPTION_WRITTEN, "SUBSCRIPTION_WRITTEN", line, message_data={"credential": credential.qualified, "counters": result.counters})
        return line
