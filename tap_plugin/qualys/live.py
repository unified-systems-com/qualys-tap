"""One live read of a Qualys subscription through the read-only transport (req-qualys-probe, -detection-read).

The plan: a subscription the grid has never read, or whose standing scope changed, or whose last complete read
is older than the complete-read interval, gets a **complete** read; any other gets a **window** read from its
watermark less a fixed overlap. The read: a probe (the first detection page at ``truncation_limit=1``), then
every detection page by Qualys's next-page link, then the knowledge base for every QID named, in chunks, each
followed to its end. Every request goes through :class:`~tap_plugin.qualys.client.ReadOnlyClient`, so nothing
but an allowlisted GET can leave, and every request is bounded by a wall-clock ceiling.

The probe failing ends the read with nothing to write. A page failing later stops the walk: what was read is
kept, the walk is recorded incomplete, and the watermark does not move. Nothing here touches the grid.
"""

import functools
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from tap_plugin.qualys.client import DETECTION_PATH, KNOWLEDGEBASE_PATH, ReadFailed, ReadOnlyClient, Response, TransportRefused
from tap_plugin.qualys.decompose import COMPLETE, WINDOW
from tap_plugin.qualys.parse import DetectionPage, KnowledgeBasePage, PageRefused, parse_detection_page, parse_knowledgebase_page

#: How often a complete read is repeated so withdrawal can be judged (req-qualys-detection-read).
COMPLETE_INTERVAL = timedelta(days=7)
#: How far before the watermark a window read starts, so a detection processed during the last read is kept.
WINDOW_OVERLAP = timedelta(hours=1)
#: Qualys's documented default page size.
TRUNCATION_LIMIT = 1000
#: QIDs asked of the knowledge base per request: short enough that the URL stays well inside any limit.
KB_CHUNK = 300
#: Ceilings: per request (the transport's own timeouts bound inactivity, not the whole attempt), per run, and
#: pages per walk. A walk stopped by one is recorded incomplete, never as a short subscription. The run ceiling
#: is checked before each request starts, so a run ends within RUN_CEILING_SECONDS + READ_CEILING_SECONDS.
READ_CEILING_SECONDS = 900.0
RUN_CEILING_SECONDS = 4 * 3600.0
MAX_DETECTION_PAGES = 5000
MAX_KB_PAGES_PER_CHUNK = 50
_EOS_TEXT = re.compile(r"end[ -]of[ -](support|life)|deprecat", re.I)
_MAX_WARNING_TEXT = 500

_BASE = {
    "action": "list",
    "status": "New,Active,Re-Opened,Fixed",
    "show_results": "1",
    "show_reopened_info": "1",
    "include_ignored": "1",
    "include_disabled": "1",
    "show_asset_id": "1",
    "host_metadata": "ec2",
    "show_cloud_tags": "1",
    "show_qds": "1",
}


class ProbeFailed(Exception):
    """The credential or the pinned version did not answer as a detection read; nothing may be written."""


@dataclass
class Plan:
    read_kind: str
    window_start: datetime | None


def plan(held: dict[str, Any] | None, standing_scope: dict[str, list[int]], now: datetime) -> Plan:
    """Complete or window, from what the grid holds of the subscription (req-qualys-detection-read)."""
    if not held or not held.get("watermark"):
        return Plan(COMPLETE, None)
    if (held.get("standing_scope") or {}) != standing_scope:
        return Plan(COMPLETE, None)
    last_complete = held.get("last_complete_read_at")
    if not last_complete or now - _as_time(last_complete) >= COMPLETE_INTERVAL:
        return Plan(COMPLETE, None)
    return Plan(WINDOW, _as_time(held["watermark"]) - WINDOW_OVERLAP)


def _as_time(value: Any) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def scope_params(scope: dict[str, list[int]]) -> dict[str, str]:
    """The standing scope as Qualys's parameters: asset groups as ``ag_ids``, tags as an any-of tag set."""
    if scope.get("asset_group_ids"):
        return {"ag_ids": ",".join(str(i) for i in scope["asset_group_ids"])}
    if scope.get("tag_ids"):
        return {"use_tags": "1", "tag_set_by": "id", "tag_include_selector": "any", "tag_set_include": ",".join(str(i) for i in scope["tag_ids"])}
    return {}


def detection_url(root: str, scope: dict[str, list[int]], window_start: datetime | None, limit: int = TRUNCATION_LIMIT, id_min: str | None = None) -> str:
    """Every detection request, built here from the run's own parameters; only ``id_min`` ever comes from Qualys."""
    params = {**_BASE, "truncation_limit": str(limit), **scope_params(scope)}
    if window_start is not None:
        params["vm_processed_after"] = window_start.strftime("%Y-%m-%dT%H:%M:%SZ")
    if id_min is not None:
        params["id_min"] = id_min
    return f"{root}{DETECTION_PATH}?{urlencode(params)}"


def next_id_min(next_url: str) -> str | None:
    """The one value a next-page link contributes: its ``id_min``, when it is a single run of digits.

    The link itself is never followed: a link that dropped a status, the scope or the window would otherwise
    broaden the read without anything noticing. The next request is rebuilt from the run's own parameters.
    """
    values = parse_qs(urlsplit(next_url).query).get("id_min", [])
    return values[0] if len(values) == 1 and values[0].isdigit() else None


def knowledgebase_url(root: str, qids: list[str]) -> str:
    return f"{root}{KNOWLEDGEBASE_PATH}?{urlencode({'action': 'list', 'details': 'All', 'show_disabled_flag': '1', 'ids': ','.join(qids)})}"


@dataclass
class LiveRead:
    """What one live read returned, and what it could not read."""

    read_kind: str
    window_start: datetime | None
    applied_filter: dict[str, Any]
    probe: dict[str, Any]
    pages: list[DetectionPage] = field(default_factory=list)
    kb_pages: list[KnowledgeBasePage] = field(default_factory=list)
    knowledgebase_asked: set[str] = field(default_factory=set)
    knowledgebase_complete: bool = True
    walk_complete: bool = True
    warnings: list[dict[str, str]] = field(default_factory=list)
    detection_pages_not_read: list[dict[str, str]] = field(default_factory=list)
    requests: int = 0


Bounded = Callable[[Callable[[], Response], str], Response]


def _limits(headers: dict[str, str]) -> dict[str, str | None]:
    """The rate-limit and concurrency headers as returned, both spellings; null where absent (req-qualys-probe-4)."""
    names = ("X-RateLimit-Limit", "X-RateLimit-Window-Sec", "X-RateLimit-Remaining", "X-RateLimit-ToWait-Sec",
             "X-Concurrency-Limit-Limit", "X-Concurrency-Limit-Running", "X-ConcurrencyLimit-Limit", "X-ConcurrencyLimit-Running")
    lowered = {k.lower(): v for k, v in headers.items()}
    return {name: lowered.get(name.lower()) for name in names}


def _eos(page: DetectionPage | KnowledgeBasePage, where: str) -> dict[str, str] | None:
    text = (page.warning or {}).get("text") or ""
    if _EOS_TEXT.search(text):
        return {"code": "API_VERSION_EOS", "detail": f"{where}: {text[:_MAX_WARNING_TEXT]}"}
    return None


def read(client: ReadOnlyClient, scope: dict[str, list[int]], the_plan: Plan, *, bounded: Bounded, clock: Callable[[], float] = time.monotonic) -> LiveRead:
    """Probe, then walk the detection pages, then the knowledge base. Raises ProbeFailed when the probe does."""
    started = clock()
    applied: dict[str, Any] = dict(scope)
    if the_plan.window_start is not None:
        applied["vm_processed_after"] = the_plan.window_start.strftime("%Y-%m-%dT%H:%M:%SZ")

    # The probe: an ordinary allowlisted read of one host. A refused credential, a scope Qualys rejects, or a
    # body that is not a detection document ends the run before anything is written (req-qualys-probe-2, -detection-read-5).
    try:
        reply = bounded(functools.partial(client.get, detection_url(client.root, scope, the_plan.window_start, limit=1)), "probe")
        probe_page = parse_detection_page(reply.body)
    except ReadFailed as exc:
        raise ProbeFailed(f"the probe was refused (HTTP {exc.status})" if exc.status else f"the probe failed: {exc}") from None
    except PageRefused as exc:
        raise ProbeFailed(f"the probe's answer is not a detection document: {exc}") from None
    except (TimeoutError, TransportRefused) as exc:
        raise ProbeFailed(f"the probe did not complete ({type(exc).__name__})") from None
    limits = _limits(reply.headers)
    # The probe's own limits, and the last response's beside them (req-qualys-probe-4): neither overwrites the other.
    result = LiveRead(the_plan.read_kind, the_plan.window_start, applied, {"detection_api_version": "6.0", "knowledgebase_api_version": "4.0", "limits": limits, "last_limits": limits})
    result.requests = 1
    if (w := _eos(probe_page, "probe")) is not None:
        result.warnings.append(w)

    def out_of_time() -> bool:
        return clock() - started >= RUN_CEILING_SECONDS

    # The detection walk.
    url: str | None = detection_url(client.root, scope, the_plan.window_start)
    while url is not None:
        if len(result.pages) >= MAX_DETECTION_PAGES or out_of_time():
            result.walk_complete = False
            result.warnings.append({"code": "TRUNCATED", "detail": f"the detection walk stopped at a ceiling after {len(result.pages)} page(s)"})
            break
        number = len(result.pages) + 1
        try:
            reply = bounded(functools.partial(client.get, url), f"detections-{number}")
            page = parse_detection_page(reply.body)
        except (ReadFailed, TransportRefused, PageRefused, TimeoutError) as exc:
            result.walk_complete = False
            result.detection_pages_not_read.append({"scope": f"detection page {number}", "reason": f"not read: {type(exc).__name__}"})
            break
        result.requests += 1
        result.probe["last_limits"] = _limits(reply.headers)
        if (w := _eos(page, f"detection page {number}")) is not None:
            result.warnings.append(w)
        result.pages.append(page)
        if page.next_url is None:
            url = None
        elif (id_min := next_id_min(page.next_url)) is None:
            result.walk_complete = False
            result.warnings.append({"code": "TRUNCATED", "detail": f"detection page {number} links onward with no usable id_min; the walk stops there"})
            url = None
        else:
            url = detection_url(client.root, scope, the_plan.window_start, id_min=id_min)

    # The knowledge base, for every QID the pages named, each chunk followed to its end (unified-systems-com/qualys-tap#16).
    named = sorted({d["qid"] for page in result.pages for host in page.hosts for d in host["detections"] if isinstance(d.get("qid"), str) and d["qid"].isdigit()}, key=int)
    result.knowledgebase_asked = set(named)
    for start in range(0, len(named), KB_CHUNK):
        # A chunk Qualys cuts short is not followed by its link: the QIDs it did not return yet are asked again,
        # by id, so every request is one this run built (unified-systems-com/qualys-tap#16).
        remaining = named[start : start + KB_CHUNK]
        for _ in range(MAX_KB_PAGES_PER_CHUNK):
            if not remaining:
                break
            if out_of_time():
                result.knowledgebase_complete = False
                break
            try:
                reply = bounded(functools.partial(client.get, knowledgebase_url(client.root, remaining)), "knowledgebase")
                kb_page = parse_knowledgebase_page(reply.body)
            except (ReadFailed, TransportRefused, PageRefused, TimeoutError):
                result.knowledgebase_complete = False
                break
            result.requests += 1
            if (w := _eos(kb_page, "knowledge base")) is not None:
                result.warnings.append(w)
            result.kb_pages.append(kb_page)
            returned = {v.get("qid") for v in kb_page.vulns}
            left = [q for q in remaining if q not in returned]
            if kb_page.next_url is None:
                break  # whole: what is left was asked and not returned
            if not returned or len(left) == len(remaining):
                # Qualys says there is more, but this page moved nothing forward: what is left is unobserved,
                # never "not returned", and asking again would only repeat the same page.
                result.knowledgebase_complete = False
                break
            remaining = left
        else:
            result.knowledgebase_complete = False
    return result
