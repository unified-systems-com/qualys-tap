"""One live read of a Qualys subscription through the read-only transport (req-qualys-probe, -detection-read).

The plan: a subscription the grid has never read, or whose standing scope changed, or whose last complete read
is older than the complete-read interval, gets a **complete** read; any other gets a **window** read from its
watermark less a fixed overlap. The read: a probe (the first detection page at ``truncation_limit=1``), then
every detection page by Qualys's next-page link, then the knowledge base for every QID named, in chunks, each
followed to its end. Every request goes through :class:`~tap_plugin.qualys.client.ReadOnlyClient`, so nothing
but an allowlisted GET can leave, and every request is bounded by a wall-clock ceiling.

The probe failing ends the read with nothing to write. A page failing later stops the walk: what was read is
kept, the walk is recorded incomplete, and the watermark does not move. That holds for a network error
(a reset, a read timeout) as much as for an HTTP error: neither may discard the pages already read
(unified-systems-com/qualys-tap#46). Nothing here touches the grid.

Each source (detections, knowledge base, tags) is read only when the envelope leaves it on, which is the
default (req-qualys-sources). A source switched off is listed on the run as not read, never as empty: with
detections off the walk is incomplete, so nothing is withdrawn and the watermark stays; with the knowledge base
off no QID was asked, so a stub's knowledge-base state is unobserved. The probe runs whatever is switched off,
because it is how the credential is checked.

With tags on, the read ends with the subscription's tags, by the tag search (req-qualys-tags). It pages by tag id until Qualys says there are no
more, and it is complete only then: a page not read, a page that does not say whether more follow, a page that
moves nothing forward, a tag below where its page started, or a tag with no usable id leaves it incomplete. A
failed tag read never touches the detection read.
"""

import functools
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import requests
from tap_plugin.qualys.client import (
    DETECTION_PATH,
    HOST_ASSET_IDS_PER_REQUEST,
    KNOWLEDGEBASE_PATH,
    ReadFailed,
    ReadOnlyClient,
    Response,
    TransportRefused,
)
from tap_plugin.qualys.parse import (
    DetectionPage,
    EmptyBody,
    KnowledgeBasePage,
    PageRefused,
    parse_detection_page,
    parse_host_asset_page,
    parse_knowledgebase_page,
    parse_tag_page,
)
from tap_plugin.qualys.read_kind import COMPLETE, WINDOW

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
#: is checked before each request starts. The per-request ceiling bounds each attempt, not the waits between
#: attempts, which the transport bounds by MAX_WAIT_TOTAL_SECONDS (unified-systems-com/qualys-tap#49).
READ_CEILING_SECONDS = 900.0
RUN_CEILING_SECONDS = 4 * 3600.0
MAX_DETECTION_PAGES = 5000
MAX_KB_PAGES_PER_CHUNK = 50
#: Tag-search pages per run: 200,000 tags at the page size, far past any subscription's tag count.
MAX_TAG_PAGES = 2000
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
    "show_qds_factors": "1",
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


def detection_url(
    root: str,
    scope: dict[str, list[int]],
    window_start: datetime | None,
    limit: int = TRUNCATION_LIMIT,
    id_min: str | None = None,
    omit: frozenset[str] = frozenset(),
) -> str:
    """Every detection request, built here from the run's own parameters; only ``id_min`` ever comes from Qualys.

    ``omit`` drops fixed parameters; only the observation command uses it, to ask what Qualys returns without them.
    """
    params = {**{k: v for k, v in _BASE.items() if k not in omit}, "truncation_limit": str(limit), **scope_params(scope)}
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
class TagRead:
    """What the tag search returned: every tag once, by id, and whether the list is the whole list."""

    tags: list[dict[str, Any]] = field(default_factory=list)
    complete: bool = False
    pages: int = 0
    not_read: list[dict[str, str]] = field(default_factory=list)
    warnings: list[dict[str, str]] = field(default_factory=list)
    unkeyable: int = 0


@dataclass
class HostAssetRead:
    """The host asset search for the hosts the detection read saw: each one's inventory, by Qualys host id."""

    assets: dict[str, dict[str, Any]] = field(default_factory=dict)
    complete: bool = False
    pages: int = 0
    not_read: list[dict[str, str]] = field(default_factory=list)
    warnings: list[dict[str, str]] = field(default_factory=list)


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
    #: None when the envelope switched tags off; the tags otherwise, complete or not.
    tags: TagRead | None = None
    #: None unless the envelope switched host assets on; each read host's inventory otherwise (req-qualys-host-assets).
    host_assets: HostAssetRead | None = None
    #: The sources the envelope switched off, each recorded on the run as not read (req-qualys-sources).
    switched_off: list[str] = field(default_factory=list)


#: Runs one attempt under the per-request ceiling, raising TimeoutError past it. The client calls it per attempt,
#: so the waits between attempts are outside it (unified-systems-com/qualys-tap#49).
Bounded = Callable[[Callable[[], Any], str], Any]


def _get(client: ReadOnlyClient, url: str, bounded: Bounded, what: str, remaining: Callable[[], float]) -> Response:
    return client.get(url, bound=functools.partial(_bound_attempt, bounded, what), remaining=remaining)


def _bound_attempt(bounded: Bounded, what: str, attempt: Callable[[], Any]) -> Any:
    return bounded(attempt, what)


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


def read_tags(client: ReadOnlyClient, *, bounded: Bounded, time_left: Callable[[], float]) -> TagRead:
    """Every tag the credential can see, page by page by tag id (req-qualys-tags).

    Whether ``startFromId`` includes the id it names is not documented, so the next page starts at the last
    id seen and a tag already held is skipped: either reading gives every tag once.
    """
    got = TagRead()
    seen: dict[str, dict[str, Any]] = {}
    start: str | None = None
    for number in range(1, MAX_TAG_PAGES + 1):
        if time_left() <= 0:
            got.warnings.append({"code": "TRUNCATED", "detail": f"the tag search stopped at the run's ceiling after {got.pages} page(s)"})
            break
        try:
            reply = client.search_tags(start, bound=functools.partial(_bound_attempt, bounded, f"tags-{number}"), remaining=time_left)
            page = parse_tag_page(reply.body)
        except (ReadFailed, TransportRefused, PageRefused, TimeoutError, requests.RequestException) as exc:
            got.not_read.append({"scope": f"tag page {number}", "reason": f"not read: {type(exc).__name__}"})
            break
        got.pages += 1
        out_of_order = False
        new: list[int] = []
        for tag in page.tags:
            tag_id = tag.get("tag_id")
            if not (isinstance(tag_id, str) and tag_id.isdigit() and len(tag_id) <= 32):
                got.unkeyable += 1
                continue
            if tag_id in seen:
                continue
            if start is not None and int(tag_id) < int(start):
                out_of_order = True  # the walk assumes id order; a tag below the start means it may have skipped one
            seen[tag_id] = tag
            new.append(int(tag_id))
        if out_of_order:
            got.warnings.append({"code": "TRUNCATED", "detail": f"tag page {number} returned a tag below its start id; the list may have gaps"})
            break
        if page.has_more is False:
            got.complete = got.unkeyable == 0
            break
        if page.has_more is None:
            got.warnings.append({"code": "TRUNCATED", "detail": f"tag page {number} did not say whether more tags follow"})
            break
        last = int(page.last_id) if page.last_id and page.last_id.isdigit() else max(new, default=None)
        if not new or last is None or (start is not None and last <= int(start)):
            got.warnings.append({"code": "TRUNCATED", "detail": f"tag page {number} said more tags follow but moved nothing forward"})
            break
        start = str(last)
    else:
        got.warnings.append({"code": "TRUNCATED", "detail": f"the tag search stopped at {MAX_TAG_PAGES} pages"})
    got.tags = list(seen.values())
    return got


def read_host_assets(client: ReadOnlyClient, host_ids: list[str], *, bounded: Bounded, time_left: Callable[[], float]) -> HostAssetRead:
    """Each host's asset record, asked by Qualys host id in groups of at most 100, each group paged to its end."""
    got = HostAssetRead()
    groups = [host_ids[i : i + HOST_ASSET_IDS_PER_REQUEST] for i in range(0, len(host_ids), HOST_ASSET_IDS_PER_REQUEST)]
    whole = True
    for number, group in enumerate(groups, 1):
        start: str | None = None
        for page_number in range(1, MAX_TAG_PAGES + 1):
            if time_left() <= 0:
                got.warnings.append({"code": "TRUNCATED", "detail": f"the host asset search stopped at the run's ceiling in group {number}"})
                return got
            try:
                reply = client.search_host_assets(group, start, bound=functools.partial(_bound_attempt, bounded, f"host-assets-{number}-{page_number}"), remaining=time_left)
                page = parse_host_asset_page(reply.body)
            except (ReadFailed, TransportRefused, PageRefused, TimeoutError, requests.RequestException) as exc:
                got.not_read.append({"scope": f"host asset group {number} page {page_number}", "reason": f"not read: {type(exc).__name__}"})
                whole = False
                break
            got.pages += 1
            new = [a for a in page.assets if a.get("qweb_host_id") in group and a["qweb_host_id"] not in got.assets]
            for asset in new:
                got.assets[asset["qweb_host_id"]] = asset
            if page.has_more is False:
                break
            ids = [int(a["host_asset_id"]) for a in page.assets if (a.get("host_asset_id") or "").isdigit()]
            last = int(page.last_id) if page.last_id and page.last_id.isdigit() else max(ids, default=None)
            if page.has_more is None or last is None or (start is not None and last <= int(start)):
                got.warnings.append({"code": "TRUNCATED", "detail": f"host asset group {number} page {page_number} could not prove the end of its list"})
                whole = False
                break
            start = str(last)
    got.complete = whole
    return got


def read(
    client: ReadOnlyClient,
    scope: dict[str, list[int]],
    the_plan: Plan,
    *,
    bounded: Bounded,
    clock: Callable[[], float] = time.monotonic,
    sources: dict[str, bool] | None = None,
) -> LiveRead:
    """Probe, then each source switched on: detections, the knowledge base, the tags. Raises ProbeFailed when the probe does.

    ``sources`` None reads detections and the knowledge base and not the tags, for callers that predate the switches.
    """
    on = {"detections": True, "knowledgebase": True, "tags": False, "host_assets": False, **(sources or {})}
    started = clock()

    def time_left() -> float:
        return RUN_CEILING_SECONDS - (clock() - started)

    applied: dict[str, Any] = dict(scope)
    if the_plan.window_start is not None:
        applied["vm_processed_after"] = the_plan.window_start.strftime("%Y-%m-%dT%H:%M:%SZ")

    # The probe: an ordinary allowlisted read of one host. A refused credential, a scope Qualys rejects, or a
    # body that is not a detection document ends the run before anything is written (req-qualys-probe-2, -detection-read-5).
    try:
        reply = _get(client, detection_url(client.root, scope, the_plan.window_start, limit=1), bounded, "probe", time_left)
        probe_page = parse_detection_page(reply.body)
    # Fixed messages only: nothing a response said, and no exception's own text, reaches the run's record.
    except ReadFailed as exc:
        raise ProbeFailed(f"the probe was refused (HTTP {exc.status})" if exc.status else "the probe read did not return a usable body") from None
    except EmptyBody:
        raise ProbeFailed("the probe's answer was empty") from None
    except PageRefused:
        raise ProbeFailed("the probe's answer is not a detection document") from None
    except (TimeoutError, TransportRefused, requests.RequestException) as exc:
        raise ProbeFailed(f"the probe did not complete ({type(exc).__name__})") from None
    limits = _limits(reply.headers)
    # The probe's own limits, and the last response's beside them (req-qualys-probe-4): neither overwrites the other.
    result = LiveRead(the_plan.read_kind, the_plan.window_start, applied, {"detection_api_version": "6.0", "knowledgebase_api_version": "4.0", "limits": limits, "last_limits": limits})
    result.requests = 1
    if (w := _eos(probe_page, "probe")) is not None:
        result.warnings.append(w)
    result.switched_off = [name for name in ("detections", "knowledgebase", "tags", "host_assets") if not on[name]]

    def out_of_time() -> bool:
        return time_left() <= 0

    # The detection walk. Switched off, it is not complete, so the read withdraws nothing and the watermark stays.
    url: str | None = detection_url(client.root, scope, the_plan.window_start)
    if not on["detections"]:
        result.walk_complete = False
        url = None
    while url is not None:
        if len(result.pages) >= MAX_DETECTION_PAGES or out_of_time():
            result.walk_complete = False
            result.warnings.append({"code": "TRUNCATED", "detail": f"the detection walk stopped at a ceiling after {len(result.pages)} page(s)"})
            break
        number = len(result.pages) + 1
        try:
            reply = _get(client, url, bounded, f"detections-{number}", time_left)
            page = parse_detection_page(reply.body)
        except (ReadFailed, TransportRefused, PageRefused, TimeoutError, requests.RequestException) as exc:
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
    if not on["knowledgebase"]:
        named = []  # nothing asked, so a QID the grid does not hold stays unobserved, never "not returned"
        result.knowledgebase_complete = False
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
                reply = _get(client, knowledgebase_url(client.root, remaining), bounded, "knowledgebase", time_left)
                kb_page = parse_knowledgebase_page(reply.body)
            except (ReadFailed, TransportRefused, PageRefused, TimeoutError, requests.RequestException):
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

    if on["host_assets"]:
        hosts = sorted({h["host_id"] for page in result.pages for h in page.hosts if isinstance(h.get("host_id"), str) and h["host_id"].isdigit()}, key=int)
        result.host_assets = read_host_assets(client, hosts, bounded=bounded, time_left=time_left) if hosts else HostAssetRead(complete=True)
        result.requests += result.host_assets.pages

    if on["tags"]:
        result.tags = read_tags(client, bounded=bounded, time_left=time_left)
        result.requests += result.tags.pages
    return result
