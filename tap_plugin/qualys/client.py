"""The read-only transport to Qualys (req-qualys-transport).

Every request leaves through one ``requests.Session`` subclass whose ``send`` decides what may be sent, so
remounting an adapter or calling ``Session.request`` directly cannot bypass it, and the client never exposes
its session. ``send`` refuses, before anything is sent: any method but GET, except the one POST read below;
any URL outside the configured API host; any path but the allowlisted operations; any parameter the operation
does not name, or one in the wrong shape; and any per-request override of TLS verification, client
certificate or proxies. ``trust_env`` is
off, so no proxy, CA bundle or netrc credential is taken from the environment. Redirects are never followed;
a 3xx is an error.

Authentication is HTTP Basic with the ``X-Requested-With`` header Qualys requires; the credential reaches
``requests`` as an auth tuple, never in a URL, and no ``__repr__`` shows it. Calls are serial (one session,
one request at a time). A 409 waits only for Qualys's throttling codes (1960 concurrency, 1965 rate), honouring
``X-RateLimit-ToWait-Sec`` within a bounded count and total time; any other 409 is an error. A 1960 wait is at
least ``CONCURRENCY_WAIT_FLOOR_SECONDS``, because the header has been reported as 0 for it
(unified-systems-com/qualys-tap#48). A transient failure (a 429 or 5xx in ``TRANSIENT_STATUSES``, a refused
or reset connection, a read timeout, a body cut short) is retried up to ``MAX_TRANSIENT_RETRIES`` times with a
growing backoff, inside the same total wait bound (unified-systems-com/qualys-tap#47). A body is read in chunks
and refused past the page ceiling.

``get`` takes an optional ``bound``, which runs one attempt (the request and its body) under the caller's
wall-clock ceiling. Waits and backoff happen between attempts, outside it, so the ceiling bounds a request and
the wait budget bounds the waiting (unified-systems-com/qualys-tap#49). An attempt abandoned at the ceiling is
not retried; the client drops the session that attempt holds and builds a new one, so nothing later shares a
connection pool with a thread that may still be running. Until that attempt has finished, every further read is
refused unsent, so calls stay serial even though the lock is no longer held by the abandoned thread.

Two reads are POSTs, because Qualys offers them in no GET form, both in the Asset Management and Tagging API
(req-qualys-transport-8; ruled 2026-11-23): the tag search, which lists the subscription's tags (req-qualys-tags),
and the host asset search, which reads the inventory of hosts the detection read saw (req-qualys-host-assets).
Each body is built here from a fixed template whose only variables are digits, and ``send`` refuses any POST
whose path, query or body is not exactly that, so a POST can carry no other criteria and no write.

Two more reads are on the list for the observation command (req-qualys-observe): the two output DTDs, each a
GET with no parameters at all. An anonymous client, which holds no credential, may send only those two, so
the command can ask whether Qualys serves them without one. An optional observer sees every response
(status, response headers, the names of the request headers, and the body) so the command can record it.
"""

import functools
import http.cookiejar
import math
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import SplitResult, parse_qsl, urlsplit

import requests
from requests.adapters import HTTPAdapter
from tap_plugin.qualys.identity import canonical_api_host
from tap_plugin.qualys.parse import MAX_PAGE_BYTES

DETECTION_PATH = "/api/6.0/fo/asset/host/vm/detection/"
KNOWLEDGEBASE_PATH = "/api/4.0/fo/knowledge_base/vuln/"
DETECTION_DTD_PATH = "/api/6.0/fo/asset/host/vm/detection/dtd/output.dtd"
KNOWLEDGEBASE_DTD_PATH = "/api/4.0/fo/knowledge_base/vuln/knowledge_base_vuln_list_output.dtd"
#: The tag search of the Asset Management and Tagging API: the one POST read (req-qualys-transport-8).
TAG_SEARCH_PATH = "/qps/rest/2.0/search/am/tag"
#: Tags per tag-search page: Qualys's documented default, the one size known to be served.
TAG_PAGE_SIZE = 100
#: The host asset search of the Asset Management API: the second POST read (req-qualys-host-assets).
HOST_ASSET_SEARCH_PATH = "/qps/rest/2.0/search/am/hostasset"
#: Host assets per page (Qualys's documented default), and host ids per request's ``qwebHostId IN`` filter.
HOST_ASSET_PAGE_SIZE = 100
HOST_ASSET_IDS_PER_REQUEST = 100
#: Reads that take no parameters at all; the only ones an anonymous client may send.
PARAMETERLESS = frozenset({DETECTION_DTD_PATH, KNOWLEDGEBASE_DTD_PATH})
USER_AGENT = "qualys-tap (read-only collector)"

_DIGITS = re.compile(r"[0-9]+")
_ID_LIST = re.compile(r"[0-9]+(,[0-9]+)*")
_ISO_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_TAG_NAMES = re.compile(r"[^\x00-\x1f]{1,4096}")
#: The only body a tag-search POST may carry: preferences for paging, and nothing that filters, sorts or writes.
_TAG_SEARCH_BODY = re.compile(
    rb"<ServiceRequest><preferences>(<startFromId>[0-9]{1,19}</startFromId>)?<limitResults>[0-9]{1,4}</limitResults></preferences></ServiceRequest>"
)
#: The only body a host-asset POST may carry: paging, and one filter naming host ids, digits only, at most 100.
_HOST_ASSET_SEARCH_BODY = re.compile(
    rb"<ServiceRequest><preferences>(<startFromId>[0-9]{1,19}</startFromId>)?<limitResults>[0-9]{1,4}</limitResults></preferences>"
    rb'<filters><Criteria field="qwebHostId" operator="IN">[0-9]{1,19}(,[0-9]{1,19}){0,99}</Criteria></filters></ServiceRequest>'
)


def _pinned(*values: str) -> Callable[[str], bool]:
    return lambda v: v in values


def _shape(pattern: re.Pattern[str]) -> Callable[[str], bool]:
    return lambda v: pattern.fullmatch(v) is not None


#: The plugin's one definition of "read" (req-qualys-transport). A change here is a spec change.
ALLOWLIST: dict[str, dict[str, Callable[[str], bool]]] = {
    DETECTION_PATH: {
        "action": _pinned("list"),
        "status": _pinned("New,Active,Re-Opened,Fixed"),
        "show_results": _pinned("1"),
        "show_reopened_info": _pinned("1"),
        "include_ignored": _pinned("1"),
        "include_disabled": _pinned("1"),
        "show_asset_id": _pinned("1"),
        "host_metadata": _pinned("ec2"),
        "show_cloud_tags": _pinned("1"),
        "show_qds": _pinned("1"),
        "show_qds_factors": _pinned("1"),
        "truncation_limit": _shape(_DIGITS),
        "id_min": _shape(_DIGITS),
        "vm_processed_after": _shape(_ISO_TIME),
        "ag_ids": _shape(_ID_LIST),
        "use_tags": _pinned("1"),
        "tag_set_by": _pinned("id"),
        "tag_include_selector": _pinned("any"),
        "tag_set_include": _shape(_ID_LIST),
    },
    KNOWLEDGEBASE_PATH: {
        "action": _pinned("list"),
        "details": _pinned("All"),
        "show_disabled_flag": _pinned("1"),
        "ids": _shape(_ID_LIST),
        "last_modified_after": _shape(_ISO_TIME),
    },
    DETECTION_DTD_PATH: {},
    KNOWLEDGEBASE_DTD_PATH: {},
}

#: The POST reads: a path and the one body shape it may carry. A change here is a spec change
#: (req-qualys-transport-8): a POST is admitted only for a read Qualys offers in no GET form.
POST_READS: dict[str, re.Pattern[bytes]] = {TAG_SEARCH_PATH: _TAG_SEARCH_BODY, HOST_ASSET_SEARCH_PATH: _HOST_ASSET_SEARCH_BODY}


def tag_search_body(start_from_id: str | None, limit: int = TAG_PAGE_SIZE) -> bytes:
    """The tag-search body for one page: from ``start_from_id`` (inclusive or not; the walk copes) or the first."""
    if start_from_id is not None and not _DIGITS.fullmatch(start_from_id):
        raise TransportRefused("a tag-search start id is digits only")
    start = f"<startFromId>{start_from_id}</startFromId>" if start_from_id is not None else ""
    return f"<ServiceRequest><preferences>{start}<limitResults>{int(limit)}</limitResults></preferences></ServiceRequest>".encode()

#: Qualys's throttling return codes in a 409 body: concurrency and rate (LIM).
THROTTLE_CODES = {"1960", "1965"}
MAX_RETRIES = 8
MAX_WAIT_TOTAL_SECONDS = 1800
DEFAULT_WAIT_SECONDS = 60
#: The least a 1960 (concurrency) wait sleeps: XSOAR's integration reports the header as 0 for 1960 and waits a
#: fixed 60s (Qualysv2.py:64-70), one vendor comment and no Qualys statement, so this is a floor, not a constant.
CONCURRENCY_WAIT_FLOOR_SECONDS = 30.0
#: Answers worth asking again: too many requests, and the server-side failures a retry can outlast.
TRANSIENT_STATUSES = frozenset({429, 500, 502, 503, 504})
#: Network failures worth asking again; anything else requests raises (an invalid URL) is not.
TRANSIENT_ERRORS: tuple[type[Exception], ...] = (requests.ConnectionError, requests.Timeout, requests.exceptions.ChunkedEncodingError)
#: Subclasses of ConnectionError that are not transient: a certificate or TLS failure, or a proxy refusal (no
#: proxy is ever configured, so one means something is wrong), will not get better by waiting.
NEVER_RETRIED: tuple[type[Exception], ...] = (requests.exceptions.SSLError, requests.exceptions.ProxyError)
MAX_TRANSIENT_RETRIES = 3
TRANSIENT_BACKOFF_SECONDS = (5.0, 30.0, 120.0)
CONNECT_TIMEOUT = 15
READ_TIMEOUT = 300


class TransportRefused(Exception):
    """A request the transport will not send; the message names the rule, never a credential."""


class ReadFailed(Exception):
    """A read that did not return a usable body: an HTTP error, exhausted throttling waits, or a body too large."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class OutOfTime(ReadFailed):
    """A read the run's own ceiling ended between attempts: no attempt starts past it, and no wait starts that would reach it."""


def _check_origin(url: str, root: str) -> SplitResult:
    parts = urlsplit(url)
    if parts.username is not None or parts.password is not None or parts.fragment:
        raise TransportRefused("a URL with userinfo or a fragment is refused")
    try:
        origin = canonical_api_host(f"{parts.scheme}://{parts.netloc}")
    except ValueError as exc:
        raise TransportRefused(f"not an https API origin: {exc}") from exc
    if origin != root:
        raise TransportRefused("a URL outside the configured API host is refused")
    return parts


def host_asset_search_body(host_ids: list[str], start_from_id: str | None, limit: int = HOST_ASSET_PAGE_SIZE) -> bytes:
    """The host-asset search body for one page of these hosts (by Qualys host id), from ``start_from_id`` or the first."""
    if not host_ids or len(host_ids) > HOST_ASSET_IDS_PER_REQUEST or not all(_DIGITS.fullmatch(i) for i in host_ids):
        raise TransportRefused(f"a host-asset search names 1 to {HOST_ASSET_IDS_PER_REQUEST} host ids, digits only")
    if start_from_id is not None and not _DIGITS.fullmatch(start_from_id):
        raise TransportRefused("a host-asset start id is digits only")
    start = f"<startFromId>{start_from_id}</startFromId>" if start_from_id is not None else ""
    return (f"<ServiceRequest><preferences>{start}<limitResults>{int(limit)}</limitResults></preferences>"
            f'<filters><Criteria field="qwebHostId" operator="IN">{",".join(host_ids)}</Criteria></filters></ServiceRequest>').encode()


def check_post(url: str, body: Any, root: str) -> str:
    """The path of an admitted POST read under ``root``, with its body; refuse anything else."""
    parts = _check_origin(url, root)
    if parts.path not in POST_READS:
        raise TransportRefused("only GET is sent, except the allowlisted POST reads")
    if parts.query:
        raise TransportRefused(f"the POST to {parts.path} takes no query")
    if not isinstance(body, bytes) or POST_READS[parts.path].fullmatch(body) is None:
        raise TransportRefused(f"the POST to {parts.path} carries a body of the wrong shape")
    return parts.path


def check_url(url: str, root: str) -> tuple[str, dict[str, str]]:
    """The operation path and parameters of an allowlisted URL under ``root``; refuse anything else."""
    parts = _check_origin(url, root)
    if parts.path not in ALLOWLIST:
        raise TransportRefused("a path outside the allowlist is refused")
    if parts.path in PARAMETERLESS:
        if parts.query:
            raise TransportRefused(f"{parts.path} takes no parameters")
        return parts.path, {}
    pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=bool(parts.query))
    params: dict[str, str] = {}
    rules = ALLOWLIST[parts.path]
    for name, value in pairs:
        if name in params:
            raise TransportRefused(f"parameter {name} given twice")
        if name not in rules:
            raise TransportRefused(f"parameter {name} is not allowlisted for {parts.path}")
        if not rules[name](value):
            raise TransportRefused(f"parameter {name} has a value of the wrong shape")
        params[name] = value
    if params.get("action") != "list":
        raise TransportRefused("every read carries action=list")
    return parts.path, params


class _GuardedSession(requests.Session):
    """A session whose ``send`` admits only allowlisted GETs, and the allowlisted POST reads, to one API host."""

    def __init__(self, root: str, verify: bool | str) -> None:
        super().__init__()
        self._root = root
        self._verify = verify
        self.trust_env = False
        # Stateless: no cookie Qualys sets is kept or sent back, so the only credential is Basic auth.
        self.cookies.set_policy(http.cookiejar.DefaultCookiePolicy(allowed_domains=[]))

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:  # type: ignore[override]
        if request.method == "POST":
            check_post(request.url or "", request.body, self._root)
            if request.headers.get("Content-Type") != "text/xml":
                raise TransportRefused("a POST read is sent as text/xml")
        elif request.method != "GET":
            raise TransportRefused("only GET is sent, except the allowlisted POST reads")
        elif request.body is not None:
            raise TransportRefused("a request with a body is refused")
        if kwargs.get("verify") is False or kwargs.get("verify") != self._verify:
            raise TransportRefused("TLS verification cannot be overridden")
        if kwargs.get("cert") or kwargs.get("proxies"):
            raise TransportRefused("a client certificate or proxy cannot be set per request")
        if "Cookie" in request.headers:
            raise TransportRefused("a request carrying a cookie is refused")
        if kwargs.get("allow_redirects", True):
            raise TransportRefused("redirects are never followed")
        path = urlsplit(request.url or "").path if request.method == "POST" else check_url(request.url or "", self._root)[0]
        # Only a username and a password, both present, make a credentialed client; anything less reads as anonymous.
        credentialed = isinstance(self.auth, tuple) and len(self.auth) == 2 and all(self.auth)
        if not credentialed and path not in PARAMETERLESS:
            raise TransportRefused("an anonymous client may read only the DTDs")
        return super().send(request, **kwargs)


@dataclass
class Response:
    """A read's body and the headers worth recording (no credential-bearing header is kept)."""

    url: str
    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)
    waits: int = 0


@dataclass
class Exchange:
    """One response as the observer sees it: never the request headers' values, never a ``Set-Cookie``."""

    url: str
    status: int
    response_headers: dict[str, str]
    request_header_names: list[str]
    body: bytes
    #: Why the body was not read whole (too large, or the stream broke); None when it was. The observer still sees
    #: the status and headers of a response the transport refused to read.
    body_not_read: str | None = None


Observer = Callable[[Exchange], None]

_RECORDED = re.compile(r"^x-(ratelimit|concurrency-?limit)-", re.I)


class ReadOnlyClient:
    """Allowlisted reads from one Qualys platform, as one user. Holds the credential; never shows it."""

    def __init__(
        self,
        api_host: str,
        username: str,
        password: str,
        *,
        ca_bundle: str | None = None,
        adapter: HTTPAdapter | None = None,
        sleep: Callable[[float], None] = time.sleep,
        observer: Observer | None = None,
        retry_transient: bool = True,
        _anonymous: bool = False,
    ) -> None:
        if not _anonymous and not (username and password):
            raise TransportRefused("a credentialed client needs a username and a password; use ReadOnlyClient.anonymous for none")
        self._root = canonical_api_host(api_host)
        self._verify: bool | str = ca_bundle or True
        self._auth = None if _anonymous else (username, password)
        self._adapter = adapter
        self._session = self._new_session()
        self._observer = observer
        self._retry_transient = retry_transient
        self._sleep = sleep
        #: An attempt abandoned at the ceiling that had already started, while it may still be running.
        self._abandoned: _Attempt | None = None
        # Calls are serial: one request (and its throttling waits) at a time, whatever the caller's threads do.
        self._lock = threading.Lock()

    def _new_session(self) -> _GuardedSession:
        # Without an injected adapter (every production caller), the session builds its own HTTPAdapter, so a
        # replacement session holds a new connection pool. An injected adapter is a test seam and is shared.
        session = _GuardedSession(self._root, self._verify)
        session.auth = self._auth
        session.headers.update({"X-Requested-With": USER_AGENT, "User-Agent": USER_AGENT})
        if self._adapter is not None:
            session.mount("https://", self._adapter)
        return session

    @classmethod
    def anonymous(
        cls,
        api_host: str,
        *,
        ca_bundle: str | None = None,
        adapter: HTTPAdapter | None = None,
        observer: Observer | None = None,
        retry_transient: bool = True,
    ) -> ReadOnlyClient:
        """A client with no credential at all, which may read only the DTDs (req-qualys-observe)."""
        return cls(api_host, "", "", ca_bundle=ca_bundle, adapter=adapter, observer=observer, retry_transient=retry_transient, _anonymous=True)

    def __repr__(self) -> str:
        return f"ReadOnlyClient({self._root})"

    @property
    def root(self) -> str:
        return self._root

    def get(self, url: str, *, bound: Bound | None = None, remaining: Callable[[], float] | None = None) -> Response:
        """One allowlisted read, waiting out Qualys's throttling and transient failures within the bounds.

        ``bound``, when given, runs each attempt under the caller's ceiling; the waits between attempts are not
        inside it. A ``TimeoutError`` from it ends the read: the attempt is abandoned, not retried. ``remaining``,
        when given, is the seconds left on the caller's run: no attempt starts once it has passed, and no wait starts
        that would reach it, so a run overshoots its ceiling by at most one attempt, plus however late a sleep returns
        (PR #62 rounds 4 and 5).
        """
        check_url(url, self._root)
        with self._lock:
            return self._get(url, bound, remaining)

    def search_tags(self, start_from_id: str | None, *, bound: Bound | None = None, remaining: Callable[[], float] | None = None) -> Response:
        """One page of the subscription's tags, by the one POST read; the same waits and bounds as ``get``."""
        url, body = f"{self._root}{TAG_SEARCH_PATH}", tag_search_body(start_from_id)
        check_post(url, body, self._root)
        with self._lock:
            return self._get(url, bound, remaining, body)

    def search_host_assets(
        self, host_ids: list[str], start_from_id: str | None, *, bound: Bound | None = None, remaining: Callable[[], float] | None = None
    ) -> Response:
        """One page of these hosts' asset records, by the second POST read; the same waits and bounds as ``get``."""
        url, body = f"{self._root}{HOST_ASSET_SEARCH_PATH}", host_asset_search_body(host_ids, start_from_id)
        check_post(url, body, self._root)
        with self._lock:
            return self._get(url, bound, remaining, body)

    def _get(self, url: str, bound: Bound | None, remaining: Callable[[], float] | None, body: bytes | None = None) -> Response:
        if self._abandoned is not None:
            if not self._abandoned.finished.is_set():
                # Qualys's concurrency limit is shared by every integration on the subscription; a second request
                # while the abandoned one may still be in flight would break the serial rule (PR #62 round 2).
                raise ReadFailed("a request abandoned at the ceiling is still running; reads stay serial until it ends")
            self._abandoned = None
        waited, transient = 0.0, 0
        for attempt in range(MAX_RETRIES + MAX_TRANSIENT_RETRIES + 1):
            if remaining is not None and remaining() <= 0:
                raise OutOfTime("the run's ceiling passed before this attempt")
            session, state = self._session, _Attempt()
            run = functools.partial(_attempt, session, url, self._verify, state, body)
            try:
                outcome = bound(run) if bound else run()
            except TimeoutError:
                # The abandoned attempt may still be running on this session; nothing later may share it, and
                # nothing later may run beside it.
                self._session = self._new_session()
                if state.abandon():  # it started, so it may still be sending: hold every read until it ends
                    self._abandoned = state
                raise
            if outcome.raw is not None:
                self._observe(url, outcome.raw, outcome.prepared, outcome.body, outcome.not_read)
            wait: float | None = None
            if outcome.error is not None:
                if not (self._retry_transient and _transient(outcome.error)):
                    raise outcome.error
                wait, transient = _backoff(transient), transient + 1
            else:
                raw = outcome.raw
                assert raw is not None
                headers = {k: v for k, v in raw.headers.items() if _RECORDED.match(k)}
                if raw.status_code == 200:
                    return Response(url=url, status=200, body=outcome.body, headers=headers, waits=attempt)
                if raw.status_code == 409 and (code := _return_code(outcome.body)) in THROTTLE_CODES:
                    wait = _wait_seconds(raw.headers)
                    if code == "1960":
                        wait = max(wait, CONCURRENCY_WAIT_FLOOR_SECONDS)
                    if attempt - transient >= MAX_RETRIES:
                        raise ReadFailed("throttled past the retry bound", status=409)
                elif self._retry_transient and raw.status_code in TRANSIENT_STATUSES:
                    wait, transient = _backoff(transient), transient + 1
                elif 300 <= raw.status_code < 400:
                    raise ReadFailed("Qualys answered with a redirect, which is never followed", status=raw.status_code)
                else:
                    raise ReadFailed(f"Qualys answered HTTP {raw.status_code}", status=raw.status_code)
            if wait is None or waited + wait > MAX_WAIT_TOTAL_SECONDS:
                raise _exhausted(outcome)
            if remaining is not None and wait >= remaining():
                raise OutOfTime("the run's ceiling would pass during the wait")
            self._sleep(wait)
            waited += wait
        raise ReadFailed("retried past the bound")  # unreachable: the counts above end the loop first

    def _observe(self, url: str, raw: requests.Response, prepared: requests.PreparedRequest, body: bytes, not_read: str | None) -> None:
        if self._observer is None:
            return
        self._observer(Exchange(
            url=url,
            status=raw.status_code,
            response_headers={k: v for k, v in raw.headers.items() if k.lower() != "set-cookie"},
            request_header_names=sorted(prepared.headers.keys()),
            body=body,
            body_not_read=not_read,
        ))



def _read(raw: requests.Response) -> bytes:
    chunks, total = [], 0
    for chunk in raw.iter_content(chunk_size=1 << 16):
        total += len(chunk)
        if total > MAX_PAGE_BYTES:
            raise ReadFailed(f"response larger than {MAX_PAGE_BYTES} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


@dataclass
class _Outcome:
    """One attempt, returned rather than applied, so an attempt run on another thread changes nothing it does not own."""

    prepared: requests.PreparedRequest
    raw: requests.Response | None = None
    body: bytes = b""
    not_read: str | None = None
    error: Exception | None = None


class _Attempt:
    """Whether one attempt has started, been abandoned, or finished: its only effect on anything the caller holds.

    Starting and abandoning are decided under one lock, so exactly one of two things is true once the caller gives
    up: the attempt had started, and the client holds every read until ``finished`` (PR #62 round 2); or it had
    not, and it never sends (PR #62 round 3, an attempt whose thread was slow to start).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started = self._abandoned = False
        self.finished = threading.Event()

    def start(self) -> bool:
        with self._lock:
            self._started = not self._abandoned
            return self._started

    def abandon(self) -> bool:
        """Mark abandoned; True when the attempt had already started and may still be running."""
        with self._lock:
            self._abandoned = True
            return self._started


def _attempt(session: requests.Session, url: str, verify: bool | str, state: _Attempt, body: bytes | None = None) -> _Outcome:
    """Send one request and read its body. Network errors come back in the outcome; only refusals raise."""
    if not state.start():
        return _Outcome(requests.PreparedRequest(), error=TimeoutError("abandoned before it started"))  # never sent
    try:
        return _send_and_read(session, url, verify, body)
    finally:
        state.finished.set()


def _send_and_read(session: requests.Session, url: str, verify: bool | str, body: bytes | None = None) -> _Outcome:
    if body is None:
        prepared = session.prepare_request(requests.Request("GET", url))
    else:
        prepared = session.prepare_request(requests.Request("POST", url, data=body, headers={"Content-Type": "text/xml"}))
    try:
        raw = session.send(prepared, verify=verify, allow_redirects=False, stream=True, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
    except requests.RequestException as exc:
        return _Outcome(prepared, error=exc)
    try:
        return _Outcome(prepared, raw, _read(raw))
    except ReadFailed as exc:
        return _Outcome(prepared, raw, not_read=str(exc), error=exc)
    except requests.RequestException as exc:
        return _Outcome(prepared, raw, not_read=type(exc).__name__, error=exc)
    finally:
        raw.close()


Bound = Callable[[Callable[[], _Outcome]], _Outcome]


def _transient(error: Exception) -> bool:
    return isinstance(error, TRANSIENT_ERRORS) and not isinstance(error, NEVER_RETRIED)


def _backoff(transient: int) -> float | None:
    """The wait before the next try of a transient failure; None once the retries are spent."""
    return TRANSIENT_BACKOFF_SECONDS[transient] if transient < MAX_TRANSIENT_RETRIES else None


def _exhausted(outcome: _Outcome) -> Exception:
    if outcome.raw is not None and outcome.raw.status_code == 409:
        return ReadFailed("throttled past the retry bound", status=409)
    if outcome.error is not None:
        return outcome.error  # the network error itself, so the caller records its type
    status = outcome.raw.status_code if outcome.raw is not None else None
    return ReadFailed(f"Qualys answered HTTP {status}, past the transient retry bound", status=status)


def _return_code(body: bytes) -> str | None:
    """The CODE in a Qualys SIMPLE_RETURN body, read without an XML parser (the body is small and untrusted)."""
    m = re.search(rb"<CODE>\s*(\d{1,6})\s*</CODE>", body[:65536])
    return m.group(1).decode() if m else None


def _wait_seconds(headers: Any) -> float:
    value = headers.get("X-RateLimit-ToWait-Sec")
    try:
        wait = float(value) if value is not None else DEFAULT_WAIT_SECONDS
    except ValueError:
        wait = DEFAULT_WAIT_SECONDS
    if not math.isfinite(wait):
        wait = DEFAULT_WAIT_SECONDS  # NaN and infinity fall back like any other malformed value
    return min(max(wait, 1.0), MAX_WAIT_TOTAL_SECONDS)
