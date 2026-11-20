"""The read-only transport to Qualys (req-qualys-transport).

Every request leaves through one ``requests.Session`` subclass whose ``send`` decides what may be sent, so
remounting an adapter or calling ``Session.request`` directly cannot bypass it, and the client never exposes
its session. ``send`` refuses, before anything is sent: any method but GET; any URL outside the configured API
host; any path but the two allowlisted operations; any parameter the operation does not name, or one in the
wrong shape; and any per-request override of TLS verification, client certificate or proxies. ``trust_env`` is
off, so no proxy, CA bundle or netrc credential is taken from the environment. Redirects are never followed;
a 3xx is an error.

Authentication is HTTP Basic with the ``X-Requested-With`` header Qualys requires; the credential reaches
``requests`` as an auth tuple, never in a URL, and no ``__repr__`` shows it. Calls are serial (one session,
one request at a time). A 409 waits only for Qualys's throttling codes (1960 concurrency, 1965 rate), honouring
``X-RateLimit-ToWait-Sec`` within a bounded count and total time; any other 409 is an error. A body is read
in chunks and refused past the page ceiling.
"""

import math
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import requests
from requests.adapters import HTTPAdapter

from tap_plugin.qualys.identity import canonical_api_host
from tap_plugin.qualys.parse import MAX_PAGE_BYTES

DETECTION_PATH = "/api/6.0/fo/asset/host/vm/detection/"
KNOWLEDGEBASE_PATH = "/api/4.0/fo/knowledge_base/vuln/"
USER_AGENT = "qualys-tap (read-only collector)"

_DIGITS = re.compile(r"[0-9]+")
_ID_LIST = re.compile(r"[0-9]+(,[0-9]+)*")
_ISO_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_TAG_NAMES = re.compile(r"[^\x00-\x1f]{1,4096}")


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
}

#: Qualys's throttling return codes in a 409 body: concurrency and rate (LIM).
THROTTLE_CODES = {"1960", "1965"}
MAX_RETRIES = 8
MAX_WAIT_TOTAL_SECONDS = 1800
DEFAULT_WAIT_SECONDS = 60
CONNECT_TIMEOUT = 15
READ_TIMEOUT = 300


class TransportRefused(Exception):
    """A request the transport will not send; the message names the rule, never a credential."""


class ReadFailed(Exception):
    """A read that did not return a usable body: an HTTP error, exhausted throttling waits, or a body too large."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def check_url(url: str, root: str) -> tuple[str, dict[str, str]]:
    """The operation path and parameters of an allowlisted URL under ``root``; refuse anything else."""
    parts = urlsplit(url)
    if parts.username is not None or parts.password is not None or parts.fragment:
        raise TransportRefused("a URL with userinfo or a fragment is refused")
    try:
        origin = canonical_api_host(f"{parts.scheme}://{parts.netloc}")
    except ValueError as exc:
        raise TransportRefused(f"not an https API origin: {exc}") from exc
    if origin != root:
        raise TransportRefused("a URL outside the configured API host is refused")
    if parts.path not in ALLOWLIST:
        raise TransportRefused("a path outside the allowlist is refused")
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
    """A session whose ``send`` admits only allowlisted GETs to one API host."""

    def __init__(self, root: str, verify: bool | str) -> None:
        super().__init__()
        self._root = root
        self._verify = verify
        self.trust_env = False

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:  # type: ignore[override]
        if request.method != "GET":
            raise TransportRefused("only GET is sent")
        if request.body is not None:
            raise TransportRefused("a request with a body is refused")
        if kwargs.get("verify") is False or kwargs.get("verify") != self._verify:
            raise TransportRefused("TLS verification cannot be overridden")
        if kwargs.get("cert") or kwargs.get("proxies"):
            raise TransportRefused("a client certificate or proxy cannot be set per request")
        if kwargs.get("allow_redirects", True):
            raise TransportRefused("redirects are never followed")
        check_url(request.url or "", self._root)
        return super().send(request, **kwargs)


@dataclass
class Response:
    """A read's body and the headers worth recording (no credential-bearing header is kept)."""

    url: str
    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)
    waits: int = 0


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
    ) -> None:
        self._root = canonical_api_host(api_host)
        self._verify: bool | str = ca_bundle or True
        self._session = _GuardedSession(self._root, self._verify)
        self._session.auth = (username, password)
        self._session.headers.update({"X-Requested-With": USER_AGENT, "User-Agent": USER_AGENT})
        if adapter is not None:
            self._session.mount("https://", adapter)
        self._sleep = sleep
        # Calls are serial: one request (and its throttling waits) at a time, whatever the caller's threads do.
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"ReadOnlyClient({self._root})"

    @property
    def root(self) -> str:
        return self._root

    def get(self, url: str) -> Response:
        """One allowlisted read, waiting out Qualys's throttling within the bounds."""
        check_url(url, self._root)
        with self._lock:
            return self._get(url)

    def _get(self, url: str) -> Response:
        waited = 0.0
        for attempt in range(MAX_RETRIES + 1):
            raw = self._session.send(
                self._session.prepare_request(requests.Request("GET", url)),
                verify=self._verify,
                allow_redirects=False,
                stream=True,
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )
            try:
                body = self._read(raw)
            finally:
                raw.close()
            headers = {k: v for k, v in raw.headers.items() if _RECORDED.match(k)}
            if raw.status_code == 200:
                return Response(url=url, status=200, body=body, headers=headers, waits=attempt)
            if raw.status_code == 409 and _return_code(body) in THROTTLE_CODES:
                wait = _wait_seconds(raw.headers)
                if attempt == MAX_RETRIES or waited + wait > MAX_WAIT_TOTAL_SECONDS:
                    raise ReadFailed("throttled past the retry bound", status=409)
                self._sleep(wait)
                waited += wait
                continue
            if 300 <= raw.status_code < 400:
                raise ReadFailed("Qualys answered with a redirect, which is never followed", status=raw.status_code)
            raise ReadFailed(f"Qualys answered HTTP {raw.status_code}", status=raw.status_code)
        raise ReadFailed("throttled past the retry bound", status=409)  # unreachable; the loop returns or raises

    @staticmethod
    def _read(raw: requests.Response) -> bytes:
        chunks, total = [], 0
        for chunk in raw.iter_content(chunk_size=1 << 16):
            total += len(chunk)
            if total > MAX_PAGE_BYTES:
                raise ReadFailed(f"response larger than {MAX_PAGE_BYTES} bytes")
            chunks.append(chunk)
        return b"".join(chunks)


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
