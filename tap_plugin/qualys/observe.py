"""The observation command: record what one Qualys subscription returns, and settle the ledger (req-qualys-observe).

For whoever first tests the plugin against a real subscription. It reads through the same read-only client as
the collector, so nothing but an allowlisted GET can leave, in a fixed order:

1. the probe (one host);
2. one full detection page;
3. the knowledge-base records for that page's QIDs;
4. two comparison reads the ledger needs: one host without ``host_metadata``, and, when the page holds an
   ignored or disabled detection, the same page without ``include_ignored`` and ``include_disabled``;
5. the two output DTDs, first with no credential, then with one if that was refused.

Every response is saved as one file under a private directory (owner-only, outside any repository): a JSON
header line with the URL, status, response headers minus ``Set-Cookie`` and the names of the request headers,
then a blank line, then the body exactly as received. Nothing is written to the grid.

The report prints statuses, counts and element names, and each ledger entry as settled, contradicted or not
reached. It never prints a body, a credential, a host name, an address or an account id, and every piece of
text that came from Qualys is stripped of control characters and bounded first.

    python -m tap_plugin.qualys.observe --list
    python -m tap_plugin.qualys.observe --key <key> [--dry-run] [--out DIR]
"""

import argparse
import functools
import json
import os
import re
import sys
import unicodedata
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlsplit
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as SafeET
import jsonschema
from defusedxml import DefusedXmlException
from requests.adapters import HTTPAdapter
from tap import secrets_root
from tap_cares.collectors.timeout import CeilingExceeded, run_with_ceiling

from tap_plugin.qualys import live
from tap_plugin.qualys.client import (
    DETECTION_DTD_PATH,
    DETECTION_PATH,
    KNOWLEDGEBASE_DTD_PATH,
    KNOWLEDGEBASE_PATH,
    THROTTLE_CODES,
    Exchange,
    ReadFailed,
    ReadOnlyClient,
    Response,
    TransportRefused,
    _return_code,
)
from tap_plugin.qualys.credential import SCOPE, Credential, discover
from tap_plugin.qualys.parse import DetectionPage, KnowledgeBasePage, PageRefused, parse_detection_page, parse_knowledgebase_page
from tap_plugin.qualys.parsers import package_table

LEDGER_PATH = Path(__file__).resolve().parent / "observe_assumptions.json"
LEDGER_SCHEMA_PATH = Path(__file__).resolve().parent / "observe_assumptions.schema.json"
#: Where recordings go unless ``--out`` names another private directory.
DEFAULT_BASE = Path.home() / ".local" / "state" / "qualys-observe"
#: Knowledge-base requests at most; the command samples, it does not collect.
MAX_KB_REQUESTS = 10
_TEXT_LIMIT = 80
_LIST_LIMIT = 6
_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-]*")
_IDENTITY = re.compile(r"SUBSCRIPTION|CUSTOMER", re.I)

SETTLED = "settled"
CONTRADICTED = "contradicted"
NOT_REACHED = "not reached"


class ObserveError(Exception):
    """The command cannot run as asked; the message carries no value from a credential or a response."""


def ledger() -> list[dict[str, str]]:
    """The ledger's entries, validated against its schema."""
    data = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(data, json.loads(LEDGER_SCHEMA_PATH.read_text(encoding="utf-8")))
    return list(data["entries"])


def safe(text: Any, limit: int = _TEXT_LIMIT) -> str:
    """Text from Qualys made printable: control and format characters dropped, whitespace collapsed, bounded."""
    cleaned = "".join(" " if ch.isspace() else ch for ch in str(text) if unicodedata.category(ch)[0] != "C" or ch.isspace())
    cleaned = " ".join(cleaned.split())
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def _names(values: Any) -> str:
    items = sorted({safe(v, _TEXT_LIMIT) for v in values})
    shown = ", ".join(items[:_LIST_LIMIT])
    return shown + (f" and {len(items) - _LIST_LIMIT} more" if len(items) > _LIST_LIMIT else "")


# ---------------------------------------------------------------------------------------------------------------
# Recording.


def _inside_repository(path: Path) -> bool:
    return any((p / ".git").exists() for p in (path, *path.parents))


def private_directory(base: Path, key: str, now: datetime) -> Path:
    """A fresh owner-only directory for one observation, refused inside any repository (req-qualys-observe-2)."""
    if not _KEY.fullmatch(key):
        raise ObserveError("the envelope key is not a plain name")
    base = base.expanduser().resolve()
    if _inside_repository(base):
        raise ObserveError("the recording directory is inside a repository; recordings are never committed")
    run = base / key / now.strftime("%Y%m%dT%H%M%SZ")
    for directory in (base, base / key):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        # A link below the checked base could point the recordings anywhere, a repository included.
        if directory.is_symlink() or directory.resolve() != directory:
            raise ObserveError("a recording directory is a symbolic link; recordings are written only where checked")
        os.chmod(directory, 0o700)
    run.mkdir(mode=0o700)
    os.chmod(run, 0o700)
    if run.resolve() != run or _inside_repository(run.resolve()):
        raise ObserveError("the recording directory is inside a repository; recordings are never committed")
    return run


class Recorder:
    """The client's observer: writes every response to its own owner-only file, and keeps it for the checks."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.exchanges: list[tuple[str, Exchange]] = []
        self.step = "unlabelled"

    def __call__(self, exchange: Exchange) -> None:
        self.exchanges.append((self.step, exchange))
        header = {
            "step": self.step,
            "url": exchange.url,
            "status": exchange.status,
            "response_headers": exchange.response_headers,
            "request_header_names": exchange.request_header_names,
        }
        path = self.directory / f"{len(self.exchanges):02d}-{self.step}.rec"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(json.dumps(header, sort_keys=True).encode("utf-8") + b"\n\n" + exchange.body)


# ---------------------------------------------------------------------------------------------------------------
# The reads.


@dataclass
class Step:
    name: str
    outcome: str
    note: str = ""


@dataclass
class Observation:
    """What the reads returned, parsed, beside the recorder's raw responses."""

    steps: list[Step] = field(default_factory=list)
    probe: DetectionPage | None = None
    page: DetectionPage | None = None
    kb_pages: list[KnowledgeBasePage] = field(default_factory=list)
    kb_asked: int = 0
    no_metadata: DetectionPage | None = None
    without_flags: DetectionPage | None = None
    flagged: set[tuple[str, str]] = field(default_factory=set)
    dtd_anonymous: dict[str, int | None] = field(default_factory=dict)
    dtd_served: dict[str, bool] = field(default_factory=dict)


Get = Callable[[str, str], Response]


def _bounded(client: ReadOnlyClient, recorder: Recorder) -> Get:
    def get(url: str, step: str) -> Response:
        recorder.step = step
        try:
            return run_with_ceiling(functools.partial(client.get, url), live.READ_CEILING_SECONDS, name=f"qualys-observe-{step}")
        except CeilingExceeded as exc:
            raise TimeoutError(f"{step} did not finish within its ceiling") from exc

    return get


def _failure(exc: Exception) -> str:
    if isinstance(exc, ReadFailed) and exc.status is not None:
        return f"HTTP {exc.status}"
    return f"not read: {type(exc).__name__}"


def _read_detection(obs: Observation, get: Get, url: str, step: str) -> DetectionPage | None:
    try:
        page = parse_detection_page(get(url, step).body)
    except (ReadFailed, TransportRefused, TimeoutError, PageRefused) as exc:
        obs.steps.append(Step(step, _failure(exc)))
        return None
    detections = sum(len(h["detections"]) for h in page.hosts)
    obs.steps.append(Step(step, "HTTP 200", f"{len(page.hosts)} host(s), {detections} detection(s), next page: {'yes' if page.next_url else 'no'}"))
    return page


def _flagged(page: DetectionPage) -> set[tuple[str, str]]:
    return {
        (str(h["host_id"]), str(d["unique_vuln_id"] or d["qid"]))
        for h in page.hosts
        for d in h["detections"]
        if d.get("is_ignored") == "1" or d.get("is_disabled") == "1"
    }


def plan(credential: Credential) -> list[str]:
    """The reads in order, as operation paths and parameter names; printed by ``--dry-run``, never a host."""
    scope = ", ".join(sorted(credential.standing_scope)) or "none"
    return [
        f"probe: GET {DETECTION_PATH} with every detection-read parameter, truncation_limit=1, standing scope: {scope}",
        f"detections: GET {DETECTION_PATH}, one page of up to {live.TRUNCATION_LIMIT} hosts, same parameters",
        f"knowledge base: GET {KNOWLEDGEBASE_PATH} for that page's QIDs, {live.KB_CHUNK} per request, at most {MAX_KB_REQUESTS} requests",
        f"no-metadata: GET {DETECTION_PATH}, one host, without host_metadata",
        f"without-flags: GET {DETECTION_PATH}, the same page without include_ignored and include_disabled (only when the page holds one)",
        f"DTDs: GET {DETECTION_DTD_PATH} and {KNOWLEDGEBASE_DTD_PATH}, with no credential, then with one if refused",
    ]


def run_reads(credential: Credential, client: ReadOnlyClient, anonymous: ReadOnlyClient, recorder: Recorder) -> Observation:
    """Every read, in the documented order. A failed read is a step outcome, never an exception."""
    obs = Observation()
    get = _bounded(client, recorder)
    root, scope = client.root, credential.standing_scope

    obs.probe = _read_detection(obs, get, live.detection_url(root, scope, None, limit=1), "probe")
    if obs.probe is not None:
        obs.page = _read_detection(obs, get, live.detection_url(root, scope, None), "detections")
    else:
        obs.steps.append(Step("detections", "skipped", "the probe failed"))

    if obs.page is not None:
        qids = sorted({d["qid"] for h in obs.page.hosts for d in h["detections"] if isinstance(d.get("qid"), str) and d["qid"].isdigit()}, key=int)
        chunks = [qids[i : i + live.KB_CHUNK] for i in range(0, len(qids), live.KB_CHUNK)][:MAX_KB_REQUESTS]
        obs.kb_asked = sum(len(c) for c in chunks)
        for number, chunk in enumerate(chunks, 1):
            step = f"knowledgebase-{number}"
            try:
                kb = parse_knowledgebase_page(get(live.knowledgebase_url(root, chunk), step).body)
            except (ReadFailed, TransportRefused, TimeoutError, PageRefused) as exc:
                obs.steps.append(Step(step, _failure(exc)))
                continue
            obs.kb_pages.append(kb)
            obs.steps.append(Step(step, "HTTP 200", f"{len(kb.vulns)} of {len(chunk)} QID(s) returned"))

    # The same host as the probe, pinned by its id, so the comparison is never between two hosts.
    probe_host = str(obs.probe.hosts[0]["host_id"]) if obs.probe is not None and obs.probe.hosts else ""
    if probe_host.isdigit():
        url = live.detection_url(root, scope, None, limit=1, id_min=probe_host, omit=frozenset({"host_metadata"}))
        obs.no_metadata = _read_detection(obs, get, url, "no-metadata")
    if obs.page is not None and obs.page.hosts and (flagged := _flagged(obs.page)):
        obs.flagged = flagged
        first = str(obs.page.hosts[0]["host_id"])
        if first.isdigit():
            url = live.detection_url(root, scope, None, id_min=first, omit=frozenset({"include_ignored", "include_disabled"}))
            obs.without_flags = _read_detection(obs, get, url, "without-flags")

    anonymous_get = _bounded(anonymous, recorder)
    for name, path in (("detection", DETECTION_DTD_PATH), ("knowledgebase", KNOWLEDGEBASE_DTD_PATH)):
        for who, getter in (("anonymous", anonymous_get), ("authenticated", get)):
            step = f"dtd-{name}-{who}"
            try:
                body = getter(f"{root}{path}", step).body
            except (ReadFailed, TransportRefused, TimeoutError) as exc:
                obs.steps.append(Step(step, _failure(exc)))
                if who == "anonymous":
                    obs.dtd_anonymous[name] = exc.status if isinstance(exc, ReadFailed) else None
                continue
            served = b"<!ELEMENT" in body[:1 << 20]
            obs.steps.append(Step(step, "HTTP 200", f"{len(body)} bytes, {'a DTD' if served else 'not a DTD'}"))
            if who == "anonymous":
                obs.dtd_anonymous[name] = 200
            obs.dtd_served[name] = obs.dtd_served.get(name, False) or served
            if served:
                break
    return obs


# ---------------------------------------------------------------------------------------------------------------
# The ledger checks. Each returns (outcome, detail); a detail holds counts and element names, never a value.

Check = Callable[[Observation, Recorder], tuple[str, str]]


def _xml_roots(recorder: Recorder) -> list[Element]:
    roots = []
    for _, ex in recorder.exchanges:
        if ex.status == 200 and urlsplit(ex.url).path in (DETECTION_PATH, KNOWLEDGEBASE_PATH):
            try:
                roots.append(SafeET.fromstring(ex.body))
            except (DefusedXmlException, SafeET.ParseError):
                continue
    return roots


def _detection_pages(obs: Observation) -> list[DetectionPage]:
    return [p for p in (obs.probe, obs.page, obs.no_metadata, obs.without_flags) if p is not None]


def check_subscription_identity(obs: Observation, recorder: Recorder) -> tuple[str, str]:
    roots = _xml_roots(recorder)
    if not roots:
        return NOT_REACHED, "no detection or knowledge-base response was read"
    named = {el.tag for root in roots for el in root.iter() if _IDENTITY.search(el.tag)}
    if named:
        return CONTRADICTED, f"element(s) {_names(named)} in the responses"
    return SETTLED, f"no element names a subscription or customer, across {len(roots)} response(s)"


def check_ec2_account_attribute(obs: Observation, recorder: Recorder) -> tuple[str, str]:
    names = {n for p in _detection_pages(obs) for h in p.hosts if h.get("ec2_metadata") for n in h["ec2_metadata"]}
    if not names:
        return NOT_REACHED, "no host carried METADATA/EC2"
    account = {n for n in names if "account" in n.lower()}
    if account:
        return SETTLED, f"attribute name(s) {_names(account)}"
    return CONTRADICTED, f"{len(names)} attribute name(s), none naming an account"


def check_cloud_resource_id_without_metadata(obs: Observation, recorder: Recorder) -> tuple[str, str]:
    if not (obs.probe and obs.probe.hosts and obs.no_metadata and obs.no_metadata.hosts):
        return NOT_REACHED, "the probe or the no-metadata read returned no host"
    if obs.probe.hosts[0].get("host_id") != obs.no_metadata.hosts[0].get("host_id"):
        return NOT_REACHED, "the no-metadata read returned a different host from the probe"
    with_meta = obs.probe.hosts[0].get("cloud_resource_id") is not None
    without = obs.no_metadata.hosts[0].get("cloud_resource_id") is not None
    if without:
        return CONTRADICTED, "CLOUD_RESOURCE_ID was returned without host_metadata"
    if with_meta:
        return SETTLED, "CLOUD_RESOURCE_ID was returned with host_metadata and not without it"
    return NOT_REACHED, "the first host carries no CLOUD_RESOURCE_ID either way"


def check_ignored_disabled_default(obs: Observation, recorder: Recorder) -> tuple[str, str]:
    if not obs.flagged:
        return NOT_REACHED, "the detection page holds no ignored or disabled detection"
    if obs.without_flags is None:
        return NOT_REACHED, "the read without the two parameters was not made or failed"
    seen_hosts = {str(h["host_id"]) for h in obs.without_flags.hosts}
    comparable = {f for f in obs.flagged if f[0] in seen_hosts}
    if not comparable:
        return NOT_REACHED, f"none of the {len(obs.flagged)} flagged detection(s) is on a host the second read returned"
    returned = _present(obs.without_flags) & comparable
    if returned:
        return CONTRADICTED, f"{len(returned)} of {len(comparable)} ignored or disabled detection(s) still returned"
    return SETTLED, f"{len(comparable)} ignored or disabled detection(s) left out"


def _present(page: DetectionPage) -> set[tuple[str, str]]:
    return {(str(h["host_id"]), str(d["unique_vuln_id"] or d["qid"])) for h in page.hosts for d in h["detections"]}


def check_unique_vuln_id_collision(obs: Observation, recorder: Recorder) -> tuple[str, str]:
    qids: dict[str, set[str]] = {}
    for page in _detection_pages(obs):
        for host in page.hosts:
            for d in host["detections"]:
                if d.get("unique_vuln_id"):
                    qids.setdefault(d["unique_vuln_id"], set()).add(str(d.get("qid")))
    if not qids:
        return NOT_REACHED, "no detection carried a UNIQUE_VULN_ID"
    colliding = sum(1 for v in qids.values() if len(v) > 1)
    if colliding:
        return CONTRADICTED, f"{colliding} id(s) seen under two or more QIDs"
    return SETTLED, f"{len(qids)} id(s), each under one QID"


def check_kb_409_meaning(obs: Observation, recorder: Recorder) -> tuple[str, str]:
    codes = [_return_code(ex.body) for _, ex in recorder.exchanges if ex.status == 409 and urlsplit(ex.url).path == KNOWLEDGEBASE_PATH]
    other = sorted({c for c in codes if c not in THROTTLE_CODES}, key=lambda c: c or "")
    if other:
        return SETTLED, f"knowledge-base 409 with code(s) {', '.join(c or 'none' for c in other)}"
    if codes:
        return NOT_REACHED, "only throttling 409s from the knowledge base"
    return NOT_REACHED, "no knowledge-base 409"


def check_concurrency_header_spelling(obs: Observation, recorder: Recorder) -> tuple[str, str]:
    api = [ex for _, ex in recorder.exchanges if urlsplit(ex.url).path in (DETECTION_PATH, KNOWLEDGEBASE_PATH)]
    if not api:
        return NOT_REACHED, "no detection or knowledge-base response"
    names = {k.lower() for ex in api for k in ex.response_headers}
    spellings = [s for s, prefix in (("X-Concurrency-Limit-*", "x-concurrency-limit-"), ("X-ConcurrencyLimit-*", "x-concurrencylimit-")) if any(n.startswith(prefix) for n in names)]
    if spellings:
        return SETTLED, " and ".join(spellings)
    return CONTRADICTED, f"neither spelling on {len(api)} response(s)"


def check_dtd_unauthenticated(obs: Observation, recorder: Recorder) -> tuple[str, str]:
    if not obs.dtd_anonymous:
        return NOT_REACHED, "no DTD was asked for"
    served = [n for n, status in obs.dtd_anonymous.items() if status == 200 and _anonymous_dtd(recorder, n)]
    refused = [n for n, status in obs.dtd_anonymous.items() if status in (401, 403)]
    if served:
        return CONTRADICTED, f"served without a credential: {', '.join(sorted(served))}"
    if refused and len(refused) == len(obs.dtd_anonymous):
        return SETTLED, "both refused without a credential"
    statuses = ", ".join(f"{n} {'HTTP ' + str(s) if s else 'not read'}" for n, s in sorted(obs.dtd_anonymous.items()))
    return NOT_REACHED, f"anonymous reads: {statuses}"


def _anonymous_dtd(recorder: Recorder, name: str) -> bool:
    return any(step == f"dtd-{name}-anonymous" and ex.status == 200 and b"<!ELEMENT" in ex.body[:1 << 20] for step, ex in recorder.exchanges)


def check_eos_warning_shape(obs: Observation, recorder: Recorder) -> tuple[str, str]:
    pages: list[Any] = [*_detection_pages(obs), *obs.kb_pages]
    warnings = [p.warning for p in pages if p.warning and not p.warning.get("url")]
    eos = [w for w in warnings if live._EOS_TEXT.search(w.get("text") or "")]
    headers = any(k.lower() in ("deprecation", "sunset") for _, ex in recorder.exchanges for k in ex.response_headers)
    codes = _names(re.sub(r"\D", "", w.get("code") or "") or "none" for w in (eos or warnings))
    if eos:
        return SETTLED, f"{len(eos)} end-of-support WARNING(s), code(s) {codes}"
    if headers:
        return CONTRADICTED, "a Deprecation or Sunset header with no end-of-support WARNING"
    if warnings:
        return NOT_REACHED, f"{len(warnings)} other WARNING(s), code(s) {codes}"
    return NOT_REACHED, "no WARNING other than next-page links"


def _table_form(results: str) -> str | None:
    """The header form of a package-like table, "unread" when the parser would not read it, None when not one."""
    lines = results.replace("\r\n", "\n").split("\n")
    marked = bool(lines) and lines[0].strip().lower().startswith("#table")
    header = lines[1] if marked and len(lines) > 1 else lines[0]
    cells = [c.strip().lower() for c in header.split("\t")]
    if not (any("package" in c for c in cells) and any("version" in c for c in cells)):
        return None
    if not package_table.matches(results):
        return "unread"
    return ("#table + " if marked else "") + ("underscored" if "_" in header else "plain")


def check_package_table_variants(obs: Observation, recorder: Recorder) -> tuple[str, str]:
    forms: Counter[str] = Counter()
    unread_headers: set[str] = set()
    for page in _detection_pages(obs):
        for host in page.hosts:
            for d in host["detections"]:
                if isinstance(d.get("results"), str) and (form := _table_form(d["results"])):
                    forms[form] += 1
                    if form == "unread":
                        unread_headers.add(d["results"].replace("\r\n", "\n").split("\n")[0])
    if not forms:
        return NOT_REACHED, "no package-like table in any result text"
    summary = ", ".join(f"{form} ×{n}" for form, n in sorted(forms.items()))
    if forms["unread"]:
        return CONTRADICTED, f"{summary}; a header the parser does not read: {_names(unread_headers)}"
    return SETTLED, summary


def check_cloud_provider_tags_shape(obs: Observation, recorder: Recorder) -> tuple[str, str]:
    paths: set[str] = set()
    found = 0
    for root in _xml_roots(recorder):
        for tags in root.iter("CLOUD_PROVIDER_TAGS"):
            found += 1
            paths.update(_paths(tags, "CLOUD_PROVIDER_TAGS"))
    if not found:
        return NOT_REACHED, "no CLOUD_PROVIDER_TAGS in any response"
    return SETTLED, f"{found} element(s); path(s) {_names(paths) if paths else '(empty)'}"


def _paths(node: Element, prefix: str) -> set[str]:
    out = set()
    for child in node:
        path = f"{prefix}/{child.tag}"
        out.add(path)
        out.update(_paths(child, path))
    return out


CHECKS: dict[str, Check] = {
    "subscription-identity": check_subscription_identity,
    "ec2-account-attribute": check_ec2_account_attribute,
    "cloud-resource-id-without-metadata": check_cloud_resource_id_without_metadata,
    "ignored-disabled-default": check_ignored_disabled_default,
    "unique-vuln-id-collision": check_unique_vuln_id_collision,
    "kb-409-meaning": check_kb_409_meaning,
    "concurrency-header-spelling": check_concurrency_header_spelling,
    "dtd-unauthenticated": check_dtd_unauthenticated,
    "eos-warning-shape": check_eos_warning_shape,
    "package-table-variants": check_package_table_variants,
    "cloud-provider-tags-shape": check_cloud_provider_tags_shape,
}


def settle(obs: Observation, recorder: Recorder) -> list[tuple[str, str, str]]:
    """Every ledger entry with its outcome (req-qualys-observe-4). A check that fails is reported, not raised."""
    results = []
    for entry in ledger():
        try:
            outcome, detail = CHECKS[entry["id"]](obs, recorder)
        except Exception as exc:  # noqa: BLE001 - one broken check must not hide the others' outcomes
            outcome, detail = NOT_REACHED, f"the check failed ({type(exc).__name__})"
        results.append((entry["id"], outcome, detail))
    return results


# ---------------------------------------------------------------------------------------------------------------
# The command.


def report(credential: Credential, directory: Path, obs: Observation, recorder: Recorder, out: TextIO) -> None:
    statuses = Counter(ex.status for _, ex in recorder.exchanges)
    print(f"qualys observe · {credential.qualified}", file=out)
    print(f"recordings: {directory} ({len(recorder.exchanges)} file(s), owner-only; never commit them)", file=out)
    print(f"responses: {len(recorder.exchanges)} ({', '.join(f'HTTP {s} ×{n}' for s, n in sorted(statuses.items())) or 'none'})", file=out)
    print("", file=out)
    print("reads:", file=out)
    for step in obs.steps:
        print(f"  {step.name:<30} {step.outcome:<18} {step.note}".rstrip(), file=out)
    print("", file=out)
    print("ledger:", file=out)
    for entry_id, outcome, detail in settle(obs, recorder):
        print(f"  {entry_id:<36} {outcome:<13} {safe(detail, 160)}", file=out)


def main(argv: list[str] | None = None, *, out: TextIO = sys.stdout, adapter: HTTPAdapter | None = None, now: datetime | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tap_plugin.qualys.observe", description="Record what one Qualys subscription returns (read-only).")
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--list", action="store_true", help="list the envelopes in scope qualys; sends nothing")
    which.add_argument("--key", help="the envelope key of the subscription to observe")
    parser.add_argument("--dry-run", action="store_true", help="print the reads in order; sends nothing")
    parser.add_argument("--out", type=Path, default=DEFAULT_BASE, help="private directory for recordings (outside any repository)")
    parser.add_argument("--secrets-root", type=Path, default=None, help="the secrets root; defaults as for any host tool")
    args = parser.parse_args(argv)

    usable, refused = discover(secrets_root.for_host_tool(args.secrets_root))
    if args.list:
        for credential in usable:
            print(f"{credential.qualified}  usable", file=out)
        for error in refused:
            print(f"{error.qualified}  refused: {error.reason}", file=out)
        if not usable and not refused:
            print(f"no envelope in scope {SCOPE}", file=out)
        return 0

    wanted = f"{SCOPE}:{args.key}"
    match = [c for c in usable if c.qualified == wanted]
    if not match:
        reasons = [e.reason for e in refused if e.qualified == wanted]
        print(f"{wanted}: {'refused: ' + reasons[0] if reasons else 'no usable envelope with that key'}", file=out)
        return 2
    credential = match[0]

    if args.dry_run:
        print(f"qualys observe · {credential.qualified} · dry run, nothing sent", file=out)
        for number, line in enumerate(plan(credential), 1):
            print(f"  {number}. {line}", file=out)
        return 0

    try:
        directory = private_directory(args.out, args.key, now or datetime.now(UTC))
    except ObserveError as exc:
        print(f"{wanted}: {exc}", file=out)
        return 2
    recorder = Recorder(directory)
    username, password = credential.basic
    client = ReadOnlyClient(credential.api_host, username, password, ca_bundle=credential.ca_bundle, adapter=adapter, observer=recorder)
    anonymous = ReadOnlyClient.anonymous(credential.api_host, ca_bundle=credential.ca_bundle, adapter=adapter, observer=recorder)
    obs = run_reads(credential, client, anonymous, recorder)
    report(credential, directory, obs, recorder, out)
    return 0 if obs.probe is not None else 1


if __name__ == "__main__":
    sys.exit(main())
