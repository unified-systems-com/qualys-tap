"""The scheduled drift check (req-qualys-drift-ci), and the comparison every DTD in hand goes through.

``compare`` reduces a DTD with the same reducer as the committed extract and returns two lists: the consumed
elements whose declaration changed, which fail a check, and the other elements added, removed or changed,
which are only reported. ``qualys_load`` uses the same comparison for the DTDs an archive carries
(req-qualys-drift-ci-4).

The command has two sources, because whether Qualys serves its API DTDs without a credential is open in the
observation ledger (``dtd-unauthenticated``):

- ``reference`` fetches Qualys's published DTD reference and compares its SHA-256 with the one the committed
  DTDs were extracted from (``tests/vendor/provenance.json``). A different hash fails the run: the reference
  changed, and the DTDs must be extracted again and compared, which ``file`` then does offline.
- ``served --host`` fetches the two DTDs from a platform host, with no credential, and compares them. Qualys
  served both without one on 2026-11-21, so this is the source the workflow runs.
- ``file <document> <path>`` compares a DTD on disk: a regular ``.dtd`` file, not a link, within the size
  bound every DTD read has.

Standard library only, so the workflow needs no install step. No credential is read or sent, nothing is
written but the run summary, and no redirect is followed.
"""

import argparse
import hashlib
import json
import os
import stat
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from tap_plugin.qualys.contract.reduce import MAX_DTD_BYTES, ReduceError, parse_dtd, reduce

HERE = Path(__file__).resolve().parent
VENDOR = HERE.parent / "tests" / "vendor"
#: The DTD read paths, as in the transport's allowlist (a test holds the two equal); repeated here so this
#: module imports no third-party package.
DTD_PATHS = {
    "detection": "/api/6.0/fo/asset/host/vm/detection/dtd/output.dtd",
    "knowledgebase": "/api/4.0/fo/knowledge_base/vuln/knowledge_base_vuln_list_output.dtd",
}
MAX_REFERENCE_BYTES = 64 << 20
TIMEOUT_SECONDS = 60
USER_AGENT = "qualys-tap drift check (read-only)"


class DriftError(Exception):
    """The check could not run: a fetch failed or a DTD could not be read."""


def _json(name: str) -> dict[str, Any]:
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def provenance() -> dict[str, Any]:
    return json.loads((VENDOR / "provenance.json").read_text(encoding="utf-8"))


def compare(document: str, dtd_text: str) -> tuple[list[str], list[str]]:
    """(consumed elements that changed, other elements added, removed or changed) against the committed DTD."""
    spec = _json("consumed.json")["documents"][document]
    committed = _json("extract.json")["documents"][document]["elements"]
    try:
        served = reduce(dtd_text, spec["elements"], spec.get("named_not_declared"))
    except ReduceError as exc:
        return [f"the DTD cannot be reduced: {str(exc)[:200]}"], []
    consumed = sorted(e for e in committed if served.get(e) != committed[e])
    new_all = parse_dtd(dtd_text)
    old_all = parse_dtd((VENDOR / spec["dtd"]).read_text(encoding="utf-8"))
    read = set(committed)
    other = sorted(
        [f"added {e}" for e in new_all.keys() - old_all.keys() if e not in read]
        + [f"removed {e}" for e in old_all.keys() - new_all.keys() if e not in read]
        + [f"changed {e}" for e in new_all.keys() & old_all.keys() if e not in read and new_all[e] != old_all[e]]
    )
    return consumed, other


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # a 3xx surfaces as an HTTPError, never followed


def fetch(url: str, limit: int) -> bytes:
    """One anonymous GET over https, bounded in size and time, no redirect followed."""
    if not url.startswith("https://"):
        raise DriftError("only https is fetched")
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        raise DriftError(f"HTTP {exc.code} for {url.split('?')[0]}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DriftError(f"{type(exc).__name__} for {url.split('?')[0]}") from None
    if len(body) > limit:
        raise DriftError(f"{url.split('?')[0]} is larger than {limit} bytes")
    return body


def _summary(lines: list[str]) -> None:
    text = "\n".join(lines) + "\n"
    print(text, end="")
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(text)


def _report(document: str, consumed: list[str], other: list[str]) -> list[str]:
    lines = [f"### {document}"]
    lines += [f"- consumed, fails: {c}" for c in consumed] or ["- no consumed element changed"]
    lines += [f"- not consumed, reported only: {o}" for o in other[:200]]
    return lines


def check_reference(fetcher: Any = None) -> int:
    meta = provenance()
    body = (fetcher or fetch)(meta["source"], MAX_REFERENCE_BYTES)
    digest = hashlib.sha256(body).hexdigest()
    if digest == meta["source_sha256"]:
        _summary(["## Qualys DTD reference", f"- unchanged: {meta['source_version']} (sha256 {digest[:16]}…)"])
        return 0
    _summary([
        "## Qualys DTD reference",
        f"- CHANGED: sha256 {digest[:16]}… differs from the {meta['source_version']} the committed DTDs came from",
        "- extract the two DTDs from the new reference into tests/vendor, then run "
        "`python -m tap_plugin.qualys.contract.drift file <document> <path>` on each to see whether a consumed element moved",
    ])
    return 1


def check_served(host: str, fetcher: Any = None) -> int:
    fetcher = fetcher or fetch
    lines, failed = ["## Served DTDs", f"- host: {host}"], False
    for document, path in DTD_PATHS.items():
        text = fetcher(host.rstrip("/") + path, MAX_DTD_BYTES).decode("utf-8", errors="replace")
        consumed, other = compare(document, text)
        failed |= bool(consumed)
        lines += _report(document, consumed, other)
    _summary(lines)
    return 1 if failed else 0


def read_dtd_file(path: Path) -> str:
    """A DTD named on the command line: a regular ``.dtd`` file, not a link, no larger than any DTD read."""
    if path.suffix != ".dtd":
        raise DriftError(f"{path.name}: only a .dtd file is compared")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise DriftError(f"{path.name}: cannot be opened ({exc.strerror})") from exc
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise DriftError(f"{path.name}: not a regular file")
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(MAX_DTD_BYTES + 1)
    if len(data) > MAX_DTD_BYTES:
        raise DriftError(f"{path.name}: larger than {MAX_DTD_BYTES} bytes")
    return data.decode("utf-8", errors="replace")


def check_file(document: str, path: Path) -> int:
    consumed, other = compare(document, read_dtd_file(path))
    _summary(["## DTD on disk", *_report(document, consumed, other)])
    return 1 if consumed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tap_plugin.qualys.contract.drift", description="Compare Qualys's DTDs with the committed extract.")
    sub = parser.add_subparsers(dest="source", required=True)
    sub.add_parser("reference", help="compare the DTD reference's hash with the one the committed DTDs came from")
    served = sub.add_parser("served", help="fetch both DTDs from a platform host, with no credential, and compare")
    served.add_argument("--host", required=True, help="a platform API root, such as https://qualysapi.qualys.com")
    on_disk = sub.add_parser("file", help="compare a DTD on disk")
    on_disk.add_argument("document", choices=sorted(DTD_PATHS))
    on_disk.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.source == "reference":
            return check_reference()
        if args.source == "served":
            return check_served(args.host)
        return check_file(args.document, args.path)
    except DriftError as exc:
        _summary(["## Drift check could not run", f"- {exc}"])
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
