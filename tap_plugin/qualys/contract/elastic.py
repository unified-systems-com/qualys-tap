"""The scheduled third-party fixture check (unified-systems-com/qualys-tap#45): our parsers over Elastic's pages.

Elastic's ``qualys_vmdr`` integration ships a mock Qualys server whose configuration holds real-shaped 5.0 detection
pages (QDS, QDS_FACTORS, a 1980 next-page warning, truncation) and 4.0 knowledge-base pages from three platforms.
It is under the Elastic License 2.0, so it is not copied into this repository: the drift workflow fetches it at a
pinned commit, refuses it unless its SHA-256 is the one recorded here, and runs ``parse_detection_page`` and
``parse_knowledgebase_page`` over every page. The suite opens no socket (req-qualys-contract-extract-2), which is
why this runs in the workflow rather than in pytest; the extraction and the expectations are tested offline.

A page that is refused, or that reads but yields a different number of hosts, detections or QIDs than recorded,
fails the run. Moving the pin is a deliberate change: new commit, new hash, new expectations, in one PR.

Needs ``defusedxml`` (the parser's), installed by hash in the workflow; nothing else beyond the standard library.
"""

import argparse
import hashlib
import re
import sys
from typing import Any

from tap_plugin.qualys.contract.drift import DriftError, _summary, fetch
from tap_plugin.qualys.parse import PageRefused, parse_detection_page, parse_knowledgebase_page

COMMIT = "73b87f14ae8af28fff7f3ff82f051b171efa4618"
PATH = "packages/qualys_vmdr/_dev/deploy/docker/files/config.yml"
URL = f"https://raw.githubusercontent.com/elastic/integrations/{COMMIT}/{PATH}"
SHA256 = "fbf3431c007840663227b63a588d43721214b7008674d1263037e4ca76065649"
MAX_BYTES = 1 << 20

#: What each XML page yields, in file order: (document, hosts or QIDs, detections, has a next-page link).
EXPECTED: list[tuple[str, int, int, bool]] = [
    ("detection", 2, 4, True),
    ("detection", 1, 2, True),
    ("detection", 1, 2, False),
    ("knowledgebase", 3, 0, False),
    ("knowledgebase", 2, 0, False),
    ("knowledgebase", 1, 0, False),
    ("knowledgebase", 2, 0, False),
    ("knowledgebase", 0, 0, False),
]

_BODY = re.compile(r"^(?P<indent> *)body: \|-\s*$")


def bodies(text: str) -> list[str]:
    """Every ``body: |-`` block scalar in the mock config, de-indented, in file order.

    The file is pinned by hash, so this reads exactly the layout Elastic committed rather than YAML in general:
    a block runs from the line after ``body: |-`` while lines are blank or indented deeper than the key.
    """
    lines, out, i = text.splitlines(), [], 0
    while i < len(lines):
        match = _BODY.match(lines[i])
        i += 1
        if not match:
            continue
        key_indent, block = len(match["indent"]), []
        while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip(" ")) > key_indent):
            block.append(lines[i])
            i += 1
        content = [line for line in block if line.strip()]
        if not content:
            out.append("")
            continue
        strip = min(len(line) - len(line.lstrip(" ")) for line in content)
        out.append("\n".join(line[strip:] for line in block).rstrip("\n"))
    return out


def read(text: str) -> list[tuple[str, int, int, bool]]:
    """(document, hosts or QIDs, detections, next link) for each XML page; PageRefused propagates."""
    results = []
    for body in bodies(text):
        if "<HOST_LIST_VM_DETECTION_OUTPUT>" in body:
            page = parse_detection_page(body.encode())
            detections = sum(len(h.get("detections") or []) for h in page.hosts)
            results.append(("detection", len(page.hosts), detections, page.next_url is not None))
        elif "<KNOWLEDGE_BASE_VULN_LIST_OUTPUT>" in body:
            kb = parse_knowledgebase_page(body.encode())
            results.append(("knowledgebase", len(kb.vulns), 0, kb.next_url is not None))
    return results


def check(fetcher: Any = None) -> int:
    raw = (fetcher or fetch)(URL, MAX_BYTES)
    digest = hashlib.sha256(raw).hexdigest()
    lines = ["## Elastic qualys_vmdr pages", f"- source: elastic/integrations@{COMMIT[:12]} `{PATH}`"]
    if digest != SHA256:
        _summary([*lines, f"- REFUSED: sha256 {digest[:16]}… is not the recorded {SHA256[:16]}…"])
        return 2
    try:
        got = read(raw.decode("utf-8"))
    except PageRefused as exc:
        _summary([*lines, f"- FAILS: a page was refused: {str(exc)[:200]}"])
        return 1
    lines += [f"- {d}: {n} {'hosts' if d == 'detection' else 'QIDs'}, {k} detections, next link {nx}" for d, n, k, nx in got]
    if got != EXPECTED:
        _summary([*lines, f"- FAILS: expected {EXPECTED}"])
        return 1
    _summary([*lines, f"- all {len(got)} pages read as recorded"])
    return 0


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(prog="python -m tap_plugin.qualys.contract.elastic", description=__doc__.splitlines()[0]).parse_args(argv)
    try:
        return check()
    except DriftError as exc:
        _summary(["## Elastic fixture check could not run", f"- {exc}"])
        return 2


if __name__ == "__main__":
    sys.exit(main())
