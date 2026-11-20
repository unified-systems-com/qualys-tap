"""Qualys's package table: ``Package`` / ``Installed Version`` / ``Required Version`` (req-qualys-parsers-5).

A package QID's result text is a table whose first row is that header, columns separated by tabs and rows by
newlines. Two variants are read as well: an underscored header (``Installed_Version``, ``Required_Version``)
and a ``#table`` line before the header, both seen in Qualys's own outputs and handled by Elastic's pipeline.
Rows after the table that are not package rows are tolerated and ignored.

The ecosystem comes from the host's ``OS``: Debian or Ubuntu gives ``deb``; an RPM-based distribution gives
``rpm``. An ``OS`` this module cannot place leaves the ecosystem null and the mapping ambiguous. Versions are
kept exactly as printed. Where a dpkg epoch (``1:2.3-4``) or an RPM architecture suffix makes the
``computing_core`` version uncertain, the mapping is ambiguous: no package is linked on a guess.
"""

import re
from collections.abc import Mapping
from typing import Any

from tap_plugin.qualys.parsers import PackageObservation, ParserFailed

PARSER_VERSION = "1"

_HEADER = ("package", "installed version", "required version")
_DEB = re.compile(r"\b(debian|ubuntu)\b", re.I)
_RPM = re.compile(r"\b(red ?hat|rhel|centos|amazon linux|fedora|rocky|alma ?linux|oracle linux|suse|sles|opensuse)\b", re.I)
_EPOCH = re.compile(r"^\d+:")
_RPM_ARCH = re.compile(r"\.(x86_64|i[3-6]86|aarch64|arm64|ppc64le|s390x|noarch)$")


def _lines(results: str) -> list[str]:
    lines = results.replace("\r\n", "\n").split("\n")
    if lines and lines[0].lstrip().lower().startswith("#table"):
        lines = lines[1:]
    return lines


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.split("\t")]


def _is_header(line: str) -> bool:
    return tuple(cell.replace("_", " ").lower() for cell in _cells(line)) == _HEADER


def matches(results: str) -> bool:
    """True when the text begins with the package-table header, in any of its forms."""
    lines = _lines(results)
    return bool(lines) and _is_header(lines[0])


def ecosystem_of(os_name: Any) -> str | None:
    if not isinstance(os_name, str):
        return None
    if _DEB.search(os_name):
        return "deb"
    if _RPM.search(os_name):
        return "rpm"
    return None


def _unambiguous(ecosystem: str | None, name: str, version: str) -> bool:
    if ecosystem is None or not name or not version:
        return False
    if ecosystem == "deb" and _EPOCH.match(version):
        return False
    return not (ecosystem == "rpm" and _RPM_ARCH.search(version))


def parse(detection: Mapping[str, Any]) -> list[PackageObservation]:
    results = detection.get("results")
    if not isinstance(results, str) or not matches(results):
        raise ParserFailed("the text does not begin with the package-table header")
    ecosystem = ecosystem_of(detection.get("os"))
    out: list[PackageObservation] = []
    for line in _lines(results)[1:]:
        cells = _cells(line)
        if len(cells) != 3 or not cells[0] or not cells[1]:
            break  # the table has ended; what follows is not package rows
        name, installed, required = cells
        out.append(PackageObservation(ecosystem, name, installed, required or None, line, _unambiguous(ecosystem, name, installed)))
    if not out:
        raise ParserFailed("a package-table header with no package row under it")
    return out
