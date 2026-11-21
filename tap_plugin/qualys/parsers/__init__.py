"""Result parsers: what a detection's result text says about packages (req-qualys-parsers).

What ties a detection to a package is in Qualys's free-text ``RESULTS``, not a structured field. Each module
here reads one output format. It declares the QIDs it reads as ``QIDS``, or the header it matches with a
``matches(results)`` function, and a QID listed by a module is matched before any header. A parser is a pure
function ``parse(detection) -> list[PackageObservation]`` with no I/O, over the validated fields ``results``,
``qid`` and ``os``.

The collector records exactly one parse state per detection, and none of them means "no package" unless a
parser read the text and found none:

- ``parsed``: a parser returned observations (an empty list is a recorded result);
- ``no_parser``: no module matches. This never means "no package";
- ``parser_failed``: the text matched a header but not the format; the raw text is kept and the failure counted;
- ``not_applicable``: the QID is listed in ``NOT_APPLICABLE`` with a reason.

Parsing edits no stored Qualys field, so an improved parser re-parses stored detections without re-collecting.
"""

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from types import ModuleType
from typing import Any

PARSED = "parsed"
NO_PARSER = "no_parser"
PARSER_FAILED = "parser_failed"
NOT_APPLICABLE_STATE = "not_applicable"


class ParserFailed(Exception):
    """The text matched a parser's header but not its format. The message names the rule, never the text."""


@dataclass(frozen=True)
class PackageObservation:
    """One package a parser read from result text, with the exact line it came from.

    Every field but ``mapping_unambiguous`` may be null. ``mapping_unambiguous`` is true only when ``ecosystem``,
    ``name`` and ``installed_version`` identify exactly one ``computing_core`` package.
    """

    ecosystem: str | None
    name: str | None
    installed_version: str | None
    required_version: str | None
    evidence: str
    mapping_unambiguous: bool

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Parsed:
    """The outcome of reading one detection: its parse state, the parser that read it, and what it found."""

    state: str
    parser_version: str | None = None
    observations: tuple[PackageObservation, ...] = ()
    failure: str | None = None


#: QIDs known to carry no package information, each with its reason. Empty until an observation names one:
#: built blind, a QID is listed here only on evidence, never by guess.
NOT_APPLICABLE: Mapping[str, str] = {}


def _modules() -> tuple[ModuleType, ...]:
    from tap_plugin.qualys.parsers import package_table

    return (package_table,)


def _register(modules: tuple[ModuleType, ...]) -> tuple[dict[str, ModuleType], tuple[ModuleType, ...]]:
    """QID claims and header matchers; a QID claimed by two modules, or by a module and NOT_APPLICABLE, is refused."""
    by_qid: dict[str, ModuleType] = {}
    for module in modules:
        for name in ("PARSER_VERSION", "parse"):
            if not hasattr(module, name):
                raise ImportError(f"parser {module.__name__} declares no {name}")
        for qid in getattr(module, "QIDS", ()):
            if qid in by_qid or qid in NOT_APPLICABLE:
                raise ImportError(f"QID {qid} is claimed twice")
            by_qid[qid] = module
    matchers = tuple(m for m in modules if callable(getattr(m, "matches", None)))
    return by_qid, matchers


#: Every registered parser, by ``<module>/<version>``.
_BY_QID, _MATCHERS = _register(_modules())
REGISTERED: Mapping[str, ModuleType] = {f"{m.__name__.rsplit('.', 1)[-1]}/{m.PARSER_VERSION}": m for m in {*_BY_QID.values(), *_MATCHERS}}


def _version(module: ModuleType) -> str:
    return f"{module.__name__.rsplit('.', 1)[-1]}/{module.PARSER_VERSION}"


def parse(detection: Mapping[str, Any]) -> Parsed:
    """Exactly one parse state for one detection (req-qualys-parsers-1)."""
    qid = detection.get("qid")
    if isinstance(qid, str) and qid in NOT_APPLICABLE:
        return Parsed(NOT_APPLICABLE_STATE)
    results = detection.get("results")
    module = _BY_QID.get(qid) if isinstance(qid, str) else None
    if module is None and isinstance(results, str):
        module = next((m for m in _MATCHERS if m.matches(results)), None)
    if module is None:
        return Parsed(NO_PARSER)
    parse_fn: Callable[[Mapping[str, Any]], list[PackageObservation]] = module.parse
    try:
        return Parsed(PARSED, _version(module), tuple(parse_fn(detection)))
    except ParserFailed as exc:
        return Parsed(PARSER_FAILED, _version(module), failure=str(exc))
