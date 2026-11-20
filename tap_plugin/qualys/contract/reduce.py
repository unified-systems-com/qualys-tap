"""Reduce a Qualys output DTD to the part this plugin reads (req-qualys-contract-extract).

The reducer takes a DTD as text and never resolves an entity, fetches anything or touches a file of its own:
the caller hands it the text. It reads ``<!ELEMENT>`` and ``<!ATTLIST>`` declarations, keeps the elements a
consumed list names, and records for each its content model, the children the model requires, and its
attributes. The committed extract and any DTD in hand at run time go through this one function, so a
difference is never an artifact of two code paths.

One tolerance, for the committed sources only: they were copied from Qualys's PDF reference, which wraps
one comment terminator across a line (``-`` then ``->``). Comments are therefore closed by ``-``, optional
whitespace, ``->``. Nothing else about the text is repaired.
"""

import re
from typing import Any

#: A DTD this large is not a Qualys output DTD (the detection DTD is about 6 KB).
MAX_DTD_BYTES = 1 << 20
#: Parameter-entity references expanded per document, and expanded text, are bounded (req-qualys-contract-extract-4).
MAX_ENTITY_REFS = 1000
#: Parameter entities nested inside one another, bounded well below Python's recursion limit.
MAX_ENTITY_DEPTH = 32
MAX_EXPANDED_BYTES = 1 << 20

_COMMENT = re.compile(r"<!--.*?-\s*->", re.S)
_DECL = re.compile(r"<!(ELEMENT|ATTLIST|ENTITY)\s+(.*?)>", re.S)
_NAME = r"[A-Za-z_][A-Za-z0-9_.:-]*"
_PE_REF = re.compile(r"%(" + _NAME + r");")


class ReduceError(ValueError):
    """A DTD the reducer will not read: too large, an external entity, an entity cycle, or malformed."""


def _expand_parameter_entities(text: str) -> str:
    """Expand internal parameter entities, refusing external ones, cycles and unbounded growth."""
    entities: dict[str, str] = {}
    for kind, body in _DECL.findall(text):
        if kind != "ENTITY":
            continue
        m = re.fullmatch(r"%\s+(" + _NAME + r")\s+(.*)", body.strip(), re.S)
        if not m:
            continue  # a general entity: not used by the declarations the reducer reads
        name, value = m.groups()
        if value.startswith(("SYSTEM", "PUBLIC")):
            raise ReduceError(f"external parameter entity %{name}; is refused")
        q = re.fullmatch(r"(['\"])(.*)\1", value.strip(), re.S)
        if not q:
            raise ReduceError(f"parameter entity %{name}; has no quoted value")
        entities[name] = q.group(2)

    refs = 0
    produced = 0  # characters every substitution has produced so far, bounded as it grows

    def expand(s: str, stack: tuple[str, ...]) -> str:
        nonlocal refs

        def one(m: re.Match[str]) -> str:
            nonlocal refs, produced
            name = m.group(1)
            if name in stack:
                raise ReduceError(f"parameter entity cycle through %{name};")
            if len(stack) >= MAX_ENTITY_DEPTH:
                raise ReduceError("parameter entities nested too deeply")
            if name not in entities:
                raise ReduceError(f"undeclared parameter entity %{name};")
            refs += 1
            if refs > MAX_ENTITY_REFS:
                raise ReduceError("too many parameter-entity references")
            out = expand(entities[name], (*stack, name))
            produced += len(out)
            if produced > MAX_EXPANDED_BYTES:
                raise ReduceError("parameter-entity expansion too large")
            return out

        return _PE_REF.sub(one, s)

    body = re.sub(r"<!ENTITY\s+%.*?>", "", text, flags=re.S)
    expanded = expand(body, ())
    if len(expanded) > MAX_EXPANDED_BYTES:
        raise ReduceError("parameter-entity expansion too large")
    return expanded


def _top_level_items(model: str) -> tuple[str, list[str]]:
    """Split a content model's outer group into its items; return the separator (',' or '|') and items."""
    inner = model.strip()
    if inner.endswith(("*", "+", "?")) and inner[:-1].endswith(")"):
        inner = inner[:-1]
    if not (inner.startswith("(") and inner.endswith(")")):
        return ",", [inner]
    inner = inner[1:-1]
    items, depth, cur, sep = [], 0, "", ","
    for ch in inner:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if depth == 0 and ch in ",|":
            sep = ch
            items.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        items.append(cur.strip())
    return sep, items


def required_children(model: str) -> list[str]:
    """The child elements a content model requires, in order.

    In a sequence, a plain name with no ``?`` or ``*`` is required, and so is every name a nested group
    requires when that group is itself required (no ``?`` or ``*``). A choice requires none of its branches,
    and an optional or repeatable-zero group requires nothing.
    """
    model = "".join(model.split())
    if model in ("EMPTY", "ANY") or "#PCDATA" in model:
        return []
    if model.endswith(("*", "?")):
        return []
    sep, items = _top_level_items(model)
    if sep == "|":
        return []
    out: list[str] = []
    for item in items:
        if re.fullmatch(_NAME + r"\+?", item):
            out.append(item.rstrip("+"))
        elif item.startswith("("):
            out.extend(required_children(item))
    return out


def single_children(model: str) -> list[str]:
    """The children a content model allows at most once: names that appear once in the model, never with
    ``*`` or ``+``, and not inside a repeatable group. A repeat of one of these is off-contract."""
    model = "".join(model.split())
    if model in ("EMPTY", "ANY") or "#PCDATA" in model:
        return []
    counts: dict[str, int] = {}
    repeatable: set[str] = set()

    def walk(group: str, repeated: bool) -> None:
        suffix = group[-1] if group[-1] in "*+?" else ""
        body = group[:-1] if suffix else group
        rep = repeated or suffix in ("*", "+")
        if body.startswith("("):
            for item in _top_level_items(body)[1]:
                walk(item, rep)
        else:
            counts[body] = counts.get(body, 0) + 1
            if rep:
                repeatable.add(body)

    walk(model, False)
    return [name for name, n in counts.items() if n == 1 and name not in repeatable]


def parse_dtd(text: str) -> dict[str, dict[str, Any]]:
    """Every element the DTD declares: its content model, the children it requires, and its attributes."""
    if len(text.encode("utf-8")) > MAX_DTD_BYTES:
        raise ReduceError("DTD larger than the reducer reads")
    text = _expand_parameter_entities(_COMMENT.sub("", text))
    elements: dict[str, dict[str, Any]] = {}
    for kind, body in _DECL.findall(text):
        body = " ".join(body.split())
        if kind == "ELEMENT":
            m = re.fullmatch(r"(" + _NAME + r")\s+(.+)", body)
            if not m:
                raise ReduceError(f"malformed ELEMENT declaration: {body[:60]}")
            name, model = m.groups()
            model = model.replace(" ", "")
            prior = elements.get(name)
            if prior and prior["content"] != model:
                raise ReduceError(f"element {name} declared twice with different content")
            elements.setdefault(name, {"content": model, "required_children": required_children(model), "single_children": single_children(model), "attributes": {}})
        elif kind == "ATTLIST":
            parts = body.split()
            if not parts:
                continue
            name, rest = parts[0], parts[1:]
            target = elements.setdefault(name, {"content": None, "required_children": [], "single_children": [], "attributes": {}})
            for i in range(0, len(rest) - 2, 3):
                target["attributes"][rest[i]] = {"type": rest[i + 1], "default": rest[i + 2]}
    return elements


def reduce(dtd_text: str, consumed: list[str], named_not_declared: dict[str, str] | None = None) -> dict[str, dict[str, Any]]:
    """The declarations of the consumed elements only; a consumed element the DTD lacks is refused.

    ``named_not_declared`` lists elements a parent's content model names but the DTD never declares (a gap
    in Qualys's published reference), each with the reason it is read anyway. Each must really appear in
    some content model and really be undeclared; it is recorded with ``content`` null and ``declared``
    false, never given a model the DTD does not state.
    """
    named_not_declared = named_not_declared or {}
    elements = parse_dtd(dtd_text)
    mentioned = {tok for decl in elements.values() if decl["content"] for tok in re.findall(_NAME, decl["content"])}
    out: dict[str, dict[str, Any]] = {}
    missing = []
    for name in consumed:
        if name in elements and elements[name]["content"] is not None:
            out[name] = {**elements[name], "declared": True}
        elif name in named_not_declared:
            if name not in mentioned:
                raise ReduceError(f"{name} is listed as named-but-undeclared, but no content model names it")
            out[name] = {"content": None, "required_children": [], "single_children": [], "attributes": {}, "declared": False, "note": named_not_declared[name]}
        else:
            missing.append(name)
    stale = [name for name in named_not_declared if name in elements and elements[name]["content"] is not None]
    if stale:
        raise ReduceError(f"listed as undeclared but the DTD declares: {', '.join(stale)}")
    if missing:
        raise ReduceError(f"consumed element(s) not declared in the DTD: {', '.join(missing)}")
    return {name: out[name] for name in sorted(out)}
