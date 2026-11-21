"""The committed DTD extract and its reducer (req-qualys-contract-extract-1, -4)."""

import json
from pathlib import Path

import jsonschema
import pytest

from tap_plugin.qualys.contract import build
from tap_plugin.qualys.contract.reduce import MAX_DTD_BYTES, ReduceError, parse_dtd, reduce, required_children


class TestGeneratedNotTyped:
    def test_committed_extract_matches_the_sources(self) -> None:
        assert build.main(["--check"]) == 0, "extract.json is out of date: run python -m tap_plugin.qualys.contract.build"

    def test_required_children_follow_the_dtd(self) -> None:
        documents = build.build()["documents"]
        detection = documents["detection"]["elements"]
        assert detection["HOST"]["required_children"] == ["ID", "DETECTION_LIST"]
        assert detection["DETECTION"]["required_children"] == ["UNIQUE_VULN_ID", "QID", "TYPE"]
        assert detection["RESPONSE"]["required_children"] == ["DATETIME"]
        assert documents["knowledgebase"]["elements"]["CVE"]["required_children"] == ["ID", "URL"]

    def test_asset_id_is_declared_by_the_served_dtd(self) -> None:
        # The reference PDF named ASSET_ID without declaring it; the DTD Qualys serves declares it, so it is read
        # as declared and consumed.json no longer lists it under named_not_declared.
        asset = build.build()["documents"]["detection"]["elements"]["ASSET_ID"]
        assert asset["declared"] is True and asset["content"] == "(#PCDATA)"


CONTRACT = Path(build.__file__).resolve().parent


@pytest.mark.parametrize("name", ["consumed", "extract"])
def test_described_and_schema_valid(name: str) -> None:
    schema = json.loads((CONTRACT / f"{name}.schema.json").read_text(encoding="utf-8"))
    data = json.loads((CONTRACT / f"{name}.json").read_text(encoding="utf-8"))
    jsonschema.validate(data, schema)
    assert data["description"]


class TestContentModels:
    @pytest.mark.parametrize(
        ("model", "required"),
        [
            ("(A,B?,C*,D+)", ["A", "D"]),
            ("(A|B)", []),
            ("(#PCDATA)", []),
            ("(A,(B|C),D)", ["A", "D"]),
            ("(A,(B,C),D)", ["A", "B", "C", "D"]),
            ("(A,(B,C)?,D)", ["A", "D"]),
            ("(A,(B,(C|E)),D)", ["A", "B", "D"]),
            ("(A,B)*", []),
            ("EMPTY", []),
        ],
    )
    def test_required_children(self, model: str, required: list[str]) -> None:
        assert required_children(model) == required


@pytest.mark.parametrize(
    ("model", "single"),
    [("(A,B?,C*,D+)", ["A", "B"]), ("(A|B)", ["A", "B"]), ("(A,(B,C)*)", ["A"]), ("(A,A)", []), ("(#PCDATA)", [])],
)
def test_single_children(model: str, single: list[str]) -> None:
    from tap_plugin.qualys.contract.reduce import single_children

    assert single_children(model) == single


class TestBounded:
    def test_external_parameter_entity_refused(self) -> None:
        with pytest.raises(ReduceError, match="external"):
            parse_dtd('<!ENTITY % x SYSTEM "http://example.invalid/x.dtd"> %x; <!ELEMENT A (#PCDATA)>')

    def test_deep_linear_chain_refused_cleanly(self) -> None:
        decls = ['<!ENTITY % e0 "X">'] + [f'<!ENTITY % e{i} "%e{i-1};">' for i in range(1, 800)]
        with pytest.raises(ReduceError, match="nested too deeply"):
            parse_dtd("".join(decls) + "<!ELEMENT A (%e799;)>")

    def test_entity_cycle_refused(self) -> None:
        with pytest.raises(ReduceError, match="cycle"):
            parse_dtd('<!ENTITY % a "%b;"><!ENTITY % b "%a;"><!ELEMENT A (%a;)>')

    def test_exponential_chain_refused(self) -> None:
        # Each level doubles: ten levels expand one reference into 1024; the bound stops it.
        decls = ['<!ENTITY % e0 "X">'] + [f'<!ENTITY % e{i} "%e{i-1};%e{i-1};">' for i in range(1, 12)]
        with pytest.raises(ReduceError, match="too many|too large"):
            parse_dtd("".join(decls) + "<!ELEMENT A (%e11;)>")

    def test_expansion_bounded_while_it_grows(self) -> None:
        # Each reference stays under the limit alone; together they would pass 1 GiB if only the end were checked.
        import tracemalloc

        dtd = '<!ENTITY % e "' + "x" * 10_000 + '">' + "<!ELEMENT A (" + "%e;" * 1000 + ")>"
        tracemalloc.start()
        try:
            with pytest.raises(ReduceError, match="too large"):
                parse_dtd(dtd)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert peak < 8 << 20  # refused near the 1 MiB bound, not after building ~10 MiB

    def test_oversized_refused(self) -> None:
        with pytest.raises(ReduceError, match="larger"):
            parse_dtd("<!ELEMENT A (#PCDATA)>" + " " * MAX_DTD_BYTES)

    def test_consumed_but_undeclared_refused(self) -> None:
        with pytest.raises(ReduceError, match="not declared"):
            reduce("<!ELEMENT A (B?)>", ["A", "B"])

    def test_named_not_declared_must_be_named(self) -> None:
        with pytest.raises(ReduceError, match="no content model names"):
            reduce("<!ELEMENT A (#PCDATA)>", ["A", "Z"], {"Z": "reason"})

    def test_named_not_declared_goes_stale_when_declared(self) -> None:
        with pytest.raises(ReduceError, match="DTD declares"):
            reduce("<!ELEMENT A (B?)><!ELEMENT B (#PCDATA)>", ["A", "B"], {"B": "reason"})

    def test_wrapped_comment_terminator_tolerated(self) -> None:
        # The PDF reference wraps one comment terminator across a line.
        assert "A" in parse_dtd("<!-- note -\n-> <!ELEMENT A (#PCDATA)>")


@pytest.mark.spec("req-qualys-contract-extract-1")
class TestAttlistForms:
    """Enumerated types, quoted and fixed defaults, and an ATTLIST before its ELEMENT (qualys-tap#18)."""

    def test_enumerated_type_and_defaults(self) -> None:
        dtd = """<!ELEMENT A (#PCDATA)>
        <!ATTLIST A mode ( x | y ) #REQUIRED
                    kind (one|two) "one"
                    version CDATA #FIXED "2.0"
                    note CDATA #IMPLIED
                    fmt NOTATION (gif | png) #IMPLIED>"""
        attrs = parse_dtd(dtd)["A"]["attributes"]
        assert attrs == {
            "mode": {"type": "(x|y)", "default": "#REQUIRED"},
            "kind": {"type": "(one|two)", "default": '"one"'},
            "version": {"type": "CDATA", "default": '#FIXED "2.0"'},
            "note": {"type": "CDATA", "default": "#IMPLIED"},
            "fmt": {"type": "NOTATION(gif|png)", "default": "#IMPLIED"},
        }

    def test_attlist_before_its_element(self) -> None:
        elements = parse_dtd("<!ATTLIST A id CDATA #REQUIRED><!ELEMENT A (B, C?)><!ELEMENT B (#PCDATA)><!ELEMENT C (#PCDATA)>")
        assert elements["A"]["content"] == "(B,C?)"
        assert elements["A"]["required_children"] == ["B"]
        assert elements["A"]["attributes"] == {"id": {"type": "CDATA", "default": "#REQUIRED"}}

    @pytest.mark.parametrize(
        "body",
        ["A mode (x|y)", "A version CDATA #FIXED", "A mode (x|y) sometimes", "A fmt NOTATION #IMPLIED", "A mode (x|y #REQUIRED"],
    )
    def test_malformed_refused(self, body: str) -> None:
        with pytest.raises(ReduceError):
            parse_dtd(f"<!ELEMENT A (#PCDATA)><!ATTLIST {body}>")
