"""The committed DTD extract and its reducer (req-qualys-contract-extract-1, -4)."""

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

    def test_undeclared_element_is_recorded_as_such(self) -> None:
        asset = build.build()["documents"]["detection"]["elements"]["ASSET_ID"]
        assert asset["declared"] is False and asset["content"] is None and asset["note"]


class TestContentModels:
    @pytest.mark.parametrize(
        ("model", "required"),
        [
            ("(A,B?,C*,D+)", ["A", "D"]),
            ("(A|B)", []),
            ("(#PCDATA)", []),
            ("(A,(B|C),D)", ["A", "D"]),
            ("(A,B)*", []),
            ("EMPTY", []),
        ],
    )
    def test_required_children(self, model: str, required: list[str]) -> None:
        assert required_children(model) == required


class TestBounded:
    def test_external_parameter_entity_refused(self) -> None:
        with pytest.raises(ReduceError, match="external"):
            parse_dtd('<!ENTITY % x SYSTEM "http://example.invalid/x.dtd"> %x; <!ELEMENT A (#PCDATA)>')

    def test_entity_cycle_refused(self) -> None:
        with pytest.raises(ReduceError, match="cycle"):
            parse_dtd('<!ENTITY % a "%b;"><!ENTITY % b "%a;"><!ELEMENT A (%a;)>')

    def test_exponential_chain_refused(self) -> None:
        # Each level doubles: ten levels expand one reference into 1024; the bound stops it.
        decls = ['<!ENTITY % e0 "X">'] + [f'<!ENTITY % e{i} "%e{i-1};%e{i-1};">' for i in range(1, 12)]
        with pytest.raises(ReduceError, match="too many|too large"):
            parse_dtd("".join(decls) + "<!ELEMENT A (%e11;)>")

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
