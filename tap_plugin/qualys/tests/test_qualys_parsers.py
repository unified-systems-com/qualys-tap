"""Result parsers (req-qualys-parsers, req-qualys-package-link-1 groundwork).

The fixture is documented, not observed (req-qualys-parsers-4): this plugin is built blind, so a parser here
does not reach Implemented on it.
"""

import importlib
import types
from pathlib import Path

import pytest

from tap_plugin.qualys import parsers
from tap_plugin.qualys.parsers import package_table

FIXTURES = Path(__file__).resolve().parent / "fixtures"
DEBIAN = "Debian GNU/Linux 12"


def _fixture(name: str) -> str:
    first, _, body = (FIXTURES / name).read_text().partition("\n")
    assert first.startswith("# fixture-evidence: ")
    return body


def _parse(results: str | None, os_name: str | None = DEBIAN, qid: str = "6666666") -> parsers.Parsed:
    return parsers.parse({"qid": qid, "results": results, "os": os_name})


class TestRegistry:
    def test_every_registered_parser_has_a_fixture_with_evidence(self) -> None:
        for name in parsers.REGISTERED:
            module = name.split("/")[0]
            text = (FIXTURES / f"{module}.txt").read_text()
            assert text.startswith("# fixture-evidence: documented (") or text.startswith("# fixture-evidence: observed (")

    def test_registered_carries_its_version(self) -> None:
        assert set(parsers.REGISTERED) == {f"package_table/{package_table.PARSER_VERSION}"}

    def test_a_qid_claimed_twice_is_refused(self) -> None:
        one = types.ModuleType("tap_plugin.qualys.parsers.one")
        two = types.ModuleType("tap_plugin.qualys.parsers.two")
        for module in (one, two):
            module.PARSER_VERSION = "1"
            module.QIDS = ("38170",)
            module.parse = lambda detection: []
        with pytest.raises(ImportError, match="claimed twice"):
            parsers._register((one, two))

    def test_a_listed_qid_wins_over_a_header_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        claimed = types.ModuleType("tap_plugin.qualys.parsers.claimed")
        claimed.PARSER_VERSION = "7"
        claimed.parse = lambda detection: []
        monkeypatch.setitem(parsers._BY_QID, "6666666", claimed)
        got = _parse(_fixture("package_table.txt"))
        assert (got.state, got.parser_version, got.observations) == ("parsed", "claimed/7", ())

    def test_parsers_are_pure(self) -> None:
        source = Path(package_table.__file__).read_text()
        for forbidden in ("import requests", "import socket", "open(", "django"):
            assert forbidden not in source


class TestFourStates:
    def test_parsed(self) -> None:
        got = _parse(_fixture("package_table.txt"))
        assert got.state == "parsed" and got.parser_version == "package_table/1" and len(got.observations) == 2

    @pytest.mark.parametrize("results", [None, "", "Vulnerable registry key found\tHKLM\\Software\\X", "Packages:\nfoo 1.0"])
    def test_no_parser_is_not_no_package(self, results: str | None) -> None:
        got = _parse(results)
        assert (got.state, got.parser_version, got.observations) == ("no_parser", None, ())

    def test_parser_failed(self) -> None:
        got = _parse("Package\tInstalled Version\tRequired Version\nnot a row")
        assert got.state == "parser_failed" and got.parser_version == "package_table/1" and "no package row" in got.failure

    def test_not_applicable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(parsers, "NOT_APPLICABLE", {"45038": "an information-gathering QID"})
        assert _parse(_fixture("package_table.txt"), qid="45038").state == "not_applicable"


class TestPackageTable:
    def test_rows_and_evidence(self) -> None:
        text = _fixture("package_table.txt")
        first, second = _parse(text).observations
        assert (first.ecosystem, first.name, first.installed_version, first.required_version) == ("deb", "webkit2gtk", "2.44.2-1~deb12u1", "2.44.3-1~deb12u1")
        assert first.mapping_unambiguous and second.name == "libjavascriptcoregtk-4.1-0"
        # Evidence is the exact line, and the text it came from is untouched.
        assert first.evidence == "webkit2gtk\t2.44.2-1~deb12u1\t2.44.3-1~deb12u1" and first.evidence in text.split("\n")

    @pytest.mark.parametrize(
        "header",
        [
            "Package\tInstalled Version\tRequired Version",
            "Package\tInstalled_Version\tRequired_Version",
            '#table cols="3"\nPackage\tInstalled_Version\tRequired_Version',
        ],
    )
    def test_header_variants(self, header: str) -> None:
        got = _parse(f"{header}\nopenssl\t3.0.11-1~deb12u1\t3.0.11-1~deb12u2")
        assert got.state == "parsed" and got.observations[0].name == "openssl"

    def test_trailing_lines_tolerated(self) -> None:
        got = _parse("Package\tInstalled Version\tRequired Version\ncurl\t7.88.1-10\t7.88.1-11\nSee the vendor advisory.\nzlib\t1\t2")
        assert [o.name for o in got.observations] == ["curl"]

    def test_crlf(self) -> None:
        got = _parse("Package\tInstalled Version\tRequired Version\r\ncurl\t7.88.1-10\t7.88.1-11\r\n")
        assert got.observations[0].installed_version == "7.88.1-10"

    def test_empty_required_version_is_null(self) -> None:
        assert _parse("Package\tInstalled Version\tRequired Version\ncurl\t7.88.1-10\t").observations[0].required_version is None

    @pytest.mark.parametrize(
        ("os_name", "ecosystem"),
        [("Ubuntu 22.04", "deb"), ("Amazon Linux 2023", "rpm"), ("Red Hat Enterprise Linux 9.3", "rpm"), ("SUSE Linux Enterprise Server 15", "rpm"), ("Windows Server 2022", None), (None, None)],
    )
    def test_ecosystem_from_os(self, os_name: str | None, ecosystem: str | None) -> None:
        (only,) = _parse("Package\tInstalled Version\tRequired Version\ncurl\t8.5.0-1\t8.5.0-2", os_name).observations
        assert only.ecosystem == ecosystem
        assert only.mapping_unambiguous is (ecosystem is not None)

    @pytest.mark.parametrize(
        ("os_name", "version"),
        [(DEBIAN, "1:2.38.1-5+deb12u1"), ("Amazon Linux 2023", "8.5.0-1.amzn2023.x86_64"), ("Amazon Linux 2023", "tzdata-2024a-1.noarch")],
    )
    def test_epoch_or_architecture_is_ambiguous(self, os_name: str, version: str) -> None:
        (only,) = _parse(f"Package\tInstalled Version\tRequired Version\npkg\t{version}\tz", os_name).observations
        assert only.installed_version == version and not only.mapping_unambiguous


def test_registry_import_is_stable() -> None:
    # Re-importing builds the same registry: claims are checked at import, not lazily.
    assert set(importlib.reload(parsers).REGISTERED) == {"package_table/1"}
