"""The Elastic fixture check (req-qualys-drift-ci-5, unified-systems-com/qualys-tap#45). No test reaches the network.

Elastic's configuration is not in this repository, so these tests build a configuration of the same layout from our
own fixtures and hold the extraction, the hash refusal and the expectations to it.
"""

import hashlib
import re
import socket
import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml

from tap_plugin.qualys.contract import elastic

TESTS = Path(__file__).resolve().parent
FIXTURES = TESTS / "fixtures"
REPO = TESTS.parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "qualys-drift.yml"


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*a: Any, **k: Any) -> None:
        raise AssertionError("these tests must not open a socket")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def _rule(body: str) -> str:
    return "  - path: /api/x/\n    responses:\n      - status_code: 200\n        body: |-\n" + textwrap.indent(body, " " * 10) + "\n"


def _config() -> str:
    """Elastic's layout: rules, each with a ``body: |-`` block, plus a quoted empty body that is not a page."""
    hld = (FIXTURES / "hld-third-party-ctis.xml").read_text()
    kb = (FIXTURES / "kb-documented.xml").read_text()
    empty = '  - path: /api/x/\n    responses:\n      - status_code: 200\n        body: "" # handling empty XML response\n'
    return "rules:\n  # Initial Request\n" + _rule(hld) + empty + _rule(kb) + _rule("not a page")


@pytest.mark.spec("req-qualys-drift-ci-5")
class TestExtraction:
    def test_block_bodies_are_read_in_order_and_deindented(self) -> None:
        got = elastic.bodies(_config())
        assert got[0] == (FIXTURES / "hld-third-party-ctis.xml").read_text().rstrip("\n")
        assert got[1] == (FIXTURES / "kb-documented.xml").read_text().rstrip("\n")
        assert got[2] == "not a page" and len(got) == 3

    def test_extraction_agrees_with_a_yaml_parser(self) -> None:
        rules = yaml.safe_load(_config())["rules"]
        parsed = [r["responses"][0]["body"] for r in rules if r["responses"][0]["body"]]
        assert elastic.bodies(_config()) == parsed

    def test_blank_lines_inside_a_body_are_kept(self) -> None:
        assert elastic.bodies(_rule("<A>\n\n<B/></A>")) == ["<A>\n\n<B/></A>"]

    def test_pages_are_read_and_others_skipped(self) -> None:
        detection, kb = elastic.read(_config())
        assert detection == ("detection", 2, 5, True)  # the ctis page: 2 hosts, 5 DETECTION elements
        assert kb[0] == "knowledgebase" and kb[1] > 0


@pytest.mark.spec("req-qualys-drift-ci-5")
class TestCheck:
    @pytest.fixture
    def pinned(self, monkeypatch: pytest.MonkeyPatch) -> bytes:
        raw = _config().encode()
        monkeypatch.setattr(elastic, "SHA256", hashlib.sha256(raw).hexdigest())
        monkeypatch.setattr(elastic, "EXPECTED", elastic.read(_config()))
        return raw

    def test_the_recorded_pages_pass(self, pinned: bytes) -> None:
        assert elastic.check(lambda url, limit: pinned) == 0

    def test_a_different_file_is_refused_unread(self, pinned: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(elastic, "read", lambda text: pytest.fail("a refused file was parsed"))
        assert elastic.check(lambda url, limit: pinned + b"\n") == 2

    def test_a_page_that_reads_short_fails(self, pinned: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
        expected = list(elastic.EXPECTED)
        expected[0] = ("detection", 2, 8, True)
        monkeypatch.setattr(elastic, "EXPECTED", expected)
        assert elastic.check(lambda url, limit: pinned) == 1

    def test_a_refused_page_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        raw = (_config() + _rule("<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE/></HOST_LIST_VM_DETECTION_OUTPUT>")).encode()
        monkeypatch.setattr(elastic, "SHA256", hashlib.sha256(raw).hexdigest())
        assert elastic.check(lambda url, limit: raw) == 1

    def test_a_fetch_failure_cannot_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fail(url: str, limit: int) -> bytes:
            raise elastic.DriftError("HTTP 404")

        monkeypatch.setattr(elastic, "fetch", fail)
        assert elastic.main([]) == 2

    def test_the_source_is_pinned_to_a_commit(self) -> None:
        assert re.fullmatch(r"[0-9a-f]{40}", elastic.COMMIT) and re.fullmatch(r"[0-9a-f]{64}", elastic.SHA256)
        assert elastic.URL == f"https://raw.githubusercontent.com/elastic/integrations/{elastic.COMMIT}/{elastic.PATH}"
        assert len(elastic.EXPECTED) == 8


@pytest.mark.spec("req-qualys-drift-ci-5")
class TestWorkflowJob:
    def test_the_job_installs_by_hash_and_runs_the_check(self) -> None:
        job = yaml.safe_load(WORKFLOW.read_text())["jobs"]["elastic-fixtures"]
        runs = [s["run"] for s in job["steps"] if "run" in s]
        assert any("--require-hashes" in r and "elastic-requirements.txt" in r for r in runs)
        assert runs[-1] == '"$RUNNER_TEMP/venv/bin/python" -m tap_plugin.qualys.contract.elastic'

    def test_the_requirement_is_the_package_pin(self) -> None:
        reqs = (REPO / "tap_plugin" / "qualys" / "contract" / "elastic-requirements.txt").read_text()
        (line,) = [x for x in reqs.splitlines() if x and not x.startswith("#")]
        pin = line.split()[0]
        assert f'"{pin}"' in (REPO / "pyproject.toml").read_text()
        assert re.search(r"--hash=sha256:[0-9a-f]{64}$", line)
