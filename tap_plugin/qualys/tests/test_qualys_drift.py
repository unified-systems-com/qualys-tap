"""The scheduled drift check and its comparison (req-qualys-drift-ci). No test reaches the network."""

import hashlib
import socket
from pathlib import Path
from typing import Any

import pytest
import yaml

from tap_plugin.qualys.contract import drift

TESTS = Path(__file__).resolve().parent
VENDOR = TESTS / "vendor"
REPO = TESTS.parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "qualys-drift.yml"


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*a: Any, **k: Any) -> None:
        raise AssertionError("these tests must not open a socket")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def _dtd(document: str) -> str:
    return (VENDOR / ("hld-output.dtd" if document == "detection" else "kb-output.dtd")).read_text()


@pytest.mark.spec("req-qualys-drift-ci-1")
class TestFailsOnConsumedDrift:
    def test_the_committed_dtds_compare_clean(self) -> None:
        for document in drift.DTD_PATHS:
            assert drift.compare(document, _dtd(document)) == ([], [])

    def test_a_consumed_content_model_change_fails(self, tmp_path: Path) -> None:
        changed = _dtd("detection").replace("<!ELEMENT HOST (ID,", "<!ELEMENT HOST (ID, NEW_THING,")
        assert drift.compare("detection", changed)[0] == ["HOST"]
        path = tmp_path / "output.dtd"
        path.write_text(changed)
        assert drift.check_file("detection", path) == 1

    def test_a_consumed_attribute_change_fails(self) -> None:
        changed = _dtd("detection").replace("<!ATTLIST QDS severity CDATA #REQUIRED>", "<!ATTLIST QDS severity CDATA #IMPLIED>")
        assert drift.compare("detection", changed)[0] == ["QDS"]

    def test_a_dtd_that_cannot_be_reduced_fails(self) -> None:
        consumed, _ = drift.compare("detection", '<!ENTITY % x SYSTEM "http://example.invalid/x">%x;')
        assert len(consumed) == 1 and consumed[0].startswith("the DTD cannot be reduced")


@pytest.mark.spec("req-qualys-drift-ci-2")
class TestReportsOtherChanges:
    def test_an_unconsumed_addition_is_reported_and_passes(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        changed = _dtd("knowledgebase") + "\n<!ELEMENT BRAND_NEW (#PCDATA)>\n"
        assert drift.compare("knowledgebase", changed) == ([], ["added BRAND_NEW"])
        path = tmp_path / "kb.dtd"
        path.write_text(changed)
        assert drift.check_file("knowledgebase", path) == 0
        assert "not consumed, reported only: added BRAND_NEW" in capsys.readouterr().out

    def test_served_check_against_a_fake_host(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        summary = tmp_path / "summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
        asked: list[str] = []

        def fetcher(url: str, limit: int) -> bytes:
            asked.append(url)
            document = "detection" if url.endswith("/detection/dtd/output.dtd") else "knowledgebase"
            return _dtd(document).encode()

        assert drift.check_served("https://qualysapi.qualys.com", fetcher) == 0
        assert asked == [f"https://qualysapi.qualys.com{p}" for p in drift.DTD_PATHS.values()]
        assert "no consumed element changed" in summary.read_text()


class TestReference:
    def test_unchanged_reference_passes(self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        body = b"the reference as recorded"
        meta = {**drift.provenance(), "source_sha256": hashlib.sha256(body).hexdigest()}
        monkeypatch.setattr(drift, "provenance", lambda: meta)
        assert drift.check_reference(lambda url, limit: body) == 0
        assert "unchanged" in capsys.readouterr().out

    def test_a_changed_reference_fails(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert drift.check_reference(lambda url, limit: b"a different pdf") == 1
        assert "CHANGED" in capsys.readouterr().out

    def test_the_reference_fetched_is_the_recorded_source(self) -> None:
        seen: list[str] = []
        drift.check_reference(lambda url, limit: seen.append(url) or b"")
        assert seen == [drift.provenance()["source"]] and len(drift.provenance()["source_sha256"]) == 64

    def test_a_failed_fetch_exits_two(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def refuse(url: str, limit: int) -> bytes:
            raise drift.DriftError("HTTP 503 for x")

        monkeypatch.setattr(drift, "fetch", refuse)
        assert drift.main(["reference"]) == 2

    def test_only_https_is_fetched(self) -> None:
        with pytest.raises(drift.DriftError, match="only https"):
            drift.fetch("http://example.invalid/x", 10)


@pytest.mark.spec("req-qualys-drift-ci-3")
class TestReadOnlyWorkflow:
    @pytest.fixture
    def workflow(self) -> dict[str, Any]:
        return yaml.safe_load(WORKFLOW.read_text())

    def test_contents_read_only_everywhere(self, workflow: dict[str, Any]) -> None:
        assert workflow["permissions"] == {"contents": "read"}
        for job in workflow["jobs"].values():
            assert job.get("permissions", {"contents": "read"}) == {"contents": "read"}

    def test_no_secret_and_no_issue(self) -> None:
        text = WORKFLOW.read_text()
        assert "secrets." not in text and "issues" not in text and "QUALYS_PASSWORD" not in text

    def test_scheduled_and_pinned(self, workflow: dict[str, Any]) -> None:
        triggers = workflow[True] if True in workflow else workflow["on"]  # YAML 1.1 reads "on" as true
        assert "schedule" in triggers
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    ref = step["uses"].split("@", 1)[1]
                    assert len(ref) == 40 and all(c in "0123456789abcdef" for c in ref)
                    assert step.get("with", {}).get("persist-credentials") is False

    def test_the_scheduled_job_compares_the_served_dtds(self, workflow: dict[str, Any]) -> None:
        (step,) = [s for s in workflow["jobs"]["served"]["steps"] if "run" in s]
        assert step["run"] == "python3 -m tap_plugin.qualys.contract.drift served --host https://qualysapi.qualys.com"

    def test_provenance_records_each_served_source(self) -> None:
        files = drift.provenance()["files"]
        for name, path in (("hld-output.dtd", drift.DTD_PATHS["detection"]), ("kb-output.dtd", drift.DTD_PATHS["knowledgebase"])):
            assert files[name]["url"] == f"https://qualysapi.qualys.com{path}"
            assert files[name]["sha256"] == hashlib.sha256((VENDOR / name).read_bytes()).hexdigest()


def test_dtd_paths_match_the_export_script() -> None:
    script = (REPO / "tools" / "qualys-export" / "qualys-export.sh").read_text()
    for path in drift.DTD_PATHS.values():
        assert f'"$API{path}"' in script


def test_standard_library_only() -> None:
    import ast

    tree = ast.parse(Path(drift.__file__).read_text())
    roots = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    roots |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert roots <= {"argparse", "hashlib", "json", "os", "urllib", "pathlib", "typing", "tap_plugin"}
