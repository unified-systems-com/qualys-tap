"""Loading an export archive end to end, through ``manage.py qualys_load`` (req-qualys-file-import).

Archives are built here in the shape ``tools/qualys-export/qualys-export.sh`` writes (script_version 2), from
the committed fixtures. The end-to-end tests run the real command, as the collector actor, through the real
GRIFT importer, and read the result back through the models.
"""

import io
import json
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import tap_plugin.compliance_core.models  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models  # noqa: F401 — trigger model registration
import tap_plugin.qualys.models  # noqa: F401 — trigger model registration
from django.core.management import CommandError, call_command

from tap_plugin.qualys import archive as archive_module
from tap_plugin.qualys.archive import ArchiveRefused, open_archive, read_snapshot
from tap_plugin.qualys.identity import subscription_key
from tap_plugin.qualys.models import QualysDetection, QualysHost, QualysQid, QualysScanRun, QualysSubscription

FIXTURES = Path(__file__).resolve().parent / "fixtures"
VENDOR = Path(__file__).resolve().parent / "vendor"
HOST = "https://qualysapi.qg2.apps.qualys.com"
KEY = subscription_key(HOST, "acme")


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def make_archive(
    tmp_path: Path,
    *,
    pages: list[bytes] | None = None,
    kb: list[bytes] | None = None,
    manifest: dict[str, Any] | None = None,
    extra: dict[str, bytes] | None = None,
    name: str = "export.tgz",
    top: str = "qualys-export-20261120T180000Z",
) -> Path:
    pages = [_fixture("hld-ec2-assembled.xml")] if pages is None else pages
    kb = [_fixture("kb-documented.xml")] if kb is None else kb
    files: dict[str, bytes] = {f"hld-{i:04d}.xml": body for i, body in enumerate(pages, start=1)}
    files.update({f"kb-{chr(97 + i // 26)}{chr(97 + i % 26)}.xml": body for i, body in enumerate(kb)})
    files["qids.txt"] = b"6666666\n38170\n11827\n45038\n"
    meta = {
        "description": "Qualys TAP export manifest",
        "script_version": 2,
        "api_host": HOST,
        "scope": None,
        "created_at": "2026-11-20T18:05:00Z",
        "detection_api": "6.0",
        "knowledgebase_api": "4.0",
        "detection_pages": len(pages),
        "knowledgebase_files": len(kb),
        "knowledgebase_complete": True,
    }
    meta.update(manifest or {})
    files["export.json"] = json.dumps(meta).encode()
    files.update(extra or {})
    path = tmp_path / name
    with tarfile.open(path, "w:gz") as tar:
        directory = tarfile.TarInfo(top)
        directory.type = tarfile.DIRTYPE
        tar.addfile(directory)
        for member, body in files.items():
            info = tarfile.TarInfo(f"{top}/{member}")
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    return path


class TestArchiveRefused:
    def _refused(self, path: Path, match: str) -> None:
        with pytest.raises(ArchiveRefused, match=match):
            open_archive(read_snapshot(path))

    def test_symlink(self, tmp_path: Path) -> None:
        path = tmp_path / "a.tgz"
        with tarfile.open(path, "w:gz") as tar:
            link = tarfile.TarInfo("top/hld-0001.xml")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tar.addfile(link)
        self._refused(path, "not a regular file")

    def test_parent_climb(self, tmp_path: Path) -> None:
        self._refused(make_archive(tmp_path, extra={"../evil": b"x"}), "climbs out")

    def test_absolute(self, tmp_path: Path) -> None:
        path = tmp_path / "a.tgz"
        with tarfile.open(path, "w:gz") as tar:
            info = tarfile.TarInfo("/etc/x")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        self._refused(path, "absolute")

    def test_too_many_members(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(archive_module, "MAX_MEMBERS", 3)
        self._refused(make_archive(tmp_path), "more than 3 members")

    def test_compression_bomb(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(archive_module, "MAX_RATIO", 2)
        self._refused(make_archive(tmp_path, extra={"filler.txt": b"A" * 200_000}), "more than 2 to 1")

    def test_counts_disagree(self, tmp_path: Path) -> None:
        self._refused(make_archive(tmp_path, manifest={"detection_pages": 2}), "counts do not match")

    def test_wrong_api_version(self, tmp_path: Path) -> None:
        self._refused(make_archive(tmp_path, manifest={"detection_api": "2.0"}), "detection API 6.0")

    def test_wrong_script_version(self, tmp_path: Path) -> None:
        self._refused(make_archive(tmp_path, manifest={"script_version": 1}), "script_version")

    def test_nested_directory(self, tmp_path: Path) -> None:
        self._refused(make_archive(tmp_path, extra={"sub/x.xml": b"x"}), "nested directory")

    def test_qids_not_utf8(self, tmp_path: Path) -> None:
        self._refused(make_archive(tmp_path, extra={"qids.txt": b"\xff\xfe"}), "not UTF-8")

    def test_archive_over_the_size_cap(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(archive_module, "MAX_ARCHIVE_BYTES", 100)
        self._refused(make_archive(tmp_path), "larger than 100 bytes")

    def test_unknown_members_are_not_kept(self, tmp_path: Path) -> None:
        archive = open_archive(read_snapshot(make_archive(tmp_path, extra={"filler.bin": b"F" * 50_000, "hld-0001.xml.headers": b"H"})))
        assert len(archive.detection_pages) == 1 and archive.dtds == {}

    def test_digest_is_of_the_bytes_loaded(self, tmp_path: Path) -> None:
        import hashlib

        data = read_snapshot(make_archive(tmp_path))
        assert open_archive(data).sha256 == hashlib.sha256(data).hexdigest()

    def test_duplicate_member_name(self, tmp_path: Path) -> None:
        path = tmp_path / "dup.tgz"
        body = _fixture("hld-ec2-assembled.xml")
        with tarfile.open(path, "w:gz") as tar:
            for _ in range(2):
                info = tarfile.TarInfo("top/hld-0001.xml")
                info.size = len(body)
                tar.addfile(info, io.BytesIO(body))
        self._refused(path, "appears twice")

    def test_not_a_tar(self, tmp_path: Path) -> None:
        path = tmp_path / "a.tgz"
        path.write_bytes(b"not a tar")
        self._refused(path, "not a readable gzip tar")


def _load(path: Path) -> str:
    out = io.StringIO()
    call_command("qualys_load", str(path), subscription="acme", stdout=out)
    return out.getvalue()


@pytest.mark.django_db
class TestLoad:
    def test_lands_on_the_grid(self, tmp_path: Path) -> None:
        output = _load(make_archive(tmp_path))
        assert "loaded run" in output
        assert QualysSubscription.objects.get(subscription_key=KEY).api_host == HOST
        assert QualysHost.objects.get(subscription_key=KEY, host_id="1001").cloud_resource_id == "i-0abc123def4567890"
        assert QualysDetection.objects.filter(subscription_key=KEY).count() == 4
        assert QualysQid.objects.get(subscription_key=KEY, qid="6666666").kb_returned is True
        run = QualysScanRun.objects.get(subscription_key=KEY)
        assert run.source == "file" and run.read_at == datetime(2026, 11, 20, 18, tzinfo=UTC)
        assert run.archive_sha256 and run.finished_at is not None

    def test_same_archive_twice_is_refused(self, tmp_path: Path) -> None:
        path = make_archive(tmp_path)
        _load(path)
        with pytest.raises(CommandError, match="already been loaded"):
            _load(path)
        assert QualysScanRun.objects.filter(subscription_key=KEY).count() == 1

    def test_older_archive_is_refused(self, tmp_path: Path) -> None:
        _load(make_archive(tmp_path))
        older = _fixture("hld-ec2-assembled.xml").replace(b"2026-11-20T18:00:00Z", b"2026-11-19T18:00:00Z")
        with pytest.raises(CommandError, match="older than"):
            _load(make_archive(tmp_path, pages=[older], name="older.tgz"))

    def test_manifest_time_gates_nothing(self, tmp_path: Path) -> None:
        _load(make_archive(tmp_path))
        older = _fixture("hld-ec2-assembled.xml").replace(b"2026-11-20T18:00:00Z", b"2026-11-19T18:00:00Z")
        # A forged future created_at does not make an older read acceptable.
        with pytest.raises(CommandError, match="older than"):
            _load(make_archive(tmp_path, pages=[older], manifest={"created_at": "2099-01-01T00:00:00Z"}, name="forged.tgz"))

    def test_future_read_time_is_refused(self, tmp_path: Path) -> None:
        future = _fixture("hld-ec2-assembled.xml").replace(b"2026-11-20T18:00:00Z", b"2099-01-01T00:00:00Z")
        with pytest.raises(CommandError, match="in the future"):
            _load(make_archive(tmp_path, pages=[future]))

    def test_one_future_page_among_current_ones_is_refused(self, tmp_path: Path) -> None:
        current = _fixture("hld-documented.xml").replace(b"2023-08-16T13:34:18Z", b"2026-11-20T18:00:00Z")
        future = _fixture("hld-documented.xml").replace(b"2023-08-16T13:34:18Z", b"2099-01-01T00:00:00Z")
        with pytest.raises(CommandError, match="in the future"):
            _load(make_archive(tmp_path, pages=[current, future]))

    def test_a_cut_short_knowledge_base_chunk_leaves_qids_unobserved(self, tmp_path: Path) -> None:
        # The export script does not follow the knowledge base's next-page link (#16): a QID asked and not
        # returned may be on the page not read, so it is unobserved (kb_returned null), never "not returned".
        cut = _fixture("kb-documented.xml").replace(b"</RESPONSE>", b"<WARNING><CODE>1980</CODE><TEXT>more</TEXT><URL>https://qualysapi.qg2.apps.qualys.com/api/4.0/fo/knowledge_base/vuln/?action=list&amp;ids=38170</URL></WARNING></RESPONSE>")
        _load(make_archive(tmp_path, kb=[cut]))
        assert QualysQid.objects.get(subscription_key=KEY, qid="38170").kb_returned is None

    def test_a_followed_chunk_is_complete(self, tmp_path: Path) -> None:
        # Version 3 asks again for what a cut-short chunk left out (#16): the link on page 1 is answered by
        # kb-aa-02.xml, so a QID asked and returned by neither page is "not returned", not unobserved.
        cut = _fixture("kb-documented.xml").replace(b"</RESPONSE>", b"<WARNING><CODE>1980</CODE><TEXT>more</TEXT><URL>https://qualysapi.qg2.apps.qualys.com/api/4.0/fo/knowledge_base/vuln/?action=list&amp;ids=38170</URL></WARNING></RESPONSE>")
        archive = make_archive(tmp_path, kb=[cut], extra={"kb-aa-02.xml": _fixture("kb-documented.xml")}, manifest={"script_version": 3, "knowledgebase_files": 2})
        _load(archive)
        assert QualysQid.objects.get(subscription_key=KEY, qid="6666666").kb_returned is True
        assert QualysQid.objects.get(subscription_key=KEY, qid="38170").kb_returned is False

    def test_a_chunk_whose_last_page_links_onward_is_unobserved(self, tmp_path: Path) -> None:
        cut = _fixture("kb-documented.xml").replace(b"</RESPONSE>", b"<WARNING><CODE>1980</CODE><TEXT>more</TEXT><URL>https://qualysapi.qg2.apps.qualys.com/api/4.0/fo/knowledge_base/vuln/?action=list&amp;ids=38170</URL></WARNING></RESPONSE>")
        _load(make_archive(tmp_path, kb=[_fixture("kb-documented.xml")], extra={"kb-aa-02.xml": cut}, manifest={"script_version": 3, "knowledgebase_files": 2}))
        assert QualysQid.objects.get(subscription_key=KEY, qid="38170").kb_returned is None

    @pytest.mark.parametrize(
        ("extra", "version", "match"),
        [
            ({"kb-aa-03.xml": b"x"}, 3, "not numbered 1..n"),
            ({"kb-aa-02.xml": b"x"}, 2, "version 2 archive holds a knowledge-base continuation"),
        ],
    )
    def test_continuation_pages_checked(self, tmp_path: Path, extra: dict[str, bytes], version: int, match: str) -> None:
        with pytest.raises(CommandError, match=match):
            _load(make_archive(tmp_path, extra=extra, manifest={"script_version": version, "knowledgebase_files": 2}))

    def test_checks_and_import_run_under_the_subscription_hold(self, tmp_path: Path) -> None:
        import contextlib

        from tap_grid.grift.importer import grift_import
        from tap_plugin.qualys.load import load_archive
        from tap_plugin.qualys.store import GridStore

        events: list[str] = []

        @contextlib.contextmanager
        def hold(key):
            events.append(f"hold {key}")
            yield
            events.append("release")

        def importer(doc):
            events.append("import")
            return grift_import(doc)

        load_archive(make_archive(tmp_path), "acme", grid=GridStore(), importer=importer, serialize=hold,
                     already_loaded=lambda k, s: events.append("dup-check") or False,
                     newest_read_time=lambda k: events.append("age-check") or None)
        assert events == [f"hold {KEY}", "dup-check", "age-check", "import", "release"]

    def test_off_contract_page_writes_nothing(self, tmp_path: Path) -> None:
        bad = _fixture("hld-ec2-assembled.xml").replace(b"<ID>1001</ID>", b"")
        with pytest.raises(CommandError, match="off-contract"):
            _load(make_archive(tmp_path, pages=[bad]))
        assert not QualysScanRun.objects.exists() and not QualysHost.objects.exists()

    def test_malformed_knowledgebase_still_loads_detections(self, tmp_path: Path) -> None:
        _load(make_archive(tmp_path, kb=[b"<KNOWLEDGE_BASE_VULN_LIST_OUTPUT><RESPONSE>"]))
        assert QualysDetection.objects.filter(subscription_key=KEY).count() == 4
        assert QualysQid.objects.get(subscription_key=KEY, qid="6666666").kb_returned is None

    def test_served_dtd_drift_is_warned(self, tmp_path: Path) -> None:
        dtd = (VENDOR / "hld-output.dtd").read_text().replace("<!ELEMENT HOST (ID,", "<!ELEMENT HOST (ID, NEW_THING,")
        output = _load(make_archive(tmp_path, extra={"hld-output.dtd": dtd.encode()}))
        assert "CONTRACT_DRIFT: hld-output.dtd: consumed element(s) differ: HOST" in output

    def test_served_dtd_unchanged_is_quiet(self, tmp_path: Path) -> None:
        output = _load(make_archive(tmp_path, extra={"hld-output.dtd": (VENDOR / "hld-output.dtd").read_bytes()}))
        assert "CONTRACT_DRIFT" not in output


@pytest.mark.django_db
class TestScopeAndWithdrawal:
    def _second_read(self, tmp_path: Path, scope: dict[str, Any] | None, name: str) -> None:
        later = _fixture("hld-documented.xml").replace(b"2023-08-16T13:34:18Z", b"2026-11-20T19:00:00Z")
        _load(make_archive(tmp_path, pages=[later], manifest={"scope": scope}, name=name))

    def test_unscoped_archive_into_unscoped_subscription_withdraws(self, tmp_path: Path) -> None:
        _load(make_archive(tmp_path))
        self._second_read(tmp_path, None, "second.tgz")
        assert QualysHost.objects.get(subscription_key=KEY, host_id="1001").state == "withdrawn"

    def test_matching_tag_scope_withdraws(self, tmp_path: Path) -> None:
        _load(make_archive(tmp_path))
        QualysSubscription.objects.filter(subscription_key=KEY).update(standing_scope={"tag_ids": [11, 12]})
        self._second_read(tmp_path, {"kind": "tag_ids", "values": ["12", "11"], "tag_match": "any"}, "second.tgz")
        assert QualysHost.objects.get(subscription_key=KEY, host_id="1001").state == "withdrawn"

    @pytest.mark.parametrize(
        "scope",
        [
            {"kind": "tag_names", "values": ["aws-111"], "tag_match": "any"},
            {"kind": "tag_ids", "values": ["11", "12"], "tag_match": "all"},
            {"kind": "tag_ids", "values": ["11"], "tag_match": "any"},
            {"kind": "asset_group_titles", "values": ["AWS Prod"]},
        ],
        ids=["names", "match-all", "different-set", "titles"],
    )
    def test_other_scopes_withdraw_nothing(self, tmp_path: Path, scope: dict[str, Any]) -> None:
        _load(make_archive(tmp_path))
        QualysSubscription.objects.filter(subscription_key=KEY).update(standing_scope={"tag_ids": [11, 12]})
        self._second_read(tmp_path, scope, "second.tgz")
        assert QualysHost.objects.get(subscription_key=KEY, host_id="1001").state == "current"
        run = QualysScanRun.objects.filter(subscription_key=KEY).order_by("-read_at").first()
        assert run.read_kind == "narrower"
