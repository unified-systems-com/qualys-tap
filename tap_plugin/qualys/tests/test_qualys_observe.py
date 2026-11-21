"""The observation command (req-qualys-observe), against a fake adapter serving the fixture pages.

The client is the real ReadOnlyClient with its guarded session; only the adapter under it is fake, so every
request in these tests went through the allowlist. No socket is opened, and nothing touches the grid.
"""

import base64
import io
import json
import os
import socket
import stat
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
from requests.adapters import HTTPAdapter

from tap_plugin.qualys import observe
from tap_plugin.qualys.client import (
    DETECTION_DTD_PATH,
    DETECTION_PATH,
    KNOWLEDGEBASE_DTD_PATH,
    KNOWLEDGEBASE_PATH,
    Exchange,
    ReadOnlyClient,
    TransportRefused,
    check_url,
)

TESTS = Path(__file__).resolve().parent
FIXTURES = TESTS / "fixtures"
VENDOR = TESTS / "vendor"
HOST = "https://qualysapi.qg2.apps.qualys.com"
USER = "acme" + "_ro"
PASSWORD = "".join(["observe", "-", "test", "-", "pw"])
ACCOUNT = "".join(["1234", "5678", "9012"])
ACCOUNT_ATTRIBUTE = (
    "<ATTRIBUTE>\n<NAME><![CDATA[latest/dynamic/instance-identity/document/accountId]]></NAME>\n"
    f"<LAST_STATUS><![CDATA[Success]]></LAST_STATUS>\n<VALUE><![CDATA[{ACCOUNT}]]></VALUE>\n</ATTRIBUTE>\n"
).encode()
SENSITIVE = ("10.0.1.15", "ip-10-0-1-15", "i-0abc123def4567890", ACCOUNT, PASSWORD, USER, "qualysapi", "us-east-1")


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _page() -> bytes:
    return _fixture("hld-ec2-assembled.xml").replace(b"</EC2>", ACCOUNT_ATTRIBUTE + b"</EC2>", 1)


def _without(body: bytes, start_tag: bytes, end_tag: bytes) -> bytes:
    start = body.index(start_tag)
    end = body.index(end_tag, start) + len(end_tag)
    return body[:start] + body[end:]


def _drop_ignored(body: bytes) -> bytes:
    """The page as Qualys would answer it without include_ignored: the ignored detection (QID 11827) gone."""
    marker = body.index(b"<QID>11827</QID>")
    start = body.rindex(b"<DETECTION>", 0, marker)
    end = body.index(b"</DETECTION>", marker) + len(b"</DETECTION>")
    return body[:start] + body[end:]


class Router(HTTPAdapter):
    """Answers by path and parameters, and records every request that reached it."""

    def __init__(self, **overrides: Any) -> None:
        super().__init__()
        self.seen: list[requests.PreparedRequest] = []
        self.overrides = overrides

    def answer(self, request: requests.PreparedRequest) -> tuple[int, bytes]:
        parts = urlsplit(request.url)
        query = parse_qs(parts.query)
        authenticated = "Authorization" in request.headers
        if parts.path == DETECTION_PATH:
            if query.get("truncation_limit") == ["1"]:
                if "host_metadata" not in query:
                    return self.overrides.get("no_metadata", (200, _without(_without(_page(), b"<WARNING>", b"</WARNING>"), b"<CLOUD_RESOURCE_ID>", b"</CLOUD_RESOURCE_ID>")))
                return self.overrides.get("probe", (200, _without(_page(), b"<WARNING>", b"</WARNING>")))
            if "include_ignored" not in query:
                return self.overrides.get("without_flags", (200, _drop_ignored(_page())))
            return self.overrides.get("page", (200, _page()))
        if parts.path == KNOWLEDGEBASE_PATH:
            return self.overrides.get("kb", (200, _fixture("kb-documented.xml")))
        if parts.path in (DETECTION_DTD_PATH, KNOWLEDGEBASE_DTD_PATH):
            if not authenticated:
                return self.overrides.get("dtd_anonymous", (401, b"<html>unauthorized</html>"))
            return 200, (VENDOR / ("hld-output.dtd" if parts.path == DETECTION_DTD_PATH else "kb-output.dtd")).read_bytes()
        return 404, b""

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        self.seen.append(request)
        status, body = self.answer(request)
        response = requests.Response()
        response.status_code = status
        response.raw = io.BytesIO(body)
        response.headers.update({"X-RateLimit-Remaining": "299", "X-ConcurrencyLimit-Limit": "2", "Set-Cookie": "QualysSession=abc; Secure"})
        response.url = request.url
        response.request = request
        return response


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*a: Any, **k: Any) -> None:
        raise AssertionError("these tests must not open a socket")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def secrets(tmp_path: Path) -> Path:
    root = tmp_path / "secrets"
    root.mkdir()
    data = {"api_host": HOST, "subscription": "acme-prod", "username": USER, "password": PASSWORD}
    (root / "acme.secret.json").write_text(json.dumps({"scope": "qualys", "key": "acme", "kind": "qualys_api_credential", "description": "test envelope", "data": data}))
    return root


def _run(secrets: Path, out_dir: Path, router: Router, *extra: str) -> tuple[int, str]:
    out = io.StringIO()
    code = observe.main(["--key", "acme", "--secrets-root", str(secrets), "--out", str(out_dir), *extra], out=out, adapter=router)
    return code, out.getvalue()


def _ledger_lines(text: str) -> dict[str, tuple[str, str]]:
    section = text.split("ledger:\n", 1)[1]
    found = {}
    for line in section.splitlines():
        parts = line.split()
        if parts and parts[0] in observe.CHECKS:
            rest = line.strip()[len(parts[0]) :].strip()
            outcome = observe.NOT_REACHED if rest.startswith(observe.NOT_REACHED) else parts[1]
            found[parts[0]] = (outcome, rest[len(outcome) :].strip())
    return found


@pytest.mark.spec("req-qualys-observe-4")
class TestLedger:
    def test_ledger_is_valid_and_every_entry_has_a_check(self) -> None:
        ids = [e["id"] for e in observe.ledger()]
        assert len(ids) == len(set(ids)) == 11
        assert set(ids) == set(observe.CHECKS)

    def test_every_entry_reported_with_an_outcome(self, secrets: Path, tmp_path: Path) -> None:
        code, text = _run(secrets, tmp_path / "rec", Router())
        assert code == 0
        lines = _ledger_lines(text)
        assert set(lines) == set(observe.CHECKS)
        assert {o for o, _ in lines.values()} <= {observe.SETTLED, observe.CONTRADICTED, observe.NOT_REACHED}

    def test_outcomes_from_the_fixture_pages(self, secrets: Path, tmp_path: Path) -> None:
        lines = _ledger_lines(_run(secrets, tmp_path / "rec", Router())[1])
        assert lines["subscription-identity"][0] == observe.SETTLED
        assert lines["ec2-account-attribute"] == (observe.SETTLED, "attribute name(s) latest/dynamic/instance-identity/document/accountId")
        assert lines["cloud-resource-id-without-metadata"][0] == observe.SETTLED
        assert lines["ignored-disabled-default"] == (observe.SETTLED, "1 ignored or disabled detection(s) left out")
        # The assembled fixture deliberately shares one UNIQUE_VULN_ID between two QIDs.
        assert lines["unique-vuln-id-collision"] == (observe.CONTRADICTED, "1 id(s) seen under two or more QIDs")
        assert lines["kb-409-meaning"][0] == observe.NOT_REACHED
        assert lines["concurrency-header-spelling"] == (observe.SETTLED, "X-ConcurrencyLimit-*")
        assert lines["dtd-unauthenticated"] == (observe.SETTLED, "both refused without a credential")
        assert lines["package-table-variants"][0] == observe.SETTLED and "plain" in lines["package-table-variants"][1]
        assert lines["cloud-provider-tags-shape"][0] == observe.NOT_REACHED

    def test_contradictions_are_reported(self, secrets: Path, tmp_path: Path) -> None:
        router = Router(
            dtd_anonymous=(200, (VENDOR / "hld-output.dtd").read_bytes()),
            without_flags=(200, _page()),
            no_metadata=(200, _without(_page(), b"<WARNING>", b"</WARNING>")),
        )
        lines = _ledger_lines(_run(secrets, tmp_path / "rec", router)[1])
        assert lines["dtd-unauthenticated"][0] == observe.CONTRADICTED
        assert lines["ignored-disabled-default"][0] == observe.CONTRADICTED
        assert lines["cloud-resource-id-without-metadata"][0] == observe.CONTRADICTED

    def test_no_metadata_read_is_pinned_to_the_probe_host(self, secrets: Path, tmp_path: Path) -> None:
        router = Router()
        _run(secrets, tmp_path / "rec", router)
        pinned = [parse_qs(urlsplit(r.url).query) for r in router.seen if urlsplit(r.url).path == DETECTION_PATH and "host_metadata" not in parse_qs(urlsplit(r.url).query)]
        assert len(pinned) == 1 and pinned[0]["id_min"] == ["1001"] and pinned[0]["truncation_limit"] == ["1"]

    def test_a_different_host_is_not_compared(self, secrets: Path, tmp_path: Path) -> None:
        other = _without(_without(_page(), b"<WARNING>", b"</WARNING>"), b"<CLOUD_RESOURCE_ID>", b"</CLOUD_RESOURCE_ID>").replace(b"<ID>1001</ID>", b"<ID>1009</ID>", 1)
        lines = _ledger_lines(_run(secrets, tmp_path / "rec", Router(no_metadata=(200, other)))[1])
        assert lines["cloud-resource-id-without-metadata"] == (observe.NOT_REACHED, "the no-metadata read returned a different host from the probe")

    def test_kb_409_with_another_code_settles(self, secrets: Path, tmp_path: Path) -> None:
        body = b"<?xml version='1.0'?><SIMPLE_RETURN><RESPONSE><CODE>2003</CODE><TEXT>no</TEXT></RESPONSE></SIMPLE_RETURN>"
        code, text = _run(secrets, tmp_path / "rec", Router(kb=(409, body)))
        assert code == 0
        assert _ledger_lines(text)["kb-409-meaning"] == (observe.SETTLED, "knowledge-base 409 with code(s) 2003")
        assert "knowledgebase-1                HTTP 409" in text

    def test_detections_alone_do_not_settle_subscription_identity(self, secrets: Path, tmp_path: Path) -> None:
        lines = _ledger_lines(_run(secrets, tmp_path / "rec", Router(kb=(500, b"<html>down</html>")))[1])
        assert lines["subscription-identity"] == (observe.NOT_REACHED, "no knowledge-base response was read")

    def test_an_anonymous_failure_that_is_not_a_refusal_is_not_retried_with_the_credential(self, secrets: Path, tmp_path: Path) -> None:
        router = Router(dtd_anonymous=(500, b"<html>down</html>"))
        code, text = _run(secrets, tmp_path / "rec", router)
        assert code == 0
        dtd = [r for r in router.seen if urlsplit(r.url).path in (DETECTION_DTD_PATH, KNOWLEDGEBASE_DTD_PATH)]
        assert len(dtd) == 2 and not any("Authorization" in r.headers for r in dtd)
        assert _ledger_lines(text)["dtd-unauthenticated"][0] == observe.NOT_REACHED

    def test_an_anonymous_200_that_is_not_a_dtd_is_not_retried_with_the_credential(self, secrets: Path, tmp_path: Path) -> None:
        router = Router(dtd_anonymous=(200, b"<html>not a DTD</html>"))
        code, text = _run(secrets, tmp_path / "rec", router)
        assert code == 0
        dtd = [r for r in router.seen if urlsplit(r.url).path in (DETECTION_DTD_PATH, KNOWLEDGEBASE_DTD_PATH)]
        assert len(dtd) == 2 and not any("Authorization" in r.headers for r in dtd)
        assert _ledger_lines(text)["dtd-unauthenticated"][0] == observe.NOT_REACHED

    def test_a_failed_probe_still_reports_every_entry(self, secrets: Path, tmp_path: Path) -> None:
        router = Router(probe=(401, b"<html>no</html>"))
        code, text = _run(secrets, tmp_path / "rec", router)
        assert code == 1
        assert "detections                     skipped" in text
        lines = _ledger_lines(text)
        assert set(lines) == set(observe.CHECKS)
        assert lines["dtd-unauthenticated"][0] == observe.SETTLED  # the DTDs are still asked for
        assert not any(urlsplit(r.url).path == KNOWLEDGEBASE_PATH for r in router.seen)

    def test_a_broken_check_does_not_hide_the_others(self, secrets: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        def broken(*a: Any) -> tuple[str, str]:
            raise KeyError("boom")

        monkeypatch.setitem(observe.CHECKS, "eos-warning-shape", broken)
        lines = _ledger_lines(_run(secrets, tmp_path / "rec", Router())[1])
        assert lines["eos-warning-shape"] == (observe.NOT_REACHED, "the check failed (KeyError)")
        assert len(lines) == 11


@pytest.mark.spec("req-qualys-observe-1")
class TestOnlyAllowlisted:
    def test_every_request_is_an_allowlisted_get(self, secrets: Path, tmp_path: Path) -> None:
        router = Router()
        _run(secrets, tmp_path / "rec", router)
        assert len(router.seen) >= 8
        for request in router.seen:
            assert request.method == "GET" and request.body is None
            check_url(request.url or "", HOST)

    def test_anonymous_requests_only_reach_the_dtds(self, secrets: Path, tmp_path: Path) -> None:
        router = Router()
        _run(secrets, tmp_path / "rec", router)
        anonymous = [urlsplit(r.url).path for r in router.seen if "Authorization" not in r.headers]
        assert sorted(anonymous) == sorted([DETECTION_DTD_PATH, KNOWLEDGEBASE_DTD_PATH])

    def test_anonymous_client_refuses_any_other_read(self) -> None:
        router = Router()
        client = ReadOnlyClient.anonymous(HOST, adapter=router)
        with pytest.raises(TransportRefused, match="only the DTDs"):
            client.get(f"{HOST}{DETECTION_PATH}?action=list")
        assert router.seen == []

    def test_an_empty_username_or_password_is_not_a_credential(self) -> None:
        # Built in code with empty values, a client would otherwise carry auth that is not None and pass the guard.
        for username, password in (("", ""), (USER, ""), ("", PASSWORD)):
            with pytest.raises(TransportRefused, match="needs a username and a password"):
                ReadOnlyClient(HOST, username, password, adapter=Router())
        router = Router()
        client = ReadOnlyClient(HOST, USER, PASSWORD, adapter=router)
        client._session.auth = ("", "")
        with pytest.raises(TransportRefused, match="only the DTDs"):
            client.get(f"{HOST}{DETECTION_PATH}?action=list")
        assert router.seen == []

    def test_dtd_reads_take_no_parameters(self) -> None:
        with pytest.raises(TransportRefused, match="takes no parameters"):
            check_url(f"{HOST}{DETECTION_DTD_PATH}?x=1", HOST)
        assert check_url(f"{HOST}{KNOWLEDGEBASE_DTD_PATH}", HOST) == (KNOWLEDGEBASE_DTD_PATH, {})


@pytest.mark.spec("req-qualys-observe-2")
class TestLocalAndPrivate:
    def test_recordings_are_owner_only_and_carry_no_credential(self, secrets: Path, tmp_path: Path) -> None:
        router = Router()
        _run(secrets, tmp_path / "rec", router)
        runs = list((tmp_path / "rec" / "acme").iterdir())
        assert len(runs) == 1
        run = runs[0]
        for directory in (tmp_path / "rec", tmp_path / "rec" / "acme", run):
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        files = sorted(run.iterdir())
        assert len(files) == len(router.seen)
        basic = base64.b64encode(f"{USER}:{PASSWORD}".encode())
        for path in files:
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            raw = path.read_bytes()
            header, _, body = raw.partition(b"\n\n")
            meta = json.loads(header)
            assert {"step", "url", "status", "response_headers", "request_header_names"} <= set(meta)
            assert not any(k.lower() == "set-cookie" for k in meta["response_headers"])
            assert PASSWORD.encode() not in raw and basic not in raw and b"QualysSession" not in raw
        probe = json.loads(files[0].read_bytes().partition(b"\n\n")[0])
        assert probe["step"] == "probe" and "Authorization" in probe["request_header_names"]
        assert files[0].read_bytes().partition(b"\n\n")[2] == _without(_page(), b"<WARNING>", b"</WARNING>")

    def test_a_linked_key_directory_is_refused(self, secrets: Path, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)
        base = tmp_path / "rec"
        base.mkdir()
        (base / "acme").symlink_to(repo, target_is_directory=True)
        router = Router()
        code, text = _run(secrets, base, router)
        assert code == 2 and "symbolic link" in text
        assert router.seen == [] and list(repo.iterdir()) == [repo / ".git"]

    def test_an_oversized_response_is_still_recorded(self, secrets: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # The transport refuses to read a body past its ceiling; the observation still records that it came back.
        from tap_plugin.qualys import client as transport

        monkeypatch.setattr(transport, "MAX_PAGE_BYTES", 64 << 10)  # above every fixture page, below this body
        router = Router(kb=(200, b"<x>" + b"y" * (128 << 10) + b"</x>"))
        code, text = _run(secrets, tmp_path / "rec", router)
        assert code == 0 and "knowledgebase-1                not read: ReadFailed" in text
        (run,) = list((tmp_path / "rec" / "acme").iterdir())
        files = sorted(run.iterdir())
        assert len(files) == len(router.seen)
        (kb,) = [f for f in files if f.name.endswith("-knowledgebase-1.rec")]
        header, _, body = kb.read_bytes().partition(b"\n\n")
        meta = json.loads(header)
        assert meta["status"] == 200 and meta["body_not_read"].startswith("response larger than") and body == b""

    def test_an_existing_base_keeps_its_mode(self, tmp_path: Path) -> None:
        from datetime import UTC, datetime

        base = tmp_path / "shared"
        base.mkdir()
        os.chmod(base, 0o755)
        run = observe.private_directory(base, "acme", datetime(2026, 11, 21, 6, 0, tzinfo=UTC))
        run.close()
        assert stat.S_IMODE(base.stat().st_mode) == 0o755
        assert stat.S_IMODE((base / "acme").stat().st_mode) == 0o700 and stat.S_IMODE(run.path.stat().st_mode) == 0o700

    def test_a_directory_others_may_write_to_is_refused(self, tmp_path: Path) -> None:
        from datetime import UTC, datetime

        now = datetime(2026, 11, 21, 6, 0, tzinfo=UTC)
        for shared in (tmp_path / "a", tmp_path / "b" / "acme"):
            shared.mkdir(parents=True)
            os.chmod(shared, 0o777)
        for base in (tmp_path / "a", tmp_path / "b"):
            with pytest.raises(observe.ObserveError, match="writable by others"):
                observe.private_directory(base, "acme", now)
        assert not (tmp_path / "a" / "acme").exists() or not any((tmp_path / "a" / "acme").iterdir())
        assert not any((tmp_path / "b" / "acme").iterdir())

    def test_same_second_observations_get_their_own_directories(self, tmp_path: Path) -> None:
        from datetime import UTC, datetime

        now = datetime(2026, 11, 21, 6, 0, tzinfo=UTC)
        runs = [observe.private_directory(tmp_path / "rec", "acme", now) for _ in range(9)]
        for run in runs:
            run.close()
        assert len({r.path for r in runs}) == 9 and runs[1].path.name == "20261121T060000Z-2"
        with pytest.raises(observe.ObserveError, match="same second"):
            observe.private_directory(tmp_path / "rec", "acme", now)

    def test_recordings_follow_the_held_directory_not_its_path(self, tmp_path: Path) -> None:
        # Whoever can rename a parent could swap the path after the checks; the writes go through the handle.
        from datetime import UTC, datetime

        run = observe.private_directory(tmp_path / "rec", "acme", datetime(2026, 11, 21, 6, 0, tzinfo=UTC))
        moved = tmp_path / "moved"
        (tmp_path / "rec").rename(moved)
        decoy = run.path
        decoy.mkdir(parents=True)
        recorder = observe.Recorder(run)
        recorder(Exchange(url=f"{HOST}/x", status=200, response_headers={}, request_header_names=[], body=b"body"))
        run.close()
        assert list(decoy.iterdir()) == []
        (written,) = (moved / "acme" / run.path.name).iterdir()
        assert written.read_bytes().endswith(b"\n\nbody")

    def test_refused_inside_a_repository(self, secrets: Path, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)
        router = Router()
        code, text = _run(secrets, repo / "recordings", router)
        assert code == 2 and "inside a repository" in text
        assert router.seen == [] and not (repo / "recordings").exists()

    def test_nothing_touches_the_grid(self) -> None:
        source = Path(observe.__file__).read_text()
        assert "django" not in source and "grift" not in source.lower() and "decompose" not in source


@pytest.mark.spec("req-qualys-observe-3")
class TestNothingSensitivePrinted:
    def test_report_holds_no_value(self, secrets: Path, tmp_path: Path) -> None:
        _, text = _run(secrets, tmp_path / "rec", Router())
        for value in SENSITIVE:
            assert value not in text
        assert "<HOST" not in text and "CDATA" not in text

    def test_qualys_text_is_stripped_and_bounded(self, secrets: Path, tmp_path: Path) -> None:
        # Characters XML 1.0 admits but a terminal acts on: DEL, NEL (C1) and a bidi override.
        hostile = "Package\x7f]0;owned\x85" + "Z" * 300 + "\tInstalled\u202eVersion\tFixed Version"
        page = _page().replace(b"<RESULTS><![CDATA[Package\tInstalled Version\tRequired Version", f"<RESULTS><![CDATA[{hostile}".encode(), 1)
        _, text = _run(secrets, tmp_path / "rec", Router(page=(200, page)))
        outcome, detail = _ledger_lines(text)["package-table-variants"]
        assert outcome == observe.CONTRADICTED
        assert "\x7f" not in text and "\x85" not in text and "\u202e" not in text
        assert "Z" * 81 not in text and "owned" in detail

    def test_safe(self) -> None:
        assert observe.safe("a\x00b\x1b[31mc\r\nd\u200be", 80) == "ab[31mc de"
        assert observe.safe("x" * 100, 10) == "x" * 9 + "…"


@pytest.mark.spec("req-qualys-observe-5")
class TestNothingSent:
    @pytest.fixture
    def no_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def refuse(*a: Any, **k: Any) -> None:
            raise AssertionError("no client may be built")

        monkeypatch.setattr(observe, "ReadOnlyClient", refuse)

    def test_dry_run_sends_nothing_and_writes_nothing(self, secrets: Path, tmp_path: Path, no_client: None) -> None:
        router = Router()
        code, text = _run(secrets, tmp_path / "rec", router, "--dry-run")
        assert code == 0 and "dry run, nothing sent" in text
        assert "6. DTDs" in text and "qualysapi" not in text
        assert router.seen == [] and not (tmp_path / "rec").exists()

    def test_list_sends_nothing(self, secrets: Path, tmp_path: Path, no_client: None) -> None:
        (secrets / "broken.secret.json").write_text(json.dumps({"scope": "qualys", "key": "broken", "kind": "qualys_api_credential", "description": "x", "data": {"api_host": HOST}}))
        out = io.StringIO()
        assert observe.main(["--list", "--secrets-root", str(secrets)], out=out) == 0
        text = out.getvalue()
        assert "qualys:acme  usable" in text and "qualys:broken  refused:" in text
        assert PASSWORD not in text and USER not in text

    def test_unknown_key(self, secrets: Path, tmp_path: Path, no_client: None) -> None:
        out = io.StringIO()
        assert observe.main(["--key", "nope", "--secrets-root", str(secrets)], out=out) == 2
        assert "no usable envelope" in out.getvalue()


class TestClientObserver:
    def test_observer_sees_every_response_without_cookies(self) -> None:
        seen: list[Any] = []
        router = Router(probe=(409, b"<SIMPLE_RETURN><RESPONSE><CODE>2003</CODE></RESPONSE></SIMPLE_RETURN>"))
        client = ReadOnlyClient(HOST, USER, PASSWORD, adapter=router, observer=seen.append)
        with pytest.raises(Exception, match="HTTP 409"):
            client.get(f"{HOST}{DETECTION_PATH}?action=list&truncation_limit=1&host_metadata=ec2")
        assert len(seen) == 1 and seen[0].status == 409
        assert "Set-Cookie" not in seen[0].response_headers and "Authorization" in seen[0].request_header_names
