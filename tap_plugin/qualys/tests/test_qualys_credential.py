"""The credential envelope (req-qualys-connection).

Envelopes are written into a private temporary secrets root per test; ``~/tap-secrets`` is never touched.
Test passwords are assembled at run time so no credential-shaped literal sits in the tree.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from tap_plugin.qualys import credential as cred
from tap_plugin.qualys.identity import subscription_key

PASSWORD = "".join(["hunter", "-", "two", "-", "pw"])
USER = "acme" + "_ro"
HOST = "https://qualysapi.qg2.apps.qualys.com"


def _data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {"api_host": HOST, "subscription": "acme-prod", "username": USER, "password": PASSWORD}
    data.update(overrides)
    return {k: v for k, v in data.items() if v is not None}


def _write(root: Path, key: str, data: dict[str, Any], *, scope: str = "qualys", kind: str = "qualys_api_credential") -> Path:
    path = root / f"{key}.secret.json"
    path.write_text(json.dumps({"scope": scope, "key": key, "kind": kind, "description": "test envelope", "data": data}))
    return path


def _one(root: Path) -> cred.Credential:
    usable, errors = cred.discover(root)
    assert errors == [], errors
    (only,) = usable
    return only


class TestValid:
    def test_canonical_host_and_key(self, tmp_path: Path) -> None:
        _write(tmp_path, "acme", _data(api_host="HTTPS://QualysAPI.qg2.apps.qualys.com/"))
        c = _one(tmp_path)
        assert c.api_host == HOST and c.label == "acme-prod" and c.key == subscription_key(HOST, "acme-prod")
        assert c.basic == (USER, PASSWORD) and c.ca_bundle is None and c.standing_scope == {}

    def test_two_spellings_give_one_key(self, tmp_path: Path) -> None:
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        _write(a, "x", _data())
        _write(b, "x", _data(api_host="https://QUALYSAPI.QG2.APPS.QUALYS.COM"))
        assert _one(a).key == _one(b).key

    def test_scope_and_ca_bundle(self, tmp_path: Path) -> None:
        _write(tmp_path, "acme", _data(scope={"tag_ids": [9, 3]}, ca_bundle="/etc/ssl/qualys.pem"))
        c = _one(tmp_path)
        assert c.standing_scope == {"tag_ids": [3, 9]} and c.ca_bundle == "/etc/ssl/qualys.pem"
        # A caller changing what it was handed changes nothing the credential holds.
        c.standing_scope["tag_ids"].append(99)
        c.standing_scope.clear()
        assert c.standing_scope == {"tag_ids": [3, 9]}

    def test_other_scopes_and_examples_are_ignored(self, tmp_path: Path) -> None:
        _write(tmp_path, "gh", {"token": "x"}, scope="github_core", kind="github_pat")
        (tmp_path / "qualys-example.secret.example.json").write_text("{}")
        assert cred.discover(tmp_path) == ([], [])


class TestRefused:
    @pytest.mark.parametrize(
        "api_host",
        ["http://qualysapi.qg2.apps.qualys.com", "https://u:p@qualysapi.qg2.apps.qualys.com", "https://qualysapi.qg2.apps.qualys.com/api",
         "https://qualysapi.qg2.apps.qualys.com?x=1", "https://qualysapi.qg2.apps.qualys.com#f"],
    )
    def test_not_a_bare_https_root(self, tmp_path: Path, api_host: str) -> None:
        _write(tmp_path, "acme", _data(api_host=api_host))
        usable, (error,) = cred.discover(tmp_path)
        assert usable == [] and error.qualified == "qualys:acme"

    @pytest.mark.parametrize(
        "data",
        [_data(extra="x"), _data(password=None), _data(scope={"asset_group_ids": [1], "tag_ids": [2]}), _data(scope={"tag_ids": []}),
         _data(ca_bundle="relative.pem"), _data(subscription="has space")],
    )
    def test_strict_schema(self, tmp_path: Path, data: dict[str, Any]) -> None:
        _write(tmp_path, "acme", data)
        usable, (error,) = cred.discover(tmp_path)
        assert usable == [] and "qualys_api_credential schema" in error.reason

    def test_wrong_kind_fails_only_itself(self, tmp_path: Path) -> None:
        _write(tmp_path, "bad", _data(), kind="github_pat")
        _write(tmp_path, "good", _data(subscription="other"))
        usable, (error,) = cred.discover(tmp_path)
        assert [c.qualified for c in usable] == ["qualys:good"] and error.qualified == "qualys:bad" and "kind" in error.reason

    def test_two_envelopes_one_subscription_are_both_refused(self, tmp_path: Path) -> None:
        _write(tmp_path, "one", _data())
        _write(tmp_path, "two", _data(api_host="https://QUALYSAPI.qg2.apps.qualys.com"))
        usable, errors = cred.discover(tmp_path)
        assert usable == [] and sorted(e.qualified for e in errors) == ["qualys:one", "qualys:two"]
        assert all("qualys:one and qualys:two" in e.reason for e in errors)

    def test_an_unreadable_envelope_is_reported_not_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "acme.secret.json").write_text('{"scope": "qualys", "key": "acme", "data": {"password": "' + PASSWORD + '"')
        usable, (error,) = cred.discover(tmp_path)
        assert usable == [] and error.qualified == "qualys:acme" and "not a readable secret envelope" in error.reason
        assert PASSWORD not in str(error)

    def test_username_with_a_colon_refused(self, tmp_path: Path) -> None:
        # HTTP Basic joins user and password with ':', so the server would split this user name (qualys-tap#29).
        _write(tmp_path, "acme", _data(username="acme:ro"))
        usable, (error,) = cred.discover(tmp_path)
        assert usable == [] and "at username (pattern)" in error.reason and "acme:ro" not in str(error)

    def test_non_latin1_password_refused(self, tmp_path: Path) -> None:
        _write(tmp_path, "acme", _data(password="pāss"))
        _, (error,) = cred.discover(tmp_path)
        assert "Latin-1" in error.reason


class TestNeverEchoed:
    def test_repr_and_errors_carry_no_value(self, tmp_path: Path) -> None:
        _write(tmp_path, "acme", _data())
        c = _one(tmp_path)
        assert PASSWORD not in repr(c) and USER not in repr(c)
        _write(tmp_path, "acme", _data(api_host="http://x.example", password=PASSWORD))
        _, (error,) = cred.discover(tmp_path)
        assert PASSWORD not in str(error) and USER not in str(error)

    def test_a_wrong_kind_echoes_nothing_from_the_envelope(self, tmp_path: Path) -> None:
        _write(tmp_path, "acme", _data(), kind="qualys_" + PASSWORD)
        _, (error,) = cred.discover(tmp_path)
        assert PASSWORD not in str(error) and "kind" in error.reason

    def test_schema_failure_names_no_value(self, tmp_path: Path) -> None:
        _write(tmp_path, "acme", _data(password=PASSWORD * 200))
        _, (error,) = cred.discover(tmp_path)
        assert PASSWORD not in str(error)


def test_every_schema_field_is_described() -> None:
    schema = json.loads(cred.SCHEMA_PATH.read_text())
    assert schema["description"] and schema["additionalProperties"] is False

    def walk(node: dict[str, Any], where: str) -> None:
        for name, sub in node.get("properties", {}).items():
            assert sub.get("description"), f"{where}.{name}"
            walk(sub, f"{where}.{name}")

    walk(schema, "data")


def test_the_example_template_validates() -> None:
    from tap.runtime_secrets import load_secret_envelope

    path = Path(cred.__file__).resolve().parent / "schemas" / "examples" / "qualys-example.secret.example.json"
    c = cred.credential_from_envelope(load_secret_envelope(path))
    assert c.qualified == "qualys:qualys-example"


def test_no_credential_pattern_is_added() -> None:
    # These credentials have no scannable shape (req-qualys-connection-6): nothing in core names this kind.
    from tap.credential_patterns import CREDENTIAL_PATTERNS

    assert not [p for p in CREDENTIAL_PATTERNS if "qualys" in repr(p).lower()]
