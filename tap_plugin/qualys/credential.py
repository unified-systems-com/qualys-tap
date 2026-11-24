"""The Qualys credential envelope: validation, canonical identity, discovery (req-qualys-connection).

One envelope per Qualys subscription, scope ``qualys``, kind ``qualys_api_credential``. This module is the
consumer-side check the secrets spec leaves to the consumer (``req-tap-cares-secrets-validation``): it validates
``data`` against the plugin's own schema, derives the canonical API host and the subscription key, and finds
every envelope in the scope.

These credentials have no scannable shape (a Qualys user name carries a subscription prefix but no issuer
marker, and the password is free text), so no ``CredentialPattern`` is added; protection rests on the envelope
layer, the leak guard, ``.gitignore`` and redaction (req-qualys-connection-6). Secret material lives only in
:class:`Credential`'s private fields, whose ``repr`` omits them, and no message built here contains a value.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
from tap.runtime_secrets import RuntimeSecretError, SecretEnvelope, load_secret_envelope
from tap.secret_naming import SECRET_EXAMPLE_SUFFIX, SECRET_SUFFIX

from tap_plugin.qualys.identity import canonical_api_host, subscription_key

SCOPE = "qualys"
KIND = "qualys_api_credential"
SCHEMA_PATH = Path(__file__).resolve().parent / "schemas" / "qualys_api_credential.schema.json"
#: The kinds of Qualys data a run can read, each on unless the envelope switches it off (req-qualys-sources).
SOURCES = ("detections", "knowledgebase", "tags")
#: What a run may write beyond Qualys's own types, each off unless the envelope turns it on (req-qualys-aws).
INTEGRATIONS = ("aws",)


class CredentialError(Exception):
    """An envelope cannot be used. The message names ``qualys:<key>`` and a reason, never a value."""

    def __init__(self, qualified: str, reason: str) -> None:
        super().__init__(f"{qualified}: {reason}")
        self.qualified = qualified
        self.reason = reason


@dataclass(frozen=True)
class Credential:
    """One validated Qualys subscription. ``repr`` names the envelope and host, never the user or password."""

    qualified: str
    api_host: str
    label: str
    key: str
    ca_bundle: str | None
    _scope: tuple[tuple[str, tuple[int, ...]], ...]
    _sources: tuple[tuple[str, bool], ...]
    _integrations: tuple[tuple[str, bool], ...]
    _username: str = field(repr=False)
    _password: str = field(repr=False)

    def __repr__(self) -> str:
        return f"Credential(qualified={self.qualified!r}, api_host={self.api_host!r}, label={self.label!r})"

    @property
    def standing_scope(self) -> dict[str, list[int]]:
        """The validated standing scope, as a fresh copy each time, so no caller can change what was validated."""
        return {kind: list(ids) for kind, ids in self._scope}

    @property
    def sources(self) -> dict[str, bool]:
        """Each source in ``SOURCES``, on or off, as a fresh copy each time."""
        return dict(self._sources)

    @property
    def integrations(self) -> dict[str, bool]:
        """Each integration in ``INTEGRATIONS``, on or off (all off unless set), as a fresh copy each time."""
        return dict(self._integrations)

    @property
    def basic(self) -> tuple[str, str]:
        """(user, password) for HTTP Basic auth; the only way the material leaves this object."""
        return self._username, self._password


def _schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _schema_reason(exc: jsonschema.ValidationError) -> str:
    """Where the data failed the schema, without the offending value."""
    where = "/".join(str(p) for p in exc.absolute_path) or "(data)"
    return f"data does not match the {KIND} schema at {where} ({exc.validator})"


def credential_from_envelope(envelope: SecretEnvelope) -> Credential:
    """Validate one envelope and build its :class:`Credential` (req-qualys-connection-3, -5).

    Raises CredentialError naming ``qualys:<key>`` and a reason. The reason never contains a value.
    """
    qualified = envelope.qualified
    if envelope.scope != SCOPE:
        raise CredentialError(qualified, f"the envelope's scope is not {SCOPE!r}")
    if envelope.kind != KIND:
        raise CredentialError(qualified, f"the envelope's kind is not {KIND!r}")
    data = dict(envelope.data)
    try:
        jsonschema.validate(data, _schema())
    except jsonschema.ValidationError as exc:
        raise CredentialError(qualified, _schema_reason(exc)) from None
    try:
        host = canonical_api_host(data["api_host"])
    except ValueError:
        raise CredentialError(qualified, "api_host is not a bare https API root (no userinfo, path, query or fragment)") from None
    for name in ("username", "password"):
        try:
            data[name].encode("latin-1")
        except UnicodeEncodeError:
            raise CredentialError(qualified, f"{name} has characters HTTP Basic auth cannot carry (Latin-1 only)") from None
    scope = data.get("scope") or {}
    switches = data.get("sources") or {}
    sources = tuple((name, switches.get(name, True)) for name in SOURCES)
    if not any(on for _, on in sources):
        raise CredentialError(qualified, "every source is switched off, so there is nothing to read")
    return Credential(
        qualified=qualified,
        api_host=host,
        label=data["subscription"],
        key=subscription_key(host, data["subscription"]),
        ca_bundle=data.get("ca_bundle"),
        _scope=tuple((k, tuple(sorted(v))) for k, v in sorted(scope.items())),
        _sources=sources,
        _integrations=tuple((name, bool((data.get("integrations") or {}).get(name, False))) for name in INTEGRATIONS),
        _username=data["username"],
        _password=data["password"],
    )


def discover(root: Path) -> tuple[list[Credential], list[CredentialError]]:
    """Every usable envelope in scope ``qualys`` under ``root``, and every one that is not.

    A malformed envelope fails only itself. Two envelopes that give the same subscription key are both refused,
    naming both keys (req-qualys-connection-4). Example templates (``*.secret.example.json``) are never read.
    """
    usable: list[Credential] = []
    errors: list[CredentialError] = []
    if not root.is_dir():
        return usable, [CredentialError(SCOPE, f"secrets root {root} is not a directory")]
    for path in sorted(root.rglob(f"*{SECRET_SUFFIX}")):
        if path.name.endswith(SECRET_EXAMPLE_SUFFIX):
            continue
        try:
            envelope = load_secret_envelope(path)
        except RuntimeSecretError:
            # A file that is not a readable envelope may or may not be ours; it cannot say its scope, so it is
            # reported by name only, never by content, and never read as "no credential configured".
            errors.append(CredentialError(f"{SCOPE}:{path.name[: -len(SECRET_SUFFIX)]}", "file is not a readable secret envelope"))
            continue
        if envelope.scope != SCOPE:
            continue
        try:
            usable.append(credential_from_envelope(envelope))
        except CredentialError as exc:
            errors.append(exc)
    by_key: dict[str, list[Credential]] = {}
    for credential in usable:
        by_key.setdefault(credential.key, []).append(credential)
    kept: list[Credential] = []
    for credentials in by_key.values():
        if len(credentials) == 1:
            kept.append(credentials[0])
            continue
        names = " and ".join(sorted(c.qualified for c in credentials))
        errors.extend(CredentialError(c.qualified, f"same subscription as {names}") for c in credentials)
    return kept, errors
