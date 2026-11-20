"""How a Qualys subscription is named, and the keys derived from that name.

Qualys is a shared service: many subscriptions answer on one platform API host, so the host alone cannot
identify one, and the operator's label is the other half (req-qualys-connection). Derived keys are compact
JSON arrays, never delimiter joins, so two different inputs can never encode alike
(req-qualys-subscription-run-1, req-qualys-neutral-1).
"""

import hashlib
import json
from urllib.parse import urlsplit


class InvalidApiHost(ValueError):
    """An ``api_host`` that is not an https origin with nothing but a host and an optional port."""


def canonical_api_host(url: str) -> str:
    """The canonical form of a platform API root: ``https://<lower-cased host>[:<port>]``.

    Refuses anything but https, and any userinfo, path, query or fragment, so one host has one spelling
    and nothing in the URL can carry a credential or redirect a read (req-qualys-connection-3).
    """
    parts = urlsplit(url.strip())
    if parts.scheme.lower() != "https":
        raise InvalidApiHost("api_host must be https")
    if parts.username is not None or parts.password is not None:
        raise InvalidApiHost("api_host must not carry userinfo")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise InvalidApiHost("api_host must not carry a path, query or fragment")
    host = (parts.hostname or "").lower()
    if not host or host.endswith("."):
        raise InvalidApiHost("api_host must name a host")
    port = parts.port
    return f"https://{host}" if port in (None, 443) else f"https://{host}:{port}"


def _compact(value: list[str]) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def subscription_key(api_host: str, label: str) -> str:
    """The key every Qualys type carries: the compact JSON array ``[canonical api_host, label]``."""
    if not label:
        raise ValueError("subscription label must not be empty")
    return _compact([canonical_api_host(api_host), label])


def neutral_source_key(subscription: str, host_id: str, cve_id: str) -> str:
    """The neutral finding's ``source_key``: SHA-256 of the compact JSON array of its three parts, as UTF-8."""
    return hashlib.sha256(_compact([subscription, host_id, cve_id]).encode("utf-8")).hexdigest()
