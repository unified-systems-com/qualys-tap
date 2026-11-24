"""The shared computing_core host, and the software installed on it (req-qualys-installed-software).

For each EC2 host whose software the host asset search returned (``req-qualys-host-assets``), a run writes the
machine as ``computing_core__host`` (created only where the grid holds none, with its key fields alone, the
shared-fact rule), ``TRACKS_HOST__qualys`` from the Qualys host to it, and ``INSTALLS_PACKAGE__computing_core`` to
each package Qualys reports installed, the package created with its key fields where absent.

The package's ecosystem comes from the host's OS, by the same rule the package-table parser uses (Debian and
Ubuntu ``deb``, RPM distributions ``rpm``). An OS it cannot place writes no package, never a guessed one.

The host's identity is decided in :func:`host_key` alone. It is computing_core's ``(realm, stable_id)`` today;
when form-3 keys land (unified-systems-com/tap#1355) and the realm becomes a dimension, that one function changes.
"""

import re
from collections.abc import Iterable
from typing import Any, Protocol

from tap_plugin.qualys import neutral
from tap_plugin.qualys.parsers.package_table import _unambiguous, ecosystem_of

HOST_TYPE = "computing_core__host"
EC2_REALM = "aws-ec2"
TRACKS_HOST = "TRACKS_HOST__qualys"
INSTALLS_PACKAGE = "INSTALLS_PACKAGE__computing_core"
_INSTANCE = re.compile(r"i-[0-9a-f]{8}(?:[0-9a-f]{9})?")


class HostView(Protocol):
    def held_keys(self, entity_type: str, keys: Iterable[tuple[str, ...]]) -> set[tuple[str, ...]] | None: ...

    def held_packages(self, keys: Iterable[tuple[str, str, str]]) -> set[tuple[str, str, str]]: ...

    def default_dimensions(self, entity_type: str) -> dict[str, str]: ...


def host_key(host: dict[str, Any]) -> tuple[str, str] | None:
    """The computing_core host a Qualys host is, as (realm, stable_id); None when Qualys names no issuer's id for it.

    An EC2 instance is ``("aws-ec2", instance id)``, computing_core's realm for it. A host Qualys reports with no
    cloud instance id has no realm Qualys can vouch for, so no shared host is written for it.
    """
    instance = host.get("cloud_resource_id")
    if host.get("cloud_provider") == "AWS" and host.get("cloud_service") == "EC2" and isinstance(instance, str) and _INSTANCE.fullmatch(instance):
        return (EC2_REALM, instance)
    return None


def _host_ref(key: tuple[str, str]) -> str:
    return f"ch:{key[0]}:{key[1]}"


def _host_end(key: tuple[str, str], minted: bool, side: str) -> dict[str, Any]:
    if minted:
        return {f"{side}_ref": _host_ref(key)}
    return {f"{side}_key": {"entity_type": HOST_TYPE, "key": {"realm": key[0], "stable_id": key[1]}}}


def packages_of(software: list[dict[str, Any]] | None, os_name: Any) -> list[tuple[str, str, str]]:
    """The packages a host's software list names, keyed only where the ecosystem and the version are unambiguous."""
    ecosystem = ecosystem_of(os_name)
    out = []
    for item in software or []:
        name, version = item.get("name"), item.get("version")
        if isinstance(name, str) and isinstance(version, str) and _unambiguous(ecosystem, name, version):
            key = (ecosystem, name, version)
            if neutral.package_fits(key):
                out.append(key)  # type: ignore[arg-type]
    return sorted(set(out))  # type: ignore[arg-type]


def build(hosts: Iterable[dict[str, Any]], assets: dict[str, dict[str, Any]], grid: HostView) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """Nodes, edges, authority claims and counters for the shared hosts and their installed software."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    counters: dict[str, int] = {}
    wanted: dict[tuple[str, str], tuple[str, list[tuple[str, str, str]], bool]] = {}
    for host in hosts:
        key = host_key(host)
        asset = assets.get(host.get("host_id") or "")
        if key is None or asset is None or asset.get("software") is None:
            continue  # no issuer's id, or no software read this run: nothing to say about installs
        known = ecosystem_of(host.get("os")) is not None
        wanted[key] = (host["host_id"], packages_of(asset["software"], host.get("os")), known)
    if not wanted:
        return nodes, edges, claims, counters
    held_hosts = grid.held_keys(HOST_TYPE, wanted)
    if held_hosts is None:
        return nodes, edges, claims, {"computing_core_absent": 1}
    all_packages = {p for _, packages, _ in wanted.values() for p in packages}
    held_packages = grid.held_packages(all_packages)
    host_dims = grid.default_dimensions(HOST_TYPE)
    package_dims = grid.default_dimensions(neutral.PACKAGE_TYPE)
    for package in sorted(all_packages - held_packages):
        nodes.append(neutral.package_node(f"p:{'/'.join(package)}", package, package_dims))
        counters["packages_created"] = counters.get("packages_created", 0) + 1
    for key, (host_id, packages, known) in sorted(wanted.items()):
        minted = key not in held_hosts
        if minted:
            # The shared-fact rule: key fields only, no dimension of this plugin's own.
            nodes.append({"entity": {"ref": _host_ref(key), "entity_type": HOST_TYPE, "name": key[1], "dimensions": dict(host_dims)},
                          "node": {"realm": key[0], "stable_id": key[1]}})
            counters["shared_hosts_created"] = counters.get("shared_hosts_created", 0) + 1
        edges.append({"entity": {"ref": f"e-tracks-host-{host_id}", "entity_type": "edge", "name": TRACKS_HOST, "dimensions": {}},
                      "edge": {"from_ref": f"h{host_id}", **_host_end(key, minted, "to"), "edge_type": TRACKS_HOST, "properties": {}}})
        for package in packages:
            edges.append({"entity": {"ref": f"e-installs-{host_id}-{'/'.join(package)}", "entity_type": "edge", "name": INSTALLS_PACKAGE, "dimensions": {}},
                          "edge": {**_host_end(key, minted, "from"), "to_key": neutral.package_ref(package), "edge_type": INSTALLS_PACKAGE, "properties": {}}})
            counters["installs"] = counters.get("installs", 0) + 1
        # The host's installed set is whole when its software list came back and its OS could be placed; otherwise
        # the claim says partial and proposes nothing.
        claims.append({"edge_type": INSTALLS_PACKAGE, "anchor": {"entity_type": HOST_TYPE, "key": {"realm": key[0], "stable_id": key[1]}},
                       "direction": "outbound", "read": "complete" if known else "partial"})
    return nodes, edges, claims, counters
