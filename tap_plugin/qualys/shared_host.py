"""The shared computing_core host, and the software installed on it (req-qualys-installed-software).

For each EC2 host whose software the host asset search returned (``req-qualys-host-assets``), a run writes the
machine as ``computing_core__host`` (created only where the grid holds none, with its key fields alone, the
shared-fact rule), ``TRACKS_HOST__qualys`` from the Qualys host to it, and ``INSTALLS_PACKAGE__computing_core`` to
each package Qualys reports installed, the package created with its key fields where absent.

The package's ecosystem comes from the host's OS, by the same rule the package-table parser uses (Debian and
Ubuntu ``deb``, RPM distributions ``rpm``). An OS it cannot place writes no package, never a guessed one.

The host's identity is decided in :func:`host_key` alone: computing_core's ``(tap.computing.host_type, stable_id)``,
the host type an identity dimension on the envelope, never a payload field (form 3, unified-systems-com/tap#1355).
"""

import ipaddress
import re
from collections.abc import Iterable
from typing import Any, Protocol

from tap_plugin.computing_core import key_dimensions
from tap_plugin.computing_core.addresses import host_scoped_kind
from tap_plugin.qualys import neutral
from tap_plugin.qualys.parsers.package_table import _unambiguous, ecosystem_of

from tap_grid.natural_key import encode_key_part

HOST_TYPE = "computing_core__host"
EC2_HOST_TYPE = key_dimensions.AWS_EC2
TRACKS_HOST = "TRACKS_HOST__qualys"
INSTALLS_PACKAGE = "INSTALLS_PACKAGE__computing_core"
INTERFACE_TYPE = "computing_core__network_interface"
CONTAINS_INTERFACE = "CONTAINS_NETWORK_INTERFACE__computing_core"
ADDRESS_TYPE = "computing_core__ip_address"
PORT_TYPE = "computing_core__port"
USES_ADDRESS = "USES_IP_ADDRESS__computing_core"
AVAILABLE_AT = "AVAILABLE_AT_IP_ADDRESS__computing_core"
INTERNET = "Internet"
TRANSPORTS = ("tcp", "udp", "sctp")
_VPC = re.compile(r"vpc-[0-9a-f]{8}(?:[0-9a-f]{9})?")
_INSTANCE = re.compile(r"i-[0-9a-f]{8}(?:[0-9a-f]{9})?")


class HostView(Protocol):
    def held_keys(self, entity_type: str, keys: Iterable[tuple[str, ...]]) -> set[tuple[str, ...]] | None: ...

    def held_packages(self, keys: Iterable[tuple[str, str, str]]) -> set[tuple[str, str, str]]: ...

    def default_dimensions(self, entity_type: str) -> dict[str, str]: ...


def host_key(host: dict[str, Any]) -> tuple[str, str] | None:
    """The computing_core host a Qualys host is, as (host type, stable_id); None when Qualys names no issuer's id for it.

    An EC2 instance is ``("aws-ec2", instance id)``, computing_core's host type for it. A host Qualys reports with no
    cloud instance id has no host type Qualys can vouch for, so no shared host is written for it.
    """
    instance = host.get("cloud_resource_id")
    if host.get("cloud_provider") == "AWS" and host.get("cloud_service") == "EC2" and isinstance(instance, str) and _INSTANCE.fullmatch(instance):
        return (EC2_HOST_TYPE, instance)
    return None


def _host_ref(key: tuple[str, str]) -> str:
    return f"ch:{key[0]}:{key[1]}"


def _host_end(key: tuple[str, str], minted: bool, side: str) -> dict[str, Any]:
    if minted:
        return {f"{side}_ref": _host_ref(key)}
    return {f"{side}_key": {"entity_type": HOST_TYPE, "key": _key_ref(key)}}


def _key_ref(key: tuple[str, str]) -> dict[str, str]:
    """A shared host named by key, each entry spelled as computing_core declares it."""
    return {key_dimensions.HOST_TYPE_ENTRY: key[0], "stable_id": key[1]}


def host_scope(key: tuple[str, str]) -> str:
    """The ``tap.computing.host`` value a host-scoped thing carries: the host's spine natural key, escaped as core escapes it."""
    return f"{encode_key_part(key[0])}|{encode_key_part(key[1])}"


def interfaces_of(interfaces: list[dict[str, Any]] | None) -> dict[str, str | None]:
    """The interfaces a host asset names, by interface name, each with its MAC where Qualys reported one.

    An interface with no name has no key (req-computing-core-interface-2), so it is not written. An empty MAC is
    unobserved, never ``""`` (req-computing-core-interface-1): Qualys returns the EC2 metadata MAC empty.
    """
    out: dict[str, str | None] = {}
    for item in interfaces or []:
        name, mac = item.get("interface_name"), item.get("mac_address")
        if isinstance(name, str) and name.strip():
            mac = mac.strip().lower() if isinstance(mac, str) and mac.strip() else None
            out[name.strip()] = out.get(name.strip()) or mac
    return out


def canonical_address(value: Any) -> str | None:
    """An address as computing_core keys it, or None for one it would refuse or that is not an address.

    IPv4-mapped IPv6 is written as IPv4, so one address is one node. Loopback, wildcard and link-local addresses
    are host-scoped, never a shared ``ip_address`` (req-computing-core-ip-4), so they are not written here.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    text = str(parsed)
    return None if host_scoped_kind(text) is not None else text


def network_of(address: str, vpc: str | None, networks: dict[str, Any]) -> str:
    """The network an address is on (req-qualys-host-network): ``Internet`` for a public address, else the name the
    envelope declares for the host's VPC, else its default."""
    if ipaddress.ip_address(address).is_global:
        return INTERNET
    return (networks.get("vpcs") or {}).get(vpc or "") or networks["default"]


def ports_of(open_ports: list[dict[str, Any]] | None) -> set[tuple[str, int]]:
    """The (transport, port number) pairs a host asset reports open; an unknown transport or a bad number is skipped."""
    out = set()
    for item in open_ports or []:
        transport, number = str(item.get("protocol") or "").strip().lower(), item.get("port")
        try:
            number = int(number)
        except (TypeError, ValueError):
            continue
        if transport in TRANSPORTS and 0 < number < 65536:
            out.add((transport, number))
    return out


def _vpc_of(host: dict[str, Any]) -> str | None:
    meta = host.get("ec2_metadata") or {}
    value = meta.get("vpcId") if isinstance(meta, dict) else None
    return value if isinstance(value, str) and _VPC.fullmatch(value) else None


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


def build(hosts: Iterable[dict[str, Any]], assets: dict[str, dict[str, Any]], grid: HostView,
          networks: dict[str, Any] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """Nodes, edges, authority claims and counters for the shared hosts, their interfaces, addresses and open ports,
    and their installed software."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    counters: dict[str, int] = {}
    # Two Qualys hosts can name one instance (a re-registered agent, a stale record): each is linked, and the
    # shared host installs what either reports (PR #87 review).
    wanted: dict[tuple[str, str], tuple[list[str], set[tuple[str, str, str]]]] = {}
    software_read: set[tuple[str, str]] = set()
    interfaces: dict[tuple[str, str], dict[str, str | None]] = {}
    # Per shared host: each interface's addresses, and the open ports with the address they are reachable at.
    bound: dict[tuple[str, str], set[tuple[str, str, str]]] = {}
    exposed: dict[tuple[str, str], set[tuple[str, str, str, int]]] = {}
    undeclared = 0
    for host in hosts:
        key = host_key(host)
        asset = assets.get(host.get("host_id") or "")
        if key is None or asset is None or (asset.get("software") is None and asset.get("interfaces") is None):
            continue  # no issuer's id, or nothing read this run that the shared host carries
        host_ids, packages = wanted.setdefault(key, ([], set()))
        host_ids.append(host["host_id"])
        if asset.get("software") is not None:
            software_read.add(key)
            packages.update(packages_of(asset["software"], host.get("os")))
        for name, mac in interfaces_of(asset.get("interfaces")).items():
            seen = interfaces.setdefault(key, {})
            seen[name] = seen.get(name) or mac
        if asset.get("interfaces") is None and asset.get("open_ports") is None:
            continue
        if networks is None:
            undeclared += 1  # no declared network: an address would land on a guessed one (req-qualys-host-network)
            continue
        vpc = _vpc_of(host)
        for item in asset.get("interfaces") or []:
            name, address = item.get("interface_name"), canonical_address(item.get("address"))
            if isinstance(name, str) and name.strip() and address:
                bound.setdefault(key, set()).add((name.strip(), network_of(address, vpc, networks), address))
        address = canonical_address(host.get("ip"))
        if address:
            net = network_of(address, vpc, networks)
            for transport, number in ports_of(asset.get("open_ports")):
                exposed.setdefault(key, set()).add((net, address, transport, number))
    if undeclared:
        counters["networks_undeclared"] = undeclared
    if not wanted:
        return nodes, edges, claims, counters
    held_hosts = grid.held_keys(HOST_TYPE, wanted)
    if held_hosts is None:
        return nodes, edges, claims, {"computing_core_absent": 1}
    all_packages = {p for _, packages in wanted.values() for p in packages}
    held_packages = grid.held_packages(all_packages)
    host_dims = grid.default_dimensions(HOST_TYPE)
    package_dims = grid.default_dimensions(neutral.PACKAGE_TYPE)
    wanted_addresses = {(net, addr) for facts in bound.values() for _, net, addr in facts}
    wanted_addresses |= {(net, addr) for facts in exposed.values() for net, addr, _, _ in facts}
    held_addresses = (grid.held_keys(ADDRESS_TYPE, wanted_addresses) or set()) if wanted_addresses else set()
    address_dims = grid.default_dimensions(ADDRESS_TYPE) if wanted_addresses else {}
    address_end: dict[tuple[str, str], dict[str, Any]] = {}
    for net, addr in sorted(wanted_addresses):
        if (net, addr) in held_addresses:
            address_end[(net, addr)] = {"entity_type": ADDRESS_TYPE, "key": {key_dimensions.NETWORK_NAME_ENTRY: net, "address": addr}}
        else:
            # The shared-fact rule: key fields only, created where absent, never rewritten.
            nodes.append({"entity": {"ref": f"ip:{net}:{addr}", "entity_type": ADDRESS_TYPE, "name": addr,
                                     "dimensions": {**address_dims, key_dimensions.NETWORK_NAME: net}},
                          "node": {"address": addr}})
            counters["addresses_created"] = counters.get("addresses_created", 0) + 1
            address_end[(net, addr)] = {"ref": f"ip:{net}:{addr}"}
    wanted_ports = {p for facts in exposed.values() for p in facts}
    held_ports = (grid.held_keys(PORT_TYPE, wanted_ports) or set()) if wanted_ports else set()
    port_dims = grid.default_dimensions(PORT_TYPE) if wanted_ports else {}
    for port in sorted(wanted_ports):
        net, addr, transport, number = port
        ref = f"port:{net}:{addr}:{transport}:{number}"
        if port in held_ports:
            port_end = {"from_key": {"entity_type": PORT_TYPE, "key": {key_dimensions.NETWORK_NAME_ENTRY: net, "address": addr,
                                                                      "transport": transport, "port_number": number}}}
        else:
            nodes.append({"entity": {"ref": ref, "entity_type": PORT_TYPE, "name": f"{addr}:{number}/{transport}",
                                     "dimensions": {**port_dims, key_dimensions.NETWORK_NAME: net}},
                          "node": {"address": addr, "transport": transport, "port_number": number}})
            counters["ports_created"] = counters.get("ports_created", 0) + 1
            port_end = {"from_ref": ref}
        # Qualys reports a host's open ports with no address of their own: the port is reachable at the host's
        # reported IP, which is all AVAILABLE_AT claims (req-computing-core-ports-6).
        to = address_end[(net, addr)]
        edges.append({"entity": {"ref": f"e-available-{ref}", "entity_type": "edge", "name": AVAILABLE_AT, "dimensions": {}},
                      "edge": {**port_end, **({"to_ref": to["ref"]} if "ref" in to else {"to_key": to}), "edge_type": AVAILABLE_AT, "properties": {}}})
    wanted_interfaces = {(host_scope(key), name) for key, names in interfaces.items() for name in names}
    held_interfaces = grid.held_keys(INTERFACE_TYPE, wanted_interfaces) or set()
    interface_dims = grid.default_dimensions(INTERFACE_TYPE) if wanted_interfaces else {}
    for package in sorted(all_packages - held_packages):
        nodes.append(neutral.package_node(f"p:{'/'.join(package)}", package, package_dims))
        counters["packages_created"] = counters.get("packages_created", 0) + 1
    for key, (host_ids, packages) in sorted(wanted.items()):
        minted = key not in held_hosts
        if minted:
            # The shared-fact rule: key fields only, no dimension of this plugin's own.
            # The host type is identity, so it rides on the envelope's dimensions (key_dimensions.HOST_TYPE).
            nodes.append({"entity": {"ref": _host_ref(key), "entity_type": HOST_TYPE, "name": key[1],
                                     "dimensions": {**host_dims, key_dimensions.HOST_TYPE: key[0]}},
                          "node": {"stable_id": key[1]}})
            counters["shared_hosts_created"] = counters.get("shared_hosts_created", 0) + 1
        for host_id in host_ids:
            edges.append({"entity": {"ref": f"e-tracks-host-{host_id}", "entity_type": "edge", "name": TRACKS_HOST, "dimensions": {}},
                          "edge": {"from_ref": f"h{host_id}", **_host_end(key, minted, "to"), "edge_type": TRACKS_HOST, "properties": {}}})
        for package in sorted(packages):
            edges.append({"entity": {"ref": f"e-installs-{key[1]}-{'/'.join(package)}", "entity_type": "edge", "name": INSTALLS_PACKAGE, "dimensions": {}},
                          "edge": {**_host_end(key, minted, "from"), "to_key": neutral.package_ref(package), "edge_type": INSTALLS_PACKAGE, "properties": {}}})
            counters["installs"] = counters.get("installs", 0) + 1
        for name, mac in sorted(interfaces.get(key, {}).items()):
            scope = host_scope(key)
            ref = f"ni:{key[1]}:{name}"
            if (scope, name) in held_interfaces:
                end = {"to_key": {"entity_type": INTERFACE_TYPE, "key": {key_dimensions.HOST_ENTRY: scope, "interface_name": name}}}
            else:
                # Created where absent, with what Qualys saw; an interface another plugin holds is never rewritten.
                nodes.append({"entity": {"ref": ref, "entity_type": INTERFACE_TYPE, "name": name,
                                         "dimensions": {**interface_dims, key_dimensions.HOST: scope}},
                              "node": {"interface_name": name, "mac_address": mac}})
                counters["interfaces_created"] = counters.get("interfaces_created", 0) + 1
                end = {"to_ref": ref}
            edges.append({"entity": {"ref": f"e-contains-{key[1]}-{name}", "entity_type": "edge", "name": CONTAINS_INTERFACE, "dimensions": {}},
                          "edge": {**_host_end(key, minted, "from"), **end, "edge_type": CONTAINS_INTERFACE, "properties": {}}})
            source = {"from_ref": ref} if "to_ref" in end else {"from_key": end["to_key"]}
            for bound_name, net, addr in sorted(bound.get(key, set())):
                if bound_name != name:
                    continue
                to = address_end[(net, addr)]
                edges.append({"entity": {"ref": f"e-uses-{key[1]}-{name}-{net}-{addr}", "entity_type": "edge", "name": USES_ADDRESS, "dimensions": {}},
                              "edge": {**source, **({"to_ref": to["ref"]} if "ref" in to else {"to_key": to}), "edge_type": USES_ADDRESS, "properties": {}}})
        if key not in software_read:
            continue
        # Always partial. A claim's scope is every live edge of its type at the anchor, whoever wrote it
        # (req-grid-reconcile-edge-authority-2), and the shared host's installs are every scanner's: a complete
        # Qualys claim would propose retiring what another scanner saw (PR #87 review). Scoping a claim to its
        # writer is the reserved claim `dimensions` field (unified-systems-com/tap#907); until then Qualys does not
        # retire installs it no longer sees.
        claims.append({"edge_type": INSTALLS_PACKAGE, "anchor": {"entity_type": HOST_TYPE, "key": _key_ref(key)},
                       "direction": "outbound", "read": "partial"})
    return nodes, edges, claims, counters
