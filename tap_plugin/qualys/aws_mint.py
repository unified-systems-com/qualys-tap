"""The optional AWS side (req-qualys-aws): aws_core nodes and edges minted from what Qualys reports.

Off unless the envelope sets ``integrations.aws``, and inert without ``aws_core`` installed (George, 2026-11-23,
Q38a, reversing Q2a for this setting). aws_core reads AWS itself and is the source of record, so this writes a
node only where aws_core holds none, and never rewrites one it holds: a GRIFT node write replaces the whole node,
and a write of what Qualys knows would wipe what aws_core read. WORKAROUND(unified-systems-com/tap#1071): the
check and the write are two steps, so aws_core can create the same node between them and this write then replaces
it, until core has an insert-only write. When aws_core next reads that resource, its own values win.

What Qualys reports comes from the host's ``CLOUD_RESOURCE_ID`` (provider AWS, service EC2), its ``METADATA/EC2``
attributes, and its ``CLOUD_PROVIDER_TAGS``. The attribute names are the ones a live subscription returned (Q38d);
a value of the wrong shape, or one that names more than one id where one is expected, is left out, never guessed.

Edges are aws_core's own, written only where one end was minted by this run: an edge between two nodes aws_core
holds is aws_core's to write. A VPC, subnet or security group gets no account or region edge, because the metadata
names the instance's account, and a shared VPC belongs to another one.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol

DOC = "latest/dynamic/instance-identity/document/"
META = "latest/meta-data/"

INSTANCE = "aws_core__aws_ec2_instance"
VPC = "aws_core__aws_vpc"
SUBNET = "aws_core__aws_subnet"
SECURITY_GROUP = "aws_core__aws_security_group"
ACCOUNT = "aws_core__aws_account"
REGION = "aws_core__aws_region"
ACCOUNT_REGION = "aws_core__aws_account_region"
#: Every type this module may mint, with its natural-key fields.
KEYS: dict[str, tuple[str, ...]] = {
    INSTANCE: ("instance_id",),
    VPC: ("vpc_id",),
    SUBNET: ("subnet_id",),
    SECURITY_GROUP: ("group_id",),
    ACCOUNT: ("account_id",),
    REGION: ("region_code",),
    ACCOUNT_REGION: ("account_id", "region_code"),
}
TYPES = frozenset(KEYS)

_DIGITS12 = frozenset("0123456789")
#: AWS's id shapes: a prefix and 8 or 17 hex digits. A value of any other shape is left out, never minted.
_AWS_ID = re.compile(r"(i|sg|vpc|subnet)-[0-9a-f]{8}(?:[0-9a-f]{9})?")
_REGION = re.compile(r"[a-z]{2}(?:-gov|-iso[a-z]*)?-[a-z]+-[0-9]{1,2}")


class AwsView(Protocol):
    def held_keys(self, entity_type: str, keys: Iterable[tuple[str, ...]]) -> set[tuple[str, ...]] | None:
        """Of these natural keys, those the grid holds for the type; None when aws_core is not installed."""
        ...

    def default_dimensions(self, entity_type: str) -> dict[str, str]: ...


@dataclass
class Minted:
    """What this run adds on the AWS side: nodes to create, edges to write, and the instances that now exist."""

    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=dict)
    #: Instance ids the grid will hold after this run, held or minted, so the host's EC2 link can be written.
    instances: set[str] = field(default_factory=set)
    absent: bool = False


def _value(meta: dict[str, Any], path: str) -> str | None:
    v = meta.get(path)
    return v.strip() if isinstance(v, str) and v.strip() else None


def _ids(text: str | None, prefix: str) -> list[str]:
    """Ids of one kind in a metadata value, split on commas and whitespace; only tokens of AWS's id shape count."""
    if not text:
        return []
    return sorted({part for part in re.split(r"[\s,]+", text) if part.startswith(prefix) and _AWS_ID.fullmatch(part)})


def _account(value: str | None) -> str | None:
    return value if value and len(value) == 12 and set(value) <= _DIGITS12 else None


def _ref(entity_type: str, key: tuple[str, ...]) -> str:
    return f"aws:{entity_type.split('__')[1]}:{'/'.join(key)}"


def _id(meta: dict[str, Any], prefix: str, *paths: str) -> str | None:
    for path in paths:
        found = _ids(_value(meta, path), prefix)
        if len(found) == 1:
            return found[0]
    return None


def observe(host: dict[str, Any]) -> dict[str, Any] | None:
    """What one Qualys host says about its EC2 instance and network, or None when it is not an AWS EC2 host.

    Names as Qualys returns them from a live subscription (field report, 2026-11-23, Q38d): the instance identity
    document under ``latest/dynamic/instance-identity/document/``, a few ``latest/meta-data/`` paths, and flat EC2
    API names (``vpcId``, ``subnetId``, ``groupId``, ``groupName``, ``ownerId``, ``instanceState``). No network
    interface id and no availability-zone id is returned, so neither is minted.
    """
    instance = host.get("cloud_resource_id")
    if not (host.get("cloud_provider") == "AWS" and host.get("cloud_service") == "EC2" and isinstance(instance, str)
            and instance.startswith("i-") and _AWS_ID.fullmatch(instance)):
        return None
    meta = host.get("ec2_metadata") or {}
    region = _value(meta, DOC + "region")
    groups = _ids(_value(meta, "groupId"), "sg-")
    names = (_value(meta, "groupName") or "").split()
    tags = host.get("cloud_tags")
    return {
        "instance_id": instance,
        "account_id": _account(_value(meta, DOC + "accountId")) or _account(_value(meta, "ownerId")),
        "region": region if region and _REGION.fullmatch(region) else None,
        "zone_name": _value(meta, DOC + "availabilityZone"),
        "ami_id": _value(meta, DOC + "imageId") or _value(meta, META + "ami-id"),
        "instance_type": _value(meta, DOC + "instanceType") or _value(meta, META + "instance-type"),
        "private_ip": _value(meta, DOC + "privateIp") or _value(meta, META + "local-ipv4"),
        "public_ip": _value(meta, META + "public-ipv4"),
        "state": _value(meta, "instanceState"),
        "vpc_id": _id(meta, "vpc-", "vpcId"),
        "subnet_id": _id(meta, "subnet-", "subnetId"),
        "security_groups": groups,
        # A group's name is paired with its id only when the host reports exactly one of each: the order of
        # several is not documented, and a wrong pairing would name the wrong group.
        "group_names": {groups[0]: names[0]} if len(groups) == 1 and len(names) == 1 else {},
        # aws_core's shape: {Key: Value}; a tag with no name cannot be a key and is left out.
        "tags": None if tags is None else {t["name"]: t.get("value") or "" for t in tags if t.get("name")},
    }


def mint(hosts: Iterable[dict[str, Any]], grid: AwsView) -> Minted:
    """Every aws_core node and edge the hosts justify that the grid lacks (req-qualys-aws)."""
    out = Minted()
    seen = [o for h in hosts if (o := observe(h)) is not None]
    if not seen:
        return out
    wanted: dict[str, dict[tuple[str, ...], dict[str, Any]]] = {t: {} for t in KEYS}
    links: set[tuple[str, str, tuple[str, ...], str, tuple[str, ...]]] = set()

    def want(entity_type: str, key: tuple[str, ...], fields: dict[str, Any]) -> None:
        held = wanted[entity_type].setdefault(key, {})
        for name, value in fields.items():
            if value is not None and held.get(name) is None:
                held[name] = value  # first report wins; a later host never blanks what an earlier one gave

    def link(slug: str, a_type: str, a: tuple[str, ...], b_type: str, b: tuple[str, ...]) -> None:
        links.add((slug, a_type, a, b_type, b))

    for o in seen:
        iid = (o["instance_id"],)
        want(INSTANCE, iid, {"name": o["instance_id"], "instance_id": o["instance_id"], "ec2_type": o["instance_type"], "ami_id": o["ami_id"],
                             "private_ip": o["private_ip"], "public_ip": o["public_ip"], "state": o["state"], "tags": o["tags"]})
        acct, region = o["account_id"], o["region"]
        if acct:
            want(ACCOUNT, (acct,), {"name": acct, "account_id": acct})
            link("BELONGS_TO_ACCOUNT__aws_core", INSTANCE, iid, ACCOUNT, (acct,))
        if region:
            want(REGION, (region,), {"name": region, "region_code": region})
        if acct and region:
            want(ACCOUNT_REGION, (acct, region), {"name": f"{acct}/{region}", "account_id": acct, "region_code": region})
            link("BELONGS_TO_ACCOUNT__aws_core", ACCOUNT_REGION, (acct, region), ACCOUNT, (acct,))
            link("HOSTS_EC2_INSTANCE__aws_core", ACCOUNT_REGION, (acct, region), INSTANCE, iid)
        vpc = (o["vpc_id"],) if o["vpc_id"] else None
        if vpc:
            want(VPC, vpc, {"name": o["vpc_id"], "vpc_id": o["vpc_id"]})
        if o["subnet_id"]:
            subnet = (o["subnet_id"],)
            # The instance's zone is its subnet's: an instance's primary interface is in the subnet it reports.
            want(SUBNET, subnet, {"name": o["subnet_id"], "subnet_id": o["subnet_id"], "availability_zone": o["zone_name"]})
            if vpc:
                link("PARTITIONED_INTO_SUBNET__aws_core", VPC, vpc, SUBNET, subnet)
        for sg in o["security_groups"]:
            want(SECURITY_GROUP, (sg,), {"name": o["group_names"].get(sg) or sg, "group_id": sg})
            if vpc:
                link("RESIDES_IN_VPC__aws_core", SECURITY_GROUP, (sg,), VPC, vpc)

    held: dict[str, set[tuple[str, ...]]] = {}
    for entity_type, keys in wanted.items():
        found = grid.held_keys(entity_type, keys)
        if found is None:
            out.absent = True
            return Minted(absent=True)
        held[entity_type] = found
    minted: dict[str, set[tuple[str, ...]]] = {t: set() for t in KEYS}
    for entity_type, keys in wanted.items():
        dims = grid.default_dimensions(entity_type)
        for key, fields in sorted(keys.items()):
            if key in held[entity_type]:
                out.counters[f"aws_{entity_type.split('__aws_')[1]}_held"] = out.counters.get(f"aws_{entity_type.split('__aws_')[1]}_held", 0) + 1
                continue
            minted[entity_type].add(key)
            out.nodes.append({"entity": {"ref": _ref(entity_type, key), "entity_type": entity_type, "name": str(fields.get("name") or "/".join(key))[:255], "dimensions": dict(dims)},
                              "node": fields})
            name = f"aws_{entity_type.split('__aws_')[1]}_created"
            out.counters[name] = out.counters.get(name, 0) + 1
    out.instances = {k[0] for k in wanted[INSTANCE]}

    def end(entity_type: str, key: tuple[str, ...], side: str) -> dict[str, Any]:
        if key in minted[entity_type]:
            return {f"{side}_ref": _ref(entity_type, key)}
        return {f"{side}_key": {"entity_type": entity_type, "key": dict(zip(KEYS[entity_type], key, strict=True))}}

    for slug, a_type, a, b_type, b in sorted(links):
        if a not in minted[a_type] and b not in minted[b_type]:
            continue  # both held: aws_core's edge to write, not ours
        ref = f"e-aws-{slug}-{'/'.join(a)}-{'/'.join(b)}"
        out.edges.append({"entity": {"ref": ref, "entity_type": "edge", "name": slug, "dimensions": {}},
                          "edge": {**end(a_type, a, "from"), **end(b_type, b, "to"), "edge_type": slug, "properties": {}}})
        out.counters["aws_edges"] = out.counters.get("aws_edges", 0) + 1
    return out
