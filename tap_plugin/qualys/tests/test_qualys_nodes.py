"""The five Qualys node types and their edges, through the service layer.

Creation, required fields, the declared natural keys (found again by the generated search), the default
dimension, display names, values stored as returned, null as unobserved, and the endpoint rules of the
edges. Payloads are derived from Qualys's documented examples, not recorded from a subscription.
"""

import pytest
import tap_plugin.compliance_core.models  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models  # noqa: F401 — trigger model registration
import tap_plugin.qualys.models  # noqa: F401 — trigger model registration

from tap_grid.constraints import InvalidEdgeError
from tap_grid.dimension_names import view
from tap_grid.models import Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node
from tap_plugin.qualys.identity import subscription_key

HOST = "https://qualysapi.qg2.apps.qualys.com"
SUB = subscription_key(HOST, "acme-prod")

SUBSCRIPTION = {"api_host": HOST, "subscription_label": "acme-prod", "subscription_key": SUB}
RUN = {"subscription_key": SUB, "run_id": "run-1", "source": "api"}
QHOST = {
    "subscription_key": SUB,
    "host_id": "12345",
    "ip": "10.0.0.5",
    "tracking_method": "AGENT",
    "cloud_provider": "AWS",
    "cloud_service": "EC2",
    "cloud_resource_id": "i-0abc123def4567890",
}
DETECTION = {
    "subscription_key": SUB,
    "host_id": "12345",
    "qid": "38170",
    "unique_vuln_id": "3978355",
    "detection_type": "Confirmed",
    "port": "443",
    "protocol": "tcp",
    "status": "Active",
    "results": "Package\tInstalled Version\tRequired Version\nopenssl\t1.1.1k\t1.1.1w",
}
QID = {"subscription_key": SUB, "qid": "38170", "title": "SSL Certificate - Subject Common Name Does Not Match"}

TYPES = {
    "qualys__qualys_subscription": (SUBSCRIPTION, "acme-prod", "run"),
    "qualys__qualys_scan_run": (RUN, "run run-1", "run"),
    "qualys__qualys_host": (QHOST, "10.0.0.5", "observation"),
    "qualys__qualys_detection": (DETECTION, "QID 38170 on host 12345", "finding"),
    "qualys__qualys_qid": (QID, "QID 38170: SSL Certificate - Subject Common Name Does Not Match", "knowledge"),
}


def _create(type_slug: str, payload: dict) -> Entity:
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    return Entity.objects.get(id=result.entity_id)


@pytest.mark.django_db
class TestNodes:
    @pytest.mark.parametrize("type_slug", sorted(TYPES))
    def test_created_named_and_dimensioned(self, type_slug: str) -> None:
        payload, name, area = TYPES[type_slug]
        entity = _create(type_slug, payload)
        assert entity.name == name
        assert view(entity.dimensions).get("qualys.area") == area

    @pytest.mark.parametrize("type_slug", sorted(TYPES))
    def test_found_again_by_natural_key(self, type_slug: str) -> None:
        payload, _, _ = TYPES[type_slug]
        entity = _create(type_slug, payload)
        model = get_model_class(type_slug)
        key = {field: payload[field] for field in model.NATURAL_KEY}
        assert model.find_existing(**key).entity_id == entity.id

    @pytest.mark.parametrize("type_slug", sorted(TYPES))
    def test_key_fields_required(self, type_slug: str) -> None:
        payload, _, _ = TYPES[type_slug]
        for field in get_model_class(type_slug).NATURAL_KEY:
            assert not create_node(type_slug, {k: v for k, v in payload.items() if k != field}).success, field

    def test_unobserved_is_null(self) -> None:
        _create("qualys__qualys_host", QHOST)
        host = get_model_class("qualys__qualys_host").find_existing(subscription_key=SUB, host_id="12345")
        assert host.dns is None and host.ec2_instance_id is None and host.state is None

    def test_values_stored_as_returned(self) -> None:
        _create("qualys__qualys_detection", DETECTION)
        detection = get_model_class("qualys__qualys_detection").find_existing(
            subscription_key=SUB, host_id="12345", qid="38170", unique_vuln_id="3978355"
        )
        assert detection.port == "443" and detection.status == "Active"
        assert detection.results == DETECTION["results"]

    def test_qid_in_the_detection_key(self) -> None:
        # One UNIQUE_VULN_ID under two QIDs on one host is two detections (req-qualys-detection-2).
        _create("qualys__qualys_detection", DETECTION)
        _create("qualys__qualys_detection", {**DETECTION, "qid": "45038", "detection_type": "Info"})
        assert get_model_class("qualys__qualys_detection").objects.filter(unique_vuln_id="3978355").count() == 2

    @pytest.mark.parametrize(
        "bad",
        [
            {"subscription_key": "bogus"},
            {"subscription_key": subscription_key(HOST, "other-label")},
            {"api_host": "https://QualysAPI.qg2.apps.qualys.com", "subscription_key": subscription_key(HOST, "acme-prod")},
        ],
        ids=["not-a-key", "another-label", "host-not-canonical"],
    )
    def test_subscription_key_must_be_derived(self, bad: dict) -> None:
        assert not create_node("qualys__qualys_subscription", {**SUBSCRIPTION, **bad}).success

    def test_unknown_warning_code_refused(self) -> None:
        bad = {**RUN, "warnings": [{"code": "SOMETHING_ELSE"}]}
        assert not create_node("qualys__qualys_scan_run", bad).success

    def test_unknown_parse_state_refused(self) -> None:
        assert not create_node("qualys__qualys_detection", {**DETECTION, "parse_state": "maybe"}).success


@pytest.mark.django_db
class TestEdges:
    def test_detection_edges(self) -> None:
        detection = _create("qualys__qualys_detection", DETECTION)
        host = _create("qualys__qualys_host", QHOST)
        qid = _create("qualys__qualys_qid", QID)
        for edge_type, target in (("DETECTED_ON_HOST__qualys", host), ("ABOUT_QID__qualys", qid)):
            edge = create_edge(detection, target, edge_type)
            assert view(edge.entity.dimensions).get("qualys.area") == "finding"

    def test_run_edges(self) -> None:
        run = _create("qualys__qualys_scan_run", RUN)
        subscription = _create("qualys__qualys_subscription", SUBSCRIPTION)
        host = _create("qualys__qualys_host", QHOST)
        assert view(create_edge(run, subscription, "RUN_OF_SUBSCRIPTION__qualys").entity.dimensions).get("qualys.area") == "run"
        assert view(create_edge(host, run, "LAST_SEEN_IN_RUN__qualys").entity.dimensions).get("qualys.area") == "run"

    def test_endpoints_enforced(self) -> None:
        host = _create("qualys__qualys_host", QHOST)
        qid = _create("qualys__qualys_qid", QID)
        with pytest.raises(InvalidEdgeError):
            create_edge(qid, host, "DETECTED_ON_HOST__qualys")
