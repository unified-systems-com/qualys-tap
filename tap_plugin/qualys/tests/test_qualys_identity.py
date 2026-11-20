"""Subscription naming and derived keys (req-qualys-connection-3, req-qualys-subscription-run-1, req-qualys-neutral-1)."""

import pytest

from tap_plugin.qualys.identity import InvalidApiHost, canonical_api_host, neutral_source_key, subscription_key


class TestCanonicalApiHost:
    @pytest.mark.parametrize(
        "spelling",
        [
            "https://qualysapi.qg2.apps.qualys.com",
            "https://QualysAPI.QG2.apps.qualys.com/",
            "https://qualysapi.qg2.apps.qualys.com:443",
            "  https://qualysapi.qg2.apps.qualys.com  ",
        ],
    )
    def test_one_host_one_spelling(self, spelling: str) -> None:
        assert canonical_api_host(spelling) == "https://qualysapi.qg2.apps.qualys.com"

    def test_non_default_port_kept(self) -> None:
        assert canonical_api_host("https://q.example:8443") == "https://q.example:8443"

    @pytest.mark.parametrize(
        "bad",
        [
            "http://qualysapi.qualys.com",
            "https://user:pw@qualysapi.qualys.com",
            "https://qualysapi.qualys.com/api/2.0/",
            "https://qualysapi.qualys.com?x=1",
            "https://qualysapi.qualys.com#f",
            "https://qualysapi.qualys.com.",
            "https://",
        ],
    )
    def test_refused(self, bad: str) -> None:
        with pytest.raises(InvalidApiHost):
            canonical_api_host(bad)


class TestDerivedKeys:
    def test_subscription_key_is_a_json_array(self) -> None:
        assert subscription_key("https://QUALYSAPI.qualys.com", "acme") == '["https://qualysapi.qualys.com","acme"]'

    def test_two_labels_on_one_host_differ(self) -> None:
        assert subscription_key("https://qualysapi.qualys.com", "a") != subscription_key("https://qualysapi.qualys.com", "b")

    def test_framing_cannot_collide(self) -> None:
        # Concatenations match ("x.y" + "z" vs "x" + "y.z"); the encodings must not.
        assert neutral_source_key("x.y", "z", "CVE-1") != neutral_source_key("x", "y.z", "CVE-1")
        assert neutral_source_key("s", "1", "2|3") != neutral_source_key("s", "1|2", "3")

    def test_empty_label_refused(self) -> None:
        with pytest.raises(ValueError):
            subscription_key("https://qualysapi.qualys.com", "")
