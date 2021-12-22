"""
Tests for MUD data models.
"""

from __future__ import annotations

from typing import Any

import pytest

from mudparser.models import (
    AccessControlEntry,
    AccessControlList,
    ACLType,
    ForwardingAction,
    MUDProfile,
)
from mudparser.models.matches import (
    ACEMatches,
    DirectionInitiated,
    EthernetMatch,
    IPv4Match,
    IPv6Match,
    MUDMatch,
    PortMatch,
    PortOperator,
    TCPMatch,
    UDPMatch,
)


class TestPortMatch:
    """Tests for PortMatch model."""

    def test_eq_operator(self):
        """Test equals operator."""
        port = PortMatch(operator=PortOperator.EQ, port=443)
        assert port.matches_port(443)
        assert not port.matches_port(80)

    def test_neq_operator(self):
        """Test not-equals operator."""
        port = PortMatch(operator=PortOperator.NEQ, port=443)
        assert not port.matches_port(443)
        assert port.matches_port(80)

    def test_lt_operator(self):
        """Test less-than operator."""
        port = PortMatch(operator=PortOperator.LT, port=1024)
        assert port.matches_port(80)
        assert port.matches_port(443)
        assert not port.matches_port(1024)
        assert not port.matches_port(8080)

    def test_gt_operator(self):
        """Test greater-than operator."""
        port = PortMatch(operator=PortOperator.GT, port=1024)
        assert not port.matches_port(80)
        assert not port.matches_port(1024)
        assert port.matches_port(8080)

    def test_range_operator(self):
        """Test range operator."""
        port = PortMatch(operator=PortOperator.RANGE, port=80, upper_port=443)
        assert port.matches_port(80)
        assert port.matches_port(443)
        assert port.matches_port(200)
        assert not port.matches_port(79)
        assert not port.matches_port(444)

    def test_range_requires_upper_port(self):
        """Test that range operator requires upper_port."""
        with pytest.raises(ValueError) as exc_info:
            PortMatch(operator=PortOperator.RANGE, port=80)
        assert "upper_port" in str(exc_info.value)

    def test_range_upper_must_be_greater(self):
        """Test that upper_port must be greater than port."""
        with pytest.raises(ValueError):
            PortMatch(operator=PortOperator.RANGE, port=443, upper_port=80)

    def test_str_representation(self):
        """Test string representation."""
        port = PortMatch(operator=PortOperator.EQ, port=443)
        assert "443" in str(port)

        range_port = PortMatch(operator=PortOperator.RANGE, port=80, upper_port=443)
        assert "80" in str(range_port)
        assert "443" in str(range_port)


class TestIPv4Match:
    """Tests for IPv4Match model."""

    def test_basic_creation(self):
        """Test basic IPv4Match creation."""
        match = IPv4Match(protocol=6)
        assert match.protocol == 6

    def test_with_dns_name(self):
        """Test IPv4Match with DNS name."""
        match = IPv4Match(
            protocol=6,
            dst_dnsname="example.com",
        )
        assert match.dst_dnsname == "example.com"

    def test_invalid_protocol(self):
        """Test invalid protocol number."""
        with pytest.raises(ValueError):
            IPv4Match(protocol=300)


class TestTCPMatch:
    """Tests for TCPMatch model."""

    def test_with_destination_port(self):
        """Test TCPMatch with destination port."""
        match = TCPMatch.from_json({
            "destination-port": {
                "operator": "eq",
                "port": 443
            }
        })
        assert match.dst_port is not None
        assert match.dst_port.port == 443

    def test_with_direction_initiated(self):
        """Test TCPMatch with direction-initiated."""
        match = TCPMatch.from_json({
            "ietf-mud:direction-initiated": "from-device"
        })
        assert match.direction_initiated == DirectionInitiated.FROM_DEVICE


class TestACEMatches:
    """Tests for ACEMatches model."""

    def test_has_matches(self):
        """Test has_matches method."""
        empty = ACEMatches()
        assert not empty.has_matches()

        with_ipv4 = ACEMatches(ipv4=IPv4Match(protocol=6))
        assert with_ipv4.has_matches()

    def test_get_protocol(self):
        """Test get_protocol method."""
        matches = ACEMatches(ipv4=IPv4Match(protocol=6))
        assert matches.get_protocol() == 6

        ipv6_matches = ACEMatches(ipv6=IPv6Match(next_header=17))
        assert ipv6_matches.get_protocol() == 17

    def test_get_dns_names(self):
        """Test get_dns_names method."""
        matches = ACEMatches(
            ipv4=IPv4Match(
                dst_dnsname="api.example.com",
                src_dnsname="client.example.com"
            )
        )
        dns = matches.get_dns_names()
        assert dns["dst"] == "api.example.com"
        assert dns["src"] == "client.example.com"

    def test_from_json(self, mud_with_all_match_types: dict[str, Any]):
        """Test creating from JSON."""
        acl_data = mud_with_all_match_types["ietf-access-control-list:access-lists"]["acl"][0]
        ace_data = acl_data["aces"]["ace"][0]

        matches = ACEMatches.from_json(ace_data["matches"])
        assert matches.ipv4 is not None
        assert matches.tcp is not None


class TestMUDMatch:
    """Tests for MUDMatch model."""

    def test_manufacturer_match(self):
        """Test manufacturer match."""
        match = MUDMatch(manufacturer="https://example.com")
        assert match.get_match_type() == "manufacturer"
        assert match.get_match_value() == "https://example.com"

    def test_local_networks_match(self):
        """Test local-networks match."""
        match = MUDMatch(local_networks=[None])
        assert match.get_match_type() == "local-networks"

    def test_controller_match(self):
        """Test controller match."""
        match = MUDMatch(controller="urn:ietf:params:mud:dns")
        assert match.get_match_type() == "controller"


class TestAccessControlEntry:
    """Tests for AccessControlEntry model."""

    def test_is_accept(self):
        """Test is_accept method."""
        ace = AccessControlEntry(
            name="test",
            matches=ACEMatches(),
            actions={"forwarding": ForwardingAction.ACCEPT},
        )
        assert ace.is_accept()
        assert not ace.is_deny()

    def test_is_deny(self):
        """Test is_deny method."""
        ace = AccessControlEntry(
            name="test",
            matches=ACEMatches(),
            actions={"forwarding": ForwardingAction.DROP},
        )
        assert ace.is_deny()
        assert not ace.is_accept()

    def test_get_description(self):
        """Test get_description method."""
        ace = AccessControlEntry.from_json({
            "name": "allow-https",
            "matches": {
                "ipv4": {"protocol": 6},
                "tcp": {"destination-port": {"operator": "eq", "port": 443}}
            },
            "actions": {"forwarding": "accept"}
        })

        desc = ace.get_description(direction="from")
        assert "ALLOW" in desc
        assert "TCP" in desc
        assert "443" in desc


class TestAccessControlList:
    """Tests for AccessControlList model."""

    def test_from_json(self, amazon_echo_short_data: dict[str, Any]):
        """Test creating from JSON."""
        acl_data = amazon_echo_short_data["ietf-access-control-list:access-lists"]["acl"][0]
        acl = AccessControlList.from_json(acl_data)

        assert acl.name == "from-ipv4-amazonecho"
        assert acl.acl_type == ACLType.IPV4
        assert len(acl.entries) == 3

    def test_len(self, amazon_echo_short_data: dict[str, Any]):
        """Test __len__ method."""
        acl_data = amazon_echo_short_data["ietf-access-control-list:access-lists"]["acl"][0]
        acl = AccessControlList.from_json(acl_data)

        assert len(acl) == 3

    def test_iteration(self, amazon_echo_short_data: dict[str, Any]):
        """Test iteration over ACEs."""
        acl_data = amazon_echo_short_data["ietf-access-control-list:access-lists"]["acl"][0]
        acl = AccessControlList.from_json(acl_data)

        entries = list(acl)
        assert len(entries) == 3

    def test_getitem_by_index(self, amazon_echo_short_data: dict[str, Any]):
        """Test getting ACE by index."""
        acl_data = amazon_echo_short_data["ietf-access-control-list:access-lists"]["acl"][0]
        acl = AccessControlList.from_json(acl_data)

        ace = acl[0]
        assert ace.name == "from-ipv4-amazonecho-0"

    def test_getitem_by_name(self, amazon_echo_short_data: dict[str, Any]):
        """Test getting ACE by name."""
        acl_data = amazon_echo_short_data["ietf-access-control-list:access-lists"]["acl"][0]
        acl = AccessControlList.from_json(acl_data)

        ace = acl["from-ipv4-amazonecho-0"]
        assert ace.name == "from-ipv4-amazonecho-0"

    def test_is_ipv4(self, amazon_echo_short_data: dict[str, Any]):
        """Test is_ipv4 method."""
        acl_data = amazon_echo_short_data["ietf-access-control-list:access-lists"]["acl"][0]
        acl = AccessControlList.from_json(acl_data)

        assert acl.is_ipv4()
        assert not acl.is_ipv6()
        assert not acl.is_ethernet()

    def test_get_accept_rules(self, amazon_echo_short_data: dict[str, Any]):
        """Test get_accept_rules method."""
        acl_data = amazon_echo_short_data["ietf-access-control-list:access-lists"]["acl"][0]
        acl = AccessControlList.from_json(acl_data)

        accept_rules = acl.get_accept_rules()
        assert len(accept_rules) == 3


class TestMUDProfile:
    """Tests for MUDProfile model."""

    def test_from_json(self, amazon_echo_short_data: dict[str, Any]):
        """Test creating from JSON."""
        profile = MUDProfile.from_json(amazon_echo_short_data)

        assert profile.version == 1
        assert "amazonecho" in profile.url.lower()
        assert profile.is_supported

    def test_get_acl(self, amazon_echo_short_data: dict[str, Any]):
        """Test get_acl method."""
        profile = MUDProfile.from_json(amazon_echo_short_data)

        acl = profile.get_acl("from-ipv4-amazonecho")
        assert acl is not None
        assert acl.name == "from-ipv4-amazonecho"

        assert profile.get_acl("nonexistent") is None

    def test_get_from_device_acls(self, amazon_echo_short_data: dict[str, Any]):
        """Test get_from_device_acls method."""
        profile = MUDProfile.from_json(amazon_echo_short_data)

        acls = profile.get_from_device_acls()
        assert len(acls) == 2

    def test_get_acl_direction(self, amazon_echo_short_data: dict[str, Any]):
        """Test get_acl_direction method."""
        profile = MUDProfile.from_json(amazon_echo_short_data)

        assert profile.get_acl_direction("from-ipv4-amazonecho") == "from"
        assert profile.get_acl_direction("to-ipv4-amazonecho") == "to"
        assert profile.get_acl_direction("nonexistent") is None

    def test_get_all_dns_names(self, amazon_echo_short_data: dict[str, Any]):
        """Test get_all_dns_names method."""
        profile = MUDProfile.from_json(amazon_echo_short_data)

        dns_names = profile.get_all_dns_names()
        assert "dcape-na.amazon.com" in dns_names

    def test_get_all_ports(self, amazon_echo_short_data: dict[str, Any]):
        """Test get_all_ports method."""
        profile = MUDProfile.from_json(amazon_echo_short_data)

        ports = profile.get_all_ports()
        assert 443 in ports["tcp"]
