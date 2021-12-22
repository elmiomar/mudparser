"""
Tests for MUD exporters.
"""

from __future__ import annotations

from typing import Any

import pytest

from mudparser import MUDParser
from mudparser.exporters import ExportFormat, MUDExporter
from mudparser.models import MUDProfile


class TestMUDExporter:
    """Tests for the main MUDExporter class."""

    def test_to_json(self, amazon_echo_short_data: dict[str, Any]):
        """Test JSON export."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        json_output = exporter.to_json()

        assert "ietf-mud:mud" in json_output
        assert "amazonecho" in json_output.lower()

    def test_to_yaml(self, amazon_echo_short_data: dict[str, Any]):
        """Test YAML export."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        yaml_output = exporter.to_yaml()

        assert "ietf-mud:mud" in yaml_output
        # YAML should have proper indentation
        assert "\n  " in yaml_output or "\n    " in yaml_output

    def test_export_by_format_string(self, amazon_echo_short_data: dict[str, Any]):
        """Test export with format string."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        json_output = exporter.export("json")
        assert "ietf-mud:mud" in json_output

    def test_export_by_format_enum(self, amazon_echo_short_data: dict[str, Any]):
        """Test export with format enum."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        yaml_output = exporter.export(ExportFormat.YAML)
        assert "ietf-mud:mud" in yaml_output

    def test_export_invalid_format(self, amazon_echo_short_data: dict[str, Any]):
        """Test export with invalid format raises error."""
        from mudparser.exceptions import MUDExportError

        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        with pytest.raises(MUDExportError):
            exporter.export("invalid_format")

    def test_get_summary(self, amazon_echo_short_data: dict[str, Any]):
        """Test get_summary method."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        summary = exporter.get_summary()

        assert "device_info" in summary
        assert "from_device_rules" in summary
        assert "to_device_rules" in summary
        assert "total_rules" in summary
        assert "supported_formats" in summary


class TestIPTablesExporter:
    """Tests for IPTables export."""

    def test_iptables_export(self, amazon_echo_short_data: dict[str, Any]):
        """Test iptables rule generation."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        rules = exporter.to_iptables(device_ip="192.168.1.100")

        # Should have shebang
        assert rules.startswith("#!/bin/bash")

        # Should have chain creation
        assert "iptables -N" in rules

        # Should have rules for the device IP
        assert "192.168.1.100" in rules

        # Should have ACCEPT rules
        assert "-j ACCEPT" in rules

        # Should have implicit deny
        assert "-j DROP" in rules

    def test_iptables_with_custom_chain_prefix(
        self, amazon_echo_short_data: dict[str, Any]
    ):
        """Test iptables with custom chain prefix."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        rules = exporter.to_iptables(
            device_ip="192.168.1.100",
            chain_prefix="IOT"
        )

        assert "IOT_FROM" in rules or "IOT_TO" in rules

    def test_iptables_without_comments(self, amazon_echo_short_data: dict[str, Any]):
        """Test iptables without comments."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        rules = exporter.to_iptables(
            device_ip="192.168.1.100",
            include_comments=False
        )

        # Should not have --comment
        assert "--comment" not in rules


class TestNFTablesExporter:
    """Tests for nftables export."""

    def test_nftables_export(self, amazon_echo_short_data: dict[str, Any]):
        """Test nftables rule generation."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        rules = exporter.to_nftables(device_ip="192.168.1.100")

        # Should have shebang
        assert rules.startswith("#!/usr/sbin/nft")

        # Should have table definition
        assert "table inet" in rules

        # Should have chain definition
        assert "chain" in rules

        # Should have device IP
        assert "192.168.1.100" in rules

        # Should have accept/drop
        assert "accept" in rules
        assert "drop" in rules

    def test_nftables_custom_table_name(self, amazon_echo_short_data: dict[str, Any]):
        """Test nftables with custom table name."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        rules = exporter.to_nftables(
            device_ip="192.168.1.100",
            table_name="iot_filter"
        )

        assert "iot_filter" in rules


class TestCiscoACLExporter:
    """Tests for Cisco ACL export."""

    def test_cisco_export(self, amazon_echo_short_data: dict[str, Any]):
        """Test Cisco ACL generation."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        rules = exporter.to_cisco_acl()

        # Should have ACL header
        assert "ip access-list extended" in rules

        # Should have permit/deny
        assert "permit" in rules
        assert "deny" in rules

        # Should have protocol
        assert "tcp" in rules or "ip" in rules

    def test_cisco_with_remarks(self, amazon_echo_short_data: dict[str, Any]):
        """Test Cisco ACL with remarks."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        rules = exporter.to_cisco_acl(include_remarks=True)

        assert "remark" in rules

    def test_cisco_without_remarks(self, amazon_echo_short_data: dict[str, Any]):
        """Test Cisco ACL without remarks."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        rules = exporter.to_cisco_acl(include_remarks=False)

        assert "remark" not in rules

    def test_cisco_custom_acl_number(self, amazon_echo_short_data: dict[str, Any]):
        """Test Cisco ACL with custom starting number."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        rules = exporter.to_cisco_acl(acl_number_start=200)

        assert "200" in rules


class TestPfSenseExporter:
    """Tests for pfSense export."""

    def test_pfsense_export(self, amazon_echo_short_data: dict[str, Any]):
        """Test pfSense XML generation."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        rules = exporter.to_pfsense(device_ip="192.168.1.100")

        # Should be valid XML
        assert "<?xml" in rules
        assert "<pfsense>" in rules
        assert "</pfsense>" in rules

        # Should have filter rules
        assert "<filter>" in rules
        assert "<rule>" in rules

        # Should have device IP
        assert "192.168.1.100" in rules

        # Should have pass/block
        assert "<type>pass</type>" in rules or "<type>block</type>" in rules

    def test_pfsense_custom_interface(self, amazon_echo_short_data: dict[str, Any]):
        """Test pfSense with custom interface."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        exporter = MUDExporter(profile)

        rules = exporter.to_pfsense(
            device_ip="192.168.1.100",
            interface="opt1"
        )

        assert "<interface>opt1</interface>" in rules


class TestExporterIntegration:
    """Integration tests for exporters via MUDParser."""

    def test_parser_export_property(self, amazon_echo_short_path):
        """Test accessing exporter via parser."""
        parser = MUDParser.from_file(amazon_echo_short_path)

        # Export property should return an exporter
        exporter = parser.export
        assert isinstance(exporter, MUDExporter)

        # Should be able to export
        json_output = exporter.to_json()
        assert "ietf-mud:mud" in json_output

    def test_parser_export_to_all_formats(self, amazon_echo_short_path):
        """Test exporting to all formats via parser."""
        parser = MUDParser.from_file(amazon_echo_short_path)

        # JSON
        json_out = parser.export.to_json()
        assert json_out

        # YAML
        yaml_out = parser.export.to_yaml()
        assert yaml_out

        # iptables
        iptables_out = parser.export.to_iptables(device_ip="10.0.0.1")
        assert iptables_out

        # nftables
        nftables_out = parser.export.to_nftables(device_ip="10.0.0.1")
        assert nftables_out

        # Cisco
        cisco_out = parser.export.to_cisco_acl()
        assert cisco_out

        # pfSense
        pfsense_out = parser.export.to_pfsense(device_ip="10.0.0.1")
        assert pfsense_out
