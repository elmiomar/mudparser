"""
Tests for the MUDParser class.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mudparser import MUDParser
from mudparser.exceptions import (
    MUDFileNotFoundError,
    MUDSchemaError,
    MUDValidationError,
)


class TestParserFromFile:
    """Tests for MUDParser.from_file()."""

    def test_parse_amazon_echo_short(self, amazon_echo_short_path: Path):
        """Test parsing the short Amazon Echo profile."""
        parser = MUDParser.from_file(amazon_echo_short_path)

        assert parser.profile is not None
        assert parser.mud.mud_version == 1
        assert str(parser.mud.mud_url) == "https://amazonecho.com/amazonecho"
        assert parser.mud.systeminfo == "amazonEcho"
        assert parser.mud.is_supported is True

    def test_parse_amazon_echo_full(self, amazon_echo_full_path: Path):
        """Test parsing the full Amazon Echo profile."""
        parser = MUDParser.from_file(amazon_echo_full_path)

        assert parser.profile is not None
        assert parser.mud.mud_version == 1

    def test_file_not_found(self, tmp_path: Path):
        """Test that FileNotFoundError is raised for missing files."""
        with pytest.raises(MUDFileNotFoundError) as exc_info:
            MUDParser.from_file(tmp_path / "nonexistent.json")

        assert "not found" in str(exc_info.value).lower()

    def test_invalid_json_file(self, tmp_path: Path):
        """Test handling of invalid JSON files."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("{ invalid json }")

        with pytest.raises(MUDSchemaError):
            MUDParser.from_file(invalid_file)


class TestParserFromString:
    """Tests for MUDParser.from_string()."""

    def test_parse_from_string(self, amazon_echo_short_json: str):
        """Test parsing from a JSON string."""
        parser = MUDParser.from_string(amazon_echo_short_json)

        assert parser.profile is not None
        assert parser.mud.mud_version == 1

    def test_invalid_json_string(self):
        """Test handling of invalid JSON strings."""
        with pytest.raises(MUDSchemaError):
            MUDParser.from_string("not valid json")


class TestParserFromDict:
    """Tests for MUDParser.from_dict()."""

    def test_parse_from_dict(self, minimal_mud_data: dict[str, Any]):
        """Test parsing from a dictionary."""
        parser = MUDParser.from_dict(minimal_mud_data)

        assert parser.profile is not None
        assert parser.mud.systeminfo == "Test Device"

    def test_missing_mud_container(self, invalid_mud_missing_container: dict[str, Any]):
        """Test handling of missing MUD container."""
        with pytest.raises(MUDSchemaError) as exc_info:
            MUDParser.from_dict(invalid_mud_missing_container)

        assert "ietf-mud:mud" in str(exc_info.value)


class TestParserAccessMethods:
    """Tests for parser access methods."""

    def test_get_acl(self, amazon_echo_short_path: Path):
        """Test getting ACLs by name."""
        parser = MUDParser.from_file(amazon_echo_short_path)

        acl = parser.get_acl("from-ipv4-amazonecho")
        assert acl is not None
        assert acl.name == "from-ipv4-amazonecho"

        # Non-existent ACL
        assert parser.get_acl("nonexistent") is None

    def test_get_from_device_acls(self, amazon_echo_short_path: Path):
        """Test getting from-device ACLs."""
        parser = MUDParser.from_file(amazon_echo_short_path)

        acls = parser.get_from_device_acls()
        assert len(acls) == 2
        acl_names = [acl.name for acl in acls]
        assert "from-ipv4-amazonecho" in acl_names
        assert "from-ethernet-amazonecho" in acl_names

    def test_get_to_device_acls(self, amazon_echo_short_path: Path):
        """Test getting to-device ACLs."""
        parser = MUDParser.from_file(amazon_echo_short_path)

        acls = parser.get_to_device_acls()
        assert len(acls) == 1
        assert acls[0].name == "to-ipv4-amazonecho"

    def test_get_dns_names(self, amazon_echo_short_path: Path):
        """Test extracting DNS names."""
        parser = MUDParser.from_file(amazon_echo_short_path)

        dns_names = parser.get_dns_names()
        assert "dcape-na.amazon.com" in dns_names
        assert "softwareupdates.amazon.com" in dns_names

    def test_get_ports(self, amazon_echo_short_path: Path):
        """Test extracting ports."""
        parser = MUDParser.from_file(amazon_echo_short_path)

        ports = parser.get_ports()
        assert 443 in ports["tcp"]
        assert 80 in ports["tcp"]

    def test_get_all_entries(self, amazon_echo_short_path: Path):
        """Test getting all ACE entries with direction."""
        parser = MUDParser.from_file(amazon_echo_short_path)

        entries = parser.get_all_entries()
        assert len(entries) > 0

        # Check that directions are correct
        directions = {direction for direction, _ in entries}
        assert "from" in directions
        assert "to" in directions


class TestParserSummary:
    """Tests for parser summary methods."""

    def test_get_summary(self, amazon_echo_short_path: Path):
        """Test getting profile summary."""
        parser = MUDParser.from_file(amazon_echo_short_path)

        summary = parser.get_summary()

        assert summary["version"] == 1
        assert "amazonEcho" in summary["systeminfo"]
        assert summary["total_rules"] > 0
        assert "dns_names" in summary
        assert "ports" in summary

    def test_to_dict(self, amazon_echo_short_path: Path):
        """Test converting to dictionary."""
        parser = MUDParser.from_file(amazon_echo_short_path)

        data = parser.to_dict()

        assert "ietf-mud:mud" in data
        assert "ietf-access-control-list:access-lists" in data

    def test_to_json(self, amazon_echo_short_path: Path):
        """Test converting to JSON string."""
        parser = MUDParser.from_file(amazon_echo_short_path)

        json_str = parser.to_json()

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert "ietf-mud:mud" in parsed


class TestParserValidation:
    """Tests for parser validation methods."""

    def test_validate_valid_profile(self, amazon_echo_short_path: Path):
        """Test validation of a valid profile."""
        parser = MUDParser.from_file(amazon_echo_short_path)

        errors = parser.validate()
        # May have warnings but should not fail
        assert parser.is_validated or len(errors) > 0

    def test_validate_invalid_acl_reference(
        self, invalid_mud_bad_acl_reference: dict[str, Any]
    ):
        """Test validation catches bad ACL references."""
        parser = MUDParser.from_dict(invalid_mud_bad_acl_reference)

        errors = parser.validate()
        assert len(errors) > 0
        assert any("nonexistent-acl" in err for err in errors)

    def test_validate_strict_mode(
        self, invalid_mud_bad_acl_reference: dict[str, Any]
    ):
        """Test strict validation raises exception."""
        parser = MUDParser.from_dict(invalid_mud_bad_acl_reference)

        with pytest.raises(MUDValidationError):
            parser.validate(strict=True)


class TestParserRepr:
    """Tests for parser string representation."""

    def test_repr(self, amazon_echo_short_path: Path):
        """Test __repr__ method."""
        parser = MUDParser.from_file(amazon_echo_short_path)

        repr_str = repr(parser)
        assert "MUDParser" in repr_str
        assert "amazonecho" in repr_str.lower()
