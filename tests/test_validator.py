"""
Tests for the MUD validator.
"""

from __future__ import annotations

from typing import Any

import pytest

from mudparser.models import MUDProfile
from mudparser.validator import (
    MUDValidator,
    ValidationResult,
    ValidationSeverity,
    validate_json,
    validate_profile,
)


class TestMUDValidator:
    """Tests for MUDValidator class."""

    def test_validate_valid_profile(self, amazon_echo_short_data: dict[str, Any]):
        """Test validation of a valid profile."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        validator = MUDValidator()

        result = validator.validate(profile)

        # Profile should be valid (may have info/warnings)
        errors = [i for i in result.issues if i.severity == ValidationSeverity.ERROR]
        assert len(errors) == 0

    def test_validate_minimal_profile(self, minimal_mud_data: dict[str, Any]):
        """Test validation of minimal valid profile."""
        profile = MUDProfile.from_json(minimal_mud_data)
        validator = MUDValidator()

        result = validator.validate(profile)
        assert result.is_valid

    def test_validate_missing_acl_reference(
        self, invalid_mud_bad_acl_reference: dict[str, Any]
    ):
        """Test detection of missing ACL references."""
        profile = MUDProfile.from_json(invalid_mud_bad_acl_reference)
        validator = MUDValidator()

        result = validator.validate(profile)

        assert not result.is_valid
        assert result.error_count > 0

        # Check for specific error
        error_messages = [e.message for e in result.errors]
        assert any("nonexistent-acl" in msg for msg in error_messages)

    def test_strict_mode(self, minimal_mud_data: dict[str, Any]):
        """Test strict mode treats warnings as errors."""
        # Modify to create warnings (e.g., no mfg-name)
        profile = MUDProfile.from_json(minimal_mud_data)

        strict_validator = MUDValidator(strict=True)
        result = strict_validator.validate(profile)

        # In strict mode, any issue (including INFO) makes it invalid
        # If there are INFO issues, is_valid should be False
        if result.issues:
            assert not result.is_valid


class TestValidationResult:
    """Tests for ValidationResult class."""

    def test_errors_property(self, invalid_mud_bad_acl_reference: dict[str, Any]):
        """Test errors property filters correctly."""
        profile = MUDProfile.from_json(invalid_mud_bad_acl_reference)
        validator = MUDValidator()

        result = validator.validate(profile)

        errors = result.errors
        for error in errors:
            assert error.severity == ValidationSeverity.ERROR

    def test_warnings_property(self, amazon_echo_short_data: dict[str, Any]):
        """Test warnings property filters correctly."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        validator = MUDValidator()

        result = validator.validate(profile)

        warnings = result.warnings
        for warning in warnings:
            assert warning.severity == ValidationSeverity.WARNING

    def test_to_dict(self, amazon_echo_short_data: dict[str, Any]):
        """Test to_dict method."""
        profile = MUDProfile.from_json(amazon_echo_short_data)
        validator = MUDValidator()

        result = validator.validate(profile)
        result_dict = result.to_dict()

        assert "is_valid" in result_dict
        assert "error_count" in result_dict
        assert "warning_count" in result_dict
        assert "issues" in result_dict


class TestValidationChecks:
    """Tests for specific validation checks."""

    def test_validate_mud_version(self):
        """Test MUD version validation."""
        data = {
            "ietf-mud:mud": {
                "mud-version": 2,  # Invalid - only version 1 supported
                "mud-url": "https://example.com/device.json",
                "last-update": "2024-01-01T00:00:00Z",
                "cache-validity": 48,
                "is-supported": True,
                "from-device-policy": {
                    "access-lists": {"access-list": []}
                },
                "to-device-policy": {
                    "access-lists": {"access-list": []}
                },
            },
            "ietf-access-control-list:access-lists": {"acl": []},
        }

        # Should fail during parsing due to Pydantic validation
        with pytest.raises(Exception):  # Could be ValueError or MUDValidationError
            MUDProfile.from_json(data)

    def test_validate_cache_validity_range(self):
        """Test cache validity range validation."""
        data = {
            "ietf-mud:mud": {
                "mud-version": 1,
                "mud-url": "https://example.com/device.json",
                "last-update": "2024-01-01T00:00:00Z",
                "cache-validity": 200,  # Invalid - max is 168
                "is-supported": True,
                "from-device-policy": {
                    "access-lists": {"access-list": []}
                },
                "to-device-policy": {
                    "access-lists": {"access-list": []}
                },
            },
            "ietf-access-control-list:access-lists": {"acl": []},
        }

        # Should fail during parsing due to Pydantic validation
        with pytest.raises(Exception):
            MUDProfile.from_json(data)

    def test_validate_http_url_warning(self, minimal_mud_data: dict[str, Any]):
        """Test warning for HTTP (non-HTTPS) MUD URL."""
        # Modify URL to use HTTP
        minimal_mud_data["ietf-mud:mud"]["mud-url"] = "http://example.com/device.json"

        profile = MUDProfile.from_json(minimal_mud_data)
        validator = MUDValidator()

        result = validator.validate(profile)

        # Should have a warning about HTTP URL
        warnings = [w for w in result.warnings if "HTTP" in w.message.upper()]
        assert len(warnings) > 0

    def test_validate_unreferenced_acl(self, minimal_mud_data: dict[str, Any]):
        """Test warning for unreferenced ACLs."""
        # Add an ACL that isn't referenced by any policy
        minimal_mud_data["ietf-access-control-list:access-lists"]["acl"].append({
            "name": "orphan-acl",
            "type": "ipv4-acl-type",
            "aces": {"ace": []},
        })

        profile = MUDProfile.from_json(minimal_mud_data)
        validator = MUDValidator()

        result = validator.validate(profile)

        # Should have a warning about unreferenced ACL
        warnings = [w for w in result.warnings if "orphan-acl" in w.message]
        assert len(warnings) > 0


class TestConvenienceFunctions:
    """Tests for convenience validation functions."""

    def test_validate_profile_function(self, amazon_echo_short_data: dict[str, Any]):
        """Test validate_profile convenience function."""
        profile = MUDProfile.from_json(amazon_echo_short_data)

        result = validate_profile(profile)
        assert isinstance(result, ValidationResult)

    def test_validate_json_function(self, amazon_echo_short_data: dict[str, Any]):
        """Test validate_json convenience function."""
        result = validate_json(amazon_echo_short_data)
        assert isinstance(result, ValidationResult)

    def test_validate_json_missing_container(
        self, invalid_mud_missing_container: dict[str, Any]
    ):
        """Test validate_json with missing container."""
        result = validate_json(invalid_mud_missing_container)

        assert not result.is_valid
        assert result.error_count > 0
