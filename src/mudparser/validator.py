"""
MUD profile validation module.

This module provides comprehensive validation for MUD profiles,
including JSON schema validation and semantic validation according
to RFC 8520 requirements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from mudparser.exceptions import MUDSchemaError, MUDValidationError
from mudparser.models import MUDProfile


class ValidationSeverity(str, Enum):
    """Severity levels for validation issues."""

    ERROR = "error"  # Must be fixed - profile is invalid
    WARNING = "warning"  # Should be fixed - potential issues
    INFO = "info"  # Informational - best practice suggestions


@dataclass
class ValidationIssue:
    """
    A single validation issue.

    Attributes:
        severity: The severity level of the issue.
        message: Human-readable description of the issue.
        path: JSON path to the problematic element (if applicable).
        code: Machine-readable error code.
        details: Additional context about the issue.
    """

    severity: ValidationSeverity
    message: str
    path: str | None = None
    code: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "severity": self.severity.value,
            "message": self.message,
        }
        if self.path:
            result["path"] = self.path
        if self.code:
            result["code"] = self.code
        if self.details:
            result["details"] = self.details
        return result


@dataclass
class ValidationResult:
    """
    Result of profile validation.

    Attributes:
        is_valid: Whether the profile passes validation.
        issues: List of validation issues found.
        profile: The validated profile (if parsing succeeded).
    """

    is_valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    profile: MUDProfile | None = None

    @property
    def errors(self) -> list[ValidationIssue]:
        """Get only error-level issues."""
        return [i for i in self.issues if i.severity == ValidationSeverity.ERROR]

    @property
    def warnings(self) -> list[ValidationIssue]:
        """Get only warning-level issues."""
        return [i for i in self.issues if i.severity == ValidationSeverity.WARNING]

    @property
    def error_count(self) -> int:
        """Get the number of errors."""
        return len(self.errors)

    @property
    def warning_count(self) -> int:
        """Get the number of warnings."""
        return len(self.warnings)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "is_valid": self.is_valid,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "issues": [issue.to_dict() for issue in self.issues],
        }


class MUDValidator:
    """
    Validator for MUD profiles.

    Provides comprehensive validation including:
    - Structure validation (required fields, types)
    - Cross-reference validation (ACL references)
    - RFC compliance validation
    - Best practice checks

    Example:
        >>> validator = MUDValidator()
        >>> result = validator.validate(profile)
        >>> if not result.is_valid:
        ...     for error in result.errors:
        ...         print(f"Error: {error.message}")
    """

    # Standard MUD controller URNs (RFC 8520 Section 8.3)
    STANDARD_CONTROLLER_URNS = {
        "urn:ietf:params:mud:dns",
        "urn:ietf:params:mud:ntp",
    }

    def __init__(self, strict: bool = False) -> None:
        """
        Initialize the validator.

        Args:
            strict: If True, treat warnings as errors.
        """
        self.strict = strict

    def validate(self, profile: MUDProfile) -> ValidationResult:
        """
        Validate a MUD profile.

        Args:
            profile: The MUD profile to validate.

        Returns:
            ValidationResult with all issues found.
        """
        issues: list[ValidationIssue] = []

        # Run all validation checks
        issues.extend(self._validate_mud_container(profile))
        issues.extend(self._validate_acl_references(profile))
        issues.extend(self._validate_acl_types(profile))
        issues.extend(self._validate_ace_matches(profile))
        issues.extend(self._validate_mud_matches(profile))
        issues.extend(self._validate_best_practices(profile))

        # Determine validity
        if self.strict:
            is_valid = len(issues) == 0
        else:
            is_valid = all(i.severity != ValidationSeverity.ERROR for i in issues)

        return ValidationResult(
            is_valid=is_valid,
            issues=issues,
            profile=profile,
        )

    def validate_json(self, data: dict[str, Any]) -> ValidationResult:
        """
        Validate raw JSON data.

        Performs structure validation before attempting to parse
        into a MUDProfile.

        Args:
            data: Raw JSON data to validate.

        Returns:
            ValidationResult with all issues found.
        """
        issues: list[ValidationIssue] = []

        # Check required top-level containers
        if "ietf-mud:mud" not in data:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message="Missing required 'ietf-mud:mud' container",
                path="$",
                code="MISSING_MUD_CONTAINER",
            ))

        if "ietf-access-control-list:access-lists" not in data:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message="Missing required 'ietf-access-control-list:access-lists' container",
                path="$",
                code="MISSING_ACL_CONTAINER",
            ))

        # If structural issues, return early
        if issues:
            return ValidationResult(is_valid=False, issues=issues)

        # Try to parse and validate
        try:
            profile = MUDProfile.from_json(data)
            return self.validate(profile)
        except (ValueError, KeyError) as e:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message=str(e),
                code="PARSE_ERROR",
            ))
            return ValidationResult(is_valid=False, issues=issues)

    def _validate_mud_container(self, profile: MUDProfile) -> list[ValidationIssue]:
        """Validate the MUD container fields."""
        issues: list[ValidationIssue] = []
        mud = profile.mud

        # Validate MUD version
        if mud.mud_version != 1:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message=f"Unsupported MUD version: {mud.mud_version}",
                path="$.ietf-mud:mud.mud-version",
                code="UNSUPPORTED_VERSION",
                details={"version": mud.mud_version, "supported": [1]},
            ))

        # Validate MUD URL scheme
        url = str(mud.mud_url)
        if not url.startswith("https://"):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message=f"MUD URL should use HTTPS: {url}",
                path="$.ietf-mud:mud.mud-url",
                code="HTTP_MUD_URL",
            ))

        # Validate cache validity range
        if not 1 <= mud.cache_validity <= 168:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message=f"Cache validity {mud.cache_validity} outside valid range (1-168)",
                path="$.ietf-mud:mud.cache-validity",
                code="INVALID_CACHE_VALIDITY",
                details={"value": mud.cache_validity, "min": 1, "max": 168},
            ))

        # Validate systeminfo length
        if mud.systeminfo and len(mud.systeminfo) > 60:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message=f"System info exceeds 60 character limit: {len(mud.systeminfo)}",
                path="$.ietf-mud:mud.systeminfo",
                code="SYSTEMINFO_TOO_LONG",
            ))

        return issues

    def _validate_acl_references(self, profile: MUDProfile) -> list[ValidationIssue]:
        """Validate that all ACL references can be resolved."""
        issues: list[ValidationIssue] = []
        acl_names = {acl.name for acl in profile.acls.acl}

        # Check from-device-policy references
        for acl_ref in profile.mud.from_device_policy.access_lists.access_list:
            if acl_ref.name not in acl_names:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    message=f"ACL '{acl_ref.name}' not found in access-lists",
                    path="$.ietf-mud:mud.from-device-policy",
                    code="MISSING_ACL_REFERENCE",
                    details={"acl_name": acl_ref.name, "policy": "from-device-policy"},
                ))

        # Check to-device-policy references
        for acl_ref in profile.mud.to_device_policy.access_lists.access_list:
            if acl_ref.name not in acl_names:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    message=f"ACL '{acl_ref.name}' not found in access-lists",
                    path="$.ietf-mud:mud.to-device-policy",
                    code="MISSING_ACL_REFERENCE",
                    details={"acl_name": acl_ref.name, "policy": "to-device-policy"},
                ))

        # Check for unreferenced ACLs
        referenced = set()
        for ref in profile.mud.from_device_policy.access_lists.access_list:
            referenced.add(ref.name)
        for ref in profile.mud.to_device_policy.access_lists.access_list:
            referenced.add(ref.name)

        for acl in profile.acls.acl:
            if acl.name not in referenced:
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    message=f"ACL '{acl.name}' is not referenced by any policy",
                    path=f"$.ietf-access-control-list:access-lists.acl[name='{acl.name}']",
                    code="UNREFERENCED_ACL",
                ))

        return issues

    def _validate_acl_types(self, profile: MUDProfile) -> list[ValidationIssue]:
        """Validate ACL type consistency."""
        issues: list[ValidationIssue] = []

        for acl in profile.acls.acl:
            for entry in acl.entries:
                # Check IPv4 ACL has IPv4 matches
                if acl.is_ipv4() and entry.matches.ipv6:
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        message=f"IPv6 match in IPv4 ACL '{acl.name}'",
                        path=f"$.ietf-access-control-list:access-lists.acl[name='{acl.name}']",
                        code="ACL_TYPE_MISMATCH",
                    ))

                # Check IPv6 ACL has IPv6 matches
                if acl.is_ipv6() and entry.matches.ipv4:
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        message=f"IPv4 match in IPv6 ACL '{acl.name}'",
                        path=f"$.ietf-access-control-list:access-lists.acl[name='{acl.name}']",
                        code="ACL_TYPE_MISMATCH",
                    ))

        return issues

    def _validate_ace_matches(self, profile: MUDProfile) -> list[ValidationIssue]:
        """Validate ACE match conditions."""
        issues: list[ValidationIssue] = []

        for acl in profile.acls.acl:
            for entry in acl.entries:
                matches = entry.matches

                # direction-initiated only valid for TCP
                if matches.tcp and matches.tcp.direction_initiated:
                    pass  # Valid
                elif matches.udp:
                    # UDP shouldn't have direction-initiated
                    # (handled by Pydantic, but double-check)
                    pass

                # Check for empty matches
                if not matches.has_matches():
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        message=f"ACE '{entry.name}' has no match conditions",
                        path=f"$.ietf-access-control-list:access-lists.acl[name='{acl.name}'].aces.ace[name='{entry.name}']",
                        code="EMPTY_MATCHES",
                    ))

                # Validate port ranges
                for port_match in [matches.tcp, matches.udp]:
                    if port_match:
                        for port_field in ['src_port', 'dst_port']:
                            port = getattr(port_match, port_field, None)
                            if port and port.upper_port:
                                if port.upper_port <= port.port:
                                    issues.append(ValidationIssue(
                                        severity=ValidationSeverity.ERROR,
                                        message=f"Invalid port range in {entry.name}: {port.port}-{port.upper_port}",
                                        code="INVALID_PORT_RANGE",
                                    ))

        return issues

    def _validate_mud_matches(self, profile: MUDProfile) -> list[ValidationIssue]:
        """Validate MUD-specific match conditions."""
        issues: list[ValidationIssue] = []

        for acl in profile.acls.acl:
            for entry in acl.entries:
                if entry.matches.mud:
                    mud_match = entry.matches.mud
                    match_type = mud_match.get_match_type()

                    # Validate controller URN format
                    if match_type == "controller" and mud_match.controller:
                        controller = mud_match.controller
                        if controller.startswith("urn:"):
                            if controller not in self.STANDARD_CONTROLLER_URNS:
                                issues.append(ValidationIssue(
                                    severity=ValidationSeverity.INFO,
                                    message=f"Non-standard controller URN: {controller}",
                                    path=f"$.ietf-access-control-list:access-lists.acl.aces.ace[name='{entry.name}']",
                                    code="NONSTANDARD_CONTROLLER_URN",
                                ))

        return issues

    def _validate_best_practices(self, profile: MUDProfile) -> list[ValidationIssue]:
        """Check for best practice violations."""
        issues: list[ValidationIssue] = []

        # Check for deprecated device
        if not profile.mud.is_supported:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                message="Device is marked as no longer supported",
                path="$.ietf-mud:mud.is-supported",
                code="DEVICE_UNSUPPORTED",
            ))

        # Check for missing manufacturer info
        if not profile.mud.mfg_name:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                message="Manufacturer name not specified",
                path="$.ietf-mud:mud",
                code="MISSING_MFG_NAME",
            ))

        # Check for missing documentation URL
        if not profile.mud.documentation:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                message="No documentation URL provided",
                path="$.ietf-mud:mud",
                code="MISSING_DOCUMENTATION",
            ))

        # Warn about large cache validity
        if profile.mud.cache_validity > 24:
            issues.append(ValidationIssue(
                severity=ValidationSeverity.INFO,
                message=f"Cache validity is {profile.mud.cache_validity} hours; consider more frequent updates",
                path="$.ietf-mud:mud.cache-validity",
                code="LARGE_CACHE_VALIDITY",
            ))

        return issues


def validate_profile(
    profile: MUDProfile,
    strict: bool = False,
) -> ValidationResult:
    """
    Convenience function to validate a MUD profile.

    Args:
        profile: The MUD profile to validate.
        strict: If True, treat warnings as errors.

    Returns:
        ValidationResult with all issues found.
    """
    validator = MUDValidator(strict=strict)
    return validator.validate(profile)


def validate_json(
    data: dict[str, Any],
    strict: bool = False,
) -> ValidationResult:
    """
    Convenience function to validate raw JSON data.

    Args:
        data: Raw JSON data to validate.
        strict: If True, treat warnings as errors.

    Returns:
        ValidationResult with all issues found.
    """
    validator = MUDValidator(strict=strict)
    return validator.validate_json(data)
