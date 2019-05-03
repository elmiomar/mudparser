"""
Main parser module for MUD profiles.

This module provides the MUDParser class, the primary interface for
parsing, validating, and working with MUD profiles.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, TextIO

import httpx

from mudparser.exceptions import (
    MUDFileNotFoundError,
    MUDNetworkError,
    MUDParserError,
    MUDSchemaError,
    MUDValidationError,
)
from mudparser.models import (
    AccessControlEntry,
    AccessControlList,
    MUDProfile,
)

if TYPE_CHECKING:
    from mudparser.exporters import MUDExporter


class MUDParser:
    """
    Main parser class for MUD profiles.

    This class provides a unified interface for parsing MUD profiles from
    various sources (files, strings, URLs) and accessing their contents.

    Attributes:
        profile: The parsed MUD profile.
        source: Description of the data source.

    Example:
        >>> parser = MUDParser.from_file("device.mud.json")
        >>> print(parser.profile.mud.systeminfo)
        >>> parser.validate()
        >>> rules = parser.export.to_iptables(device_ip="192.168.1.100")
    """

    def __init__(self, profile: MUDProfile, source: str = "unknown") -> None:
        """
        Initialize the parser with a parsed profile.

        Args:
            profile: The parsed MUD profile.
            source: Description of where the profile came from.
        """
        self._profile = profile
        self._source = source
        self._validated = False
        self._exporter: MUDExporter | None = None

    @property
    def profile(self) -> MUDProfile:
        """Get the parsed MUD profile."""
        return self._profile

    @property
    def mud(self) -> Any:
        """Get the MUD container (shortcut)."""
        return self._profile.mud

    @property
    def source(self) -> str:
        """Get the source description."""
        return self._source

    @property
    def export(self) -> "MUDExporter":
        """Get the exporter for this profile."""
        if self._exporter is None:
            from mudparser.exporters import MUDExporter
            self._exporter = MUDExporter(self._profile)
        return self._exporter

    # =========================================================================
    # Factory Methods
    # =========================================================================

    @classmethod
    def from_file(cls, file_path: str | Path) -> "MUDParser":
        """
        Parse a MUD profile from a file.

        Args:
            file_path: Path to the MUD JSON file.

        Returns:
            MUDParser instance with the parsed profile.

        Raises:
            MUDFileNotFoundError: If the file doesn't exist.
            MUDSchemaError: If the JSON is malformed.
            MUDValidationError: If the profile doesn't conform to the schema.
        """
        path = Path(file_path)

        if not path.exists():
            raise MUDFileNotFoundError(str(path))

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise MUDSchemaError(
                f"Invalid JSON in file: {e}",
                path=str(path),
            ) from e

        profile = cls._parse_json_data(data)
        return cls(profile, source=str(path))

    @classmethod
    def from_string(cls, json_string: str, source: str = "string") -> "MUDParser":
        """
        Parse a MUD profile from a JSON string.

        Args:
            json_string: JSON string containing the MUD profile.
            source: Description of the source for error messages.

        Returns:
            MUDParser instance with the parsed profile.

        Raises:
            MUDSchemaError: If the JSON is malformed.
            MUDValidationError: If the profile doesn't conform to the schema.
        """
        try:
            data = json.loads(json_string)
        except json.JSONDecodeError as e:
            raise MUDSchemaError(f"Invalid JSON string: {e}") from e

        profile = cls._parse_json_data(data)
        return cls(profile, source=source)

    @classmethod
    def from_dict(cls, data: dict[str, Any], source: str = "dict") -> "MUDParser":
        """
        Parse a MUD profile from a dictionary.

        Args:
            data: Dictionary containing the MUD profile data.
            source: Description of the source for error messages.

        Returns:
            MUDParser instance with the parsed profile.

        Raises:
            MUDValidationError: If the profile doesn't conform to the schema.
        """
        profile = cls._parse_json_data(data)
        return cls(profile, source=source)

    @classmethod
    def from_file_object(cls, file_obj: TextIO, source: str = "file") -> "MUDParser":
        """
        Parse a MUD profile from a file object.

        Args:
            file_obj: File-like object to read from.
            source: Description of the source for error messages.

        Returns:
            MUDParser instance with the parsed profile.

        Raises:
            MUDSchemaError: If the JSON is malformed.
            MUDValidationError: If the profile doesn't conform to the schema.
        """
        try:
            data = json.load(file_obj)
        except json.JSONDecodeError as e:
            raise MUDSchemaError(f"Invalid JSON: {e}") from e

        profile = cls._parse_json_data(data)
        return cls(profile, source=source)

    @classmethod
    def from_url(
        cls,
        url: str,
        timeout: float = 30.0,
        verify_ssl: bool = True,
    ) -> "MUDParser":
        """
        Fetch and parse a MUD profile from a URL.

        Args:
            url: URL to fetch the MUD profile from.
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.

        Returns:
            MUDParser instance with the parsed profile.

        Raises:
            MUDNetworkError: If the request fails.
            MUDSchemaError: If the response isn't valid JSON.
            MUDValidationError: If the profile doesn't conform to the schema.
        """
        try:
            response = httpx.get(
                url,
                timeout=timeout,
                verify=verify_ssl,
                follow_redirects=True,
                headers={"Accept": "application/mud+json, application/json"},
            )
            response.raise_for_status()
        except httpx.TimeoutException as e:
            raise MUDNetworkError(f"Request timed out: {e}", url=url) from e
        except httpx.HTTPStatusError as e:
            raise MUDNetworkError(
                f"HTTP error {e.response.status_code}: {e.response.reason_phrase}",
                url=url,
                status_code=e.response.status_code,
            ) from e
        except httpx.RequestError as e:
            raise MUDNetworkError(f"Network error: {e}", url=url) from e

        try:
            data = response.json()
        except json.JSONDecodeError as e:
            raise MUDSchemaError(f"Invalid JSON in response: {e}") from e

        profile = cls._parse_json_data(data)
        return cls(profile, source=url)

    @classmethod
    async def from_url_async(
        cls,
        url: str,
        timeout: float = 30.0,
        verify_ssl: bool = True,
    ) -> "MUDParser":
        """
        Asynchronously fetch and parse a MUD profile from a URL.

        Args:
            url: URL to fetch the MUD profile from.
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.

        Returns:
            MUDParser instance with the parsed profile.

        Raises:
            MUDNetworkError: If the request fails.
            MUDSchemaError: If the response isn't valid JSON.
            MUDValidationError: If the profile doesn't conform to the schema.
        """
        async with httpx.AsyncClient(verify=verify_ssl) as client:
            try:
                response = await client.get(
                    url,
                    timeout=timeout,
                    follow_redirects=True,
                    headers={"Accept": "application/mud+json, application/json"},
                )
                response.raise_for_status()
            except httpx.TimeoutException as e:
                raise MUDNetworkError(f"Request timed out: {e}", url=url) from e
            except httpx.HTTPStatusError as e:
                raise MUDNetworkError(
                    f"HTTP error {e.response.status_code}: {e.response.reason_phrase}",
                    url=url,
                    status_code=e.response.status_code,
                ) from e
            except httpx.RequestError as e:
                raise MUDNetworkError(f"Network error: {e}", url=url) from e

        try:
            data = response.json()
        except json.JSONDecodeError as e:
            raise MUDSchemaError(f"Invalid JSON in response: {e}") from e

        profile = cls._parse_json_data(data)
        return cls(profile, source=url)

    # =========================================================================
    # Parsing Implementation
    # =========================================================================

    @classmethod
    def _parse_json_data(cls, data: dict[str, Any]) -> MUDProfile:
        """
        Parse JSON data into a MUDProfile.

        Args:
            data: Dictionary containing the MUD profile data.

        Returns:
            Parsed MUDProfile instance.

        Raises:
            MUDSchemaError: If required fields are missing.
            MUDValidationError: If validation fails.
        """
        # Check for required top-level keys
        if "ietf-mud:mud" not in data:
            raise MUDSchemaError(
                "Missing required 'ietf-mud:mud' container",
                path="$",
            )

        if "ietf-access-control-list:access-lists" not in data:
            raise MUDSchemaError(
                "Missing required 'ietf-access-control-list:access-lists' container",
                path="$",
            )

        try:
            return MUDProfile.from_json(data)
        except ValueError as e:
            raise MUDValidationError(str(e)) from e
        except KeyError as e:
            raise MUDSchemaError(f"Missing required field: {e}") from e

    # =========================================================================
    # Validation
    # =========================================================================

    def validate(self, strict: bool = False) -> list[str]:
        """
        Validate the MUD profile.

        Performs semantic validation beyond the basic schema checks,
        including cross-reference validation and RFC compliance checks.

        Args:
            strict: If True, raise exception on first error.
                   If False, collect and return all errors.

        Returns:
            List of validation error messages (empty if valid).

        Raises:
            MUDValidationError: If strict=True and validation fails.
        """
        errors: list[str] = []

        # Validate ACL references
        errors.extend(self._validate_acl_references())

        # Validate MUD URL format
        errors.extend(self._validate_mud_url())

        # Validate cache validity
        errors.extend(self._validate_cache_validity())

        # Validate direction-initiated usage
        errors.extend(self._validate_direction_initiated())

        if strict and errors:
            raise MUDValidationError(
                f"Profile validation failed with {len(errors)} error(s)",
                errors=[{"message": e} for e in errors],
            )

        self._validated = len(errors) == 0
        return errors

    def _validate_acl_references(self) -> list[str]:
        """Validate that all ACL references can be resolved."""
        errors: list[str] = []
        acl_names = {acl.name for acl in self._profile.acls.acl}

        for policy_name, policy in [
            ("from-device-policy", self._profile.mud.from_device_policy),
            ("to-device-policy", self._profile.mud.to_device_policy),
        ]:
            for acl_ref in policy.access_lists.access_list:
                if acl_ref.name not in acl_names:
                    errors.append(
                        f"ACL '{acl_ref.name}' referenced in {policy_name} does not exist"
                    )

        return errors

    def _validate_mud_url(self) -> list[str]:
        """Validate the MUD URL format."""
        errors: list[str] = []
        url = str(self._profile.mud.mud_url)

        if not url.startswith("https://"):
            errors.append(
                f"MUD URL should use HTTPS scheme: {url}"
            )

        return errors

    def _validate_cache_validity(self) -> list[str]:
        """Validate cache validity is within RFC bounds."""
        errors: list[str] = []
        validity = self._profile.mud.cache_validity

        if not 1 <= validity <= 168:
            errors.append(
                f"Cache validity {validity} is outside valid range (1-168 hours)"
            )

        return errors

    def _validate_direction_initiated(self) -> list[str]:
        """Validate that direction-initiated is only used with TCP."""
        errors: list[str] = []

        for acl in self._profile.acls.acl:
            for entry in acl.entries:
                if entry.matches.tcp and entry.matches.tcp.direction_initiated:
                    # This is valid - TCP with direction-initiated
                    continue

                # Check if direction-initiated is used without TCP
                if (entry.matches.udp and
                    hasattr(entry.matches.udp, 'direction_initiated') and
                    entry.matches.udp.direction_initiated):
                    errors.append(
                        f"ACE '{entry.name}' uses direction-initiated with UDP "
                        f"(only valid for TCP)"
                    )

        return errors

    @property
    def is_validated(self) -> bool:
        """Check if the profile has been validated."""
        return self._validated

    # =========================================================================
    # Profile Access Methods
    # =========================================================================

    def get_acl(self, name: str) -> AccessControlList | None:
        """
        Get an ACL by name.

        Args:
            name: The ACL name to look up.

        Returns:
            The ACL if found, None otherwise.
        """
        return self._profile.get_acl(name)

    def get_from_device_acls(self) -> list[AccessControlList]:
        """Get all ACLs for outbound (from-device) traffic."""
        return self._profile.get_from_device_acls()

    def get_to_device_acls(self) -> list[AccessControlList]:
        """Get all ACLs for inbound (to-device) traffic."""
        return self._profile.get_to_device_acls()

    def get_all_entries(self) -> list[tuple[str, AccessControlEntry]]:
        """
        Get all ACEs from all ACLs with their direction.

        Returns:
            List of (direction, ACE) tuples.
        """
        entries: list[tuple[str, AccessControlEntry]] = []

        for acl in self.get_from_device_acls():
            for entry in acl.entries:
                entries.append(("from", entry))

        for acl in self.get_to_device_acls():
            for entry in acl.entries:
                entries.append(("to", entry))

        return entries

    def get_dns_names(self) -> set[str]:
        """Get all DNS names referenced in the profile."""
        return self._profile.get_all_dns_names()

    def get_ports(self) -> dict[str, set[int]]:
        """Get all ports referenced in the profile."""
        return self._profile.get_all_ports()

    # =========================================================================
    # Output Methods
    # =========================================================================

    def print_rules(self) -> None:
        """Print all rules in human-readable format."""
        print(self._profile.print_rules())

    def to_dict(self) -> dict[str, Any]:
        """Convert the profile to a dictionary."""
        return self._profile.to_dict()

    def to_json(self, indent: int = 2) -> str:
        """
        Convert the profile to a JSON string.

        Args:
            indent: JSON indentation level.

        Returns:
            JSON string representation.
        """
        return json.dumps(self.to_dict(), indent=indent, default=str)

    # =========================================================================
    # Summary and Information
    # =========================================================================

    def get_summary(self) -> dict[str, Any]:
        """
        Get a summary of the MUD profile.

        Returns:
            Dictionary with profile summary information.
        """
        return {
            "url": str(self._profile.mud.mud_url),
            "version": self._profile.mud.mud_version,
            "systeminfo": self._profile.mud.systeminfo,
            "last_update": self._profile.mud.last_update.isoformat(),
            "cache_validity_hours": self._profile.mud.cache_validity,
            "is_supported": self._profile.mud.is_supported,
            "manufacturer": self._profile.mud.mfg_name,
            "model": self._profile.mud.model_name,
            "total_acls": len(self._profile.acls.acl),
            "from_device_acls": len(self.get_from_device_acls()),
            "to_device_acls": len(self.get_to_device_acls()),
            "from_device_rules": sum(len(acl.entries) for acl in self.get_from_device_acls()),
            "to_device_rules": sum(len(acl.entries) for acl in self.get_to_device_acls()),
            "total_rules": sum(len(acl.entries) for acl in self._profile.acls.acl),
            "dns_names": list(self.get_dns_names()),
            "ports": {k: list(v) for k, v in self.get_ports().items()},
            "source": self._source,
        }

    def __repr__(self) -> str:
        return (
            f"MUDParser(url={self._profile.mud.mud_url!r}, "
            f"systeminfo={self._profile.mud.systeminfo!r}, "
            f"source={self._source!r})"
        )
