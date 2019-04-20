"""
MUD Profile models.

This module defines Pydantic models for the MUD (Manufacturer Usage Description)
container and related structures as specified in RFC 8520.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    field_validator,
)

from mudparser.models.acl import AccessControlList


class AccessListReference(BaseModel):
    """
    Reference to an Access Control List by name.

    Used in policy definitions to reference ACLs defined in the
    access-lists container.

    Attributes:
        name: The name of the referenced ACL.
    """

    model_config = ConfigDict(populate_by_name=True)

    name: str


class AccessListsContainer(BaseModel):
    """Container for ACL references in a policy."""

    model_config = ConfigDict(populate_by_name=True)

    access_list: list[AccessListReference] = Field(
        default_factory=list, alias="access-list"
    )


class PolicyReference(BaseModel):
    """
    Policy container referencing access lists.

    A policy groups related ACLs together for a specific direction
    (from-device or to-device).

    Attributes:
        access_lists: Container holding the list of ACL references.
    """

    model_config = ConfigDict(populate_by_name=True)

    access_lists: AccessListsContainer = Field(alias="access-lists")

    @property
    def acl_names(self) -> list[str]:
        """Get the list of ACL names referenced by this policy."""
        return [ref.name for ref in self.access_lists.access_list]


class MUDContainer(BaseModel):
    """
    The main MUD container with metadata and policy references.

    This represents the 'ietf-mud:mud' container in a MUD profile,
    containing device metadata and references to access control policies.

    Attributes:
        mud_version: MUD specification version (currently 1).
        mud_url: The canonical URL for this MUD file.
        last_update: Timestamp of last modification.
        cache_validity: Hours before the MUD file should be refreshed (1-168).
        is_supported: Whether the manufacturer still supports this device.
        systeminfo: Human-readable device description (max 60 chars).
        mfg_name: Manufacturer name.
        model_name: Device model name.
        firmware_rev: Firmware revision.
        software_rev: Software revision.
        documentation: URL to device documentation.
        extensions: List of extension names used in this profile.
        from_device_policy: Policy for outbound (device-initiated) traffic.
        to_device_policy: Policy for inbound (to-device) traffic.
    """

    model_config = ConfigDict(populate_by_name=True)

    mud_version: int = Field(alias="mud-version", ge=1)
    mud_url: HttpUrl = Field(alias="mud-url")
    last_update: datetime = Field(alias="last-update")
    cache_validity: int = Field(default=48, alias="cache-validity", ge=1, le=168)
    is_supported: bool = Field(alias="is-supported")
    systeminfo: str | None = Field(None, max_length=60)
    mfg_name: str | None = Field(None, alias="mfg-name")
    model_name: str | None = Field(None, alias="model-name")
    firmware_rev: str | None = Field(None, alias="firmware-rev")
    software_rev: str | None = Field(None, alias="software-rev")
    documentation: HttpUrl | None = None
    extensions: list[str] = Field(default_factory=list)
    from_device_policy: PolicyReference = Field(alias="from-device-policy")
    to_device_policy: PolicyReference = Field(alias="to-device-policy")

    @field_validator("mud_version")
    @classmethod
    def validate_version(cls, v: int) -> int:
        """Validate that the MUD version is supported."""
        if v != 1:
            raise ValueError(f"Unsupported MUD version: {v}. Only version 1 is supported.")
        return v


class ACLsContainer(BaseModel):
    """
    Container for Access Control Lists.

    This represents the 'ietf-access-control-list:access-lists' container.

    Attributes:
        acl: List of Access Control Lists.
    """

    model_config = ConfigDict(populate_by_name=True)

    acl: list[AccessControlList] = Field(default_factory=list)


class MUDProfile(BaseModel):
    """
    A complete MUD Profile.

    This is the root model representing an entire MUD file, containing
    both the MUD metadata container and the ACL definitions.

    Attributes:
        mud: The MUD container with metadata and policy references.
        acls: The container holding all ACL definitions.
    """

    model_config = ConfigDict(populate_by_name=True)

    mud: MUDContainer = Field(alias="ietf-mud:mud")
    acls: ACLsContainer = Field(alias="ietf-access-control-list:access-lists")

    # Cached resolved policies
    _from_device_acls: list[AccessControlList] | None = None
    _to_device_acls: list[AccessControlList] | None = None

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "MUDProfile":
        """Create a MUDProfile from JSON data."""
        # Parse ACLs
        acls_data = data.get("ietf-access-control-list:access-lists", {})
        acl_list = [AccessControlList.from_json(acl) for acl in acls_data.get("acl", [])]

        # Parse MUD container
        mud_data = data.get("ietf-mud:mud", {})

        return cls(
            mud=MUDContainer(**mud_data),
            acls=ACLsContainer(acl=acl_list),
        )

    @property
    def version(self) -> int:
        """Get the MUD version."""
        return self.mud.mud_version

    @property
    def url(self) -> str:
        """Get the MUD URL."""
        return str(self.mud.mud_url)

    @property
    def last_update(self) -> datetime:
        """Get the last update timestamp."""
        return self.mud.last_update

    @property
    def cache_validity(self) -> int:
        """Get the cache validity in hours."""
        return self.mud.cache_validity

    @property
    def is_supported(self) -> bool:
        """Check if the device is still supported."""
        return self.mud.is_supported

    @property
    def systeminfo(self) -> str | None:
        """Get the system info string."""
        return self.mud.systeminfo

    def get_acl(self, name: str) -> AccessControlList | None:
        """
        Get an ACL by name.

        Args:
            name: The ACL name to look up.

        Returns:
            The ACL if found, None otherwise.
        """
        for acl in self.acls.acl:
            if acl.name == name:
                return acl
        return None

    def get_from_device_acls(self) -> list[AccessControlList]:
        """
        Get all ACLs referenced by the from-device policy.

        Returns:
            List of ACLs for outbound traffic control.
        """
        if self._from_device_acls is None:
            self._from_device_acls = self._resolve_policy_acls(
                self.mud.from_device_policy
            )
        return self._from_device_acls

    def get_to_device_acls(self) -> list[AccessControlList]:
        """
        Get all ACLs referenced by the to-device policy.

        Returns:
            List of ACLs for inbound traffic control.
        """
        if self._to_device_acls is None:
            self._to_device_acls = self._resolve_policy_acls(
                self.mud.to_device_policy
            )
        return self._to_device_acls

    def _resolve_policy_acls(self, policy: PolicyReference) -> list[AccessControlList]:
        """Resolve ACL references in a policy to actual ACL objects."""
        resolved: list[AccessControlList] = []
        for acl_name in policy.acl_names:
            acl = self.get_acl(acl_name)
            if acl:
                resolved.append(acl)
        return resolved

    def get_acl_direction(self, acl_name: str) -> str | None:
        """
        Determine which policy direction an ACL belongs to.

        Args:
            acl_name: The name of the ACL.

        Returns:
            'from' for from-device, 'to' for to-device, None if not found.
        """
        if acl_name in self.mud.from_device_policy.acl_names:
            return "from"
        if acl_name in self.mud.to_device_policy.acl_names:
            return "to"
        return None

    def print_rules(self) -> str:
        """
        Generate a human-readable representation of all rules.

        Returns:
            Multi-line string with all rules organized by direction.
        """
        lines: list[str] = [
            "=" * 60,
            f"MUD Profile: {self.mud.systeminfo or 'Unknown Device'}",
            f"URL: {self.url}",
            f"Version: {self.version}",
            f"Last Update: {self.last_update}",
            f"Supported: {self.is_supported}",
            "=" * 60,
            "",
            "### FROM-DEVICE POLICY (Outbound) ###",
            "",
        ]

        for acl in self.get_from_device_acls():
            lines.append(acl.print_rules("from"))
            lines.append("")

        lines.extend([
            "### TO-DEVICE POLICY (Inbound) ###",
            "",
        ])

        for acl in self.get_to_device_acls():
            lines.append(acl.print_rules("to"))
            lines.append("")

        return "\n".join(lines)

    def get_all_dns_names(self) -> set[str]:
        """
        Get all DNS names referenced in the profile.

        Returns:
            Set of all DNS names used in match conditions.
        """
        dns_names: set[str] = set()

        for acl in self.acls.acl:
            for entry in acl.entries:
                names = entry.matches.get_dns_names()
                if names["src"]:
                    dns_names.add(names["src"])
                if names["dst"]:
                    dns_names.add(names["dst"])

        return dns_names

    def get_all_ports(self) -> dict[str, set[int]]:
        """
        Get all ports referenced in the profile.

        Returns:
            Dictionary with 'tcp' and 'udp' keys containing port sets.
        """
        ports: dict[str, set[int]] = {"tcp": set(), "udp": set()}

        for acl in self.acls.acl:
            for entry in acl.entries:
                if entry.matches.tcp:
                    if entry.matches.tcp.src_port:
                        ports["tcp"].add(entry.matches.tcp.src_port.port)
                    if entry.matches.tcp.dst_port:
                        ports["tcp"].add(entry.matches.tcp.dst_port.port)
                if entry.matches.udp:
                    if entry.matches.udp.src_port:
                        ports["udp"].add(entry.matches.udp.src_port.port)
                    if entry.matches.udp.dst_port:
                        ports["udp"].add(entry.matches.udp.dst_port.port)

        return ports

    def to_dict(self) -> dict[str, Any]:
        """Convert the profile to a dictionary representation."""
        return {
            "ietf-mud:mud": self.mud.model_dump(by_alias=True, exclude_none=True),
            "ietf-access-control-list:access-lists": {
                "acl": [acl.to_dict() for acl in self.acls.acl]
            },
        }
