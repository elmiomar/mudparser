"""
Access Control List (ACL) models.

This module defines Pydantic models for Access Control Lists as
specified in RFC 8519 (YANG ACL model).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Iterator

from pydantic import BaseModel, ConfigDict, Field

from mudparser.models.ace import AccessControlEntry


class ACLType(str, Enum):
    """
    Types of Access Control Lists.

    As defined in RFC 8519, ACLs can be typed to indicate what
    kind of traffic they apply to.
    """

    IPV4 = "ipv4-acl-type"
    IPV6 = "ipv6-acl-type"
    ETHERNET = "ethernet-acl-type"
    MIXED = "mixed-eth-ipv4-acl-type"
    MIXED_IPV6 = "mixed-eth-ipv6-acl-type"


class ACEs(BaseModel):
    """
    Container for Access Control Entries.

    Attributes:
        ace: List of Access Control Entries in this ACL.
    """

    model_config = ConfigDict(populate_by_name=True)

    ace: list[AccessControlEntry] = Field(default_factory=list)


class AccessControlList(BaseModel):
    """
    An Access Control List containing multiple entries.

    Each ACL has a unique name, a type indicating what kind of traffic
    it applies to, and a list of ACEs (Access Control Entries) that
    define the actual rules.

    Attributes:
        name: Unique identifier for this ACL.
        acl_type: The type of ACL (IPv4, IPv6, Ethernet, etc.).
        aces: Container holding the list of ACEs.
    """

    model_config = ConfigDict(populate_by_name=True)

    name: str
    acl_type: ACLType = Field(alias="type")
    aces: ACEs

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "AccessControlList":
        """Create an ACL from JSON data."""
        aces_data = data.get("aces", {}).get("ace", [])
        entries = [AccessControlEntry.from_json(ace) for ace in aces_data]

        return cls(
            name=data["name"],
            acl_type=ACLType(data["type"]),
            aces=ACEs(ace=entries),
        )

    @property
    def entries(self) -> list[AccessControlEntry]:
        """Get the list of ACEs in this ACL."""
        return self.aces.ace

    def __len__(self) -> int:
        """Return the number of entries in this ACL."""
        return len(self.entries)

    def __iter__(self) -> Iterator[AccessControlEntry]:
        """Iterate over ACEs in this ACL."""
        return iter(self.entries)

    def __getitem__(self, key: str | int) -> AccessControlEntry:
        """Get an ACE by name or index."""
        if isinstance(key, int):
            return self.entries[key]
        for entry in self.entries:
            if entry.name == key:
                return entry
        raise KeyError(f"ACE '{key}' not found in ACL '{self.name}'")

    def get_entry(self, name: str) -> AccessControlEntry | None:
        """Get an ACE by name, returning None if not found."""
        for entry in self.entries:
            if entry.name == name:
                return entry
        return None

    def is_ipv4(self) -> bool:
        """Check if this is an IPv4 ACL."""
        return self.acl_type == ACLType.IPV4

    def is_ipv6(self) -> bool:
        """Check if this is an IPv6 ACL."""
        return self.acl_type == ACLType.IPV6

    def is_ethernet(self) -> bool:
        """Check if this is an Ethernet ACL."""
        return self.acl_type == ACLType.ETHERNET

    def print_rules(self, direction: str = "from") -> str:
        """
        Generate a human-readable representation of all rules.

        Args:
            direction: Traffic direction ('from' or 'to' device).

        Returns:
            Multi-line string with all rules.
        """
        lines: list[str] = [
            f"##### ACL::{self.name}::START #####",
            f"Type: {self.acl_type.value}",
            "",
        ]

        for entry in self.entries:
            lines.append(f"  {entry.get_description(direction)}")

        lines.extend([
            "",
            "(implicit deny all)",
            f"##### ACL::{self.name}::END #####",
        ])

        return "\n".join(lines)

    def get_accept_rules(self) -> list[AccessControlEntry]:
        """Get all ACEs that accept traffic."""
        return [entry for entry in self.entries if entry.is_accept()]

    def get_deny_rules(self) -> list[AccessControlEntry]:
        """Get all ACEs that deny traffic."""
        return [entry for entry in self.entries if entry.is_deny()]

    def to_dict(self) -> dict[str, Any]:
        """Convert ACL to dictionary representation."""
        return {
            "name": self.name,
            "type": self.acl_type.value,
            "aces": {
                "ace": [entry.to_dict() for entry in self.entries]
            },
        }
