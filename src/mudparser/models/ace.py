"""
Access Control Entry (ACE) models.

This module defines Pydantic models for Access Control Entries as
specified in RFC 8519 (ACL model) with MUD extensions from RFC 8520.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mudparser.models.matches import ACEMatches


class ForwardingAction(str, Enum):
    """
    Forwarding actions for ACL entries.

    As defined in RFC 8519, these are the actions that can be taken
    when traffic matches an ACE.
    """

    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"  # Interpreted as drop by MUD managers


class ACEActions(BaseModel):
    """
    Actions to take when an ACE matches.

    Attributes:
        forwarding: The forwarding decision (accept, drop, reject).
        logging: Whether to log matching traffic.
    """

    model_config = ConfigDict(populate_by_name=True)

    forwarding: ForwardingAction
    logging: bool | None = None


class AccessControlEntry(BaseModel):
    """
    A single Access Control Entry (ACE).

    An ACE defines a rule consisting of:
    - Match conditions (what traffic to match)
    - Actions (what to do with matched traffic)

    Attributes:
        name: Unique identifier for this ACE within its ACL.
        matches: The match conditions for this entry.
        actions: The actions to take when matched.
        statistics: Optional statistics about rule hits (read-only).
    """

    model_config = ConfigDict(populate_by_name=True)

    name: str
    matches: ACEMatches
    actions: ACEActions
    statistics: dict[str, Any] | None = None

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "AccessControlEntry":
        """Create an ACE from JSON data."""
        return cls(
            name=data["name"],
            matches=ACEMatches.from_json(data.get("matches", {})),
            actions=ACEActions(**data.get("actions", {})),
            statistics=data.get("statistics"),
        )

    def is_accept(self) -> bool:
        """Check if this ACE allows traffic."""
        return self.actions.forwarding == ForwardingAction.ACCEPT

    def is_deny(self) -> bool:
        """Check if this ACE denies traffic."""
        return self.actions.forwarding in (ForwardingAction.DROP, ForwardingAction.REJECT)

    def get_description(self, direction: str = "from") -> str:
        """
        Generate a human-readable description of this ACE.

        Args:
            direction: Traffic direction ('from' or 'to' device).

        Returns:
            Human-readable rule description.
        """
        parts: list[str] = []

        # Action
        action = "ALLOW" if self.is_accept() else "DENY"
        parts.append(f"[{direction.upper()}] {action}")

        # Protocol
        protocol = self._get_protocol_name()
        if protocol:
            parts.append(protocol)

        # DNS names
        dns_names = self.matches.get_dns_names()
        if direction == "from":
            if dns_names["dst"]:
                parts.append(f"to {dns_names['dst']}")
        else:
            if dns_names["src"]:
                parts.append(f"from {dns_names['src']}")

        # Ports
        port_info = self._get_port_info(direction)
        if port_info:
            parts.append(port_info)

        # MUD matches
        if self.matches.mud:
            mud_type = self.matches.mud.get_match_type()
            if mud_type:
                parts.append(f"({mud_type})")

        # Ethernet
        if self.matches.eth and self.matches.eth.ethertype:
            parts.append(f"ethertype {self.matches.eth.ethertype}")

        return " ".join(parts)

    def _get_protocol_name(self) -> str | None:
        """Get the protocol name from matches."""
        proto = self.matches.get_protocol()
        if proto is not None:
            protocol_map = {
                1: "ICMP",
                6: "TCP",
                17: "UDP",
                58: "ICMPv6",
            }
            return protocol_map.get(proto, f"proto:{proto}")

        # Check for L4 matches
        if self.matches.tcp:
            return "TCP"
        if self.matches.udp:
            return "UDP"
        if self.matches.icmp:
            return "ICMP"

        return None

    def _get_port_info(self, direction: str) -> str | None:
        """Get port information from matches."""
        if self.matches.tcp:
            if direction == "from" and self.matches.tcp.dst_port:
                return f"port {self.matches.tcp.dst_port}"
            elif direction == "to" and self.matches.tcp.src_port:
                return f"port {self.matches.tcp.src_port}"

        if self.matches.udp:
            if direction == "from" and self.matches.udp.dst_port:
                return f"port {self.matches.udp.dst_port}"
            elif direction == "to" and self.matches.udp.src_port:
                return f"port {self.matches.udp.src_port}"

        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert ACE to dictionary representation."""
        return {
            "name": self.name,
            "matches": self.matches.model_dump(by_alias=True, exclude_none=True),
            "actions": self.actions.model_dump(by_alias=True, exclude_none=True),
        }
