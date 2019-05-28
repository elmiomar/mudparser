"""
Cisco IOS ACL exporter.

Exports MUD profiles to Cisco IOS extended access list format.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mudparser.models import MUDProfile, AccessControlEntry, AccessControlList


class CiscoACLExporter:
    """
    Exporter for Cisco IOS extended access lists.

    Generates Cisco IOS ACL configuration that implements the MUD profile's
    access control policies.
    """

    def __init__(self, profile: "MUDProfile") -> None:
        """
        Initialize the exporter.

        Args:
            profile: The MUD profile to export.
        """
        self._profile = profile

    def export(
        self,
        acl_number_start: int = 100,
        include_remarks: bool = True,
    ) -> str:
        """
        Export to Cisco IOS ACL format.

        Args:
            acl_number_start: Starting number for extended ACLs.
            include_remarks: Include remark statements.

        Returns:
            Cisco IOS ACL configuration as a string.
        """
        lines: list[str] = []
        systeminfo = self._profile.mud.systeminfo or "MUD Device"
        current_acl = acl_number_start

        # Header
        lines.extend([
            "!",
            f"! Cisco IOS ACLs generated from MUD profile",
            f"! Device: {systeminfo}",
            f"! MUD URL: {self._profile.mud.mud_url}",
            "!",
            "! Note: DNS names need to be resolved to IP addresses",
            "! or use domain-based ACLs (object-group network with fqdn)",
            "!",
            "",
        ])

        # FROM-DEVICE ACLs (outbound from device perspective)
        for acl in self._profile.get_from_device_acls():
            lines.extend(self._export_acl(
                acl,
                direction="from",
                acl_number=current_acl,
                include_remarks=include_remarks,
            ))
            current_acl += 1
            lines.append("")

        # TO-DEVICE ACLs (inbound to device perspective)
        for acl in self._profile.get_to_device_acls():
            lines.extend(self._export_acl(
                acl,
                direction="to",
                acl_number=current_acl,
                include_remarks=include_remarks,
            ))
            current_acl += 1
            lines.append("")

        # Interface application hints
        lines.extend([
            "!",
            "! Apply ACLs to interface (example):",
            "! interface GigabitEthernet0/1",
            f"!   ip access-group {acl_number_start} in   ! Traffic from IoT device",
            f"!   ip access-group {acl_number_start + 1} out  ! Traffic to IoT device",
            "!",
        ])

        return "\n".join(lines)

    def _export_acl(
        self,
        acl: "AccessControlList",
        direction: str,
        acl_number: int,
        include_remarks: bool,
    ) -> list[str]:
        """Export a single ACL to Cisco format."""
        lines: list[str] = []
        direction_label = "FROM" if direction == "from" else "TO"

        if include_remarks:
            lines.extend([
                f"! ACL for {direction_label}-DEVICE traffic",
                f"! Original ACL name: {acl.name}",
            ])

        lines.append(f"ip access-list extended {acl_number}")

        if include_remarks:
            lines.append(f" remark MUD ACL: {acl.name}")

        for entry in acl.entries:
            rule = self._generate_ace(entry, direction, include_remarks)
            if rule:
                lines.extend(rule)

        # Implicit deny at end
        lines.append(" deny ip any any")

        return lines

    def _generate_ace(
        self,
        entry: "AccessControlEntry",
        direction: str,
        include_remarks: bool,
    ) -> list[str]:
        """Generate Cisco ACE statements from a MUD ACE."""
        lines: list[str] = []

        if include_remarks:
            lines.append(f" remark ACE: {entry.name}")

        # Build the ACE
        parts: list[str] = []

        # Action
        action = "permit" if entry.is_accept() else "deny"
        parts.append(f" {action}")

        # Protocol
        protocol = self._get_protocol(entry)
        parts.append(protocol)

        # Source
        dns_names = entry.matches.get_dns_names()
        if direction == "from":
            # Traffic from device - source is the device
            parts.append("any")  # Will be applied on device-facing interface
            # Destination
            if dns_names["dst"]:
                parts.append(f"host {dns_names['dst']}")
            else:
                parts.append("any")
        else:
            # Traffic to device - destination is the device
            if dns_names["src"]:
                parts.append(f"host {dns_names['src']}")
            else:
                parts.append("any")
            parts.append("any")  # Device address

        # Ports
        port_info = self._get_port_info(entry, direction)
        if port_info:
            parts.append(port_info)

        # State tracking hint
        if protocol in ("tcp", "udp"):
            if entry.matches.tcp and entry.matches.tcp.direction_initiated:
                if entry.matches.tcp.direction_initiated.value == "from-device":
                    parts.append("established")

        lines.append(" ".join(parts))
        return lines

    def _get_protocol(self, entry: "AccessControlEntry") -> str:
        """Get the protocol for Cisco ACL."""
        if entry.matches.tcp:
            return "tcp"
        if entry.matches.udp:
            return "udp"
        if entry.matches.icmp:
            return "icmp"

        proto = entry.matches.get_protocol()
        if proto:
            protocol_map = {1: "icmp", 6: "tcp", 17: "udp"}
            return protocol_map.get(proto, str(proto))

        return "ip"

    def _get_port_info(self, entry: "AccessControlEntry", direction: str) -> str | None:
        """Get port matching info for Cisco ACL."""
        if entry.matches.tcp:
            tcp = entry.matches.tcp
            if direction == "from" and tcp.dst_port:
                return self._format_port(tcp.dst_port, "eq")
            elif direction == "to" and tcp.src_port:
                return self._format_port(tcp.src_port, "eq")

        if entry.matches.udp:
            udp = entry.matches.udp
            if direction == "from" and udp.dst_port:
                return self._format_port(udp.dst_port, "eq")
            elif direction == "to" and udp.src_port:
                return self._format_port(udp.src_port, "eq")

        return None

    def _format_port(self, port_match: "PortMatch", default_op: str) -> str:  # type: ignore[name-defined]
        """Format a port match for Cisco ACL."""
        from mudparser.models.matches import PortOperator

        op_map = {
            PortOperator.EQ: "eq",
            PortOperator.NEQ: "neq",
            PortOperator.LT: "lt",
            PortOperator.GT: "gt",
            PortOperator.RANGE: "range",
        }

        op = op_map.get(port_match.operator, default_op)

        if port_match.operator == PortOperator.RANGE:
            return f"{op} {port_match.port} {port_match.upper_port}"
        return f"{op} {port_match.port}"
