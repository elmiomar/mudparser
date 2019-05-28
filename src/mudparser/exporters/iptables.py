"""
IPTables firewall rule exporter.

Exports MUD profiles to Linux iptables rule format.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mudparser.models import MUDProfile, AccessControlEntry


class IPTablesExporter:
    """
    Exporter for Linux iptables firewall rules.

    Generates iptables commands that implement the MUD profile's
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
        device_ip: str,
        device_interface: str = "eth0",
        chain_prefix: str = "MUD",
        include_comments: bool = True,
    ) -> str:
        """
        Export to iptables rules.

        Args:
            device_ip: IP address of the IoT device.
            device_interface: Network interface for the device.
            chain_prefix: Prefix for custom chain names.
            include_comments: Include rule comments.

        Returns:
            iptables rule commands as a string.
        """
        lines: list[str] = []
        systeminfo = self._profile.mud.systeminfo or "MUD Device"

        # Header
        lines.extend([
            "#!/bin/bash",
            f"# IPTables rules generated from MUD profile",
            f"# Device: {systeminfo}",
            f"# MUD URL: {self._profile.mud.mud_url}",
            f"# Device IP: {device_ip}",
            "",
        ])

        # Create custom chains
        from_chain = f"{chain_prefix}_FROM_{self._sanitize_name(systeminfo)}"
        to_chain = f"{chain_prefix}_TO_{self._sanitize_name(systeminfo)}"

        lines.extend([
            "# Create custom chains",
            f"iptables -N {from_chain} 2>/dev/null || iptables -F {from_chain}",
            f"iptables -N {to_chain} 2>/dev/null || iptables -F {to_chain}",
            "",
        ])

        # Jump rules to custom chains
        lines.extend([
            "# Jump to custom chains",
            f"iptables -A FORWARD -s {device_ip} -j {from_chain}",
            f"iptables -A FORWARD -d {device_ip} -j {to_chain}",
            "",
        ])

        # FROM-DEVICE rules (outbound from device)
        lines.append("# FROM-DEVICE rules (outbound traffic from IoT device)")
        for acl in self._profile.get_from_device_acls():
            if include_comments:
                lines.append(f"# ACL: {acl.name}")
            for entry in acl.entries:
                rule = self._generate_rule(
                    entry,
                    direction="from",
                    device_ip=device_ip,
                    chain=from_chain,
                    include_comment=include_comments,
                )
                if rule:
                    lines.append(rule)
        lines.append("")

        # TO-DEVICE rules (inbound to device)
        lines.append("# TO-DEVICE rules (inbound traffic to IoT device)")
        for acl in self._profile.get_to_device_acls():
            if include_comments:
                lines.append(f"# ACL: {acl.name}")
            for entry in acl.entries:
                rule = self._generate_rule(
                    entry,
                    direction="to",
                    device_ip=device_ip,
                    chain=to_chain,
                    include_comment=include_comments,
                )
                if rule:
                    lines.append(rule)
        lines.append("")

        # Default deny rules
        lines.extend([
            "# Default deny (implicit deny all)",
            f"iptables -A {from_chain} -j DROP",
            f"iptables -A {to_chain} -j DROP",
            "",
        ])

        return "\n".join(lines)

    def _generate_rule(
        self,
        entry: "AccessControlEntry",
        direction: str,
        device_ip: str,
        chain: str,
        include_comment: bool = True,
    ) -> str | None:
        """Generate a single iptables rule from an ACE."""
        parts = [f"iptables -A {chain}"]

        # Source/destination based on direction
        if direction == "from":
            parts.append(f"-s {device_ip}")
        else:
            parts.append(f"-d {device_ip}")

        # Protocol
        protocol = self._get_protocol(entry)
        if protocol:
            parts.append(f"-p {protocol}")

        # DNS names (will need resolution)
        dns_names = entry.matches.get_dns_names()
        if direction == "from" and dns_names["dst"]:
            # For outbound, destination is the remote host
            parts.append(f"-d {dns_names['dst']}")
        elif direction == "to" and dns_names["src"]:
            # For inbound, source is the remote host
            parts.append(f"-s {dns_names['src']}")

        # Ports
        port_info = self._get_port_info(entry, direction)
        if port_info:
            parts.append(port_info)

        # TCP flags for direction-initiated
        if entry.matches.tcp and entry.matches.tcp.direction_initiated:
            if direction == "from":
                # Device initiates - allow SYN out, established back
                pass  # Connection tracking handles this
            else:
                # External initiates - allow SYN in
                pass

        # State tracking for established connections
        if protocol in ("tcp", "udp"):
            parts.append("-m state --state NEW,ESTABLISHED")

        # Action
        action = "ACCEPT" if entry.is_accept() else "DROP"
        parts.append(f"-j {action}")

        # Comment
        if include_comment:
            comment = entry.name.replace('"', '\\"')
            parts.insert(-1, f'-m comment --comment "{comment}"')

        return " ".join(parts)

    def _get_protocol(self, entry: "AccessControlEntry") -> str | None:
        """Get the protocol from an ACE."""
        if entry.matches.tcp:
            return "tcp"
        if entry.matches.udp:
            return "udp"
        if entry.matches.icmp:
            return "icmp"

        proto = entry.matches.get_protocol()
        if proto:
            protocol_map = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}
            return protocol_map.get(proto, str(proto))

        return None

    def _get_port_info(self, entry: "AccessControlEntry", direction: str) -> str | None:
        """Get port matching info from an ACE."""
        parts: list[str] = []

        if entry.matches.tcp:
            tcp = entry.matches.tcp
            if direction == "from" and tcp.dst_port:
                parts.append(f"--dport {self._format_port(tcp.dst_port)}")
            elif direction == "to" and tcp.src_port:
                parts.append(f"--sport {self._format_port(tcp.src_port)}")

        if entry.matches.udp:
            udp = entry.matches.udp
            if direction == "from" and udp.dst_port:
                parts.append(f"--dport {self._format_port(udp.dst_port)}")
            elif direction == "to" and udp.src_port:
                parts.append(f"--sport {self._format_port(udp.src_port)}")

        return " ".join(parts) if parts else None

    def _format_port(self, port_match: "PortMatch") -> str:  # type: ignore[name-defined]
        """Format a port match for iptables."""
        from mudparser.models.matches import PortOperator

        if port_match.operator == PortOperator.RANGE:
            return f"{port_match.port}:{port_match.upper_port}"
        return str(port_match.port)

    def _sanitize_name(self, name: str) -> str:
        """Sanitize a name for use in chain names."""
        # Remove special characters, keep alphanumeric and underscores
        return "".join(c if c.isalnum() else "_" for c in name)[:20].upper()
