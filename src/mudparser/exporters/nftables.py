"""
NFTables firewall rule exporter.

Exports MUD profiles to Linux nftables configuration format.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mudparser.models import MUDProfile, AccessControlEntry


class NFTablesExporter:
    """
    Exporter for Linux nftables firewall rules.

    Generates nftables configuration that implements the MUD profile's
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
        table_name: str = "mud_rules",
        include_comments: bool = True,
    ) -> str:
        """
        Export to nftables configuration.

        Args:
            device_ip: IP address of the IoT device.
            table_name: Name for the nftables table.
            include_comments: Include rule comments.

        Returns:
            nftables configuration as a string.
        """
        lines: list[str] = []
        systeminfo = self._profile.mud.systeminfo or "MUD Device"
        safe_name = self._sanitize_name(systeminfo)

        # Header comment
        lines.extend([
            "#!/usr/sbin/nft -f",
            f"# nftables rules generated from MUD profile",
            f"# Device: {systeminfo}",
            f"# MUD URL: {self._profile.mud.mud_url}",
            f"# Device IP: {device_ip}",
            "",
        ])

        # Flush existing table if it exists
        lines.extend([
            f"# Flush existing rules",
            f"table inet {table_name}",
            f"delete table inet {table_name}",
            "",
        ])

        # Create table and chains
        lines.extend([
            f"table inet {table_name} {{",
            "",
            f"    # Chain for traffic FROM the IoT device (outbound)",
            f"    chain from_{safe_name} {{",
            f"        type filter hook forward priority 0; policy drop;",
            "",
        ])

        # FROM-DEVICE rules
        for acl in self._profile.get_from_device_acls():
            if include_comments:
                lines.append(f"        # ACL: {acl.name}")
            for entry in acl.entries:
                rule = self._generate_rule(
                    entry,
                    direction="from",
                    device_ip=device_ip,
                    include_comment=include_comments,
                )
                if rule:
                    lines.append(f"        {rule}")
            lines.append("")

        lines.extend([
            f"        # Default: drop all other traffic from device",
            f"        ip saddr {device_ip} counter drop",
            "    }",
            "",
        ])

        # TO-DEVICE rules
        lines.extend([
            f"    # Chain for traffic TO the IoT device (inbound)",
            f"    chain to_{safe_name} {{",
            f"        type filter hook forward priority 0; policy drop;",
            "",
        ])

        for acl in self._profile.get_to_device_acls():
            if include_comments:
                lines.append(f"        # ACL: {acl.name}")
            for entry in acl.entries:
                rule = self._generate_rule(
                    entry,
                    direction="to",
                    device_ip=device_ip,
                    include_comment=include_comments,
                )
                if rule:
                    lines.append(f"        {rule}")
            lines.append("")

        lines.extend([
            f"        # Default: drop all other traffic to device",
            f"        ip daddr {device_ip} counter drop",
            "    }",
            "}",
            "",
        ])

        return "\n".join(lines)

    def _generate_rule(
        self,
        entry: "AccessControlEntry",
        direction: str,
        device_ip: str,
        include_comment: bool = True,
    ) -> str | None:
        """Generate a single nftables rule from an ACE."""
        parts: list[str] = []

        # IP family
        parts.append("ip")

        # Source/destination based on direction
        if direction == "from":
            parts.append(f"saddr {device_ip}")
        else:
            parts.append(f"daddr {device_ip}")

        # DNS names
        dns_names = entry.matches.get_dns_names()
        if direction == "from" and dns_names["dst"]:
            parts.append(f"daddr {dns_names['dst']}")
        elif direction == "to" and dns_names["src"]:
            parts.append(f"saddr {dns_names['src']}")

        # Protocol
        protocol = self._get_protocol(entry)
        if protocol:
            parts.append(f"{protocol}")

            # Ports
            port_info = self._get_port_info(entry, direction, protocol)
            if port_info:
                parts.append(port_info)

        # Connection tracking
        if protocol in ("tcp", "udp"):
            parts.append("ct state new,established")

        # Counter
        parts.append("counter")

        # Action
        action = "accept" if entry.is_accept() else "drop"
        parts.append(action)

        # Comment
        if include_comment:
            comment = entry.name.replace('"', '\\"')
            parts.append(f'comment "{comment}"')

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
            return protocol_map.get(proto, f"ip protocol {proto}")

        return None

    def _get_port_info(
        self,
        entry: "AccessControlEntry",
        direction: str,
        protocol: str,
    ) -> str | None:
        """Get port matching info from an ACE."""
        if protocol not in ("tcp", "udp"):
            return None

        if entry.matches.tcp:
            tcp = entry.matches.tcp
            if direction == "from" and tcp.dst_port:
                return f"dport {self._format_port(tcp.dst_port)}"
            elif direction == "to" and tcp.src_port:
                return f"sport {self._format_port(tcp.src_port)}"

        if entry.matches.udp:
            udp = entry.matches.udp
            if direction == "from" and udp.dst_port:
                return f"dport {self._format_port(udp.dst_port)}"
            elif direction == "to" and udp.src_port:
                return f"sport {self._format_port(udp.src_port)}"

        return None

    def _format_port(self, port_match: "PortMatch") -> str:  # type: ignore[name-defined]
        """Format a port match for nftables."""
        from mudparser.models.matches import PortOperator

        if port_match.operator == PortOperator.RANGE:
            return f"{port_match.port}-{port_match.upper_port}"
        return str(port_match.port)

    def _sanitize_name(self, name: str) -> str:
        """Sanitize a name for use in chain names."""
        return "".join(c if c.isalnum() else "_" for c in name)[:20].lower()
