"""
pfSense firewall rule exporter.

Exports MUD profiles to pfSense XML configuration format.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING
from xml.dom import minidom

if TYPE_CHECKING:
    from mudparser.models import MUDProfile, AccessControlEntry


class PfSenseExporter:
    """
    Exporter for pfSense firewall rules.

    Generates pfSense filter rules in XML format that can be imported
    into pfSense's configuration.
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
        interface: str = "lan",
    ) -> str:
        """
        Export to pfSense XML format.

        Args:
            device_ip: IP address of the IoT device.
            interface: pfSense interface name (e.g., "lan", "wan").

        Returns:
            pfSense filter rules in XML format.
        """
        systeminfo = self._profile.mud.systeminfo or "MUD Device"

        # Create root element
        root = ET.Element("pfsense")

        # Add comment
        comment = ET.Comment(
            f" pfSense rules generated from MUD profile\n"
            f"     Device: {systeminfo}\n"
            f"     MUD URL: {self._profile.mud.mud_url}\n"
            f"     Device IP: {device_ip} "
        )
        root.append(comment)

        # Filter section
        filter_elem = ET.SubElement(root, "filter")

        rule_idx = 0

        # FROM-DEVICE rules (outbound from device)
        for acl in self._profile.get_from_device_acls():
            for entry in acl.entries:
                rule = self._create_rule(
                    entry,
                    direction="from",
                    device_ip=device_ip,
                    interface=interface,
                    acl_name=acl.name,
                    idx=rule_idx,
                )
                filter_elem.append(rule)
                rule_idx += 1

        # Default deny for from-device
        filter_elem.append(self._create_default_deny(
            direction="from",
            device_ip=device_ip,
            interface=interface,
            idx=rule_idx,
        ))
        rule_idx += 1

        # TO-DEVICE rules (inbound to device)
        for acl in self._profile.get_to_device_acls():
            for entry in acl.entries:
                rule = self._create_rule(
                    entry,
                    direction="to",
                    device_ip=device_ip,
                    interface=interface,
                    acl_name=acl.name,
                    idx=rule_idx,
                )
                filter_elem.append(rule)
                rule_idx += 1

        # Default deny for to-device
        filter_elem.append(self._create_default_deny(
            direction="to",
            device_ip=device_ip,
            interface=interface,
            idx=rule_idx,
        ))

        # Pretty print
        xml_str = ET.tostring(root, encoding="unicode")
        dom = minidom.parseString(xml_str)
        return dom.toprettyxml(indent="  ")

    def _create_rule(
        self,
        entry: "AccessControlEntry",
        direction: str,
        device_ip: str,
        interface: str,
        acl_name: str,
        idx: int,
    ) -> ET.Element:
        """Create a pfSense filter rule element."""
        rule = ET.Element("rule")

        # Tracker ID
        tracker = ET.SubElement(rule, "tracker")
        tracker.text = str(1000000000 + idx)

        # Type (pass/block)
        type_elem = ET.SubElement(rule, "type")
        type_elem.text = "pass" if entry.is_accept() else "block"

        # Interface
        iface = ET.SubElement(rule, "interface")
        iface.text = interface

        # IP version
        ipprotocol = ET.SubElement(rule, "ipprotocol")
        ipprotocol.text = "inet"  # IPv4

        # Protocol
        protocol = self._get_protocol(entry)
        if protocol:
            proto = ET.SubElement(rule, "protocol")
            proto.text = protocol

        # Source and destination based on direction
        dns_names = entry.matches.get_dns_names()

        source = ET.SubElement(rule, "source")
        destination = ET.SubElement(rule, "destination")

        if direction == "from":
            # Traffic from device
            src_addr = ET.SubElement(source, "address")
            src_addr.text = device_ip

            if dns_names["dst"]:
                dst_addr = ET.SubElement(destination, "address")
                dst_addr.text = dns_names["dst"]
            else:
                ET.SubElement(destination, "any")
        else:
            # Traffic to device
            if dns_names["src"]:
                src_addr = ET.SubElement(source, "address")
                src_addr.text = dns_names["src"]
            else:
                ET.SubElement(source, "any")

            dst_addr = ET.SubElement(destination, "address")
            dst_addr.text = device_ip

        # Ports
        self._add_ports(entry, direction, source, destination)

        # State type (for TCP/UDP)
        if protocol in ("tcp", "udp"):
            statetype = ET.SubElement(rule, "statetype")
            statetype.text = "keep state"

        # Description
        descr = ET.SubElement(rule, "descr")
        descr.text = f"MUD: {acl_name} - {entry.name}"

        # Log (optional)
        # ET.SubElement(rule, "log")

        return rule

    def _create_default_deny(
        self,
        direction: str,
        device_ip: str,
        interface: str,
        idx: int,
    ) -> ET.Element:
        """Create a default deny rule."""
        rule = ET.Element("rule")

        # Tracker ID
        tracker = ET.SubElement(rule, "tracker")
        tracker.text = str(1000000000 + idx)

        # Type
        type_elem = ET.SubElement(rule, "type")
        type_elem.text = "block"

        # Interface
        iface = ET.SubElement(rule, "interface")
        iface.text = interface

        # IP version
        ipprotocol = ET.SubElement(rule, "ipprotocol")
        ipprotocol.text = "inet"

        # Source and destination
        source = ET.SubElement(rule, "source")
        destination = ET.SubElement(rule, "destination")

        if direction == "from":
            src_addr = ET.SubElement(source, "address")
            src_addr.text = device_ip
            ET.SubElement(destination, "any")
        else:
            ET.SubElement(source, "any")
            dst_addr = ET.SubElement(destination, "address")
            dst_addr.text = device_ip

        # Description
        descr = ET.SubElement(rule, "descr")
        dir_label = "FROM" if direction == "from" else "TO"
        descr.text = f"MUD: Default deny {dir_label} device"

        # Log default denies
        ET.SubElement(rule, "log")

        return rule

    def _get_protocol(self, entry: "AccessControlEntry") -> str | None:
        """Get the protocol for pfSense rule."""
        if entry.matches.tcp:
            return "tcp"
        if entry.matches.udp:
            return "udp"
        if entry.matches.icmp:
            return "icmp"

        proto = entry.matches.get_protocol()
        if proto:
            protocol_map = {1: "icmp", 6: "tcp", 17: "udp"}
            return protocol_map.get(proto)

        return None

    def _add_ports(
        self,
        entry: "AccessControlEntry",
        direction: str,
        source: ET.Element,
        destination: ET.Element,
    ) -> None:
        """Add port information to source/destination elements."""
        if entry.matches.tcp:
            tcp = entry.matches.tcp
            if direction == "from" and tcp.dst_port:
                port = ET.SubElement(destination, "port")
                port.text = self._format_port(tcp.dst_port)
            elif direction == "to" and tcp.src_port:
                port = ET.SubElement(source, "port")
                port.text = self._format_port(tcp.src_port)

        if entry.matches.udp:
            udp = entry.matches.udp
            if direction == "from" and udp.dst_port:
                port = ET.SubElement(destination, "port")
                port.text = self._format_port(udp.dst_port)
            elif direction == "to" and udp.src_port:
                port = ET.SubElement(source, "port")
                port.text = self._format_port(udp.src_port)

    def _format_port(self, port_match: "PortMatch") -> str:  # type: ignore[name-defined]
        """Format a port match for pfSense."""
        from mudparser.models.matches import PortOperator

        if port_match.operator == PortOperator.RANGE:
            return f"{port_match.port}-{port_match.upper_port}"
        return str(port_match.port)
