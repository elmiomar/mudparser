"""
Base exporter class and utilities.

This module provides the base MUDExporter class that orchestrates
exports to various formats.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import TYPE_CHECKING, Any

import yaml

from mudparser.exceptions import MUDExportError

if TYPE_CHECKING:
    from mudparser.models import MUDProfile


class ExportFormat(str, Enum):
    """Supported export formats."""

    JSON = "json"
    YAML = "yaml"
    IPTABLES = "iptables"
    NFTABLES = "nftables"
    CISCO = "cisco"
    PFSENSE = "pfsense"


class MUDExporter:
    """
    Main exporter class for MUD profiles.

    Provides methods to export MUD profiles to various formats
    including JSON, YAML, and firewall rules.

    Example:
        >>> from mudparser import MUDParser
        >>> parser = MUDParser.from_file("device.mud.json")
        >>> # Export to JSON
        >>> json_output = parser.export.to_json()
        >>> # Export to iptables rules
        >>> rules = parser.export.to_iptables(device_ip="192.168.1.100")
    """

    def __init__(self, profile: "MUDProfile") -> None:
        """
        Initialize the exporter.

        Args:
            profile: The MUD profile to export.
        """
        self._profile = profile

    @property
    def profile(self) -> "MUDProfile":
        """Get the profile being exported."""
        return self._profile

    # =========================================================================
    # Data Format Exports
    # =========================================================================

    def to_json(self, indent: int = 2, sort_keys: bool = False) -> str:
        """
        Export the profile to JSON format.

        Args:
            indent: Indentation level for pretty printing.
            sort_keys: Whether to sort dictionary keys.

        Returns:
            JSON string representation.
        """
        return json.dumps(
            self._profile.to_dict(),
            indent=indent,
            sort_keys=sort_keys,
            default=str,
        )

    def to_yaml(self, default_flow_style: bool = False) -> str:
        """
        Export the profile to YAML format.

        Args:
            default_flow_style: Use flow style for collections.

        Returns:
            YAML string representation.
        """
        # Convert datetime objects to strings
        data = self._convert_for_yaml(self._profile.to_dict())
        return yaml.dump(
            data,
            default_flow_style=default_flow_style,
            sort_keys=False,
            allow_unicode=True,
        )

    def _convert_for_yaml(self, obj: Any) -> Any:
        """Convert objects for YAML serialization."""
        if isinstance(obj, dict):
            return {k: self._convert_for_yaml(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_for_yaml(item) for item in obj]
        elif hasattr(obj, "isoformat"):
            return obj.isoformat()
        return obj

    def to_dict(self) -> dict[str, Any]:
        """
        Export the profile to a dictionary.

        Returns:
            Dictionary representation.
        """
        return self._profile.to_dict()

    # =========================================================================
    # Firewall Rule Exports
    # =========================================================================

    def to_iptables(
        self,
        device_ip: str,
        device_interface: str = "eth0",
        chain_prefix: str = "MUD",
        include_comments: bool = True,
    ) -> str:
        """
        Export the profile to iptables rules.

        Args:
            device_ip: IP address of the IoT device.
            device_interface: Network interface for the device.
            chain_prefix: Prefix for custom chain names.
            include_comments: Include rule comments.

        Returns:
            iptables rule commands.
        """
        from mudparser.exporters.iptables import IPTablesExporter

        exporter = IPTablesExporter(self._profile)
        return exporter.export(
            device_ip=device_ip,
            device_interface=device_interface,
            chain_prefix=chain_prefix,
            include_comments=include_comments,
        )

    def to_nftables(
        self,
        device_ip: str,
        table_name: str = "mud_rules",
        include_comments: bool = True,
    ) -> str:
        """
        Export the profile to nftables rules.

        Args:
            device_ip: IP address of the IoT device.
            table_name: Name for the nftables table.
            include_comments: Include rule comments.

        Returns:
            nftables configuration.
        """
        from mudparser.exporters.nftables import NFTablesExporter

        exporter = NFTablesExporter(self._profile)
        return exporter.export(
            device_ip=device_ip,
            table_name=table_name,
            include_comments=include_comments,
        )

    def to_cisco_acl(
        self,
        acl_number_start: int = 100,
        include_remarks: bool = True,
    ) -> str:
        """
        Export the profile to Cisco IOS ACL format.

        Args:
            acl_number_start: Starting ACL number.
            include_remarks: Include ACL remarks.

        Returns:
            Cisco IOS ACL configuration.
        """
        from mudparser.exporters.cisco import CiscoACLExporter

        exporter = CiscoACLExporter(self._profile)
        return exporter.export(
            acl_number_start=acl_number_start,
            include_remarks=include_remarks,
        )

    def to_pfsense(
        self,
        device_ip: str,
        interface: str = "lan",
    ) -> str:
        """
        Export the profile to pfSense XML format.

        Args:
            device_ip: IP address of the IoT device.
            interface: pfSense interface name.

        Returns:
            pfSense filter rules in XML format.
        """
        from mudparser.exporters.pfsense import PfSenseExporter

        exporter = PfSenseExporter(self._profile)
        return exporter.export(
            device_ip=device_ip,
            interface=interface,
        )

    # =========================================================================
    # Format Detection
    # =========================================================================

    def export(self, format: ExportFormat | str, **kwargs: Any) -> str:
        """
        Export to the specified format.

        Args:
            format: The export format.
            **kwargs: Format-specific options.

        Returns:
            Exported content as string.

        Raises:
            MUDExportError: If the format is not supported.
        """
        if isinstance(format, str):
            try:
                format = ExportFormat(format.lower())
            except ValueError:
                raise MUDExportError(
                    f"Unsupported export format: {format}",
                    export_format=format,
                    reason=f"Supported formats: {', '.join(f.value for f in ExportFormat)}",
                )

        match format:
            case ExportFormat.JSON:
                return self.to_json(**kwargs)
            case ExportFormat.YAML:
                return self.to_yaml(**kwargs)
            case ExportFormat.IPTABLES:
                return self.to_iptables(**kwargs)
            case ExportFormat.NFTABLES:
                return self.to_nftables(**kwargs)
            case ExportFormat.CISCO:
                return self.to_cisco_acl(**kwargs)
            case ExportFormat.PFSENSE:
                return self.to_pfsense(**kwargs)
            case _:
                raise MUDExportError(
                    f"Unsupported export format: {format}",
                    export_format=str(format),
                )

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def get_summary(self) -> dict[str, Any]:
        """
        Get a summary of what will be exported.

        Returns:
            Dictionary with export summary information.
        """
        from_acls = self._profile.get_from_device_acls()
        to_acls = self._profile.get_to_device_acls()

        return {
            "device_info": self._profile.mud.systeminfo,
            "from_device_rules": sum(len(acl.entries) for acl in from_acls),
            "to_device_rules": sum(len(acl.entries) for acl in to_acls),
            "total_rules": sum(len(acl.entries) for acl in self._profile.acls.acl),
            "dns_names": list(self._profile.get_all_dns_names()),
            "ports": {k: list(v) for k, v in self._profile.get_all_ports().items()},
            "supported_formats": [f.value for f in ExportFormat],
        }
