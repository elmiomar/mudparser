#!/usr/bin/env python3
"""
Firewall Rule Export Example.

This script demonstrates how to export MUD profiles to various
firewall rule formats.
"""

from pathlib import Path
import sys

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mudparser import MUDParser


def main():
    # Find a sample MUD file
    data_dir = Path(__file__).parent.parent / "data"
    mud_file = data_dir / "amazon_echo_short.json"

    if not mud_file.exists():
        print(f"Sample file not found: {mud_file}")
        return

    print("=" * 60)
    print("MudParser Firewall Export Example")
    print("=" * 60)

    # Parse the MUD file
    parser = MUDParser.from_file(mud_file)
    print(f"Loaded: {parser.mud.systeminfo}")

    device_ip = "192.168.1.100"
    print(f"Device IP: {device_ip}")

    # Export to iptables
    print("\n" + "-" * 60)
    print("1. IPTABLES EXPORT")
    print("-" * 60)
    iptables_rules = parser.export.to_iptables(
        device_ip=device_ip,
        chain_prefix="MUD",
        include_comments=True,
    )
    print(iptables_rules[:1000] + "..." if len(iptables_rules) > 1000 else iptables_rules)

    # Export to nftables
    print("\n" + "-" * 60)
    print("2. NFTABLES EXPORT")
    print("-" * 60)
    nftables_rules = parser.export.to_nftables(
        device_ip=device_ip,
        table_name="mud_iot",
    )
    print(nftables_rules[:1000] + "..." if len(nftables_rules) > 1000 else nftables_rules)

    # Export to Cisco ACL
    print("\n" + "-" * 60)
    print("3. CISCO ACL EXPORT")
    print("-" * 60)
    cisco_rules = parser.export.to_cisco_acl(
        acl_number_start=100,
        include_remarks=True,
    )
    print(cisco_rules[:1000] + "..." if len(cisco_rules) > 1000 else cisco_rules)

    # Export to pfSense
    print("\n" + "-" * 60)
    print("4. PFSENSE EXPORT")
    print("-" * 60)
    pfsense_rules = parser.export.to_pfsense(
        device_ip=device_ip,
        interface="lan",
    )
    print(pfsense_rules[:1000] + "..." if len(pfsense_rules) > 1000 else pfsense_rules)

    # Save to files
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)

    print("\n" + "-" * 60)
    print("SAVING FILES")
    print("-" * 60)

    files = [
        ("iptables_rules.sh", iptables_rules),
        ("nftables_rules.nft", nftables_rules),
        ("cisco_acl.ios", cisco_rules),
        ("pfsense_rules.xml", pfsense_rules),
    ]

    for filename, content in files:
        filepath = output_dir / filename
        filepath.write_text(content)
        print(f"Saved: {filepath}")

    print("\n" + "=" * 60)
    print("Export completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
