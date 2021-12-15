#!/usr/bin/env python3
"""
Basic MudParser Usage Example.

This script demonstrates the fundamental features of MudParser.
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
    print("MudParser Basic Usage Example")
    print("=" * 60)

    # Parse the MUD file
    print(f"\n1. Parsing: {mud_file.name}")
    parser = MUDParser.from_file(mud_file)

    # Display basic info
    print("\n2. Device Information:")
    print(f"   Name: {parser.mud.systeminfo}")
    print(f"   MUD URL: {parser.mud.mud_url}")
    print(f"   Version: {parser.mud.mud_version}")
    print(f"   Supported: {parser.mud.is_supported}")
    print(f"   Cache Validity: {parser.mud.cache_validity} hours")

    # Get summary
    print("\n3. Profile Summary:")
    summary = parser.get_summary()
    print(f"   Total ACLs: {summary['total_acls']}")
    print(f"   Total Rules: {summary['total_rules']}")
    print(f"   From-Device ACLs: {summary['from_device_acls']}")
    print(f"   To-Device ACLs: {summary['to_device_acls']}")

    # List DNS names
    print("\n4. Referenced DNS Names:")
    for name in sorted(parser.get_dns_names()):
        print(f"   - {name}")

    # List ports
    print("\n5. Referenced Ports:")
    ports = parser.get_ports()
    print(f"   TCP: {sorted(ports['tcp'])}")
    print(f"   UDP: {sorted(ports['udp'])}")

    # List ACLs
    print("\n6. Access Control Lists:")
    for acl in parser.profile.acls.acl:
        print(f"\n   ACL: {acl.name}")
        print(f"   Type: {acl.acl_type.value}")
        print(f"   Entries: {len(acl)}")
        for entry in acl.entries:
            action = "ALLOW" if entry.is_accept() else "DENY"
            print(f"     - [{action}] {entry.name}")

    # Validate
    print("\n7. Validation:")
    errors = parser.validate()
    if errors:
        print(f"   Issues found: {len(errors)}")
        for error in errors:
            print(f"   - {error}")
    else:
        print("   Profile is valid!")

    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
