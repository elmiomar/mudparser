# Firewall Generation Examples

## Generate iptables Rules

```python
from mudparser import MUDParser

parser = MUDParser.from_file("device.mud.json")

# Generate iptables rules
rules = parser.export.to_iptables(
    device_ip="192.168.1.100",
    device_interface="eth0",
    chain_prefix="IOT",
    include_comments=True,
)

print(rules)

# Save to file
with open("iot_rules.sh", "w") as f:
    f.write(rules)
```

## Generate nftables Rules

```python
from mudparser import MUDParser

parser = MUDParser.from_file("device.mud.json")

# Generate nftables configuration
rules = parser.export.to_nftables(
    device_ip="192.168.1.100",
    table_name="iot_rules",
)

# Save to file
with open("iot_rules.nft", "w") as f:
    f.write(rules)

# Apply: nft -f iot_rules.nft
```

## Generate Cisco ACLs

```python
from mudparser import MUDParser

parser = MUDParser.from_file("device.mud.json")

# Generate Cisco IOS ACLs
acls = parser.export.to_cisco_acl(
    acl_number_start=100,
    include_remarks=True,
)

print(acls)
```

## Generate pfSense Rules

```python
from mudparser import MUDParser

parser = MUDParser.from_file("device.mud.json")

# Generate pfSense XML
xml_rules = parser.export.to_pfsense(
    device_ip="192.168.1.100",
    interface="lan",
)

# Save to file for import
with open("pfsense_rules.xml", "w") as f:
    f.write(xml_rules)
```

## Batch Processing Multiple Devices

```python
from mudparser import MUDParser
from pathlib import Path

devices = [
    {"file": "echo.mud.json", "ip": "192.168.1.100"},
    {"file": "camera.mud.json", "ip": "192.168.1.101"},
    {"file": "thermostat.mud.json", "ip": "192.168.1.102"},
]

all_rules = ["#!/bin/bash", "# IoT Firewall Rules", ""]

for device in devices:
    parser = MUDParser.from_file(device["file"])
    rules = parser.export.to_iptables(device_ip=device["ip"])

    # Extract just the rules (skip header)
    lines = rules.split("\n")
    rule_lines = [l for l in lines if l.startswith("iptables")]
    all_rules.extend(rule_lines)
    all_rules.append("")

# Save combined rules
with open("all_iot_rules.sh", "w") as f:
    f.write("\n".join(all_rules))
```

## Export with DNS Resolution

```python
import socket
from mudparser import MUDParser

parser = MUDParser.from_file("device.mud.json")

# Get DNS names that need resolution
dns_names = parser.get_dns_names()

# Resolve DNS names
ip_mapping = {}
for name in dns_names:
    try:
        ip = socket.gethostbyname(name)
        ip_mapping[name] = ip
        print(f"Resolved {name} -> {ip}")
    except socket.gaierror:
        print(f"Could not resolve {name}")

# Generate rules (DNS names will be in rules as-is)
rules = parser.export.to_iptables(device_ip="192.168.1.100")

# Optionally replace DNS names with IPs
for name, ip in ip_mapping.items():
    rules = rules.replace(f"-d {name}", f"-d {ip}")
    rules = rules.replace(f"-s {name}", f"-s {ip}")

print(rules)
```

## Generate Rules for Multiple Formats

```python
from mudparser import MUDParser
from pathlib import Path

parser = MUDParser.from_file("device.mud.json")
device_ip = "192.168.1.100"
output_dir = Path("firewall_rules")
output_dir.mkdir(exist_ok=True)

# Generate all formats
formats = {
    "iptables": ("rules.sh", {"device_ip": device_ip}),
    "nftables": ("rules.nft", {"device_ip": device_ip}),
    "cisco": ("rules.ios", {}),
    "pfsense": ("rules.xml", {"device_ip": device_ip}),
}

for format_name, (filename, kwargs) in formats.items():
    rules = parser.export.export(format_name, **kwargs)
    output_path = output_dir / filename
    output_path.write_text(rules)
    print(f"Generated {output_path}")
```

## Conditional Rule Generation

```python
from mudparser import MUDParser

parser = MUDParser.from_file("device.mud.json")

# Get summary to decide on generation
summary = parser.export.get_summary()

print(f"Device: {summary['device_info']}")
print(f"Total rules: {summary['total_rules']}")

# Only generate if there are rules
if summary['total_rules'] > 0:
    rules = parser.export.to_iptables(device_ip="192.168.1.100")

    # Check for specific ports
    if 443 in summary['ports']['tcp']:
        print("Note: Device uses HTTPS")

    if 53 in summary['ports']['udp']:
        print("Note: Device uses DNS")
else:
    print("No rules to generate")
```

## CLI-Based Generation

```bash
# Generate iptables rules
mudparser export device.mud.json -f iptables -d 192.168.1.100 > rules.sh

# Generate nftables rules
mudparser export device.mud.json -f nftables -d 192.168.1.100 -o rules.nft

# Generate Cisco ACL
mudparser export device.mud.json -f cisco > device.acl

# Generate pfSense XML
mudparser export device.mud.json -f pfsense -d 192.168.1.100 -o pfsense_import.xml
```

## Integration Script

```python
#!/usr/bin/env python3
"""
Generate and optionally apply firewall rules from MUD profile.
"""

import argparse
import subprocess
import sys
from pathlib import Path

from mudparser import MUDParser
from mudparser.validator import MUDValidator

def main():
    parser = argparse.ArgumentParser(description="Generate firewall rules from MUD")
    parser.add_argument("mud_file", help="MUD profile file")
    parser.add_argument("--device-ip", required=True, help="Device IP address")
    parser.add_argument("--format", choices=["iptables", "nftables"], default="iptables")
    parser.add_argument("--apply", action="store_true", help="Apply rules immediately")
    parser.add_argument("--output", help="Output file")

    args = parser.parse_args()

    # Parse and validate
    mud_parser = MUDParser.from_file(args.mud_file)
    validator = MUDValidator()
    result = validator.validate(mud_parser.profile)

    if not result.is_valid:
        print("ERROR: MUD profile validation failed", file=sys.stderr)
        for error in result.errors:
            print(f"  - {error.message}", file=sys.stderr)
        sys.exit(1)

    print(f"Device: {mud_parser.mud.systeminfo}")
    print(f"Generating {args.format} rules for {args.device_ip}")

    # Generate rules
    if args.format == "iptables":
        rules = mud_parser.export.to_iptables(device_ip=args.device_ip)
    else:
        rules = mud_parser.export.to_nftables(device_ip=args.device_ip)

    # Output
    if args.output:
        Path(args.output).write_text(rules)
        print(f"Saved to {args.output}")
    else:
        print(rules)

    # Apply if requested
    if args.apply:
        print("\nApplying rules...")
        if args.format == "iptables":
            subprocess.run(["bash", "-c", rules], check=True)
        else:
            subprocess.run(["nft", "-f", "-"], input=rules, text=True, check=True)
        print("Rules applied successfully")

if __name__ == "__main__":
    main()
```
