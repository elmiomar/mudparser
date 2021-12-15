# Basic Parsing Examples

## Parse and Display Profile Info

```python
from mudparser import MUDParser

# Parse the profile
parser = MUDParser.from_file("device.mud.json")

# Display basic info
print(f"Device: {parser.mud.systeminfo}")
print(f"MUD URL: {parser.mud.mud_url}")
print(f"Version: {parser.mud.mud_version}")
print(f"Supported: {parser.mud.is_supported}")
print(f"Cache Validity: {parser.mud.cache_validity} hours")
```

## List All ACLs and Rules

```python
from mudparser import MUDParser

parser = MUDParser.from_file("device.mud.json")

# Iterate over all ACLs
for acl in parser.profile.acls.acl:
    print(f"\nACL: {acl.name}")
    print(f"Type: {acl.acl_type.value}")
    print(f"Entries: {len(acl)}")

    for entry in acl.entries:
        action = "ALLOW" if entry.is_accept() else "DENY"
        print(f"  - [{action}] {entry.name}")
```

## Extract Network Resources

```python
from mudparser import MUDParser

parser = MUDParser.from_file("device.mud.json")

# Get all DNS names
dns_names = parser.get_dns_names()
print("DNS Names:")
for name in sorted(dns_names):
    print(f"  - {name}")

# Get all ports
ports = parser.get_ports()
print("\nTCP Ports:", sorted(ports["tcp"]))
print("UDP Ports:", sorted(ports["udp"]))
```

## Analyze Policies by Direction

```python
from mudparser import MUDParser

parser = MUDParser.from_file("device.mud.json")

# From-device (outbound) ACLs
print("=== OUTBOUND POLICIES ===")
for acl in parser.get_from_device_acls():
    print(f"\n{acl.name}:")
    for entry in acl.entries:
        desc = entry.get_description(direction="from")
        print(f"  {desc}")

# To-device (inbound) ACLs
print("\n=== INBOUND POLICIES ===")
for acl in parser.get_to_device_acls():
    print(f"\n{acl.name}:")
    for entry in acl.entries:
        desc = entry.get_description(direction="to")
        print(f"  {desc}")
```

## Check Match Details

```python
from mudparser import MUDParser

parser = MUDParser.from_file("device.mud.json")

for direction, entry in parser.get_all_entries():
    print(f"\n[{direction.upper()}] {entry.name}")

    matches = entry.matches

    # IPv4 matches
    if matches.ipv4:
        print(f"  IPv4 Protocol: {matches.ipv4.protocol}")
        if matches.ipv4.dst_dnsname:
            print(f"  Destination: {matches.ipv4.dst_dnsname}")

    # TCP matches
    if matches.tcp:
        if matches.tcp.dst_port:
            print(f"  Dest Port: {matches.tcp.dst_port}")
        if matches.tcp.direction_initiated:
            print(f"  Direction: {matches.tcp.direction_initiated.value}")

    # MUD matches
    if matches.mud:
        match_type = matches.mud.get_match_type()
        print(f"  MUD Match: {match_type}")
```

## Validate and Report

```python
from mudparser import MUDParser
from mudparser.validator import MUDValidator, ValidationSeverity

parser = MUDParser.from_file("device.mud.json")
validator = MUDValidator()

result = validator.validate(parser.profile)

print(f"Valid: {result.is_valid}")
print(f"Errors: {result.error_count}")
print(f"Warnings: {result.warning_count}")

if result.issues:
    print("\nIssues found:")
    for issue in result.issues:
        severity = issue.severity.value.upper()
        print(f"  [{severity}] {issue.message}")
```

## Convert Between Formats

```python
from mudparser import MUDParser
import json

# Parse from file
parser = MUDParser.from_file("device.mud.json")

# Convert to dictionary
data = parser.to_dict()

# Convert to JSON string
json_str = parser.to_json(indent=2)

# Convert to YAML
yaml_str = parser.export.to_yaml()

# Parse from string
parser2 = MUDParser.from_string(json_str)

# Parse from dict
parser3 = MUDParser.from_dict(data)
```

## Async URL Fetching

```python
import asyncio
from mudparser import MUDParser

async def fetch_multiple_profiles(urls):
    profiles = []
    for url in urls:
        try:
            parser = await MUDParser.from_url_async(url)
            profiles.append(parser)
            print(f"Fetched: {parser.mud.systeminfo}")
        except Exception as e:
            print(f"Failed to fetch {url}: {e}")
    return profiles

# Run async
urls = [
    "https://example.com/device1.mud.json",
    "https://example.com/device2.mud.json",
]
profiles = asyncio.run(fetch_multiple_profiles(urls))
```

## Error Handling

```python
from mudparser import MUDParser
from mudparser.exceptions import (
    MUDFileNotFoundError,
    MUDSchemaError,
    MUDValidationError,
    MUDNetworkError,
)

def safe_parse(source):
    try:
        if source.startswith("http"):
            return MUDParser.from_url(source)
        else:
            return MUDParser.from_file(source)
    except MUDFileNotFoundError as e:
        print(f"File not found: {e.file_path}")
    except MUDSchemaError as e:
        print(f"Invalid JSON: {e.message}")
    except MUDNetworkError as e:
        print(f"Network error: {e.message}")
        if e.status_code:
            print(f"HTTP Status: {e.status_code}")
    except MUDValidationError as e:
        print(f"Validation error: {e.message}")
    return None

# Usage
parser = safe_parse("device.mud.json")
if parser:
    print(f"Loaded: {parser.mud.systeminfo}")
```
