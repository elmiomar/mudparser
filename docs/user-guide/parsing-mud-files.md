# Parsing MUD Files

MudParser provides multiple ways to parse MUD profiles from various sources.

## Parsing from File

The most common way to parse a MUD profile:

```python
from mudparser import MUDParser

parser = MUDParser.from_file("path/to/device.mud.json")
```

You can also use `pathlib.Path`:

```python
from pathlib import Path

parser = MUDParser.from_file(Path("device.mud.json"))
```

## Parsing from String

Parse a JSON string directly:

```python
json_string = '''
{
  "ietf-mud:mud": { ... },
  "ietf-access-control-list:access-lists": { ... }
}
'''

parser = MUDParser.from_string(json_string)
```

## Parsing from Dictionary

Parse from a Python dictionary:

```python
data = {
    "ietf-mud:mud": {
        "mud-version": 1,
        "mud-url": "https://example.com/device.json",
        # ...
    },
    "ietf-access-control-list:access-lists": {
        "acl": [...]
    }
}

parser = MUDParser.from_dict(data)
```

## Parsing from URL

Fetch and parse a MUD profile from a URL:

```python
parser = MUDParser.from_url("https://example.com/device.mud.json")
```

With options:

```python
parser = MUDParser.from_url(
    "https://example.com/device.mud.json",
    timeout=30.0,      # Request timeout in seconds
    verify_ssl=True,   # Verify SSL certificates
)
```

### Async URL Fetching

For async applications:

```python
import asyncio

async def fetch_profile():
    parser = await MUDParser.from_url_async("https://example.com/device.mud.json")
    return parser

parser = asyncio.run(fetch_profile())
```

## Parsing from File Object

Parse from an open file object:

```python
with open("device.mud.json") as f:
    parser = MUDParser.from_file_object(f)
```

## Accessing Parsed Data

### MUD Container

Access the main MUD metadata:

```python
# Version and URL
print(parser.mud.mud_version)      # 1
print(parser.mud.mud_url)          # https://example.com/device.json

# Timestamps and caching
print(parser.mud.last_update)      # datetime object
print(parser.mud.cache_validity)   # Hours (1-168)

# Device information
print(parser.mud.systeminfo)       # "My Device"
print(parser.mud.is_supported)     # True/False
print(parser.mud.mfg_name)         # Manufacturer name (optional)
print(parser.mud.model_name)       # Model name (optional)
```

### Access Control Lists

Access ACLs in the profile:

```python
# Get all ACLs
for acl in parser.profile.acls.acl:
    print(f"ACL: {acl.name}, Type: {acl.acl_type}")

# Get ACL by name
acl = parser.get_acl("from-ipv4-device")
if acl:
    print(f"Found ACL with {len(acl)} entries")

# Get ACLs by policy direction
from_acls = parser.get_from_device_acls()  # Outbound
to_acls = parser.get_to_device_acls()      # Inbound
```

### Access Control Entries

Access individual ACE rules:

```python
acl = parser.get_acl("from-ipv4-device")

for entry in acl.entries:
    print(f"ACE: {entry.name}")
    print(f"  Action: {entry.actions.forwarding}")

    # Check matches
    if entry.matches.ipv4:
        print(f"  Protocol: {entry.matches.ipv4.protocol}")
    if entry.matches.tcp:
        if entry.matches.tcp.dst_port:
            print(f"  Dest Port: {entry.matches.tcp.dst_port.port}")
```

### Get All Entries with Direction

```python
for direction, entry in parser.get_all_entries():
    print(f"[{direction}] {entry.name}: {entry.actions.forwarding}")
```

## Extracting Resources

### DNS Names

Get all DNS names referenced in the profile:

```python
dns_names = parser.get_dns_names()
print(f"Referenced hosts: {dns_names}")
# {'api.example.com', 'updates.example.com'}
```

### Ports

Get all ports referenced:

```python
ports = parser.get_ports()
print(f"TCP ports: {ports['tcp']}")  # {443, 80}
print(f"UDP ports: {ports['udp']}")  # {53}
```

## Profile Summary

Get a complete summary:

```python
summary = parser.get_summary()

print(f"Device: {summary['systeminfo']}")
print(f"Total Rules: {summary['total_rules']}")
print(f"From-Device ACLs: {summary['from_device_acls']}")
print(f"To-Device ACLs: {summary['to_device_acls']}")
```

## Printing Rules

Display rules in human-readable format:

```python
parser.print_rules()
```

Output:
```
============================================================
MUD Profile: My IoT Device
URL: https://example.com/device.json
Version: 1
Last Update: 2024-01-15T10:00:00
Supported: True
============================================================

### FROM-DEVICE POLICY (Outbound) ###

##### ACL::from-ipv4-device::START #####
Type: ipv4-acl-type

  [FROM] ALLOW TCP to api.example.com port eq 443

(implicit deny all)
##### ACL::from-ipv4-device::END #####
```

## Error Handling

Handle parsing errors appropriately:

```python
from mudparser import MUDParser
from mudparser.exceptions import (
    MUDFileNotFoundError,
    MUDSchemaError,
    MUDNetworkError,
    MUDValidationError,
)

try:
    parser = MUDParser.from_file("device.mud.json")
except MUDFileNotFoundError as e:
    print(f"File not found: {e.file_path}")
except MUDSchemaError as e:
    print(f"Invalid JSON structure: {e}")
except MUDValidationError as e:
    print(f"Validation failed: {e}")
```

For URL fetching:

```python
try:
    parser = MUDParser.from_url("https://example.com/device.json")
except MUDNetworkError as e:
    print(f"Network error: {e.message}")
    if e.status_code:
        print(f"HTTP status: {e.status_code}")
```
