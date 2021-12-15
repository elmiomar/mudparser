# Quick Start

Get started with MudParser in 5 minutes.

## Your First MUD Profile

Let's parse and analyze a MUD profile. First, create a sample MUD file:

```json title="device.mud.json"
{
  "ietf-mud:mud": {
    "mud-version": 1,
    "mud-url": "https://example.com/mydevice.json",
    "last-update": "2024-01-15T10:00:00Z",
    "cache-validity": 48,
    "is-supported": true,
    "systeminfo": "My IoT Device",
    "from-device-policy": {
      "access-lists": {
        "access-list": [{"name": "from-ipv4"}]
      }
    },
    "to-device-policy": {
      "access-lists": {
        "access-list": [{"name": "to-ipv4"}]
      }
    }
  },
  "ietf-access-control-list:access-lists": {
    "acl": [
      {
        "name": "from-ipv4",
        "type": "ipv4-acl-type",
        "aces": {
          "ace": [
            {
              "name": "allow-https-out",
              "matches": {
                "ipv4": {"protocol": 6},
                "tcp": {
                  "destination-port": {"operator": "eq", "port": 443}
                }
              },
              "actions": {"forwarding": "accept"}
            }
          ]
        }
      },
      {
        "name": "to-ipv4",
        "type": "ipv4-acl-type",
        "aces": {
          "ace": [
            {
              "name": "allow-https-response",
              "matches": {
                "ipv4": {"protocol": 6},
                "tcp": {
                  "source-port": {"operator": "eq", "port": 443}
                }
              },
              "actions": {"forwarding": "accept"}
            }
          ]
        }
      }
    ]
  }
}
```

## Parsing the Profile

```python
from mudparser import MUDParser

# Parse from file
parser = MUDParser.from_file("device.mud.json")

# Access basic information
print(f"Device: {parser.mud.systeminfo}")
print(f"MUD URL: {parser.mud.mud_url}")
print(f"Version: {parser.mud.mud_version}")
print(f"Supported: {parser.mud.is_supported}")
```

Output:
```
Device: My IoT Device
MUD URL: https://example.com/mydevice.json
Version: 1
Supported: True
```

## Exploring the Profile

```python
# Get a summary
summary = parser.get_summary()
print(f"Total ACLs: {summary['total_acls']}")
print(f"Total Rules: {summary['total_rules']}")
print(f"DNS Names: {summary['dns_names']}")
print(f"Ports: {summary['ports']}")

# List ACLs
for acl in parser.profile.acls.acl:
    print(f"ACL: {acl.name} ({acl.acl_type.value})")
    for entry in acl.entries:
        print(f"  - {entry.name}: {entry.actions.forwarding.value}")
```

## Validating the Profile

```python
# Validate for RFC 8520 compliance
errors = parser.validate()

if errors:
    print("Validation issues:")
    for error in errors:
        print(f"  - {error}")
else:
    print("Profile is valid!")

# Strict validation (raises exception on any issue)
try:
    parser.validate(strict=True)
    print("Passed strict validation!")
except MUDValidationError as e:
    print(f"Validation failed: {e}")
```

## Exporting to Firewall Rules

```python
# Export to iptables
iptables_rules = parser.export.to_iptables(device_ip="192.168.1.100")
print(iptables_rules)

# Export to nftables
nftables_rules = parser.export.to_nftables(device_ip="192.168.1.100")

# Export to Cisco ACL
cisco_rules = parser.export.to_cisco_acl()

# Export to pfSense XML
pfsense_rules = parser.export.to_pfsense(device_ip="192.168.1.100")

# Export to JSON/YAML
json_output = parser.export.to_json(indent=2)
yaml_output = parser.export.to_yaml()
```

## Using the CLI

MudParser also provides a command-line interface:

```bash
# Validate a MUD file
mudparser validate device.mud.json

# Show profile information
mudparser info device.mud.json

# Print rules in human-readable format
mudparser rules device.mud.json

# Export to iptables
mudparser export device.mud.json -f iptables -d 192.168.1.100

# Export to file
mudparser export device.mud.json -f nftables -d 192.168.1.100 -o rules.nft

# Fetch from URL
mudparser fetch https://example.com/device.mud.json --validate
```

## Next Steps

- Learn more about [parsing MUD files](user-guide/parsing-mud-files.md)
- Understand [validation options](user-guide/validation.md)
- Explore [export formats](user-guide/exporting.md)
- See the full [API reference](api-reference/parser.md)
