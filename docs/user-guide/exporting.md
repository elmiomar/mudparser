# Exporting

MudParser can export MUD profiles to various formats including data formats and firewall rules.

## Export Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| `json` | JSON data format | Data interchange |
| `yaml` | YAML data format | Human-readable config |
| `iptables` | Linux iptables rules | Linux firewalls |
| `nftables` | Linux nftables rules | Modern Linux firewalls |
| `cisco` | Cisco IOS ACLs | Cisco network devices |
| `pfsense` | pfSense XML | BSD firewalls |

## Basic Export

```python
from mudparser import MUDParser

parser = MUDParser.from_file("device.mud.json")

# Access the exporter
exporter = parser.export
```

## Data Format Exports

### JSON Export

```python
# Default formatting
json_output = parser.export.to_json()

# Custom formatting
json_output = parser.export.to_json(indent=4, sort_keys=True)

# Save to file
with open("output.json", "w") as f:
    f.write(parser.export.to_json())
```

### YAML Export

```python
yaml_output = parser.export.to_yaml()

# With flow style
yaml_output = parser.export.to_yaml(default_flow_style=True)
```

## Firewall Rule Exports

### iptables (Linux)

Generate iptables rules for Linux:

```python
rules = parser.export.to_iptables(
    device_ip="192.168.1.100",        # Required: Device IP
    device_interface="eth0",           # Optional: Interface
    chain_prefix="MUD",                # Optional: Chain name prefix
    include_comments=True,             # Optional: Add comments
)
print(rules)
```

Output:
```bash
#!/bin/bash
# IPTables rules generated from MUD profile
# Device: My IoT Device
# Device IP: 192.168.1.100

# Create custom chains
iptables -N MUD_FROM_MY_IOT_DEVICE 2>/dev/null || iptables -F MUD_FROM_MY_IOT_DEVICE
iptables -N MUD_TO_MY_IOT_DEVICE 2>/dev/null || iptables -F MUD_TO_MY_IOT_DEVICE

# Jump to custom chains
iptables -A FORWARD -s 192.168.1.100 -j MUD_FROM_MY_IOT_DEVICE
iptables -A FORWARD -d 192.168.1.100 -j MUD_TO_MY_IOT_DEVICE

# FROM-DEVICE rules
iptables -A MUD_FROM_MY_IOT_DEVICE -s 192.168.1.100 -p tcp -d api.example.com --dport 443 -m state --state NEW,ESTABLISHED -m comment --comment "allow-https" -j ACCEPT

# Default deny
iptables -A MUD_FROM_MY_IOT_DEVICE -j DROP
iptables -A MUD_TO_MY_IOT_DEVICE -j DROP
```

### nftables (Linux)

Generate modern nftables rules:

```python
rules = parser.export.to_nftables(
    device_ip="192.168.1.100",
    table_name="mud_rules",            # Optional: Table name
    include_comments=True,
)
```

Output:
```
#!/usr/sbin/nft -f
# nftables rules generated from MUD profile

table inet mud_rules {
    chain from_my_iot_device {
        type filter hook forward priority 0; policy drop;

        ip saddr 192.168.1.100 tcp dport 443 ct state new,established counter accept comment "allow-https"

        ip saddr 192.168.1.100 counter drop
    }
}
```

### Cisco IOS ACL

Generate Cisco IOS extended access lists:

```python
rules = parser.export.to_cisco_acl(
    acl_number_start=100,              # Optional: Starting ACL number
    include_remarks=True,              # Optional: Include remarks
)
```

Output:
```
!
! Cisco IOS ACLs generated from MUD profile
!
ip access-list extended 100
 remark MUD ACL: from-ipv4-device
 remark ACE: allow-https
 permit tcp any host api.example.com eq 443
 deny ip any any
```

### pfSense

Generate pfSense XML configuration:

```python
rules = parser.export.to_pfsense(
    device_ip="192.168.1.100",
    interface="lan",                   # Optional: Interface name
)
```

Output is XML that can be imported into pfSense.

## Generic Export Method

Use the `export()` method for any format:

```python
from mudparser.exporters import ExportFormat

# By string
output = parser.export.export("iptables", device_ip="192.168.1.100")

# By enum
output = parser.export.export(ExportFormat.NFTABLES, device_ip="192.168.1.100")
```

## CLI Export

Export from the command line:

```bash
# Export to JSON (stdout)
mudparser export device.mud.json -f json

# Export to file
mudparser export device.mud.json -f yaml -o output.yaml

# Export iptables (requires device IP)
mudparser export device.mud.json -f iptables -d 192.168.1.100

# Export nftables to file
mudparser export device.mud.json -f nftables -d 192.168.1.100 -o rules.nft

# Export Cisco ACL
mudparser export device.mud.json -f cisco

# Export pfSense
mudparser export device.mud.json -f pfsense -d 192.168.1.100 -o pfsense_rules.xml
```

## Export Summary

Get information about what will be exported:

```python
summary = parser.export.get_summary()

print(f"Device: {summary['device_info']}")
print(f"From-device rules: {summary['from_device_rules']}")
print(f"To-device rules: {summary['to_device_rules']}")
print(f"DNS names: {summary['dns_names']}")
print(f"Ports: {summary['ports']}")
print(f"Supported formats: {summary['supported_formats']}")
```

## Handling DNS Names

Note that firewall rules export DNS names as-is. For production use:

1. **iptables/nftables**: DNS names will be resolved at rule insertion time
2. **Cisco**: Use FQDN ACLs or resolve names manually
3. **pfSense**: Supports DNS aliases

Consider using tools like `dnsmasq` or network-level DNS resolution.

## Best Practices

1. **Test rules** before deploying to production
2. **Resolve DNS names** to IPs where needed
3. **Include logging** for denied traffic
4. **Review default deny** rules match your security policy
5. **Backup existing rules** before applying new ones

## Error Handling

```python
from mudparser.exceptions import MUDExportError

try:
    rules = parser.export.to_iptables(device_ip="192.168.1.100")
except MUDExportError as e:
    print(f"Export failed: {e.message}")
    print(f"Format: {e.export_format}")
```
