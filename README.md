# MudParser

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![RFC 8520](https://img.shields.io/badge/RFC-8520-green.svg)](https://datatracker.ietf.org/doc/html/rfc8520)
[![RFC 9761](https://img.shields.io/badge/RFC-9761-green.svg)](https://datatracker.ietf.org/doc/html/rfc9761)
[![Tests](https://img.shields.io/badge/tests-90%20passed-brightgreen.svg)]()
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

A production-grade Python library for parsing, validating, and exporting **Manufacturer Usage Description (MUD)** profiles as defined in [RFC 8520](https://datatracker.ietf.org/doc/html/rfc8520) with full support for [RFC 9761](https://datatracker.ietf.org/doc/html/rfc9761) TLS/DTLS profiles.

MUD profiles allow IoT device manufacturers to formally describe the network behavior their devices require, enabling network administrators to automatically configure access control policies and significantly reduce the attack surface of IoT deployments.

---

## Table of Contents

- [What is MUD?](#what-is-mud)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Detailed Usage Guide](#detailed-usage-guide)
  - [Parsing MUD Files](#parsing-mud-files)
  - [Accessing Profile Data](#accessing-profile-data)
  - [Working with ACLs and ACEs](#working-with-acls-and-aces)
  - [Validation](#validation)
  - [Exporting to Firewall Rules](#exporting-to-firewall-rules)
- [Command Line Interface](#command-line-interface)
- [Interactive Web Demo](#interactive-web-demo)
- [RFC Compliance](#rfc-compliance)
- [Sample MUD Profiles](#sample-mud-profiles)
- [API Reference](#api-reference)
- [Architecture](#architecture)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## What is MUD?

**Manufacturer Usage Description (MUD)** is an IETF standard ([RFC 8520](https://datatracker.ietf.org/doc/html/rfc8520)) that provides a formal way for IoT device manufacturers to describe the intended network behavior of their devices.

### The Problem MUD Solves

IoT devices often have well-defined, limited network communication patterns. However, without formal descriptions:
- Network administrators don't know what traffic is legitimate
- Devices may be over-permissioned on the network
- Compromised devices can be used to attack other systems
- Manual firewall configuration is error-prone and time-consuming

### How MUD Works

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  IoT Device │────>│ MUD Manager │────>│  Firewall   │
│  (sends URL)│     │  (fetches)  │     │  (enforces) │
└─────────────┘     └──────┬──────┘     └─────────────┘
                          │
                          v
                   ┌─────────────┐
                   │  MUD File   │
                   │  (on web)   │
                   └─────────────┘
```

1. **Device Announcement**: IoT device announces its MUD URL (via DHCP, LLDP, or 802.1X)
2. **Profile Fetch**: MUD manager fetches the MUD file from the URL
3. **Policy Generation**: MUD file is parsed and converted to firewall rules
4. **Enforcement**: Rules are applied to restrict device communication

### MUD File Structure

A MUD file is a JSON document containing:
- **Metadata**: Device info, update timestamps, support status
- **Access Control Lists (ACLs)**: Network communication rules
- **Policy References**: Which ACLs apply to inbound/outbound traffic

---

## Features

### Core Capabilities

| Feature | Description |
|---------|-------------|
| **RFC 8520 Compliant** | Full implementation of the MUD specification |
| **RFC 9761 Support** | TLS/DTLS profile extensions for secure communications |
| **Modern Python** | Built for Python 3.10+ with type hints and Pydantic v2 |
| **Multiple Input Sources** | Parse from files, strings, URLs, or dictionaries |
| **Async Support** | Asynchronous URL fetching for high-performance applications |

### Validation

| Feature | Description |
|---------|-------------|
| **Schema Validation** | Validates against RFC 8520 JSON schema |
| **Semantic Validation** | Cross-reference checking, constraint validation |
| **Severity Levels** | Errors, warnings, and informational messages |
| **Detailed Reporting** | Path-specific error messages with context |

### Export Formats

| Format | Platform | Use Case |
|--------|----------|----------|
| **iptables** | Linux | Traditional Linux firewall |
| **nftables** | Linux | Modern Linux firewall (netfilter) |
| **Cisco ACL** | Cisco IOS | Enterprise routers and switches |
| **pfSense** | BSD/pfSense | BSD-based firewalls |
| **JSON** | Any | Re-serialization, APIs |
| **YAML** | Any | Human-readable configuration |

### User Interfaces

| Interface | Description |
|-----------|-------------|
| **Python API** | Full-featured library for programmatic access |
| **CLI** | Rich command-line interface with syntax highlighting |
| **Web Demo** | Interactive Streamlit application |

---

## Installation

### Requirements

- **Python 3.10 or higher** (uses modern features like match/case, union types)
- **pip** package manager

### Basic Installation

```bash
pip install mudparser
```

### Installation with Extras

```bash
# Development tools (pytest, mypy, ruff)
pip install mudparser[dev]

# Documentation tools (mkdocs, mkdocstrings)
pip install mudparser[docs]

# Demo application (streamlit)
pip install mudparser[demo]

# All extras
pip install mudparser[all]
```

### Installation from Source

```bash
# Clone the repository
git clone https://github.com/elmiomar/mudparser.git
cd mudparser

# Install in development mode
pip install -e .

# Or with all extras
pip install -e ".[all]"
```

### Verify Installation

```bash
# Check version
mudparser --version

# Run a quick test
mudparser --help
```

---

## Quick Start

### 30-Second Example

```python
from mudparser import MUDParser

# Parse a MUD file
parser = MUDParser.from_file("device.mud.json")

# Get device info
print(f"Device: {parser.mud.systeminfo}")
print(f"Rules: {parser.get_summary()['total_rules']}")

# Generate firewall rules
rules = parser.export.to_iptables(device_ip="192.168.1.100")
print(rules)
```

### CLI Quick Start

```bash
# View profile information
mudparser info device.mud.json

# Validate a profile
mudparser validate device.mud.json

# Export to iptables
mudparser export device.mud.json -f iptables -d 192.168.1.100
```

---

## Detailed Usage Guide

### Parsing MUD Files

#### From a Local File

```python
from mudparser import MUDParser

# Parse from file path (string or Path object)
parser = MUDParser.from_file("path/to/device.mud.json")

# With pathlib
from pathlib import Path
parser = MUDParser.from_file(Path("data") / "device.mud.json")
```

#### From a JSON String

```python
from mudparser import MUDParser

json_content = '''
{
    "ietf-mud:mud": {
        "mud-version": 1,
        "mud-url": "https://example.com/device.mud.json",
        "last-update": "2024-01-15T00:00:00Z",
        "cache-validity": 48,
        "is-supported": true,
        "systeminfo": "My IoT Device",
        "from-device-policy": { ... },
        "to-device-policy": { ... }
    },
    "ietf-access-control-list:access-lists": { ... }
}
'''

parser = MUDParser.from_string(json_content, source="inline")
```

#### From a URL

```python
from mudparser import MUDParser

# Synchronous fetch
parser = MUDParser.from_url("https://iotanalytics.unsw.edu.au/mud/amazonEchoMud.json")

# Asynchronous fetch (for high-performance applications)
import asyncio

async def fetch_profile():
    parser = await MUDParser.from_url_async(
        "https://iotanalytics.unsw.edu.au/mud/amazonEchoMud.json"
    )
    return parser

parser = asyncio.run(fetch_profile())
```

#### From a Dictionary

```python
from mudparser import MUDParser

data = {
    "ietf-mud:mud": {
        "mud-version": 1,
        "mud-url": "https://example.com/device.mud.json",
        "last-update": "2024-01-15T00:00:00Z",
        "cache-validity": 48,
        "is-supported": True,
        "systeminfo": "My IoT Device",
        "from-device-policy": {
            "access-lists": {
                "access-list": [{"name": "from-device-acl"}]
            }
        },
        "to-device-policy": {
            "access-lists": {
                "access-list": [{"name": "to-device-acl"}]
            }
        }
    },
    "ietf-access-control-list:access-lists": {
        "acl": [
            # ... ACL definitions
        ]
    }
}

parser = MUDParser.from_dict(data, source="programmatic")
```

### Accessing Profile Data

#### MUD Container (Metadata)

```python
from mudparser import MUDParser

parser = MUDParser.from_file("device.mud.json")

# Core metadata (always present)
print(f"MUD Version: {parser.mud.mud_version}")          # 1
print(f"MUD URL: {parser.mud.mud_url}")                  # https://...
print(f"Last Update: {parser.mud.last_update}")          # datetime object
print(f"Cache Validity: {parser.mud.cache_validity}h")   # Hours (1-168)
print(f"Is Supported: {parser.mud.is_supported}")        # True/False
print(f"System Info: {parser.mud.systeminfo}")           # Device description

# Optional metadata
print(f"Manufacturer: {parser.mud.mfg_name}")            # May be None
print(f"Model: {parser.mud.model_name}")                 # May be None
print(f"Firmware: {parser.mud.firmware_rev}")            # May be None
print(f"Software: {parser.mud.software_rev}")            # May be None
print(f"Documentation: {parser.mud.documentation}")      # URL or None
print(f"MUD Signature: {parser.mud.mud_signature}")      # Signature URL
print(f"Extensions: {parser.mud.extensions}")            # List of extensions
```

#### Profile Summary

```python
summary = parser.get_summary()

print(f"URL: {summary['url']}")
print(f"Version: {summary['version']}")
print(f"Device: {summary['systeminfo']}")
print(f"Last Update: {summary['last_update']}")
print(f"Cache Validity: {summary['cache_validity_hours']} hours")
print(f"Supported: {summary['is_supported']}")
print(f"Manufacturer: {summary['manufacturer']}")
print(f"Model: {summary['model']}")

# Rule counts
print(f"Total ACLs: {summary['total_acls']}")
print(f"From-Device ACLs: {summary['from_device_acls']}")
print(f"To-Device ACLs: {summary['to_device_acls']}")
print(f"Total Rules: {summary['total_rules']}")
print(f"From-Device Rules: {summary['from_device_rules']}")
print(f"To-Device Rules: {summary['to_device_rules']}")

# Network resources
print(f"DNS Names: {summary['dns_names']}")
print(f"TCP Ports: {summary['ports']['tcp']}")
print(f"UDP Ports: {summary['ports']['udp']}")
```

#### Extracting Network Resources

```python
# Get all DNS names referenced in the profile
dns_names = parser.get_dns_names()
print("DNS Names:")
for name in sorted(dns_names):
    print(f"  - {name}")

# Get all ports used
ports = parser.get_ports()
print(f"TCP Ports: {sorted(ports['tcp'])}")
print(f"UDP Ports: {sorted(ports['udp'])}")

# Get all ACE entries with direction
for direction, entry in parser.get_all_entries():
    print(f"[{direction}] {entry.name}: {entry.get_description(direction)}")
```

### Working with ACLs and ACEs

#### Iterating Over ACLs

```python
# Get all ACLs
for acl in parser.profile.acls.acl:
    print(f"\nACL: {acl.name}")
    print(f"  Type: {acl.acl_type.value}")  # ipv4-acl-type, ipv6-acl-type, etc.
    print(f"  Rules: {len(acl)}")

# Get ACLs by direction
print("\n=== FROM-DEVICE (Outbound) ===")
for acl in parser.get_from_device_acls():
    print(f"  {acl.name}: {len(acl)} rules")

print("\n=== TO-DEVICE (Inbound) ===")
for acl in parser.get_to_device_acls():
    print(f"  {acl.name}: {len(acl)} rules")
```

#### Working with ACL Entries (ACEs)

```python
for acl in parser.profile.acls.acl:
    print(f"\nACL: {acl.name}")

    for entry in acl.entries:
        # Basic info
        print(f"  Rule: {entry.name}")

        # Action
        if entry.is_accept():
            print("    Action: ALLOW")
        else:
            print("    Action: DENY")

        # Get human-readable description
        desc = entry.get_description(direction="from")
        print(f"    Description: {desc}")

        # Access match conditions
        matches = entry.matches

        # Protocol information
        protocol = matches.get_protocol()
        print(f"    Protocol: {protocol}")

        # DNS names in this rule
        dns_names = matches.get_dns_names()
        if dns_names:
            print(f"    DNS Names: {dns_names}")
```

#### Accessing Match Details

```python
for acl in parser.profile.acls.acl:
    for entry in acl.entries:
        matches = entry.matches

        # IPv4 matches
        if matches.ipv4:
            print(f"  IPv4 Protocol: {matches.ipv4.protocol}")
            if matches.ipv4.src_network:
                print(f"  Source Network: {matches.ipv4.src_network}")
            if matches.ipv4.dst_network:
                print(f"  Dest Network: {matches.ipv4.dst_network}")
            if matches.ipv4.src_dnsname:
                print(f"  Source DNS: {matches.ipv4.src_dnsname}")
            if matches.ipv4.dst_dnsname:
                print(f"  Dest DNS: {matches.ipv4.dst_dnsname}")

        # IPv6 matches
        if matches.ipv6:
            print(f"  IPv6 Protocol: {matches.ipv6.protocol}")
            if matches.ipv6.dst_network:
                print(f"  Dest Network: {matches.ipv6.dst_network}")

        # TCP matches
        if matches.tcp:
            if matches.tcp.src_port:
                print(f"  TCP Source Port: {matches.tcp.src_port}")
            if matches.tcp.dst_port:
                print(f"  TCP Dest Port: {matches.tcp.dst_port}")
            if matches.tcp.direction_initiated:
                print(f"  Direction: {matches.tcp.direction_initiated.value}")

        # UDP matches
        if matches.udp:
            if matches.udp.src_port:
                print(f"  UDP Source Port: {matches.udp.src_port}")
            if matches.udp.dst_port:
                print(f"  UDP Dest Port: {matches.udp.dst_port}")

        # ICMP matches
        if matches.icmp:
            print(f"  ICMP Type: {matches.icmp.type}, Code: {matches.icmp.code}")

        # Ethernet matches
        if matches.eth:
            if matches.eth.src_mac:
                print(f"  Source MAC: {matches.eth.src_mac}")
            if matches.eth.dst_mac:
                print(f"  Dest MAC: {matches.eth.dst_mac}")
            if matches.eth.ethertype:
                print(f"  Ethertype: {matches.eth.ethertype}")

        # MUD-specific matches
        if matches.mud:
            match_type = matches.mud.get_match_type()
            print(f"  MUD Match Type: {match_type}")
            if matches.mud.manufacturer:
                print(f"  Manufacturer: {matches.mud.manufacturer}")
            if matches.mud.controller:
                print(f"  Controller: {matches.mud.controller}")
            if matches.mud.local_networks:
                print("  Local Networks: Yes")
            if matches.mud.same_manufacturer:
                print("  Same Manufacturer: Yes")
```

### Validation

#### Basic Validation

```python
from mudparser import MUDParser

parser = MUDParser.from_file("device.mud.json")

# Simple validation (returns list of error strings)
errors = parser.validate()

if errors:
    print("Validation FAILED:")
    for error in errors:
        print(f"  - {error}")
else:
    print("Validation PASSED!")
```

#### Detailed Validation

```python
from mudparser import MUDParser
from mudparser.validator import MUDValidator, ValidationSeverity

parser = MUDParser.from_file("device.mud.json")
validator = MUDValidator()

# Full validation with detailed results
result = validator.validate(parser.profile)

# Summary
print(f"Valid: {result.is_valid}")
print(f"Total Issues: {len(result.issues)}")
print(f"Errors: {result.error_count}")
print(f"Warnings: {result.warning_count}")

# Detailed issues
for issue in result.issues:
    severity_icon = {
        ValidationSeverity.ERROR: "ERROR",
        ValidationSeverity.WARNING: "WARNING",
        ValidationSeverity.INFO: "INFO"
    }[issue.severity]

    print(f"[{severity_icon}] {issue.message}")
    if issue.path:
        print(f"         Path: {issue.path}")

# Get only errors
for error in result.errors:
    print(f"Error: {error.message}")

# Get only warnings
for warning in result.warnings:
    print(f"Warning: {warning.message}")
```

#### Strict Mode Validation

```python
# Strict mode treats warnings as errors
result = validator.validate(parser.profile, strict=True)

if not result.is_valid:
    print("Profile has errors or warnings in strict mode")
```

#### Convenience Functions

```python
from mudparser.validator import validate_profile, validate_json

# Validate a MUDProfile object
result = validate_profile(parser.profile)

# Validate raw JSON data
result = validate_json({
    "ietf-mud:mud": { ... },
    "ietf-access-control-list:access-lists": { ... }
})
```

### Exporting to Firewall Rules

#### iptables Export

```python
from mudparser import MUDParser

parser = MUDParser.from_file("device.mud.json")

# Basic export
rules = parser.export.to_iptables(device_ip="192.168.1.100")

# With options
rules = parser.export.to_iptables(
    device_ip="192.168.1.100",
    chain_prefix="IOT",           # Custom chain prefix (default: MUD)
    include_comments=True,        # Include rule comments (default: True)
)

print(rules)

# Save to file
with open("firewall_rules.sh", "w") as f:
    f.write(rules)
```

**Example iptables output:**

```bash
#!/bin/bash
# IPTables rules generated from MUD profile
# Device: Amazon Echo
# MUD URL: https://example.com/echo.mud.json
# Device IP: 192.168.1.100

# Create custom chains
iptables -N IOT_FROM_ECHO 2>/dev/null || iptables -F IOT_FROM_ECHO
iptables -N IOT_TO_ECHO 2>/dev/null || iptables -F IOT_TO_ECHO

# Jump to custom chains
iptables -A FORWARD -s 192.168.1.100 -j IOT_FROM_ECHO
iptables -A FORWARD -d 192.168.1.100 -j IOT_TO_ECHO

# FROM-DEVICE rules (outbound traffic from IoT device)
iptables -A IOT_FROM_ECHO -s 192.168.1.100 -p tcp -d api.amazon.com --dport 443 \
    -m state --state NEW,ESTABLISHED -m comment --comment "allow-https-api" -j ACCEPT

# Default deny
iptables -A IOT_FROM_ECHO -j DROP
iptables -A IOT_TO_ECHO -j DROP
```

#### nftables Export

```python
rules = parser.export.to_nftables(
    device_ip="192.168.1.100",
    table_name="iot_devices",     # Custom table name (default: mud_filter)
)

# Save to file
with open("rules.nft", "w") as f:
    f.write(rules)

# Apply with: nft -f rules.nft
```

**Example nftables output:**

```
#!/usr/sbin/nft -f
# nftables rules generated from MUD profile
# Device: Amazon Echo

table inet iot_devices {
    chain from_echo {
        type filter hook forward priority 0; policy drop;

        ip saddr 192.168.1.100 tcp dport 443 ip daddr api.amazon.com accept
        ip saddr 192.168.1.100 udp dport 53 accept
    }

    chain to_echo {
        type filter hook forward priority 0; policy drop;

        ip daddr 192.168.1.100 tcp sport 443 ip saddr api.amazon.com accept
    }
}
```

#### Cisco ACL Export

```python
rules = parser.export.to_cisco_acl(
    acl_number_start=100,         # Starting ACL number (default: 100)
    include_remarks=True,         # Include remark statements (default: True)
)

print(rules)
```

**Example Cisco ACL output:**

```
! Cisco ACL generated from MUD profile
! Device: Amazon Echo
! MUD URL: https://example.com/echo.mud.json

! FROM-DEVICE ACL (outbound from IoT device)
access-list 100 remark MUD profile: Amazon Echo - from-device
access-list 100 permit tcp any host api.amazon.com eq 443
access-list 100 permit udp any any eq 53
access-list 100 deny ip any any

! TO-DEVICE ACL (inbound to IoT device)
access-list 101 remark MUD profile: Amazon Echo - to-device
access-list 101 permit tcp host api.amazon.com eq 443 any
access-list 101 deny ip any any
```

#### pfSense XML Export

```python
rules = parser.export.to_pfsense(
    device_ip="192.168.1.100",
    interface="lan",              # Interface name (default: lan)
)

# Save to file for import
with open("pfsense_rules.xml", "w") as f:
    f.write(rules)
```

#### JSON/YAML Export

```python
# JSON export (re-serialized MUD profile)
json_output = parser.export.to_json(indent=2)

# YAML export (human-readable)
yaml_output = parser.export.to_yaml()
```

#### Generic Export Interface

```python
from mudparser.exporters import ExportFormat

# Export using format enum
output = parser.export.export(
    format=ExportFormat.IPTABLES,
    device_ip="192.168.1.100"
)

# Export using format string
output = parser.export.export(
    format="nftables",
    device_ip="192.168.1.100"
)

# Available formats
for fmt in ExportFormat:
    print(f"  - {fmt.value}")
```

#### Export Summary

```python
# Get export summary before generating rules
summary = parser.export.get_summary()

print(f"Device: {summary['device_info']}")
print(f"From-Device Rules: {summary['from_device_rules']}")
print(f"To-Device Rules: {summary['to_device_rules']}")
print(f"Total Rules: {summary['total_rules']}")
print(f"DNS Names: {summary['dns_names']}")
print(f"Ports: {summary['ports']}")
print(f"Supported Formats: {summary['supported_formats']}")
```

---

## Command Line Interface

The `mudparser` CLI provides a rich, user-friendly interface for working with MUD profiles.

### Available Commands

| Command | Description |
|---------|-------------|
| `validate` | Validate a MUD profile against RFC 8520 |
| `info` | Display profile information and summary |
| `rules` | Show access control rules in human-readable format |
| `export` | Export to firewall rule format |
| `fetch` | Fetch a MUD profile from URL |
| `diff` | Compare two MUD profiles |
| `demo` | Launch interactive Streamlit demo |

### Command: `validate`

Validate a MUD profile for RFC compliance.

```bash
# Basic validation
mudparser validate device.mud.json

# Verbose output (show all issues including warnings)
mudparser validate device.mud.json --verbose

# Strict mode (treat warnings as errors)
mudparser validate device.mud.json --strict

# JSON output (for scripting)
mudparser validate device.mud.json --json
```

### Command: `info`

Display profile information and summary.

```bash
# Show profile info
mudparser info device.mud.json

# JSON output
mudparser info device.mud.json --json
```

**Example output:**

```
╭──────────────────────────────── MUD Profile ─────────────────────────────────╮
│ Amazon Echo                                                                   │
│ URL: https://amazonecho.com/amazonecho                                        │
╰──────────────────────────────────────────────────────────────────────────────╯
                  Profile Metadata
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property       ┃ Value                            ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ MUD Version    │ 1                                │
│ Last Update    │ 2024-01-15T00:00:00+00:00        │
│ Cache Validity │ 48 hours                         │
│ Supported      │ Yes                              │
└────────────────┴──────────────────────────────────┘
         Access Control Summary
┏━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━┓
┃ Direction              ┃ ACLs ┃ Rules ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━┩
│ From Device (Outbound) │ 2    │ 15    │
│ To Device (Inbound)    │ 1    │ 8     │
│ Total                  │ 3    │ 23    │
└────────────────────────┴──────┴───────┘

Referenced DNS Names:
  - api.amazonalexa.com
  - device-metrics-us.amazon.com
  - softwareupdates.amazon.com

Referenced Ports:
  TCP: 80, 443
  UDP: 53, 123
```

### Command: `rules`

Show access control rules in human-readable format.

```bash
# Show all rules
mudparser rules device.mud.json

# Show only from-device (outbound) rules
mudparser rules device.mud.json --direction from

# Show only to-device (inbound) rules
mudparser rules device.mud.json --direction to

# JSON output
mudparser rules device.mud.json --json
```

### Command: `export`

Export to firewall rule format.

```bash
# Export to iptables
mudparser export device.mud.json -f iptables -d 192.168.1.100

# Export to nftables with custom table name
mudparser export device.mud.json -f nftables -d 192.168.1.100

# Export to Cisco ACL
mudparser export device.mud.json -f cisco

# Export to pfSense
mudparser export device.mud.json -f pfsense -d 192.168.1.100

# Save to file
mudparser export device.mud.json -f iptables -d 192.168.1.100 -o rules.sh

# Available formats: iptables, nftables, cisco, pfsense, json, yaml
```

### Command: `fetch`

Fetch a MUD profile from URL.

```bash
# Fetch and display info
mudparser fetch https://iotanalytics.unsw.edu.au/mud/amazonEchoMud.json

# Fetch and save to file
mudparser fetch https://example.com/device.mud.json -o device.mud.json

# Fetch and validate
mudparser fetch https://example.com/device.mud.json --validate
```

### Command: `diff`

Compare two MUD profiles.

```bash
# Compare two profiles
mudparser diff old.mud.json new.mud.json

# Show only changes in rules
mudparser diff old.mud.json new.mud.json --rules-only
```

### Command: `demo`

Launch the interactive Streamlit web demo.

```bash
# Launch on default port (8501)
mudparser demo

# Launch on custom port
mudparser demo --port 8080
```

### Global Options

```bash
# Show version
mudparser --version

# Show help
mudparser --help

# Show help for a specific command
mudparser validate --help
```

---

## Interactive Web Demo

MudParser includes an interactive Streamlit web application for exploring MUD profiles.

### Launching the Demo

```bash
# Via CLI
mudparser demo

# Directly with Streamlit
streamlit run demo/streamlit_app.py

# On a custom port
mudparser demo --port 8080
```

### Demo Features

1. **Load Profiles**: Upload files, paste JSON, or use built-in samples
2. **Overview Tab**: Device info, metadata, and rule summaries
3. **Rules Tab**: Interactive ACL/ACE browser with filtering
4. **Validation Tab**: Detailed validation results with severity levels
5. **Export Tab**: Generate and download firewall rules
6. **Raw JSON Tab**: View and download the original profile

### Screenshots

The demo provides:
- Visual representation of ACLs and rules
- Color-coded action indicators (ALLOW/DENY)
- Interactive export with format selection
- Real-time validation feedback

---

## RFC Compliance

### RFC 8520 - Manufacturer Usage Description Specification

MudParser fully implements RFC 8520, including:

#### MUD Container

| Field | Status | Description |
|-------|--------|-------------|
| `mud-version` | ✅ | MUD specification version |
| `mud-url` | ✅ | URL of this MUD file |
| `mud-signature` | ✅ | URL of PKCS#7 signature |
| `last-update` | ✅ | Last modification timestamp |
| `cache-validity` | ✅ | Hours this file can be cached (1-168) |
| `is-supported` | ✅ | Whether device is still supported |
| `systeminfo` | ✅ | Device description (max 60 chars) |
| `mfg-name` | ✅ | Manufacturer name |
| `model-name` | ✅ | Model name |
| `firmware-rev` | ✅ | Firmware revision |
| `software-rev` | ✅ | Software revision |
| `documentation` | ✅ | Documentation URL |
| `extensions` | ✅ | List of MUD extensions |
| `from-device-policy` | ✅ | Outbound traffic policy |
| `to-device-policy` | ✅ | Inbound traffic policy |

#### Access Control Lists (RFC 8519)

| Feature | Status | Description |
|---------|--------|-------------|
| IPv4 ACL | ✅ | IPv4 access control list |
| IPv6 ACL | ✅ | IPv6 access control list |
| Ethernet ACL | ✅ | Layer 2 access control list |

#### Match Types

| Match Type | Status | Fields |
|------------|--------|--------|
| IPv4 | ✅ | protocol, src/dst network, src/dst DNS name, DSCP, ECN, length, TTL, flags |
| IPv6 | ✅ | protocol, src/dst network, src/dst DNS name, DSCP, ECN, flow-label, length, hop-limit |
| TCP | ✅ | src/dst port (with operators), flags, direction-initiated |
| UDP | ✅ | src/dst port (with operators) |
| ICMP | ✅ | type, code |
| ICMPv6 | ✅ | type, code |
| Ethernet | ✅ | src/dst MAC address, ethertype |

#### MUD-Specific Extensions

| Extension | Status | Description |
|-----------|--------|-------------|
| `manufacturer` | ✅ | Match by manufacturer domain |
| `same-manufacturer` | ✅ | Match devices from same manufacturer |
| `model` | ✅ | Match by model URI |
| `local-networks` | ✅ | Match local network traffic |
| `controller` | ✅ | Match MUD controller (dns, ntp, gateway) |
| `my-controller` | ✅ | Match custom controller URIs |

#### Port Operators

| Operator | Status | Description |
|----------|--------|-------------|
| `eq` | ✅ | Equals |
| `lt` | ✅ | Less than |
| `gt` | ✅ | Greater than |
| `neq` | ✅ | Not equal |
| `range` | ✅ | Port range |

### RFC 9761 - MUD for TLS/DTLS Profiles

MudParser supports RFC 9761 TLS profile extensions:

| Feature | Status | Description |
|---------|--------|-------------|
| TLS version constraints | ✅ | Minimum/maximum TLS versions |
| Cipher suite restrictions | ✅ | Allowed/forbidden cipher suites |
| SPKI pin sets | ✅ | Certificate pinning with SPKI hashes |
| Client authentication | ✅ | Client certificate requirements |
| Server authentication | ✅ | Server certificate requirements |
| DTLS profiles | ✅ | DTLS-specific settings |

---

## Sample MUD Profiles

MudParser includes several sample MUD profiles for testing:

| File | Device | Description |
|------|--------|-------------|
| `data/amazon_echo.json` | Amazon Echo | Full profile with many rules |
| `data/amazon_echo_short.json` | Amazon Echo | Simplified version |
| `data/ring_doorbell.json` | Ring Doorbell | Smart doorbell profile |
| `data/philips_hue_bulb.json` | Philips Hue | Smart light bulb profile |
| `data/nest_smoke_sensor.json` | Nest Protect | Smoke/CO detector profile |

### Testing with Sample Profiles

```bash
# View Amazon Echo profile
mudparser info data/amazon_echo_short.json

# Validate Ring Doorbell
mudparser validate data/ring_doorbell.json

# Export Philips Hue to iptables
mudparser export data/philips_hue_bulb.json -f iptables -d 192.168.1.100

# Compare profiles
mudparser diff data/amazon_echo_short.json data/amazon_echo.json
```

### Online MUD Profile Sources

- [UNSW IoT Analytics](https://iotanalytics.unsw.edu.au/mudprofiles.html) - 28 real device profiles
- [NIST MUD-PD](https://github.com/usnistgov/MUD-PD) - MUD profile generator
- [Community MUD Files](https://github.com/iot-onboarding/mudfiles) - Crowd-sourced profiles

---

## API Reference

### Main Classes

#### `MUDParser`

The main entry point for parsing MUD files.

```python
class MUDParser:
    # Class methods for parsing
    @classmethod
    def from_file(cls, path: str | Path, source: str = None) -> MUDParser

    @classmethod
    def from_string(cls, content: str, source: str = None) -> MUDParser

    @classmethod
    def from_url(cls, url: str, timeout: float = 30.0) -> MUDParser

    @classmethod
    async def from_url_async(cls, url: str, timeout: float = 30.0) -> MUDParser

    @classmethod
    def from_dict(cls, data: dict, source: str = None) -> MUDParser

    # Properties
    @property
    def mud(self) -> MUD  # MUD container

    @property
    def profile(self) -> MUDProfile  # Full profile

    @property
    def export(self) -> MUDExporter  # Exporter interface

    # Methods
    def validate(self, strict: bool = False) -> list[str]
    def get_summary(self) -> dict[str, Any]
    def get_acl(self, name: str) -> AccessControlList | None
    def get_from_device_acls(self) -> list[AccessControlList]
    def get_to_device_acls(self) -> list[AccessControlList]
    def get_dns_names(self) -> set[str]
    def get_ports(self) -> dict[str, set[int]]
    def get_all_entries(self) -> Iterator[tuple[str, AccessControlEntry]]
    def to_dict(self) -> dict
    def to_json(self, indent: int = None) -> str
```

#### `MUDValidator`

Validation engine with detailed results.

```python
class MUDValidator:
    def validate(
        self,
        profile: MUDProfile,
        strict: bool = False
    ) -> ValidationResult

class ValidationResult:
    is_valid: bool
    issues: list[ValidationIssue]
    error_count: int
    warning_count: int
    errors: list[ValidationIssue]  # Property
    warnings: list[ValidationIssue]  # Property
    def to_dict(self) -> dict

class ValidationIssue:
    severity: ValidationSeverity
    message: str
    path: str | None

class ValidationSeverity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
```

#### `MUDExporter`

Export interface for generating firewall rules.

```python
class MUDExporter:
    def to_json(self, indent: int = None) -> str
    def to_yaml(self) -> str
    def to_iptables(
        self,
        device_ip: str,
        chain_prefix: str = "MUD",
        include_comments: bool = True
    ) -> str
    def to_nftables(
        self,
        device_ip: str,
        table_name: str = "mud_filter"
    ) -> str
    def to_cisco_acl(
        self,
        acl_number_start: int = 100,
        include_remarks: bool = True
    ) -> str
    def to_pfsense(
        self,
        device_ip: str,
        interface: str = "lan"
    ) -> str
    def export(
        self,
        format: str | ExportFormat,
        **kwargs
    ) -> str
    def get_summary(self) -> dict[str, Any]
```

### Data Models

#### `MUD` (Container)

```python
class MUD(BaseModel):
    mud_version: int
    mud_url: HttpUrl
    mud_signature: HttpUrl | None
    last_update: datetime
    cache_validity: int  # 1-168 hours
    is_supported: bool
    systeminfo: str | None
    mfg_name: str | None
    model_name: str | None
    firmware_rev: str | None
    software_rev: str | None
    documentation: HttpUrl | None
    extensions: list[str]
    from_device_policy: PolicyReference
    to_device_policy: PolicyReference
```

#### `AccessControlList`

```python
class AccessControlList(BaseModel):
    name: str
    acl_type: ACLType
    aces: ACEs

    @property
    def entries(self) -> list[AccessControlEntry]

    def is_ipv4(self) -> bool
    def is_ipv6(self) -> bool
    def is_ethernet(self) -> bool
    def get_accept_rules(self) -> list[AccessControlEntry]
    def get_deny_rules(self) -> list[AccessControlEntry]
```

#### `AccessControlEntry`

```python
class AccessControlEntry(BaseModel):
    name: str
    matches: ACEMatches
    actions: ACEActions

    def is_accept(self) -> bool
    def is_deny(self) -> bool
    def get_description(self, direction: str = "from") -> str
```

### Exceptions

```python
class MUDParserError(Exception):
    """Base exception for all MUD parser errors."""

class MUDFileNotFoundError(MUDParserError):
    """Raised when a MUD file is not found."""
    file_path: str

class MUDSchemaError(MUDParserError):
    """Raised when JSON structure is invalid."""
    message: str

class MUDValidationError(MUDParserError):
    """Raised when validation fails."""
    message: str
    errors: list[str]

class MUDNetworkError(MUDParserError):
    """Raised when network operations fail."""
    message: str
    url: str | None
    status_code: int | None
```

---

## Architecture

### Project Structure

```
mudparser/
├── pyproject.toml              # Modern Python packaging
├── README.md                   # This file
├── CHANGELOG.md                # Version history
├── LICENSE                     # MIT License
│
├── src/mudparser/              # Main package (src layout)
│   ├── __init__.py             # Package exports
│   ├── __main__.py             # CLI entry point
│   ├── parser.py               # MUDParser class
│   ├── validator.py            # Validation engine
│   ├── cli.py                  # Typer CLI application
│   ├── exceptions.py           # Custom exceptions
│   │
│   ├── models/                 # Pydantic data models
│   │   ├── __init__.py
│   │   ├── mud.py              # MUD container model
│   │   ├── acl.py              # ACL models
│   │   ├── ace.py              # ACE models
│   │   ├── matches.py          # Match condition models
│   │   └── tls.py              # RFC 9761 TLS models
│   │
│   └── exporters/              # Export implementations
│       ├── __init__.py
│       ├── base.py             # MUDExporter class
│       ├── iptables.py         # iptables generator
│       ├── nftables.py         # nftables generator
│       ├── cisco.py            # Cisco ACL generator
│       └── pfsense.py          # pfSense XML generator
│
├── tests/                      # Test suite
│   ├── conftest.py             # Pytest fixtures
│   ├── test_parser.py
│   ├── test_models.py
│   ├── test_validator.py
│   └── test_exporter.py
│
├── docs/                       # MkDocs documentation
│   ├── index.md
│   ├── installation.md
│   ├── quickstart.md
│   └── ...
│
├── examples/                   # Example scripts
│   ├── basic_usage.py
│   └── export_to_firewall.py
│
├── demo/                       # Streamlit demo app
│   └── streamlit_app.py
│
└── data/                       # Sample MUD profiles
    ├── amazon_echo.json
    ├── ring_doorbell.json
    └── ...
```

### Design Principles

1. **Type Safety**: Full type hints with Pydantic v2 for runtime validation
2. **RFC Compliance**: Strict adherence to RFC 8520 and RFC 9761
3. **Extensibility**: Easy to add new export formats
4. **Testability**: High test coverage with comprehensive fixtures
5. **User Experience**: Rich CLI with helpful error messages

### Dependencies

#### Runtime

| Package | Purpose |
|---------|---------|
| `pydantic>=2.0` | Data validation and models |
| `httpx>=0.25` | HTTP client for URL fetching |
| `pyyaml>=6.0` | YAML export |
| `typer>=0.9` | CLI framework |
| `rich>=13.0` | Terminal formatting |

#### Development

| Package | Purpose |
|---------|---------|
| `pytest>=7.0` | Testing framework |
| `pytest-cov>=4.0` | Coverage reporting |
| `pytest-asyncio>=0.21` | Async test support |
| `mypy>=1.5` | Type checking |
| `ruff>=0.1` | Linting and formatting |

---

## Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/elmiomar/mudparser.git
cd mudparser

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\activate   # Windows

# Install in development mode with all extras
pip install -e ".[all]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=mudparser --cov-report=html

# Run specific test file
pytest tests/test_parser.py

# Run specific test
pytest tests/test_parser.py::TestParserFromFile::test_parse_amazon_echo_short

# Run tests matching a pattern
pytest -k "validation"
```

### Code Quality

```bash
# Linting with ruff
ruff check src/

# Auto-fix linting issues
ruff check src/ --fix

# Format code
ruff format src/

# Type checking
mypy src/mudparser/
```

### Building Documentation

```bash
# Install docs dependencies
pip install -e ".[docs]"

# Serve documentation locally (with hot reload)
mkdocs serve

# Build static site
mkdocs build

# Deploy to GitHub Pages
mkdocs gh-deploy
```

### Creating a Release

```bash
# Update version in pyproject.toml
# Update CHANGELOG.md

# Build package
python -m build

# Upload to PyPI
python -m twine upload dist/*
```

---

## Troubleshooting

### Common Issues

#### "ModuleNotFoundError: No module named 'mudparser'"

**Solution**: Install the package:
```bash
pip install mudparser
# or for development
pip install -e .
```

#### "MUDFileNotFoundError: File not found"

**Solution**: Check the file path:
```python
from pathlib import Path

# Use absolute path
parser = MUDParser.from_file(Path("data/device.mud.json").absolute())

# Or verify file exists
path = Path("device.mud.json")
if not path.exists():
    print(f"File not found: {path}")
```

#### "MUDSchemaError: Missing required field"

**Solution**: Ensure your MUD file has all required fields:
```json
{
    "ietf-mud:mud": {
        "mud-version": 1,
        "mud-url": "https://example.com/device.mud.json",
        "last-update": "2024-01-15T00:00:00Z",
        "cache-validity": 48,
        "is-supported": true,
        "from-device-policy": { ... },
        "to-device-policy": { ... }
    },
    "ietf-access-control-list:access-lists": { ... }
}
```

#### Validation warnings about HTTP URLs

**Solution**: MUD URLs should use HTTPS:
```json
{
    "ietf-mud:mud": {
        "mud-url": "https://example.com/device.mud.json"
    }
}
```

#### Export missing DNS resolution

**Note**: MudParser exports DNS names as-is. For production use, resolve DNS names before applying rules:
```python
import socket

dns_names = parser.get_dns_names()
for name in dns_names:
    try:
        ip = socket.gethostbyname(name)
        print(f"{name} -> {ip}")
    except socket.gaierror:
        print(f"Could not resolve: {name}")
```

### Getting Help

1. Check the [documentation](https://elmimouni.net/mudparser)
2. Search [existing issues](https://github.com/elmiomar/mudparser/issues)
3. Open a [new issue](https://github.com/elmiomar/mudparser/issues/new)

---

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Run linting (`ruff check src/`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Contribution Guidelines

- Follow the existing code style
- Add tests for new features
- Update documentation as needed
- Keep commits focused and atomic
- Write clear commit messages

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Omar Ilias EL MIMOUNI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Acknowledgements

### Standards and Specifications

- [RFC 8520](https://datatracker.ietf.org/doc/html/rfc8520) - Manufacturer Usage Description Specification
- [RFC 9761](https://datatracker.ietf.org/doc/html/rfc9761) - MUD for TLS and DTLS Profiles
- [RFC 8519](https://datatracker.ietf.org/doc/html/rfc8519) - YANG Data Model for Network Access Control Lists
- [IETF OPSAWG Working Group](https://datatracker.ietf.org/wg/opsawg/about/)

### Resources and Tools

- [UNSW IoT Analytics](https://iotanalytics.unsw.edu.au/mudprofiles.html) - Sample MUD profiles
- [NIST MUD-PD](https://github.com/usnistgov/MUD-PD) - MUD profile generator tool
- [NIST MUD Implementation](https://github.com/usnistgov/nist-mud) - Reference implementation
- [Community MUD Files](https://github.com/iot-onboarding/mudfiles) - Crowd-sourced profiles

### Authors

- **Omar Ilias EL MIMOUNI** - *Initial work* - [omarilias.elmimouni@nist.gov](mailto:omarilias.elmimouni@nist.gov)

---

## Links

- **Documentation**: [https://elmimouni.net/mudparser](https://elmimouni.net/mudparser)
- **GitHub Repository**: [https://github.com/elmiomar/mudparser](https://github.com/elmiomar/mudparser)
- **Issue Tracker**: [https://github.com/elmiomar/mudparser/issues](https://github.com/elmiomar/mudparser/issues)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)
- **PyPI Package**: [https://pypi.org/project/mudparser/](https://pypi.org/project/mudparser/)

---

<p align="center">
  <sub>Built with Python and Pydantic | RFC 8520 & RFC 9761 Compliant</sub>
</p>
