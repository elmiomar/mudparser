# MudParser

**Production-ready parser for MUD (Manufacturer Usage Description) profiles.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

MudParser is a Python library for parsing, validating, and exporting MUD profiles as defined in:

- **[RFC 8520](https://datatracker.ietf.org/doc/rfc8520/)** - Manufacturer Usage Description Specification
- **[RFC 9761](https://datatracker.ietf.org/doc/rfc9761/)** - MUD (D)TLS Profiles for IoT Devices

## What is MUD?

MUD (Manufacturer Usage Description) is a standard that allows IoT device manufacturers to formally describe the network behavior their devices require. This enables network administrators to automatically configure access control policies that restrict IoT devices to only the network communications they need.

## Features

- **Complete RFC 8520 Support** - Parse all MUD profile elements including ACLs, policies, and MUD-specific matches
- **RFC 9761 TLS Profiles** - Support for TLS/DTLS profile constraints
- **Comprehensive Validation** - Validate profiles for RFC compliance and best practices
- **Multiple Export Formats**:
    - JSON and YAML data formats
    - iptables (Linux)
    - nftables (Linux)
    - Cisco IOS ACLs
    - pfSense XML
- **Modern Python** - Built with Python 3.10+, Pydantic v2, and type hints
- **CLI Tool** - Full-featured command-line interface
- **Async Support** - Async URL fetching for MUD profiles

## Quick Example

```python
from mudparser import MUDParser

# Parse a MUD file
parser = MUDParser.from_file("device.mud.json")

# Access device information
print(f"Device: {parser.mud.systeminfo}")
print(f"Supported: {parser.mud.is_supported}")

# Validate the profile
errors = parser.validate()
if not errors:
    print("Profile is valid!")

# Export to iptables rules
rules = parser.export.to_iptables(device_ip="192.168.1.100")
print(rules)
```

## Installation

```bash
pip install mudparser
```

For all features including the demo application:

```bash
pip install mudparser[all]
```

## Documentation Sections

<div class="grid cards" markdown>

-   :material-download:{ .lg .middle } **Installation**

    ---

    Get started with installing MudParser

    [Installation Guide →](installation.md)

-   :material-rocket-launch:{ .lg .middle } **Quick Start**

    ---

    Parse your first MUD profile in 5 minutes

    [Quick Start →](quickstart.md)

-   :material-book-open-variant:{ .lg .middle } **User Guide**

    ---

    Learn how to use all features

    [User Guide →](user-guide/parsing-mud-files.md)

-   :material-api:{ .lg .middle } **API Reference**

    ---

    Detailed API documentation

    [API Reference →](api-reference/parser.md)

</div>

## License

MudParser is released under the MIT License. See the [LICENSE](https://github.com/elmiomar/mudparser/blob/main/LICENSE) file for details.

## Acknowledgements

- Original mudparser by Omar Ilias EL MIMOUNI (NIST)
- IETF OPSAWG for the MUD specification
