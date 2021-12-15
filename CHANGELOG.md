# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-04

### Added

#### Core Features
- **RFC 8520 Full Compliance** - Complete implementation of Manufacturer Usage Description specification
- **RFC 9761 Support** - TLS/DTLS profile extensions for secure communications
- **Modern Python 3.10+** - Leveraging match/case statements, union types, and modern syntax
- **Pydantic v2 Models** - Type-safe data models with automatic validation

#### Parsing
- `MUDParser.from_file()` - Parse MUD profiles from local files
- `MUDParser.from_string()` - Parse from JSON strings
- `MUDParser.from_url()` - Fetch and parse from HTTP/HTTPS URLs
- `MUDParser.from_url_async()` - Async URL fetching support
- `MUDParser.from_dict()` - Parse from Python dictionaries

#### Data Models
- `MUDProfile` - Complete MUD container model with all RFC 8520 fields
- `AccessControlList` - ACL model per RFC 8519
- `AccessControlEntry` - ACE model with full match support
- **Match Types:**
  - `IPv4Match` - IPv4 header matching (protocol, addresses, DSCP, TTL)
  - `IPv6Match` - IPv6 header matching (protocol, addresses, flow label)
  - `TCPMatch` - TCP matching (ports, flags, direction-initiated)
  - `UDPMatch` - UDP matching (ports)
  - `ICMPMatch` - ICMP/ICMPv6 matching (type, code)
  - `EthernetMatch` - Ethernet frame matching (MAC addresses, ethertype)
  - `MUDMatch` - MUD-specific matching (manufacturer, controller, local-networks)
- **Port Operators:** eq, lt, gt, neq, range
- **TLS Models (RFC 9761):**
  - `TLSProfile` - TLS profile constraints
  - `DTLSProfile` - DTLS profile constraints
  - `CipherSuiteConstraints` - Allowed/forbidden cipher suites
  - `SPKIPinSet` - Certificate pinning support

#### Validation
- `MUDValidator` - Comprehensive validation engine
- `ValidationResult` - Detailed validation results with severity levels
- `ValidationIssue` - Individual issues with path and context
- Schema validation against RFC 8520
- Semantic validation (cross-references, constraints)
- Configurable severity levels (ERROR, WARNING, INFO)

#### Export Capabilities
- **iptables** - Linux firewall rules with chain management
- **nftables** - Modern Linux firewall configuration
- **Cisco ACL** - Cisco IOS access control lists
- **pfSense** - BSD firewall XML rules
- **JSON** - Re-serialized MUD profile
- **YAML** - Human-readable format

#### Command Line Interface
- `mudparser validate` - Validate MUD profiles with detailed reporting
- `mudparser info` - Display profile summary and metadata
- `mudparser rules` - Show access control rules in human-readable format
- `mudparser export` - Export to firewall formats
- `mudparser fetch` - Fetch profiles from URLs
- `mudparser diff` - Compare two MUD profiles
- `mudparser demo` - Launch interactive Streamlit demo
- Rich terminal output with syntax highlighting
- JSON/YAML output options

#### Interactive Demo
- Streamlit web application
- File upload and JSON paste support
- Visual profile overview
- Interactive rule browser
- Validation report display
- One-click export to all formats
- Download generated rules

#### Documentation
- MkDocs with Material theme
- Comprehensive user guide
- API reference documentation
- RFC compliance documentation
- Example code for all features
- Installation and quickstart guides

#### Testing
- pytest test suite
- Comprehensive test fixtures
- Model validation tests
- Parser tests
- Exporter tests
- CLI tests

### Changed

#### Breaking Changes
- **Package Structure** - Moved to `src/` layout (`src/mudparser/`)
- **Python Version** - Now requires Python 3.10+ (previously 3.5+)
- **Import Paths** - Models now under `mudparser.models.*`
- **API Changes:**
  - `MUDParser` is now the main entry point (replaces old `mudparser` module)
  - Validation returns `ValidationResult` instead of simple boolean
  - Export methods require explicit device IP for firewall formats

#### Improvements
- Complete rewrite with modern Python idioms
- Type hints throughout the codebase
- Pydantic v2 for data validation (replaces manual parsing)
- Async support for URL fetching
- Better error messages with context

### Removed
- `setup.py` - Replaced with `pyproject.toml`
- Old `mudparser/` package structure
- Python 2.x and Python 3.5-3.9 support

### Fixed
- Proper handling of optional MUD fields
- Correct parsing of port range operators
- DNS name extraction from all match types
- ACL cross-reference validation

## [1.0.0-alpha] - Previous

### Added
- Initial alpha implementation
- Basic MUD file parsing
- Simple profile representation

### Notes
- Alpha version, not production-ready
- Limited RFC 8520 compliance
- No validation or export capabilities

---

## Migration Guide (1.x to 2.0)

### Installation

```bash
# Old
pip install mudparser
# or
python setup.py install

# New
pip install mudparser
# or for development
pip install -e ".[dev]"
```

### Basic Usage

```python
# Old (1.x)
from mudparser import MUDParser
parser = MUDParser()
parser.parse_file("device.mud.json")

# New (2.0)
from mudparser import MUDParser
parser = MUDParser.from_file("device.mud.json")
```

### Accessing Data

```python
# Old (1.x)
mud_url = parser.mud_url
system_info = parser.systeminfo

# New (2.0)
mud_url = parser.mud.mud_url
system_info = parser.mud.systeminfo
```

### Validation

```python
# Old (1.x)
# No validation available

# New (2.0)
errors = parser.validate()
# or detailed
from mudparser.validator import MUDValidator
validator = MUDValidator()
result = validator.validate(parser.profile)
```

### Export

```python
# Old (1.x)
# No export available

# New (2.0)
rules = parser.export.to_iptables(device_ip="192.168.1.100")
```

---

[2.0.0]: https://github.com/elmiomar/mudparser/releases/tag/v2.0.0
[1.0.0-alpha]: https://github.com/elmiomar/mudparser/releases/tag/v1.0.0-alpha
