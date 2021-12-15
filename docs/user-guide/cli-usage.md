# CLI Usage

MudParser provides a full-featured command-line interface for working with MUD profiles.

## Installation

The CLI is included with the main package:

```bash
pip install mudparser
```

Verify installation:

```bash
mudparser --version
```

## Commands Overview

| Command | Description |
|---------|-------------|
| `validate` | Validate a MUD profile |
| `info` | Display profile information |
| `rules` | Print rules in human-readable format |
| `export` | Export to various formats |
| `fetch` | Fetch profile from URL |
| `diff` | Compare two profiles |
| `demo` | Launch web demo (requires extras) |

## Validate Command

Check a MUD profile for RFC 8520 compliance.

```bash
# Basic validation
mudparser validate device.mud.json

# Strict mode (warnings become errors)
mudparser validate device.mud.json --strict

# JSON output for scripting
mudparser validate device.mud.json --json
```

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--strict` | `-s` | Treat warnings as errors |
| `--json` | `-j` | Output as JSON |

### Exit Codes

- `0` - Valid profile
- `1` - Validation failed

## Info Command

Display detailed information about a MUD profile.

```bash
# Display profile info
mudparser info device.mud.json

# JSON output
mudparser info device.mud.json --json
```

### Example Output

```
╭────────────────── MUD Profile ──────────────────╮
│ My IoT Device                                   │
│ URL: https://example.com/device.json            │
╰─────────────────────────────────────────────────╯

┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property        ┃ Value                          ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ MUD Version     │ 1                              │
│ Last Update     │ 2024-01-15T10:00:00Z           │
│ Cache Validity  │ 48 hours                       │
│ Supported       │ Yes                            │
└─────────────────┴────────────────────────────────┘

┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━┓
┃ Direction             ┃ ACLs ┃ Rules ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━┩
│ From Device (Outbound)│ 1    │ 3     │
│ To Device (Inbound)   │ 1    │ 2     │
│ Total                 │ 2    │ 5     │
└───────────────────────┴──────┴───────┘

Referenced DNS Names:
  - api.example.com
  - updates.example.com

Referenced Ports:
  TCP: 80, 443
  UDP: 53
```

## Rules Command

Print all rules in human-readable format.

```bash
mudparser rules device.mud.json
```

### Example Output

```
============================================================
MUD Profile: My IoT Device
URL: https://example.com/device.json
Version: 1
============================================================

### FROM-DEVICE POLICY (Outbound) ###

##### ACL::from-ipv4-device::START #####
Type: ipv4-acl-type

  [FROM] ALLOW TCP to api.example.com port eq 443
  [FROM] ALLOW TCP to updates.example.com port eq 443

(implicit deny all)
##### ACL::from-ipv4-device::END #####
```

## Export Command

Export profiles to various formats.

```bash
# Export to JSON (stdout)
mudparser export device.mud.json -f json

# Export to YAML
mudparser export device.mud.json -f yaml

# Export to iptables (requires device IP)
mudparser export device.mud.json -f iptables -d 192.168.1.100

# Export to nftables
mudparser export device.mud.json -f nftables -d 192.168.1.100

# Export to Cisco ACL
mudparser export device.mud.json -f cisco

# Export to pfSense
mudparser export device.mud.json -f pfsense -d 192.168.1.100

# Save to file
mudparser export device.mud.json -f iptables -d 192.168.1.100 -o rules.sh
```

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--format` | `-f` | Export format (required) |
| `--device-ip` | `-d` | Device IP (required for firewall formats) |
| `--output` | `-o` | Output file path |

### Supported Formats

- `json` - JSON format
- `yaml` - YAML format
- `iptables` - Linux iptables
- `nftables` - Linux nftables
- `cisco` - Cisco IOS ACL
- `pfsense` - pfSense XML

## Fetch Command

Fetch and optionally validate a MUD profile from a URL.

```bash
# Fetch and display summary
mudparser fetch https://example.com/device.mud.json

# Fetch and validate
mudparser fetch https://example.com/device.mud.json --validate

# Fetch and save to file
mudparser fetch https://example.com/device.mud.json -o device.json
```

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--validate` | `-v` | Validate the fetched profile |
| `--output` | `-o` | Save to file |

## Diff Command

Compare two MUD profiles.

```bash
mudparser diff old_device.json new_device.json
```

### Example Output

```
╭─────────── Comparing MUD Profiles ───────────╮
│ File 1: old_device.json                      │
│ File 2: new_device.json                      │
╰──────────────────────────────────────────────╯

┏━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━┓
┃ Property    ┃ File 1   ┃ File 2   ┃ Match ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━┩
│ System Info │ Device   │ Device   │ Yes   │
│ Version     │ 1        │ 1        │ Yes   │
└─────────────┴──────────┴──────────┴───────┘

┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━┓
┃ Metric            ┃ File 1 ┃ File 2 ┃ Diff ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━┩
│ Total Rules       │ 5      │ 7      │ +2   │
│ From-Device Rules │ 3      │ 4      │ +1   │
│ To-Device Rules   │ 2      │ 3      │ +1   │
└───────────────────┴────────┴────────┴──────┘

DNS Name Changes:
  + new-api.example.com
```

## Demo Command

Launch the interactive Streamlit demo application.

```bash
# Requires demo extras
pip install mudparser[demo]

# Launch demo
mudparser demo
```

## Global Options

| Option | Short | Description |
|--------|-------|-------------|
| `--version` | `-v` | Show version |
| `--help` | | Show help |

## Shell Completion

Generate shell completion scripts:

```bash
# Bash
mudparser --install-completion bash

# Zsh
mudparser --install-completion zsh

# Fish
mudparser --install-completion fish
```

## Scripting

Use JSON output for scripting:

```bash
# Get info as JSON
info=$(mudparser info device.mud.json --json)
device_name=$(echo $info | jq -r '.systeminfo')

# Check validation
if mudparser validate device.mud.json --json | jq -e '.is_valid' > /dev/null; then
    echo "Profile is valid"
else
    echo "Profile is invalid"
fi

# Export rules
mudparser export device.mud.json -f iptables -d $(get_device_ip) | bash
```
