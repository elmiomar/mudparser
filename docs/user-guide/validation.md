# Validation

MudParser provides comprehensive validation for MUD profiles to ensure RFC 8520 compliance.

## Basic Validation

Validate a parsed profile:

```python
from mudparser import MUDParser

parser = MUDParser.from_file("device.mud.json")

# Returns list of error messages
errors = parser.validate()

if errors:
    print("Validation issues found:")
    for error in errors:
        print(f"  - {error}")
else:
    print("Profile is valid!")
```

## Strict Validation

Use strict mode to raise an exception on any issue:

```python
from mudparser.exceptions import MUDValidationError

try:
    parser.validate(strict=True)
    print("Validation passed!")
except MUDValidationError as e:
    print(f"Validation failed: {e.message}")
    for err in e.errors:
        print(f"  - {err['message']}")
```

## Using the Validator Directly

For more control, use the `MUDValidator` class:

```python
from mudparser.validator import MUDValidator, ValidationSeverity

validator = MUDValidator(strict=False)
result = validator.validate(parser.profile)

print(f"Valid: {result.is_valid}")
print(f"Errors: {result.error_count}")
print(f"Warnings: {result.warning_count}")

# Access issues by severity
for issue in result.errors:
    print(f"ERROR: {issue.message}")

for issue in result.warnings:
    print(f"WARNING: {issue.message}")
```

## Validation Checks

### Structure Validation

MudParser validates the basic structure:

- Required `ietf-mud:mud` container
- Required `ietf-access-control-list:access-lists` container
- Required fields within MUD container

### MUD Container Validation

| Field | Validation |
|-------|------------|
| `mud-version` | Must be 1 (only supported version) |
| `mud-url` | Must be valid HTTPS URL (warning if HTTP) |
| `cache-validity` | Must be 1-168 hours |
| `systeminfo` | Max 60 characters |

### ACL Reference Validation

- All ACLs referenced in policies must exist
- Unreferenced ACLs generate warnings

### ACL Type Validation

- IPv4 ACLs shouldn't have IPv6 matches
- IPv6 ACLs shouldn't have IPv4 matches

### ACE Match Validation

- `direction-initiated` only valid for TCP
- Port ranges must have upper > lower

### MUD-Specific Match Validation

- Controller URNs are checked against standard URNs
- Non-standard URNs generate informational messages

## Validation Severity Levels

| Severity | Description |
|----------|-------------|
| `ERROR` | Profile is invalid, must be fixed |
| `WARNING` | Potential issue, should be addressed |
| `INFO` | Informational, best practice suggestion |

## Validation Result

Access detailed validation results:

```python
result = validator.validate(profile)

# Check overall validity
if result.is_valid:
    print("Profile passes validation")

# Get counts
print(f"Errors: {result.error_count}")
print(f"Warnings: {result.warning_count}")

# Iterate over all issues
for issue in result.issues:
    print(f"[{issue.severity.value}] {issue.message}")
    if issue.path:
        print(f"  Path: {issue.path}")
    if issue.code:
        print(f"  Code: {issue.code}")

# Convert to dictionary
result_dict = result.to_dict()
```

## Validating Raw JSON

Validate JSON before parsing:

```python
from mudparser.validator import validate_json

data = {
    "ietf-mud:mud": {...},
    "ietf-access-control-list:access-lists": {...}
}

result = validate_json(data)

if not result.is_valid:
    for error in result.errors:
        print(f"Error: {error.message}")
```

## CLI Validation

Validate from the command line:

```bash
# Basic validation
mudparser validate device.mud.json

# Strict validation
mudparser validate device.mud.json --strict

# JSON output for scripting
mudparser validate device.mud.json --json
```

Example output:
```
╭──────────────────── Validation Result ────────────────────╮
│ Profile is valid                                          │
│ Errors: 0 | Warnings: 2                                   │
╰───────────────────────────────────────────────────────────╯

┏━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Severity  ┃ Message                           ┃ Path    ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ WARNING   │ Manufacturer name not specified   │ -       │
│ INFO      │ No documentation URL provided     │ -       │
└───────────┴───────────────────────────────────┴─────────┘
```

## Common Validation Errors

### Missing ACL Reference

```
ERROR: ACL 'from-ipv4-device' referenced in from-device-policy does not exist
```

**Fix:** Ensure all ACLs referenced in policies are defined in `access-lists`.

### Invalid Cache Validity

```
ERROR: Cache validity 200 outside valid range (1-168)
```

**Fix:** Set `cache-validity` to a value between 1 and 168 hours.

### HTTP URL Warning

```
WARNING: MUD URL should use HTTPS: http://example.com/device.json
```

**Fix:** Use HTTPS for the MUD URL as required by RFC 8520.

## Custom Validation

Extend validation with custom checks:

```python
from mudparser.validator import MUDValidator, ValidationIssue, ValidationSeverity

class CustomValidator(MUDValidator):
    def validate(self, profile):
        result = super().validate(profile)

        # Add custom check
        if not profile.mud.mfg_name:
            result.issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="Manufacturer name is recommended for production",
                code="CUSTOM_MFG_CHECK",
            ))

        return result
```
