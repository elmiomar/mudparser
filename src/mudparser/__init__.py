"""
MudParser - A production-ready parser for MUD (Manufacturer Usage Description) profiles.

This library provides comprehensive support for parsing, validating, and exporting
MUD profiles as defined in RFC 8520 and RFC 9761 (TLS/DTLS profiles).

Example:
    >>> from mudparser import MUDParser
    >>> profile = MUDParser.from_file("device.mud.json")
    >>> print(profile.mud.systeminfo)
    >>> rules = profile.export.to_iptables(device_ip="192.168.1.100")
"""

from mudparser.exceptions import (
    MUDParserError,
    MUDValidationError,
    MUDSchemaError,
    MUDFileNotFoundError,
    MUDNetworkError,
)
from mudparser.parser import MUDParser
from mudparser.models import (
    MUDProfile,
    MUDContainer,
    AccessControlList,
    AccessControlEntry,
    PolicyReference,
    ForwardingAction,
)

__version__ = "2.0.0"
__author__ = "Omar I. EL MIMOUNI"
__email__ = "omarilias.elmimouni@nist.gov"

__all__ = [
    # Main parser
    "MUDParser",
    # Models
    "MUDProfile",
    "MUDContainer",
    "AccessControlList",
    "AccessControlEntry",
    "PolicyReference",
    "ForwardingAction",
    # Exceptions
    "MUDParserError",
    "MUDValidationError",
    "MUDSchemaError",
    "MUDFileNotFoundError",
    "MUDNetworkError",
    # Version
    "__version__",
]
