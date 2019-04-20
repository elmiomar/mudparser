"""
Match condition models for ACL entries.

This module defines Pydantic models for all match types supported by
RFC 8520 (MUD) and RFC 8519 (ACL model), including:
- IPv4 and IPv6 header matching
- TCP and UDP port matching
- ICMP type/code matching
- Ethernet frame matching
- MUD-specific abstract matches
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class PortOperator(str, Enum):
    """Port matching operators as defined in RFC 8519."""

    EQ = "eq"  # equals
    NEQ = "neq"  # not equal
    LT = "lt"  # less than
    GT = "gt"  # greater than
    RANGE = "range"  # port range (requires lower and upper)


class DirectionInitiated(str, Enum):
    """TCP connection direction as defined in RFC 8520."""

    FROM_DEVICE = "from-device"
    TO_DEVICE = "to-device"


class PortMatch(BaseModel):
    """
    Port matching specification.

    Supports single port matching with operators (eq, neq, lt, gt)
    and port range matching.

    Attributes:
        operator: The comparison operator.
        port: The port number (or lower bound for range).
        upper_port: Upper bound for range operator (required for range).
    """

    model_config = ConfigDict(populate_by_name=True)

    operator: PortOperator = Field(default=PortOperator.EQ)
    port: Annotated[int, Field(ge=0, le=65535)]
    upper_port: Annotated[int | None, Field(ge=0, le=65535, alias="upper-port")] = None

    @model_validator(mode="after")
    def validate_range(self) -> "PortMatch":
        """Ensure upper_port is set for range operator and valid."""
        if self.operator == PortOperator.RANGE:
            if self.upper_port is None:
                raise ValueError("upper_port is required for range operator")
            if self.upper_port <= self.port:
                raise ValueError("upper_port must be greater than port")
        return self

    def matches_port(self, port: int) -> bool:
        """Check if a given port matches this specification."""
        match self.operator:
            case PortOperator.EQ:
                return port == self.port
            case PortOperator.NEQ:
                return port != self.port
            case PortOperator.LT:
                return port < self.port
            case PortOperator.GT:
                return port > self.port
            case PortOperator.RANGE:
                return self.port <= port <= (self.upper_port or self.port)

    def __str__(self) -> str:
        if self.operator == PortOperator.RANGE:
            return f"{self.port}-{self.upper_port}"
        return f"{self.operator.value} {self.port}"


class IPv4Match(BaseModel):
    """
    IPv4 header match conditions.

    Attributes:
        protocol: IP protocol number (e.g., 6 for TCP, 17 for UDP).
        src_network: Source network in CIDR notation.
        dst_network: Destination network in CIDR notation.
        src_dnsname: Source DNS name (ietf-acldns extension).
        dst_dnsname: Destination DNS name (ietf-acldns extension).
        dscp: Differentiated Services Code Point.
        ecn: Explicit Congestion Notification.
        length: Total packet length.
        ttl: Time to Live.
        ihl: Internet Header Length.
        flags: IP flags.
        offset: Fragment offset.
        identification: IP identification field.
    """

    model_config = ConfigDict(populate_by_name=True)

    protocol: int | None = None
    src_network: str | None = Field(None, alias="source-ipv4-network")
    dst_network: str | None = Field(None, alias="destination-ipv4-network")
    src_dnsname: str | None = Field(None, alias="ietf-acldns:src-dnsname")
    dst_dnsname: str | None = Field(None, alias="ietf-acldns:dst-dnsname")
    dscp: int | None = None
    ecn: int | None = None
    length: int | None = None
    ttl: int | None = None
    ihl: int | None = None
    flags: str | None = None
    offset: int | None = None
    identification: int | None = None

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: int | None) -> int | None:
        if v is not None and not 0 <= v <= 255:
            raise ValueError("Protocol must be between 0 and 255")
        return v


class IPv6Match(BaseModel):
    """
    IPv6 header match conditions.

    Attributes:
        next_header: Next header protocol number.
        src_network: Source network in CIDR notation.
        dst_network: Destination network in CIDR notation.
        src_dnsname: Source DNS name (ietf-acldns extension).
        dst_dnsname: Destination DNS name (ietf-acldns extension).
        dscp: Differentiated Services Code Point.
        ecn: Explicit Congestion Notification.
        flow_label: IPv6 flow label.
        length: Payload length.
        hop_limit: Hop limit (similar to TTL).
    """

    model_config = ConfigDict(populate_by_name=True)

    next_header: int | None = Field(None, alias="next-header")
    src_network: str | None = Field(None, alias="source-ipv6-network")
    dst_network: str | None = Field(None, alias="destination-ipv6-network")
    src_dnsname: str | None = Field(None, alias="ietf-acldns:src-dnsname")
    dst_dnsname: str | None = Field(None, alias="ietf-acldns:dst-dnsname")
    dscp: int | None = None
    ecn: int | None = None
    flow_label: int | None = Field(None, alias="flow-label")
    length: int | None = None
    hop_limit: int | None = Field(None, alias="hop-limit")

    @field_validator("next_header")
    @classmethod
    def validate_next_header(cls, v: int | None) -> int | None:
        if v is not None and not 0 <= v <= 255:
            raise ValueError("Next header must be between 0 and 255")
        return v


class TCPMatch(BaseModel):
    """
    TCP header match conditions.

    Attributes:
        src_port: Source port matching specification.
        dst_port: Destination port matching specification.
        direction_initiated: Connection initiation direction (MUD extension).
        sequence_number: TCP sequence number.
        acknowledgement_number: TCP acknowledgement number.
        data_offset: Data offset.
        reserved: Reserved bits.
        flags: TCP flags (URG, ACK, PSH, RST, SYN, FIN).
        window_size: TCP window size.
        urgent_pointer: Urgent pointer.
        options: TCP options.
    """

    model_config = ConfigDict(populate_by_name=True)

    src_port: PortMatch | None = Field(None, alias="source-port")
    dst_port: PortMatch | None = Field(None, alias="destination-port")
    direction_initiated: DirectionInitiated | None = Field(
        None, alias="ietf-mud:direction-initiated"
    )
    sequence_number: int | None = Field(None, alias="sequence-number")
    acknowledgement_number: int | None = Field(None, alias="acknowledgement-number")
    data_offset: int | None = Field(None, alias="data-offset")
    reserved: int | None = None
    flags: str | None = None
    window_size: int | None = Field(None, alias="window-size")
    urgent_pointer: int | None = Field(None, alias="urgent-pointer")
    options: str | None = None

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "TCPMatch":
        """Create TCPMatch from JSON data, handling port objects."""
        processed = {}
        for key, value in data.items():
            if key in ("source-port", "destination-port") and isinstance(value, dict):
                processed[key] = PortMatch(**value)
            else:
                processed[key] = value
        return cls(**processed)


class UDPMatch(BaseModel):
    """
    UDP header match conditions.

    Attributes:
        src_port: Source port matching specification.
        dst_port: Destination port matching specification.
        length: UDP datagram length.
    """

    model_config = ConfigDict(populate_by_name=True)

    src_port: PortMatch | None = Field(None, alias="source-port")
    dst_port: PortMatch | None = Field(None, alias="destination-port")
    length: int | None = None

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "UDPMatch":
        """Create UDPMatch from JSON data, handling port objects."""
        processed = {}
        for key, value in data.items():
            if key in ("source-port", "destination-port") and isinstance(value, dict):
                processed[key] = PortMatch(**value)
            else:
                processed[key] = value
        return cls(**processed)


class ICMPMatch(BaseModel):
    """
    ICMP/ICMPv6 match conditions.

    Attributes:
        icmp_type: ICMP type code.
        icmp_code: ICMP code.
        rest_of_header: Remaining header bytes.
    """

    model_config = ConfigDict(populate_by_name=True)

    icmp_type: int | None = Field(None, alias="type")
    icmp_code: int | None = Field(None, alias="code")
    rest_of_header: str | None = Field(None, alias="rest-of-header")

    @field_validator("icmp_type", "icmp_code")
    @classmethod
    def validate_icmp_values(cls, v: int | None) -> int | None:
        if v is not None and not 0 <= v <= 255:
            raise ValueError("ICMP type/code must be between 0 and 255")
        return v


class EthernetMatch(BaseModel):
    """
    Ethernet frame match conditions.

    Attributes:
        src_mac: Source MAC address.
        src_mac_mask: Source MAC address mask.
        dst_mac: Destination MAC address.
        dst_mac_mask: Destination MAC address mask.
        ethertype: Ethernet type field (e.g., 0x0800 for IPv4).
    """

    model_config = ConfigDict(populate_by_name=True)

    src_mac: str | None = Field(None, alias="source-mac-address")
    src_mac_mask: str | None = Field(None, alias="source-mac-address-mask")
    dst_mac: str | None = Field(None, alias="destination-mac-address")
    dst_mac_mask: str | None = Field(None, alias="destination-mac-address-mask")
    ethertype: str | int | None = None

    @field_validator("ethertype")
    @classmethod
    def normalize_ethertype(cls, v: str | int | None) -> str | None:
        """Normalize ethertype to string representation."""
        if v is None:
            return None
        if isinstance(v, int):
            return f"0x{v:04x}"
        return v


class MUDMatch(BaseModel):
    """
    MUD-specific abstract match conditions (RFC 8520 Section 6).

    These matches allow specifying abstract network entities rather than
    specific IP addresses, enabling dynamic policy updates.

    Attributes:
        manufacturer: Match devices from specific manufacturer (by MUD URL authority).
        same_manufacturer: Match devices from same manufacturer as this device.
        model: Match devices with same MUD URL (same model).
        local_networks: Match traffic on local networks (not default route).
        controller: Match traffic to/from named controller class.
        my_controller: Match traffic to/from device-specific controller.
    """

    model_config = ConfigDict(populate_by_name=True)

    manufacturer: str | None = None
    same_manufacturer: list[Any] | None = Field(None, alias="same-manufacturer")
    model: str | None = None
    local_networks: list[Any] | None = Field(None, alias="local-networks")
    controller: str | None = None
    my_controller: list[Any] | None = Field(None, alias="my-controller")

    def get_match_type(self) -> str | None:
        """Return the type of MUD match that is set."""
        if self.manufacturer is not None:
            return "manufacturer"
        if self.same_manufacturer is not None:
            return "same-manufacturer"
        if self.model is not None:
            return "model"
        if self.local_networks is not None:
            return "local-networks"
        if self.controller is not None:
            return "controller"
        if self.my_controller is not None:
            return "my-controller"
        return None

    def get_match_value(self) -> Any:
        """Return the value of the set match type."""
        match_type = self.get_match_type()
        if match_type:
            return getattr(self, match_type.replace("-", "_"))
        return None


class ACEMatches(BaseModel):
    """
    Container for all match types in an ACE.

    An ACE can have multiple match conditions that are ANDed together.
    All specified conditions must match for the ACE to apply.

    Attributes:
        ipv4: IPv4 header match conditions.
        ipv6: IPv6 header match conditions.
        tcp: TCP header match conditions.
        udp: UDP header match conditions.
        icmp: ICMP match conditions.
        eth: Ethernet frame match conditions.
        mud: MUD-specific abstract match conditions.
    """

    model_config = ConfigDict(populate_by_name=True)

    ipv4: IPv4Match | None = None
    ipv6: IPv6Match | None = None
    tcp: TCPMatch | None = None
    udp: UDPMatch | None = None
    icmp: ICMPMatch | None = None
    eth: EthernetMatch | None = None
    mud: MUDMatch | None = Field(None, alias="ietf-mud:mud")

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "ACEMatches":
        """Create ACEMatches from JSON data with proper type handling."""
        processed: dict[str, Any] = {}

        for key, value in data.items():
            if value is None:
                continue

            match key:
                case "ipv4":
                    processed["ipv4"] = IPv4Match(**value)
                case "ipv6":
                    processed["ipv6"] = IPv6Match(**value)
                case "tcp":
                    processed["tcp"] = TCPMatch.from_json(value)
                case "udp":
                    processed["udp"] = UDPMatch.from_json(value)
                case "icmp":
                    processed["icmp"] = ICMPMatch(**value)
                case "eth":
                    processed["eth"] = EthernetMatch(**value)
                case "ietf-mud:mud":
                    processed["mud"] = MUDMatch(**value)
                case _:
                    # Handle unknown match types gracefully
                    pass

        return cls(**processed)

    def has_matches(self) -> bool:
        """Check if any match conditions are specified."""
        return any(
            [self.ipv4, self.ipv6, self.tcp, self.udp, self.icmp, self.eth, self.mud]
        )

    def get_protocol(self) -> int | None:
        """Get the IP protocol number from IPv4/IPv6 matches."""
        if self.ipv4 and self.ipv4.protocol:
            return self.ipv4.protocol
        if self.ipv6 and self.ipv6.next_header:
            return self.ipv6.next_header
        return None

    def get_dns_names(self) -> dict[str, str | None]:
        """Get source and destination DNS names from matches."""
        result: dict[str, str | None] = {"src": None, "dst": None}
        for ip_match in (self.ipv4, self.ipv6):
            if ip_match:
                if ip_match.src_dnsname:
                    result["src"] = ip_match.src_dnsname
                if ip_match.dst_dnsname:
                    result["dst"] = ip_match.dst_dnsname
        return result
