"""
TLS/DTLS Profile models for RFC 9761.

This module defines Pydantic models for MUD TLS and DTLS profiles
as specified in RFC 9761 (Manufacturer Usage Description (MUD) for
TLS and DTLS Profiles for IoT Devices).

These models allow manufacturers to specify expected TLS/DTLS behavior
for their devices, enabling network security services to detect
unexpected or malicious TLS usage.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TLSVersion(str, Enum):
    """
    TLS/DTLS version identifiers.

    These correspond to the version values that can appear in
    TLS/DTLS handshake messages.
    """

    TLS_1_0 = "tls-1.0"
    TLS_1_1 = "tls-1.1"
    TLS_1_2 = "tls-1.2"
    TLS_1_3 = "tls-1.3"
    DTLS_1_0 = "dtls-1.0"
    DTLS_1_2 = "dtls-1.2"
    DTLS_1_3 = "dtls-1.3"

    @property
    def is_dtls(self) -> bool:
        """Check if this is a DTLS version."""
        return self.value.startswith("dtls")

    @property
    def is_deprecated(self) -> bool:
        """Check if this version is deprecated/insecure."""
        return self in (TLSVersion.TLS_1_0, TLSVersion.TLS_1_1, TLSVersion.DTLS_1_0)


class CipherSuiteType(str, Enum):
    """Categories of cipher suites."""

    RECOMMENDED = "recommended"
    SECURE = "secure"
    WEAK = "weak"
    INSECURE = "insecure"


class CipherSuite(BaseModel):
    """
    TLS Cipher Suite specification.

    Attributes:
        name: The IANA cipher suite name (e.g., "TLS_AES_128_GCM_SHA256").
        value: The numeric cipher suite value (e.g., 0x1301).
        suite_type: Classification of the cipher suite security.
    """

    model_config = ConfigDict(populate_by_name=True)

    name: str
    value: int | None = None
    suite_type: CipherSuiteType | None = Field(None, alias="type")

    @classmethod
    def from_name(cls, name: str) -> "CipherSuite":
        """Create a CipherSuite from just the name."""
        return cls(name=name)

    def is_secure(self) -> bool:
        """Check if this cipher suite is considered secure."""
        if self.suite_type:
            return self.suite_type in (CipherSuiteType.RECOMMENDED, CipherSuiteType.SECURE)
        # Default heuristics based on name
        insecure_patterns = ["NULL", "EXPORT", "DES", "RC4", "MD5", "anon"]
        return not any(pattern in self.name for pattern in insecure_patterns)


class SPKIHash(BaseModel):
    """
    Subject Public Key Info (SPKI) hash for certificate pinning.

    Attributes:
        algorithm: Hash algorithm (e.g., "sha256").
        value: Base64-encoded hash value.
    """

    model_config = ConfigDict(populate_by_name=True)

    algorithm: str = Field(default="sha256")
    value: str

    def __str__(self) -> str:
        return f"{self.algorithm}/{self.value}"


class ClientAuthentication(str, Enum):
    """Client authentication requirements."""

    NONE = "none"
    OPTIONAL = "optional"
    REQUIRED = "required"


class TLSClientProfile(BaseModel):
    """
    TLS client profile (device acting as TLS client).

    Defines the expected TLS behavior when the device initiates
    TLS connections to servers.

    Attributes:
        tls_versions: Supported TLS/DTLS versions.
        cipher_suites: Allowed cipher suites.
        spki_pins: Certificate pins for server validation.
        client_auth: Client authentication behavior.
        alpn_protocols: Application-Layer Protocol Negotiation protocols.
        sni_required: Whether SNI extension is required.
    """

    model_config = ConfigDict(populate_by_name=True)

    tls_versions: list[TLSVersion] = Field(
        default_factory=list, alias="tls-versions"
    )
    cipher_suites: list[CipherSuite] = Field(
        default_factory=list, alias="cipher-suites"
    )
    spki_pins: list[SPKIHash] = Field(default_factory=list, alias="spki-pins")
    client_auth: ClientAuthentication = Field(
        default=ClientAuthentication.NONE, alias="client-authentication"
    )
    alpn_protocols: list[str] = Field(default_factory=list, alias="alpn-protocols")
    sni_required: bool = Field(default=True, alias="sni-required")

    def get_min_version(self) -> TLSVersion | None:
        """Get the minimum supported TLS version."""
        if not self.tls_versions:
            return None
        # Sort by version number (simplified)
        version_order = {
            TLSVersion.TLS_1_0: 0,
            TLSVersion.TLS_1_1: 1,
            TLSVersion.TLS_1_2: 2,
            TLSVersion.TLS_1_3: 3,
            TLSVersion.DTLS_1_0: 0,
            TLSVersion.DTLS_1_2: 2,
            TLSVersion.DTLS_1_3: 3,
        }
        return min(self.tls_versions, key=lambda v: version_order.get(v, 99))

    def allows_deprecated_versions(self) -> bool:
        """Check if deprecated versions are allowed."""
        return any(v.is_deprecated for v in self.tls_versions)


class TLSServerProfile(BaseModel):
    """
    TLS server profile (device acting as TLS server).

    Defines the expected TLS behavior when the device accepts
    incoming TLS connections.

    Attributes:
        tls_versions: Supported TLS/DTLS versions.
        cipher_suites: Allowed cipher suites.
        client_auth: Client authentication requirements.
        alpn_protocols: Application-Layer Protocol Negotiation protocols.
    """

    model_config = ConfigDict(populate_by_name=True)

    tls_versions: list[TLSVersion] = Field(
        default_factory=list, alias="tls-versions"
    )
    cipher_suites: list[CipherSuite] = Field(
        default_factory=list, alias="cipher-suites"
    )
    client_auth: ClientAuthentication = Field(
        default=ClientAuthentication.NONE, alias="client-authentication"
    )
    alpn_protocols: list[str] = Field(default_factory=list, alias="alpn-protocols")


class TLSProfile(BaseModel):
    """
    Complete TLS/DTLS profile for a device (RFC 9761).

    This profile describes the expected TLS behavior for an IoT device,
    allowing network security services to detect unexpected TLS usage
    that might indicate compromise or malfunction.

    Attributes:
        client_profile: TLS profile for outgoing connections.
        server_profile: TLS profile for incoming connections.
        description: Human-readable description.
    """

    model_config = ConfigDict(populate_by_name=True)

    client_profile: TLSClientProfile | None = Field(
        None, alias="client-profile"
    )
    server_profile: TLSServerProfile | None = Field(
        None, alias="server-profile"
    )
    description: str | None = None

    def has_client_profile(self) -> bool:
        """Check if a client profile is defined."""
        return self.client_profile is not None

    def has_server_profile(self) -> bool:
        """Check if a server profile is defined."""
        return self.server_profile is not None

    def get_all_cipher_suites(self) -> list[CipherSuite]:
        """Get all cipher suites from both profiles."""
        suites: list[CipherSuite] = []
        if self.client_profile:
            suites.extend(self.client_profile.cipher_suites)
        if self.server_profile:
            suites.extend(self.server_profile.cipher_suites)
        return suites

    def get_all_tls_versions(self) -> set[TLSVersion]:
        """Get all TLS versions from both profiles."""
        versions: set[TLSVersion] = set()
        if self.client_profile:
            versions.update(self.client_profile.tls_versions)
        if self.server_profile:
            versions.update(self.server_profile.tls_versions)
        return versions

    def has_security_concerns(self) -> list[str]:
        """
        Check for potential security concerns in the profile.

        Returns:
            List of security concern descriptions.
        """
        concerns: list[str] = []

        # Check for deprecated versions
        all_versions = self.get_all_tls_versions()
        deprecated = [v for v in all_versions if v.is_deprecated]
        if deprecated:
            concerns.append(
                f"Deprecated TLS versions allowed: {', '.join(v.value for v in deprecated)}"
            )

        # Check for insecure cipher suites
        for suite in self.get_all_cipher_suites():
            if not suite.is_secure():
                concerns.append(f"Potentially insecure cipher suite: {suite.name}")

        # Check client profile specifics
        if self.client_profile:
            if not self.client_profile.sni_required:
                concerns.append("SNI not required for client connections")
            if not self.client_profile.spki_pins:
                concerns.append("No certificate pinning configured")

        return concerns

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "TLSProfile":
        """Create TLSProfile from JSON data."""
        client_data = data.get("client-profile")
        server_data = data.get("server-profile")

        client_profile = None
        if client_data:
            # Parse cipher suites
            cipher_suites = [
                CipherSuite.from_name(cs) if isinstance(cs, str) else CipherSuite(**cs)
                for cs in client_data.get("cipher-suites", [])
            ]
            # Parse SPKI pins
            spki_pins = [
                SPKIHash(**pin) if isinstance(pin, dict) else SPKIHash(value=pin)
                for pin in client_data.get("spki-pins", [])
            ]
            client_profile = TLSClientProfile(
                tls_versions=[TLSVersion(v) for v in client_data.get("tls-versions", [])],
                cipher_suites=cipher_suites,
                spki_pins=spki_pins,
                client_auth=ClientAuthentication(
                    client_data.get("client-authentication", "none")
                ),
                alpn_protocols=client_data.get("alpn-protocols", []),
                sni_required=client_data.get("sni-required", True),
            )

        server_profile = None
        if server_data:
            cipher_suites = [
                CipherSuite.from_name(cs) if isinstance(cs, str) else CipherSuite(**cs)
                for cs in server_data.get("cipher-suites", [])
            ]
            server_profile = TLSServerProfile(
                tls_versions=[TLSVersion(v) for v in server_data.get("tls-versions", [])],
                cipher_suites=cipher_suites,
                client_auth=ClientAuthentication(
                    server_data.get("client-authentication", "none")
                ),
                alpn_protocols=server_data.get("alpn-protocols", []),
            )

        return cls(
            client_profile=client_profile,
            server_profile=server_profile,
            description=data.get("description"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        result: dict[str, Any] = {}

        if self.client_profile:
            result["client-profile"] = self.client_profile.model_dump(
                by_alias=True, exclude_none=True
            )

        if self.server_profile:
            result["server-profile"] = self.server_profile.model_dump(
                by_alias=True, exclude_none=True
            )

        if self.description:
            result["description"] = self.description

        return result
