"""
Custom exceptions for the MudParser library.

This module defines a hierarchy of exceptions for handling various error
conditions that may occur during MUD profile parsing, validation, and export.
"""

from typing import Any


class MUDParserError(Exception):
    """
    Base exception for all MudParser errors.

    All custom exceptions in this library inherit from this class,
    allowing users to catch all library-specific errors with a single
    except clause.

    Attributes:
        message: Human-readable error description.
        details: Optional dictionary with additional error context.
    """

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} - Details: {self.details}"
        return self.message


class MUDValidationError(MUDParserError):
    """
    Raised when MUD profile validation fails.

    This exception is raised when the MUD profile data doesn't conform
    to the expected schema or contains semantic errors.

    Attributes:
        message: Description of the validation failure.
        field: The field that failed validation (if applicable).
        value: The invalid value (if applicable).
        errors: List of all validation errors (for batch validation).
    """

    def __init__(
        self,
        message: str,
        field: str | None = None,
        value: Any = None,
        errors: list[dict[str, Any]] | None = None,
    ) -> None:
        details: dict[str, Any] = {}
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = value
        if errors:
            details["errors"] = errors

        self.field = field
        self.value = value
        self.errors = errors or []

        super().__init__(message, details)


class MUDSchemaError(MUDParserError):
    """
    Raised when the MUD profile doesn't conform to the JSON schema.

    This exception indicates structural problems with the JSON document,
    such as missing required fields, incorrect types, or invalid formats.

    Attributes:
        message: Description of the schema violation.
        path: JSON path to the problematic element.
        schema_path: Path in the schema where the violation was detected.
    """

    def __init__(
        self,
        message: str,
        path: str | None = None,
        schema_path: str | None = None,
    ) -> None:
        details: dict[str, Any] = {}
        if path:
            details["path"] = path
        if schema_path:
            details["schema_path"] = schema_path

        self.path = path
        self.schema_path = schema_path

        super().__init__(message, details)


class MUDFileNotFoundError(MUDParserError):
    """
    Raised when a MUD profile file cannot be found.

    Attributes:
        message: Error description.
        file_path: The path to the file that was not found.
    """

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        super().__init__(
            f"MUD profile file not found: {file_path}",
            {"file_path": file_path},
        )


class MUDNetworkError(MUDParserError):
    """
    Raised when there's an error fetching a MUD profile from a URL.

    This exception covers network-related failures such as connection
    timeouts, DNS failures, HTTP errors, and SSL/TLS issues.

    Attributes:
        message: Error description.
        url: The URL that failed.
        status_code: HTTP status code (if applicable).
    """

    def __init__(
        self,
        message: str,
        url: str,
        status_code: int | None = None,
    ) -> None:
        details: dict[str, Any] = {"url": url}
        if status_code:
            details["status_code"] = status_code

        self.url = url
        self.status_code = status_code

        super().__init__(message, details)


class MUDExportError(MUDParserError):
    """
    Raised when there's an error exporting a MUD profile.

    This exception is raised when the export process fails, such as
    when generating firewall rules with missing required information.

    Attributes:
        message: Error description.
        format: The export format that failed.
        reason: Specific reason for the failure.
    """

    def __init__(
        self,
        message: str,
        export_format: str,
        reason: str | None = None,
    ) -> None:
        details: dict[str, Any] = {"format": export_format}
        if reason:
            details["reason"] = reason

        self.export_format = export_format
        self.reason = reason

        super().__init__(message, details)


class MUDACLReferenceError(MUDParserError):
    """
    Raised when an ACL reference in the policy cannot be resolved.

    This exception indicates that a policy references an ACL by name,
    but that ACL doesn't exist in the access-lists section.

    Attributes:
        message: Error description.
        acl_name: The name of the unresolved ACL.
        policy: The policy that contains the invalid reference.
    """

    def __init__(self, acl_name: str, policy: str) -> None:
        self.acl_name = acl_name
        self.policy = policy
        super().__init__(
            f"ACL '{acl_name}' referenced in {policy} does not exist",
            {"acl_name": acl_name, "policy": policy},
        )


class MUDUnsupportedVersionError(MUDParserError):
    """
    Raised when the MUD profile version is not supported.

    Attributes:
        message: Error description.
        version: The unsupported version number.
        supported_versions: List of supported versions.
    """

    def __init__(self, version: int, supported_versions: list[int] | None = None) -> None:
        self.version = version
        self.supported_versions = supported_versions or [1]
        super().__init__(
            f"MUD version {version} is not supported. Supported versions: {self.supported_versions}",
            {"version": version, "supported_versions": self.supported_versions},
        )
