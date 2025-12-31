"""SIEM Integration Engine.

Provides structured security event logging for Security Information
and Event Management (SIEM) systems.

Supported Formats:
- CEF (Common Event Format): ArcSight, QRadar
- LEEF (Log Event Extended Format): IBM QRadar
- JSON: Splunk, ELK, general purpose
- Syslog (RFC 5424): Universal logging

Event Categories:
- Authentication: Login, logout, token operations
- Authorization: Access control decisions
- Cryptographic: Encryption, decryption, signing, key operations
- Configuration: System configuration changes
- Audit: Compliance and audit trail events

References:
- CEF: ArcSight Common Event Format
- LEEF: IBM Log Event Extended Format
- RFC 5424: The Syslog Protocol
"""

import json
import logging
import socket
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Callable, Optional


class EventCategory(str, Enum):
    """Security event categories."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHIC = "cryptographic"
    KEY_MANAGEMENT = "key-management"
    CONFIGURATION = "configuration"
    AUDIT = "audit"
    POLICY = "policy"
    CERTIFICATE = "certificate"


class EventType(str, Enum):
    """Specific event types within categories."""

    # Authentication events
    LOGIN_SUCCESS = "login-success"
    LOGIN_FAILURE = "login-failure"
    LOGOUT = "logout"
    TOKEN_ISSUED = "token-issued"
    TOKEN_REVOKED = "token-revoked"
    TOKEN_EXPIRED = "token-expired"
    MFA_SUCCESS = "mfa-success"
    MFA_FAILURE = "mfa-failure"

    # Authorization events
    ACCESS_GRANTED = "access-granted"
    ACCESS_DENIED = "access-denied"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    PERMISSION_CHANGE = "permission-change"

    # Cryptographic events
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    DECRYPT_FAILURE = "decrypt-failure"
    SIGN = "sign"
    VERIFY = "verify"
    VERIFY_FAILURE = "verify-failure"
    HASH = "hash"
    MAC = "mac"

    # Key management events
    KEY_GENERATED = "key-generated"
    KEY_IMPORTED = "key-imported"
    KEY_EXPORTED = "key-exported"
    KEY_ROTATED = "key-rotated"
    KEY_DELETED = "key-deleted"
    KEY_COMPROMISED = "key-compromised"
    KEY_EXPIRED = "key-expired"

    # Certificate events
    CERT_ISSUED = "cert-issued"
    CERT_RENEWED = "cert-renewed"
    CERT_REVOKED = "cert-revoked"
    CERT_EXPIRED = "cert-expired"
    CERT_VALIDATION_SUCCESS = "cert-validation-success"
    CERT_VALIDATION_FAILURE = "cert-validation-failure"

    # Policy events
    POLICY_VIOLATION = "policy-violation"
    POLICY_CREATED = "policy-created"
    POLICY_UPDATED = "policy-updated"
    POLICY_DELETED = "policy-deleted"
    POLICY_EVALUATED = "policy-evaluated"

    # Configuration events
    CONFIG_CHANGED = "config-changed"
    ALGORITHM_DEPRECATED = "algorithm-deprecated"
    ALGORITHM_MIGRATION = "algorithm-migration"

    # Audit events
    AUDIT_LOG_ACCESS = "audit-log-access"
    AUDIT_LOG_EXPORT = "audit-log-export"
    COMPLIANCE_CHECK = "compliance-check"


class Severity(IntEnum):
    """Event severity levels (following CEF standard)."""

    UNKNOWN = 0
    LOW = 1
    LOW_MEDIUM = 2
    MEDIUM = 3
    MEDIUM_HIGH = 4
    HIGH = 5
    HIGH_CRITICAL = 6
    CRITICAL = 7
    CRITICAL_EMERGENCY = 8
    EMERGENCY = 9
    CATASTROPHIC = 10

    @classmethod
    def from_string(cls, name: str) -> "Severity":
        """Convert string to severity."""
        mapping = {
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
            "emergency": cls.EMERGENCY,
        }
        return mapping.get(name.lower(), cls.UNKNOWN)


class OutputFormat(str, Enum):
    """SIEM output formats."""

    CEF = "cef"  # Common Event Format
    LEEF = "leef"  # Log Event Extended Format
    JSON = "json"  # JSON format
    SYSLOG = "syslog"  # RFC 5424 syslog


class SyslogFacility(IntEnum):
    """Syslog facility codes."""

    KERN = 0
    USER = 1
    MAIL = 2
    DAEMON = 3
    AUTH = 4
    SYSLOG = 5
    LPR = 6
    NEWS = 7
    UUCP = 8
    CRON = 9
    AUTHPRIV = 10
    FTP = 11
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23


@dataclass
class SecurityEvent:
    """A security event for SIEM."""

    event_id: str
    timestamp: datetime
    category: EventCategory
    event_type: EventType
    severity: Severity
    message: str
    source_ip: Optional[str] = None
    source_host: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_host: Optional[str] = None
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    reason: Optional[str] = None
    algorithm: Optional[str] = None
    key_id: Optional[str] = None
    policy_id: Optional[str] = None
    custom_fields: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert event to dictionary."""
        result = {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "category": self.category.value,
            "event_type": self.event_type.value,
            "severity": int(self.severity),
            "severity_name": self.severity.name.lower(),
            "message": self.message,
        }

        # Add optional fields if present
        optional = [
            "source_ip",
            "source_host",
            "destination_ip",
            "destination_host",
            "user_id",
            "user_name",
            "session_id",
            "correlation_id",
            "resource_type",
            "resource_id",
            "action",
            "outcome",
            "reason",
            "algorithm",
            "key_id",
            "policy_id",
        ]

        for field_name in optional:
            value = getattr(self, field_name)
            if value is not None:
                result[field_name] = value

        if self.custom_fields:
            result["custom"] = self.custom_fields

        return result


@dataclass
class SIEMConfig:
    """Configuration for SIEM output."""

    enabled: bool = True
    format: OutputFormat = OutputFormat.JSON
    vendor: str = "CryptoServe"
    product: str = "CryptoAgile"
    version: str = "1.0"

    # Syslog settings
    syslog_host: Optional[str] = None
    syslog_port: int = 514
    syslog_facility: SyslogFacility = SyslogFacility.AUTH
    syslog_protocol: str = "udp"  # udp, tcp, or tls

    # CEF/LEEF settings
    device_vendor: str = "CryptoServe"
    device_product: str = "CryptoAgile"
    device_version: str = "1.0"

    # Filtering
    min_severity: Severity = Severity.LOW
    include_categories: Optional[list[EventCategory]] = None
    exclude_categories: Optional[list[EventCategory]] = None


class SIEMEngine:
    """Security Information and Event Management integration.

    Provides structured security event logging for SIEM systems.

    Usage:
        engine = SIEMEngine()

        # Log an event
        engine.log_event(
            category=EventCategory.CRYPTOGRAPHIC,
            event_type=EventType.ENCRYPT,
            severity=Severity.LOW,
            message="File encrypted successfully",
            user_id="user-123",
            algorithm="AES-256-GCM",
        )

        # Configure output
        engine.configure(
            format=OutputFormat.CEF,
            syslog_host="siem.company.com",
        )
    """

    def __init__(self, config: Optional[SIEMConfig] = None):
        """Initialize SIEM engine."""
        self._config = config or SIEMConfig()
        self._handlers: list[Callable[[SecurityEvent], None]] = []
        self._logger = logging.getLogger("crypto-serve.siem")
        self._hostname = socket.gethostname()
        self._lock = threading.Lock()

    def configure(self, **kwargs) -> None:
        """Update SIEM configuration.

        Args:
            **kwargs: Configuration options to update
        """
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self._config, key):
                    setattr(self._config, key, value)
                else:
                    raise ValueError(f"Unknown configuration option: {key}")

    def add_handler(self, handler: Callable[[SecurityEvent], None]) -> None:
        """Add a custom event handler.

        Args:
            handler: Callable that receives SecurityEvent
        """
        with self._lock:
            self._handlers.append(handler)

    def remove_handler(self, handler: Callable[[SecurityEvent], None]) -> None:
        """Remove a custom event handler.

        Args:
            handler: Handler to remove
        """
        with self._lock:
            if handler in self._handlers:
                self._handlers.remove(handler)

    def log_event(
        self,
        category: EventCategory,
        event_type: EventType,
        severity: Severity,
        message: str,
        **kwargs,
    ) -> SecurityEvent:
        """Log a security event.

        Args:
            category: Event category
            event_type: Specific event type
            severity: Event severity
            message: Human-readable message
            **kwargs: Additional event fields

        Returns:
            The created SecurityEvent
        """
        if not self._config.enabled:
            return None

        # Check severity filter
        if severity < self._config.min_severity:
            return None

        # Check category filters
        if self._config.include_categories:
            if category not in self._config.include_categories:
                return None
        if self._config.exclude_categories:
            if category in self._config.exclude_categories:
                return None

        # Create event
        event = SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            category=category,
            event_type=event_type,
            severity=severity,
            message=message,
            **kwargs,
        )

        # Format and output
        formatted = self._format_event(event)

        # Log to Python logger
        log_level = self._severity_to_log_level(severity)
        self._logger.log(log_level, formatted)

        # Send to syslog if configured
        if self._config.syslog_host:
            self._send_syslog(event, formatted)

        # Call custom handlers
        for handler in self._handlers:
            try:
                handler(event)
            except Exception as e:
                self._logger.error(f"Handler error: {e}")

        return event

    def _format_event(self, event: SecurityEvent) -> str:
        """Format event according to configured format.

        Args:
            event: Event to format

        Returns:
            Formatted string
        """
        fmt = self._config.format

        if fmt == OutputFormat.CEF:
            return self._format_cef(event)
        elif fmt == OutputFormat.LEEF:
            return self._format_leef(event)
        elif fmt == OutputFormat.SYSLOG:
            return self._format_syslog(event)
        else:
            return self._format_json(event)

    def _format_cef(self, event: SecurityEvent) -> str:
        """Format event as CEF (Common Event Format).

        CEF Format:
        CEF:Version|Device Vendor|Device Product|Device Version|
        Device Event Class ID|Name|Severity|Extension
        """
        # Map severity to CEF (0-10)
        cef_severity = min(int(event.severity), 10)

        # Build extension with key=value pairs
        extensions = []

        if event.source_ip:
            extensions.append(f"src={event.source_ip}")
        if event.source_host:
            extensions.append(f"shost={event.source_host}")
        if event.destination_ip:
            extensions.append(f"dst={event.destination_ip}")
        if event.destination_host:
            extensions.append(f"dhost={event.destination_host}")
        if event.user_id:
            extensions.append(f"suid={event.user_id}")
        if event.user_name:
            extensions.append(f"suser={event.user_name}")
        if event.outcome:
            extensions.append(f"outcome={event.outcome}")
        if event.reason:
            extensions.append(f"reason={event.reason}")
        if event.algorithm:
            extensions.append(f"cs1={event.algorithm}")
            extensions.append("cs1Label=Algorithm")
        if event.key_id:
            extensions.append(f"cs2={event.key_id}")
            extensions.append("cs2Label=KeyID")
        if event.correlation_id:
            extensions.append(f"externalId={event.correlation_id}")

        # Add timestamp
        extensions.append(f"rt={int(event.timestamp.timestamp() * 1000)}")
        extensions.append(f"deviceCustomDate1={event.timestamp.isoformat()}")
        extensions.append("deviceCustomDate1Label=EventTime")

        # Escape message for CEF
        msg = event.message.replace("\\", "\\\\").replace("|", "\\|")

        extension_str = " ".join(extensions)

        return (
            f"CEF:0|{self._config.device_vendor}|{self._config.device_product}|"
            f"{self._config.device_version}|{event.event_type.value}|"
            f"{msg}|{cef_severity}|{extension_str}"
        )

    def _format_leef(self, event: SecurityEvent) -> str:
        """Format event as LEEF (Log Event Extended Format).

        LEEF Format:
        LEEF:Version|Vendor|Product|Version|EventID|Extension
        """
        # Build extension
        parts = []

        parts.append(f"cat={event.category.value}")
        parts.append(f"sev={int(event.severity)}")

        if event.source_ip:
            parts.append(f"src={event.source_ip}")
        if event.source_host:
            parts.append(f"srcHostName={event.source_host}")
        if event.destination_ip:
            parts.append(f"dst={event.destination_ip}")
        if event.user_id:
            parts.append(f"usrName={event.user_id}")
        if event.user_name:
            parts.append(f"identSrc={event.user_name}")
        if event.outcome:
            parts.append(f"outcome={event.outcome}")
        if event.algorithm:
            parts.append(f"algorithm={event.algorithm}")
        if event.key_id:
            parts.append(f"keyId={event.key_id}")
        if event.correlation_id:
            parts.append(f"correlationId={event.correlation_id}")

        # Add timestamp
        parts.append(
            f"devTime={event.timestamp.strftime('%b %d %Y %H:%M:%S')}"
        )

        extension = "\t".join(parts)

        return (
            f"LEEF:2.0|{self._config.device_vendor}|{self._config.device_product}|"
            f"{self._config.device_version}|{event.event_type.value}|"
            f"{extension}"
        )

    def _format_syslog(self, event: SecurityEvent) -> str:
        """Format event as RFC 5424 syslog message."""
        # Priority = Facility * 8 + Severity
        # Map our 0-10 severity to syslog 0-7 (inverted: 0 is emergency)
        syslog_severity = max(0, min(7, 7 - (int(event.severity) // 2)))
        priority = int(self._config.syslog_facility) * 8 + syslog_severity

        # Version 1
        version = 1

        # Timestamp in RFC 3339 format
        timestamp = event.timestamp.isoformat()

        # Hostname
        hostname = self._hostname

        # App-name
        app_name = self._config.product

        # Proc-id and message-id
        proc_id = "-"
        msg_id = event.event_type.value

        # Structured data
        sd = (
            f'[crypto@12345 category="{event.category.value}" '
            f'eventType="{event.event_type.value}" severity="{event.severity}"'
        )
        if event.user_id:
            sd += f' userId="{event.user_id}"'
        if event.algorithm:
            sd += f' algorithm="{event.algorithm}"'
        if event.correlation_id:
            sd += f' correlationId="{event.correlation_id}"'
        sd += "]"

        return (
            f"<{priority}>{version} {timestamp} {hostname} {app_name} "
            f"{proc_id} {msg_id} {sd} {event.message}"
        )

    def _format_json(self, event: SecurityEvent) -> str:
        """Format event as JSON."""
        data = event.to_dict()
        data["@timestamp"] = event.timestamp.isoformat()
        data["host"] = {"name": self._hostname}
        data["log"] = {
            "level": self._severity_to_level_name(event.severity),
        }
        data["event"] = {
            "category": event.category.value,
            "type": event.event_type.value,
            "severity": int(event.severity),
        }
        return json.dumps(data, default=str)

    def _send_syslog(self, event: SecurityEvent, message: str) -> None:
        """Send event to syslog server.

        Args:
            event: The event being sent
            message: Formatted message
        """
        try:
            if self._config.syslog_protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(
                    message.encode("utf-8"),
                    (self._config.syslog_host, self._config.syslog_port),
                )
                sock.close()
            elif self._config.syslog_protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect(
                    (self._config.syslog_host, self._config.syslog_port)
                )
                sock.sendall(message.encode("utf-8") + b"\n")
                sock.close()
        except Exception as e:
            self._logger.error(f"Failed to send syslog: {e}")

    def _severity_to_log_level(self, severity: Severity) -> int:
        """Map severity to Python logging level."""
        if severity >= Severity.EMERGENCY:
            return logging.CRITICAL
        elif severity >= Severity.CRITICAL:
            return logging.CRITICAL
        elif severity >= Severity.HIGH:
            return logging.ERROR
        elif severity >= Severity.MEDIUM:
            return logging.WARNING
        else:
            return logging.INFO

    def _severity_to_level_name(self, severity: Severity) -> str:
        """Map severity to log level name."""
        if severity >= Severity.CRITICAL:
            return "critical"
        elif severity >= Severity.HIGH:
            return "error"
        elif severity >= Severity.MEDIUM:
            return "warning"
        else:
            return "info"

    # Convenience methods for common events

    def log_authentication_success(
        self,
        user_id: str,
        user_name: Optional[str] = None,
        source_ip: Optional[str] = None,
        method: Optional[str] = None,
        **kwargs,
    ) -> SecurityEvent:
        """Log successful authentication."""
        message = f"Authentication successful for user {user_id}"
        if method:
            message += f" via {method}"

        return self.log_event(
            category=EventCategory.AUTHENTICATION,
            event_type=EventType.LOGIN_SUCCESS,
            severity=Severity.LOW,
            message=message,
            user_id=user_id,
            user_name=user_name,
            source_ip=source_ip,
            outcome="success",
            custom_fields={"method": method} if method else {},
            **kwargs,
        )

    def log_authentication_failure(
        self,
        user_id: str,
        reason: str,
        source_ip: Optional[str] = None,
        **kwargs,
    ) -> SecurityEvent:
        """Log failed authentication."""
        return self.log_event(
            category=EventCategory.AUTHENTICATION,
            event_type=EventType.LOGIN_FAILURE,
            severity=Severity.MEDIUM,
            message=f"Authentication failed for user {user_id}: {reason}",
            user_id=user_id,
            source_ip=source_ip,
            outcome="failure",
            reason=reason,
            **kwargs,
        )

    def log_access_denied(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        action: str,
        reason: Optional[str] = None,
        **kwargs,
    ) -> SecurityEvent:
        """Log access denied event."""
        return self.log_event(
            category=EventCategory.AUTHORIZATION,
            event_type=EventType.ACCESS_DENIED,
            severity=Severity.MEDIUM,
            message=f"Access denied: {user_id} cannot {action} {resource_type}/{resource_id}",
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            outcome="denied",
            reason=reason,
            **kwargs,
        )

    def log_encryption(
        self,
        algorithm: str,
        key_id: Optional[str] = None,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        data_size: Optional[int] = None,
        **kwargs,
    ) -> SecurityEvent:
        """Log encryption operation."""
        message = f"Data encrypted using {algorithm}"
        if data_size:
            message += f" ({data_size} bytes)"

        return self.log_event(
            category=EventCategory.CRYPTOGRAPHIC,
            event_type=EventType.ENCRYPT,
            severity=Severity.LOW,
            message=message,
            algorithm=algorithm,
            key_id=key_id,
            user_id=user_id,
            resource_type=resource_type,
            outcome="success",
            custom_fields={"data_size": data_size} if data_size else {},
            **kwargs,
        )

    def log_decryption(
        self,
        algorithm: str,
        key_id: Optional[str] = None,
        user_id: Optional[str] = None,
        success: bool = True,
        reason: Optional[str] = None,
        **kwargs,
    ) -> SecurityEvent:
        """Log decryption operation."""
        if success:
            return self.log_event(
                category=EventCategory.CRYPTOGRAPHIC,
                event_type=EventType.DECRYPT,
                severity=Severity.LOW,
                message=f"Data decrypted using {algorithm}",
                algorithm=algorithm,
                key_id=key_id,
                user_id=user_id,
                outcome="success",
                **kwargs,
            )
        else:
            return self.log_event(
                category=EventCategory.CRYPTOGRAPHIC,
                event_type=EventType.DECRYPT_FAILURE,
                severity=Severity.HIGH,
                message=f"Decryption failed using {algorithm}: {reason or 'unknown'}",
                algorithm=algorithm,
                key_id=key_id,
                user_id=user_id,
                outcome="failure",
                reason=reason,
                **kwargs,
            )

    def log_key_generated(
        self,
        key_id: str,
        algorithm: str,
        key_size: Optional[int] = None,
        user_id: Optional[str] = None,
        purpose: Optional[str] = None,
        **kwargs,
    ) -> SecurityEvent:
        """Log key generation."""
        message = f"Key generated: {key_id} ({algorithm}"
        if key_size:
            message += f", {key_size} bits"
        message += ")"

        return self.log_event(
            category=EventCategory.KEY_MANAGEMENT,
            event_type=EventType.KEY_GENERATED,
            severity=Severity.LOW,
            message=message,
            key_id=key_id,
            algorithm=algorithm,
            user_id=user_id,
            outcome="success",
            custom_fields={
                "key_size": key_size,
                "purpose": purpose,
            },
            **kwargs,
        )

    def log_key_rotation(
        self,
        old_key_id: str,
        new_key_id: str,
        algorithm: str,
        user_id: Optional[str] = None,
        reason: Optional[str] = None,
        **kwargs,
    ) -> SecurityEvent:
        """Log key rotation."""
        return self.log_event(
            category=EventCategory.KEY_MANAGEMENT,
            event_type=EventType.KEY_ROTATED,
            severity=Severity.MEDIUM,
            message=f"Key rotated: {old_key_id} -> {new_key_id}",
            key_id=new_key_id,
            algorithm=algorithm,
            user_id=user_id,
            reason=reason,
            outcome="success",
            custom_fields={"old_key_id": old_key_id},
            **kwargs,
        )

    def log_key_compromised(
        self,
        key_id: str,
        algorithm: str,
        discovery_method: str,
        user_id: Optional[str] = None,
        **kwargs,
    ) -> SecurityEvent:
        """Log key compromise (critical security event)."""
        return self.log_event(
            category=EventCategory.KEY_MANAGEMENT,
            event_type=EventType.KEY_COMPROMISED,
            severity=Severity.EMERGENCY,
            message=f"SECURITY ALERT: Key {key_id} has been compromised",
            key_id=key_id,
            algorithm=algorithm,
            user_id=user_id,
            reason=discovery_method,
            outcome="compromised",
            custom_fields={"discovery_method": discovery_method},
            **kwargs,
        )

    def log_policy_violation(
        self,
        policy_id: str,
        violation_type: str,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[str] = None,
        **kwargs,
    ) -> SecurityEvent:
        """Log policy violation."""
        return self.log_event(
            category=EventCategory.POLICY,
            event_type=EventType.POLICY_VIOLATION,
            severity=Severity.HIGH,
            message=f"Policy violation: {policy_id} - {violation_type}",
            policy_id=policy_id,
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            reason=details,
            outcome="violation",
            custom_fields={"violation_type": violation_type},
            **kwargs,
        )

    def log_certificate_validation(
        self,
        subject: str,
        issuer: str,
        serial_number: str,
        valid: bool,
        reason: Optional[str] = None,
        **kwargs,
    ) -> SecurityEvent:
        """Log certificate validation result."""
        if valid:
            return self.log_event(
                category=EventCategory.CERTIFICATE,
                event_type=EventType.CERT_VALIDATION_SUCCESS,
                severity=Severity.LOW,
                message=f"Certificate validated: {subject}",
                outcome="success",
                custom_fields={
                    "subject": subject,
                    "issuer": issuer,
                    "serial_number": serial_number,
                },
                **kwargs,
            )
        else:
            return self.log_event(
                category=EventCategory.CERTIFICATE,
                event_type=EventType.CERT_VALIDATION_FAILURE,
                severity=Severity.HIGH,
                message=f"Certificate validation failed: {subject} - {reason}",
                reason=reason,
                outcome="failure",
                custom_fields={
                    "subject": subject,
                    "issuer": issuer,
                    "serial_number": serial_number,
                },
                **kwargs,
            )

    def log_algorithm_deprecated(
        self,
        algorithm: str,
        replacement: str,
        deadline: Optional[str] = None,
        user_id: Optional[str] = None,
        **kwargs,
    ) -> SecurityEvent:
        """Log deprecated algorithm usage."""
        message = f"Deprecated algorithm used: {algorithm}. Use {replacement} instead."
        if deadline:
            message += f" Migration deadline: {deadline}"

        return self.log_event(
            category=EventCategory.CONFIGURATION,
            event_type=EventType.ALGORITHM_DEPRECATED,
            severity=Severity.MEDIUM_HIGH,
            message=message,
            algorithm=algorithm,
            user_id=user_id,
            custom_fields={
                "replacement": replacement,
                "deadline": deadline,
            },
            **kwargs,
        )


# Singleton instance
siem_engine = SIEMEngine()
