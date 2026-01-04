"""Certificate Transparency (CT) Monitoring Engine.

Monitors public CT logs for certificate issuance to detect:
- Unauthorized certificate issuance
- Rogue or misissued certificates
- CA compromise indicators
- Certificate expiration alerts

CT Log Architecture:
- CT logs are append-only, cryptographically verifiable
- Certificates must be logged before browsers trust them (Chrome/Safari require SCTs)
- Public logs enable domain owners to detect unauthorized issuance

Data Sources:
- crt.sh: Free CT log aggregator (PostgreSQL database of all logged certs)
- Google CT API: Direct log queries
- Certificate Search APIs

Standards:
- RFC 6962: Certificate Transparency
- RFC 9162: Certificate Transparency Version 2.0
"""

import asyncio
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class CTAlertSeverity(str, Enum):
    """Severity levels for CT alerts."""
    CRITICAL = "critical"   # Likely rogue cert, immediate action needed
    HIGH = "high"           # Unexpected cert, investigate
    MEDIUM = "medium"       # Anomaly detected
    LOW = "low"             # Informational
    INFO = "info"           # Normal issuance


class CTAlertType(str, Enum):
    """Types of CT alerts."""
    UNEXPECTED_ISSUER = "unexpected_issuer"
    UNEXPECTED_DOMAIN = "unexpected_domain"
    EXPIRED_CERT = "expired_cert"
    EXPIRING_SOON = "expiring_soon"
    NEW_CERT_ISSUED = "new_cert_issued"
    WILDCARD_ISSUED = "wildcard_issued"
    REVOKED_CERT = "revoked_cert"
    DUPLICATE_SERIAL = "duplicate_serial"
    WEAK_ALGORITHM = "weak_algorithm"


@dataclass
class CTLogEntry:
    """A certificate entry from CT logs."""
    id: int
    issuer_name: str
    issuer_ca_id: int | None
    common_name: str
    name_value: str  # All SANs
    not_before: datetime
    not_after: datetime
    serial_number: str
    sha256_fingerprint: str
    entry_timestamp: datetime | None = None
    log_name: str | None = None

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.not_after

    @property
    def days_until_expiry(self) -> int:
        delta = self.not_after - datetime.now(timezone.utc)
        return delta.days

    @property
    def is_wildcard(self) -> bool:
        return self.common_name.startswith("*.")

    @property
    def domains(self) -> list[str]:
        """Parse name_value into list of domains."""
        if not self.name_value:
            return []
        return [d.strip() for d in self.name_value.split("\n") if d.strip()]


@dataclass
class CTAlert:
    """An alert generated from CT monitoring."""
    alert_type: CTAlertType
    severity: CTAlertSeverity
    domain: str
    message: str
    certificate: CTLogEntry | None = None
    details: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DomainConfig:
    """Configuration for monitoring a domain."""
    domain: str
    include_subdomains: bool = True
    expected_issuers: list[str] = field(default_factory=list)
    alert_on_wildcard: bool = True
    expiry_warning_days: int = 30


@dataclass
class CTMonitoringResult:
    """Result of CT monitoring scan."""
    domain: str
    certificates: list[CTLogEntry]
    alerts: list[CTAlert]
    scanned_at: datetime
    total_certs: int
    active_certs: int
    expired_certs: int
    issuers: dict[str, int]  # issuer name -> count


class CTMonitor:
    """Certificate Transparency monitoring engine.

    Queries CT logs to find all certificates issued for monitored domains
    and generates alerts for suspicious or unexpected certificates.
    """

    # crt.sh API base URL
    CRTSH_API = "https://crt.sh"

    # Known legitimate CAs (for alert tuning)
    TRUSTED_ISSUERS = {
        "Let's Encrypt",
        "DigiCert",
        "Sectigo",
        "GlobalSign",
        "Amazon",
        "Cloudflare",
        "Google Trust Services",
        "Microsoft",
        "ZeroSSL",
    }

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=True,
            )
        return self._client

    async def close(self):
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def search_certificates(
        self,
        domain: str,
        include_subdomains: bool = True,
        exclude_expired: bool = False,
    ) -> list[CTLogEntry]:
        """Search CT logs for certificates matching a domain.

        Uses crt.sh which aggregates multiple CT logs.

        Args:
            domain: Domain to search for (e.g., "example.com")
            include_subdomains: Include *.example.com
            exclude_expired: Filter out expired certificates

        Returns:
            List of certificate entries from CT logs
        """
        client = await self._get_client()

        # crt.sh search pattern
        search_domain = f"%.{domain}" if include_subdomains else domain

        try:
            response = await client.get(
                f"{self.CRTSH_API}/",
                params={
                    "q": search_domain,
                    "output": "json",
                    "exclude": "expired" if exclude_expired else None,
                },
            )
            response.raise_for_status()

            data = response.json()
            if not data:
                return []

            # Deduplicate by serial+issuer_ca_id (same cert appears in multiple CT logs)
            seen_certs: dict[str, CTLogEntry] = {}
            for row in data:
                try:
                    # Unique key: serial number + issuer CA ID
                    serial = row.get("serial_number", "")
                    issuer_ca_id = row.get("issuer_ca_id")
                    unique_key = f"{serial}:{issuer_ca_id}"

                    # Keep only the first occurrence (or could keep newest)
                    if unique_key in seen_certs:
                        continue

                    entry = CTLogEntry(
                        id=row.get("id", 0),
                        issuer_name=row.get("issuer_name", "Unknown"),
                        issuer_ca_id=issuer_ca_id,
                        common_name=row.get("common_name", ""),
                        name_value=row.get("name_value", ""),
                        not_before=self._parse_date(row.get("not_before")),
                        not_after=self._parse_date(row.get("not_after")),
                        serial_number=serial,
                        sha256_fingerprint=self._compute_fingerprint(row),
                        entry_timestamp=self._parse_date(row.get("entry_timestamp")),
                    )
                    seen_certs[unique_key] = entry
                except Exception as e:
                    logger.warning(f"Failed to parse CT log entry: {e}")

            return list(seen_certs.values())

        except httpx.HTTPError as e:
            logger.error(f"CT log query failed for {domain}: {e}")
            return []

    def _parse_date(self, date_str: str | None) -> datetime:
        """Parse date from crt.sh format."""
        if not date_str:
            return datetime.now(timezone.utc)
        try:
            # crt.sh uses ISO format
            if "T" in date_str:
                # Handle Z suffix
                parsed = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                # Ensure timezone-aware (fromisoformat may return naive datetime)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed
            else:
                return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc
                )
        except ValueError:
            return datetime.now(timezone.utc)

    def _compute_fingerprint(self, row: dict) -> str:
        """Compute SHA256 fingerprint from certificate data."""
        # crt.sh provides serial + issuer which is unique
        unique_str = f"{row.get('serial_number', '')}:{row.get('issuer_ca_id', '')}"
        return hashlib.sha256(unique_str.encode()).hexdigest()[:32]

    def analyze_certificates(
        self,
        certificates: list[CTLogEntry],
        config: DomainConfig,
    ) -> list[CTAlert]:
        """Analyze certificates and generate alerts.

        Only generates actionable security alerts:
        - Expiring soon (active certs needing renewal)
        - Unexpected issuers (if configured)
        - Wildcard certificates (once per unique wildcard)

        Note: Duplicate serial detection removed - crt.sh deduplication
        handles this, and same-serial from different CAs is expected.
        Expired cert alerts removed - not actionable security alerts.

        Args:
            certificates: List of CT log entries (already deduplicated)
            config: Domain monitoring configuration

        Returns:
            List of alerts generated
        """
        alerts = []
        seen_wildcards: set[str] = set()  # Track unique wildcard CNs
        seen_expiring: set[str] = set()  # Track unique expiring CNs
        seen_weak_issuers: set[str] = set()  # Track weak algorithm issuers

        for cert in certificates:
            # Only alert on ACTIVE certs expiring soon (actionable, dedupe by CN)
            if not cert.is_expired and cert.days_until_expiry <= config.expiry_warning_days:
                if cert.common_name not in seen_expiring:
                    seen_expiring.add(cert.common_name)
                    alerts.append(CTAlert(
                        alert_type=CTAlertType.EXPIRING_SOON,
                        severity=CTAlertSeverity.MEDIUM,
                        domain=config.domain,
                        message=f"Certificate expiring in {cert.days_until_expiry} days: {cert.common_name}",
                        certificate=cert,
                    ))

            # Check unexpected issuers
            if config.expected_issuers:
                issuer_matched = any(
                    expected.lower() in cert.issuer_name.lower()
                    for expected in config.expected_issuers
                )
                if not issuer_matched:
                    alerts.append(CTAlert(
                        alert_type=CTAlertType.UNEXPECTED_ISSUER,
                        severity=CTAlertSeverity.HIGH,
                        domain=config.domain,
                        message=f"Unexpected issuer '{cert.issuer_name}' for {cert.common_name}",
                        certificate=cert,
                        details={"expected_issuers": config.expected_issuers},
                    ))

            # Check wildcard issuance (only alert once per unique wildcard CN)
            if config.alert_on_wildcard and cert.is_wildcard:
                if cert.common_name not in seen_wildcards:
                    seen_wildcards.add(cert.common_name)
                    # Only alert on active wildcards
                    if not cert.is_expired:
                        alerts.append(CTAlert(
                            alert_type=CTAlertType.WILDCARD_ISSUED,
                            severity=CTAlertSeverity.INFO,  # Informational, not a problem
                            domain=config.domain,
                            message=f"Active wildcard certificate: {cert.common_name}",
                            certificate=cert,
                        ))

            # Check for weak algorithms in issuer name (only once per issuer)
            issuer_lower = cert.issuer_name.lower()
            if ("sha1" in issuer_lower or "md5" in issuer_lower) and not cert.is_expired:
                if cert.issuer_name not in seen_weak_issuers:
                    seen_weak_issuers.add(cert.issuer_name)
                    alerts.append(CTAlert(
                        alert_type=CTAlertType.WEAK_ALGORITHM,
                        severity=CTAlertSeverity.HIGH,
                        domain=config.domain,
                        message=f"Active certificate from weak-algorithm CA: {cert.issuer_name}",
                        certificate=cert,
                    ))

        return alerts

    async def monitor_domain(
        self,
        config: DomainConfig,
    ) -> CTMonitoringResult:
        """Monitor a domain for certificate activity.

        Args:
            config: Domain monitoring configuration

        Returns:
            Monitoring result with certificates and alerts
        """
        certificates = await self.search_certificates(
            domain=config.domain,
            include_subdomains=config.include_subdomains,
            exclude_expired=False,  # We want to count expired certs
        )

        alerts = self.analyze_certificates(certificates, config)

        # Count by issuer
        issuers: dict[str, int] = {}
        for cert in certificates:
            issuer = cert.issuer_name
            issuers[issuer] = issuers.get(issuer, 0) + 1

        active_certs = sum(1 for c in certificates if not c.is_expired)
        expired_certs = sum(1 for c in certificates if c.is_expired)

        return CTMonitoringResult(
            domain=config.domain,
            certificates=certificates,
            alerts=alerts,
            scanned_at=datetime.now(timezone.utc),
            total_certs=len(certificates),
            active_certs=active_certs,
            expired_certs=expired_certs,
            issuers=issuers,
        )

    async def monitor_domains(
        self,
        domains: list[DomainConfig],
    ) -> list[CTMonitoringResult]:
        """Monitor multiple domains concurrently.

        Args:
            domains: List of domain configurations

        Returns:
            List of monitoring results
        """
        tasks = [self.monitor_domain(config) for config in domains]
        return await asyncio.gather(*tasks)

    async def find_recent_certificates(
        self,
        domain: str,
        days: int = 7,
    ) -> list[CTLogEntry]:
        """Find certificates issued in the last N days.

        Args:
            domain: Domain to search
            days: Number of days to look back

        Returns:
            Recently issued certificates
        """
        all_certs = await self.search_certificates(domain, exclude_expired=True)
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        return [
            cert for cert in all_certs
            if cert.entry_timestamp and cert.entry_timestamp >= cutoff
        ]

    async def get_certificate_details(self, cert_id: int) -> dict[str, Any] | None:
        """Get detailed certificate information from crt.sh.

        Args:
            cert_id: crt.sh certificate ID

        Returns:
            Certificate details or None
        """
        client = await self._get_client()

        try:
            response = await client.get(
                f"{self.CRTSH_API}/",
                params={"id": cert_id, "output": "json"},
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Failed to get certificate details for {cert_id}: {e}")
            return None


# Singleton instance
ct_monitor = CTMonitor()
