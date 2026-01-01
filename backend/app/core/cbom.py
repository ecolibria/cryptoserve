"""CBOM (Cryptographic Bill of Materials) Export Service.

Generates CycloneDX-compatible crypto bills of materials from crypto inventory.
CBOM tracks cryptographic libraries and algorithms used in applications,
enabling organizations to manage their crypto inventory and plan PQC migration.

Supports multiple export formats:
- Native JSON (full CBOM data)
- CycloneDX 1.5 (SBOM standard with crypto extensions)
- SPDX 2.3 (alternative SBOM format)

Usage:
    from app.core.cbom import cbom_service

    # Generate CBOM from inventory
    cbom = cbom_service.generate_cbom(inventory)

    # Export in different formats
    cyclonedx = cbom_service.to_cyclonedx(cbom)
    spdx = cbom_service.to_spdx(cbom)
"""

import hashlib
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from app.core.crypto_inventory import (
    CryptoInventory,
    DetectedLibrary,
    DetectedAlgorithm,
    QuantumRisk,
)


class CBOMVersion(str, Enum):
    """CBOM specification versions."""
    V1_0 = "1.0"


@dataclass
class CryptoComponent:
    """A cryptographic component in the CBOM."""
    bom_ref: str
    type: str  # library, algorithm, protocol
    name: str
    version: str | None
    purl: str | None  # Package URL for CycloneDX compatibility
    category: str
    quantum_risk: str
    is_deprecated: bool
    algorithms: list[str] = field(default_factory=list)
    properties: dict = field(default_factory=dict)


@dataclass
class QuantumReadiness:
    """Quantum readiness assessment."""
    score: float  # 0-100
    has_pqc: bool
    vulnerable_count: int
    safe_count: int
    deprecated_count: int
    risk_level: str  # critical, high, medium, low, none
    migration_urgency: str  # immediate, high, medium, low, none


@dataclass
class CBOM:
    """Cryptographic Bill of Materials - complete crypto inventory."""
    id: str
    version: str
    created_at: str

    # Identity
    identity_id: str
    identity_name: str
    team: str | None
    department: str | None

    # Components
    components: list[CryptoComponent]

    # Quantum analysis
    quantum_readiness: QuantumReadiness

    # Environment
    python_version: str | None
    environment: str | None

    # Git info (for CI/CD)
    git_commit: str | None = None
    git_branch: str | None = None
    git_repo: str | None = None

    # Metadata
    scan_source: str | None = None
    content_hash: str | None = None  # SHA-256 of crypto content for verification

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


class CBOMService:
    """Service for generating and exporting CBOMs."""

    def __init__(self):
        self.version = CBOMVersion.V1_0

    def generate_cbom(
        self,
        inventory: CryptoInventory,
        team: str | None = None,
        department: str | None = None,
        git_info: dict | None = None,
        scan_source: str | None = None,
    ) -> CBOM:
        """
        Generate CBOM from crypto inventory.

        Args:
            inventory: CryptoInventory from scanner
            team: Optional team name
            department: Optional department name
            git_info: Optional git metadata (commit, branch, repo)
            scan_source: Source of the scan (sdk_init, cicd_gate, etc.)

        Returns:
            Complete CBOM
        """
        # Generate unique ID
        cbom_id = f"cbom_{uuid.uuid4().hex[:12]}"

        # Build components from libraries
        components = []
        for lib in inventory.libraries:
            purl = self._generate_purl(lib.name, lib.version)

            component = CryptoComponent(
                bom_ref=f"crypto-lib-{lib.name}",
                type="library",
                name=lib.name,
                version=lib.version,
                purl=purl,
                category=lib.category,
                quantum_risk=lib.quantum_risk.value,
                is_deprecated=lib.is_deprecated,
                algorithms=lib.algorithms,
                properties={
                    "deprecation_reason": lib.deprecation_reason,
                    "recommendation": lib.recommendation,
                }
            )
            components.append(component)

        # Add algorithm components
        for algo in inventory.algorithms:
            component = CryptoComponent(
                bom_ref=f"crypto-algo-{algo.name}-{algo.library}",
                type="algorithm",
                name=algo.name,
                version=None,
                purl=None,
                category=algo.category,
                quantum_risk=algo.quantum_risk.value,
                is_deprecated=algo.is_weak,
                properties={
                    "library": algo.library,
                    "weakness_reason": algo.weakness_reason,
                }
            )
            components.append(component)

        # Calculate quantum readiness
        quantum_readiness = self._calculate_quantum_readiness(inventory)

        # Calculate content hash
        content_hash = self._calculate_content_hash(components)

        # Extract git info
        git_commit = git_info.get("commit") if git_info else None
        git_branch = git_info.get("branch") if git_info else None
        git_repo = git_info.get("repo") if git_info else None

        return CBOM(
            id=cbom_id,
            version=self.version.value,
            created_at=datetime.now(timezone.utc).isoformat(),
            identity_id=inventory.identity_id,
            identity_name=inventory.identity_name,
            team=team,
            department=department,
            components=components,
            quantum_readiness=quantum_readiness,
            python_version=None,  # Can be extracted from inventory
            environment=None,
            git_commit=git_commit,
            git_branch=git_branch,
            git_repo=git_repo,
            scan_source=scan_source,
            content_hash=content_hash,
        )

    def _generate_purl(self, name: str, version: str | None) -> str:
        """Generate Package URL for CycloneDX compatibility."""
        if version:
            return f"pkg:pypi/{name}@{version}"
        return f"pkg:pypi/{name}"

    def _calculate_quantum_readiness(self, inventory: CryptoInventory) -> QuantumReadiness:
        """Calculate quantum readiness assessment."""
        summary = inventory.quantum_summary

        safe_count = summary.get("quantum_safe", 0)
        vulnerable_count = summary.get("quantum_vulnerable", 0)
        has_pqc = summary.get("has_pqc", False)
        deprecated_count = inventory.risk_summary.get("deprecated_libraries", 0)

        total = safe_count + vulnerable_count

        # Calculate score (0-100)
        if total == 0:
            score = 100.0
        else:
            score = (safe_count / total) * 100

        # Apply bonuses/penalties
        if has_pqc:
            score = min(100, score + 20)
        if deprecated_count > 0:
            score = max(0, score - (deprecated_count * 10))

        score = round(score, 1)

        # Determine risk level
        if vulnerable_count == 0:
            risk_level = "none"
        elif score >= 80:
            risk_level = "low"
        elif score >= 60:
            risk_level = "medium"
        elif score >= 40:
            risk_level = "high"
        else:
            risk_level = "critical"

        # Determine migration urgency
        if deprecated_count > 0:
            migration_urgency = "immediate"
        elif vulnerable_count > 0 and not has_pqc:
            if score < 50:
                migration_urgency = "high"
            else:
                migration_urgency = "medium"
        elif vulnerable_count > 0:
            migration_urgency = "low"
        else:
            migration_urgency = "none"

        return QuantumReadiness(
            score=score,
            has_pqc=has_pqc,
            vulnerable_count=vulnerable_count,
            safe_count=safe_count,
            deprecated_count=deprecated_count,
            risk_level=risk_level,
            migration_urgency=migration_urgency,
        )

    def _calculate_content_hash(self, components: list[CryptoComponent]) -> str:
        """Calculate SHA-256 hash of crypto content for verification."""
        # Create deterministic string from components
        content_parts = []
        for comp in sorted(components, key=lambda c: c.bom_ref):
            content_parts.append(f"{comp.bom_ref}:{comp.name}:{comp.version}:{comp.quantum_risk}")

        content_string = "|".join(content_parts)
        return hashlib.sha256(content_string.encode()).hexdigest()

    def to_cyclonedx(self, cbom: CBOM) -> dict:
        """
        Convert CBOM to CycloneDX 1.5 format.

        CycloneDX is the industry standard for Software Bill of Materials.
        We embed the full CBOM data as an extension for crypto-specific details.

        Args:
            cbom: CBOM to convert

        Returns:
            CycloneDX 1.5 compatible JSON structure
        """
        # Build components list
        components = []
        for comp in cbom.components:
            if comp.type == "library":
                cdx_component = {
                    "type": "library",
                    "bom-ref": comp.bom_ref,
                    "name": comp.name,
                    "version": comp.version or "unknown",
                    "purl": comp.purl,
                    "properties": [
                        {"name": "crypto:category", "value": comp.category},
                        {"name": "crypto:quantum-risk", "value": comp.quantum_risk},
                        {"name": "crypto:is-deprecated", "value": str(comp.is_deprecated).lower()},
                    ]
                }

                # Add algorithms as properties
                if comp.algorithms:
                    cdx_component["properties"].append({
                        "name": "crypto:algorithms",
                        "value": ",".join(comp.algorithms)
                    })

                components.append(cdx_component)

        # Build CycloneDX structure
        cyclonedx = {
            "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": cbom.created_at,
                "tools": [
                    {
                        "vendor": "CryptoServe",
                        "name": "crypto-inventory",
                        "version": "1.0.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": cbom.identity_name,
                    "bom-ref": cbom.identity_id,
                },
                "properties": [
                    {"name": "cbom:version", "value": cbom.version},
                    {"name": "cbom:id", "value": cbom.id},
                    {"name": "cbom:content-hash", "value": cbom.content_hash},
                    {"name": "cbom:quantum-readiness-score", "value": str(cbom.quantum_readiness.score)},
                    {"name": "cbom:risk-level", "value": cbom.quantum_readiness.risk_level},
                    {"name": "cbom:migration-urgency", "value": cbom.quantum_readiness.migration_urgency},
                ]
            },
            "components": components,
            # Embed full CBOM as extension for detailed crypto analysis
            "extensions": {
                "cbom": cbom.to_dict()
            }
        }

        # Add git info if available
        if cbom.git_repo:
            cyclonedx["metadata"]["properties"].append({
                "name": "git:repo", "value": cbom.git_repo
            })
        if cbom.git_branch:
            cyclonedx["metadata"]["properties"].append({
                "name": "git:branch", "value": cbom.git_branch
            })
        if cbom.git_commit:
            cyclonedx["metadata"]["properties"].append({
                "name": "git:commit", "value": cbom.git_commit
            })

        return cyclonedx

    def to_spdx(self, cbom: CBOM) -> dict:
        """
        Convert CBOM to SPDX 2.3 format.

        SPDX is an alternative SBOM standard. We embed CBOM data
        in annotations for crypto-specific details.

        Args:
            cbom: CBOM to convert

        Returns:
            SPDX 2.3 compatible JSON structure
        """
        spdx_id = f"SPDXRef-{cbom.id.replace('_', '-')}"

        # Build packages list
        packages = []

        # Main application package
        main_package = {
            "SPDXID": f"SPDXRef-Application-{cbom.identity_id}",
            "name": cbom.identity_name,
            "versionInfo": "1.0.0",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "primaryPackagePurpose": "APPLICATION",
        }
        packages.append(main_package)

        # Crypto library packages
        for comp in cbom.components:
            if comp.type == "library":
                pkg = {
                    "SPDXID": f"SPDXRef-{comp.bom_ref}",
                    "name": comp.name,
                    "versionInfo": comp.version or "unknown",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "primaryPackagePurpose": "LIBRARY",
                    "externalRefs": []
                }

                if comp.purl:
                    pkg["externalRefs"].append({
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": comp.purl
                    })

                packages.append(pkg)

        # Build relationships
        relationships = [
            {
                "spdxElementId": spdx_id,
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": f"SPDXRef-Application-{cbom.identity_id}"
            }
        ]

        # Add DEPENDS_ON relationships for crypto libraries
        for comp in cbom.components:
            if comp.type == "library":
                relationships.append({
                    "spdxElementId": f"SPDXRef-Application-{cbom.identity_id}",
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": f"SPDXRef-{comp.bom_ref}"
                })

        # Build annotations for CBOM data
        annotations = [
            {
                "annotationDate": cbom.created_at,
                "annotationType": "OTHER",
                "annotator": "Tool: CryptoServe crypto-inventory",
                "comment": f"CBOM Data (JSON): {__import__('json').dumps(cbom.to_dict())}"
            }
        ]

        spdx = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": spdx_id,
            "name": f"CBOM for {cbom.identity_name}",
            "documentNamespace": f"https://cbom.csnp.org/spdx/{cbom.id}",
            "creationInfo": {
                "created": cbom.created_at,
                "creators": ["Tool: CryptoServe-1.0.0"],
                "licenseListVersion": "3.19"
            },
            "packages": packages,
            "relationships": relationships,
            "annotations": annotations
        }

        return spdx

    def to_json(self, cbom: CBOM) -> dict:
        """
        Convert CBOM to native JSON format.

        This is the full CBOM representation with all crypto details.

        Args:
            cbom: CBOM to convert

        Returns:
            Native CBOM JSON structure
        """
        return cbom.to_dict()


# Singleton instance
cbom_service = CBOMService()
