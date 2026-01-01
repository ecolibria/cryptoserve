"""Tests for CBOM (Cryptographic Bill of Materials) service."""

import pytest
from app.core.cbom import cbom_service, CBOM, CryptoComponent, QuantumReadiness
from app.core.crypto_inventory import (
    CryptoInventory,
    DetectedLibrary,
    DetectedAlgorithm,
    InventorySource,
    QuantumRisk,
)


@pytest.fixture
def sample_inventory():
    """Create a sample crypto inventory for testing."""
    libraries = [
        DetectedLibrary(
            name="cryptography",
            version="41.0.0",
            category="general",
            algorithms=["AES", "RSA", "ECDSA", "SHA-256"],
            quantum_risk=QuantumRisk.HIGH,
            source=InventorySource.IMPORT_SCAN,
            is_deprecated=False,
        ),
        DetectedLibrary(
            name="pycrypto",
            version="2.6.1",
            category="general",
            algorithms=["AES", "DES", "RSA"],
            quantum_risk=QuantumRisk.HIGH,
            source=InventorySource.IMPORT_SCAN,
            is_deprecated=True,
            deprecation_reason="Unmaintained since 2013",
            recommendation="Migrate to pycryptodome",
        ),
        DetectedLibrary(
            name="bcrypt",
            version="4.0.1",
            category="kdf",
            algorithms=["bcrypt"],
            quantum_risk=QuantumRisk.NONE,
            source=InventorySource.IMPORT_SCAN,
            is_deprecated=False,
        ),
    ]

    algorithms = [
        DetectedAlgorithm(
            name="AES",
            category="symmetric",
            library="cryptography",
            quantum_risk=QuantumRisk.NONE,
            is_weak=False,
            source=InventorySource.IMPORT_SCAN,
        ),
        DetectedAlgorithm(
            name="RSA",
            category="asymmetric",
            library="cryptography",
            quantum_risk=QuantumRisk.HIGH,
            is_weak=False,
            source=InventorySource.IMPORT_SCAN,
        ),
    ]

    return CryptoInventory(
        identity_id="test-app-123",
        identity_name="Test Application",
        scan_timestamp="2024-01-15T10:30:00Z",
        libraries=libraries,
        algorithms=algorithms,
        secrets_detected=[],
        quantum_summary={
            "total_libraries": 3,
            "quantum_safe": 1,
            "quantum_vulnerable": 2,
            "has_pqc": False,
        },
        risk_summary={
            "deprecated_libraries": 1,
            "weak_algorithms": 0,
        },
        source=InventorySource.IMPORT_SCAN,
    )


@pytest.fixture
def pqc_inventory():
    """Create an inventory with PQC libraries."""
    libraries = [
        DetectedLibrary(
            name="liboqs",
            version="0.9.0",
            category="pqc",
            algorithms=["Kyber", "Dilithium"],
            quantum_risk=QuantumRisk.NONE,
            source=InventorySource.IMPORT_SCAN,
            is_deprecated=False,
        ),
        DetectedLibrary(
            name="cryptography",
            version="41.0.0",
            category="general",
            algorithms=["AES", "X25519"],
            quantum_risk=QuantumRisk.HIGH,
            source=InventorySource.IMPORT_SCAN,
            is_deprecated=False,
        ),
    ]

    return CryptoInventory(
        identity_id="pqc-app-456",
        identity_name="PQC Ready App",
        scan_timestamp="2024-01-15T10:30:00Z",
        libraries=libraries,
        algorithms=[],
        secrets_detected=[],
        quantum_summary={
            "total_libraries": 2,
            "quantum_safe": 1,
            "quantum_vulnerable": 1,
            "has_pqc": True,
        },
        risk_summary={
            "deprecated_libraries": 0,
            "weak_algorithms": 0,
        },
        source=InventorySource.IMPORT_SCAN,
    )


class TestCBOMGeneration:
    """Tests for CBOM generation."""

    def test_generate_cbom_basic(self, sample_inventory):
        """Test basic CBOM generation."""
        cbom = cbom_service.generate_cbom(sample_inventory)

        assert cbom.id.startswith("cbom_")
        assert cbom.version == "1.0"
        assert cbom.identity_id == "test-app-123"
        assert cbom.identity_name == "Test Application"
        assert len(cbom.components) == 5  # 3 libraries + 2 algorithms
        assert cbom.content_hash is not None

    def test_generate_cbom_with_metadata(self, sample_inventory):
        """Test CBOM generation with team/department/git info."""
        cbom = cbom_service.generate_cbom(
            sample_inventory,
            team="security",
            department="engineering",
            git_info={
                "commit": "abc123",
                "branch": "main",
                "repo": "github.com/org/repo",
            },
            scan_source="cicd_gate",
        )

        assert cbom.team == "security"
        assert cbom.department == "engineering"
        assert cbom.git_commit == "abc123"
        assert cbom.git_branch == "main"
        assert cbom.git_repo == "github.com/org/repo"
        assert cbom.scan_source == "cicd_gate"

    def test_cbom_components_include_libraries(self, sample_inventory):
        """Test that CBOM includes library components."""
        cbom = cbom_service.generate_cbom(sample_inventory)

        library_components = [c for c in cbom.components if c.type == "library"]
        assert len(library_components) == 3

        crypto_lib = next(c for c in library_components if c.name == "cryptography")
        assert crypto_lib.version == "41.0.0"
        assert crypto_lib.category == "general"
        assert crypto_lib.quantum_risk == "high"
        assert crypto_lib.is_deprecated is False
        assert crypto_lib.purl == "pkg:pypi/cryptography@41.0.0"

    def test_cbom_components_include_algorithms(self, sample_inventory):
        """Test that CBOM includes algorithm components."""
        cbom = cbom_service.generate_cbom(sample_inventory)

        algo_components = [c for c in cbom.components if c.type == "algorithm"]
        assert len(algo_components) == 2

        rsa_algo = next(c for c in algo_components if c.name == "RSA")
        assert rsa_algo.category == "asymmetric"
        assert rsa_algo.quantum_risk == "high"

    def test_cbom_deprecated_library_flagged(self, sample_inventory):
        """Test that deprecated libraries are properly flagged."""
        cbom = cbom_service.generate_cbom(sample_inventory)

        pycrypto = next(c for c in cbom.components if c.name == "pycrypto")
        assert pycrypto.is_deprecated is True
        assert pycrypto.properties["deprecation_reason"] == "Unmaintained since 2013"
        assert pycrypto.properties["recommendation"] == "Migrate to pycryptodome"


class TestQuantumReadiness:
    """Tests for quantum readiness calculation."""

    def test_quantum_readiness_with_vulnerabilities(self, sample_inventory):
        """Test quantum readiness score with vulnerable libraries."""
        cbom = cbom_service.generate_cbom(sample_inventory)

        qr = cbom.quantum_readiness
        assert qr.vulnerable_count == 2
        assert qr.safe_count == 1
        assert qr.deprecated_count == 1
        assert qr.has_pqc is False
        # Score penalized for deprecated library
        assert qr.score < 50
        assert qr.risk_level in ["high", "critical"]
        assert qr.migration_urgency == "immediate"  # Due to deprecated

    def test_quantum_readiness_with_pqc(self, pqc_inventory):
        """Test quantum readiness score with PQC libraries."""
        cbom = cbom_service.generate_cbom(pqc_inventory)

        qr = cbom.quantum_readiness
        assert qr.has_pqc is True
        assert qr.deprecated_count == 0
        # PQC bonus should improve score
        assert qr.score >= 50
        assert qr.migration_urgency in ["low", "medium", "none"]

    def test_quantum_readiness_no_crypto(self):
        """Test quantum readiness with no crypto libraries."""
        inventory = CryptoInventory(
            identity_id="no-crypto-app",
            identity_name="No Crypto App",
            scan_timestamp="2024-01-15T10:30:00Z",
            libraries=[],
            algorithms=[],
            secrets_detected=[],
            quantum_summary={
                "total_libraries": 0,
                "quantum_safe": 0,
                "quantum_vulnerable": 0,
                "has_pqc": False,
            },
            risk_summary={
                "deprecated_libraries": 0,
                "weak_algorithms": 0,
            },
            source=InventorySource.IMPORT_SCAN,
        )

        cbom = cbom_service.generate_cbom(inventory)
        assert cbom.quantum_readiness.score == 100.0
        assert cbom.quantum_readiness.risk_level == "none"


class TestCycloneDXExport:
    """Tests for CycloneDX export format."""

    def test_cyclonedx_structure(self, sample_inventory):
        """Test CycloneDX export has correct structure."""
        cbom = cbom_service.generate_cbom(sample_inventory)
        cdx = cbom_service.to_cyclonedx(cbom)

        assert cdx["bomFormat"] == "CycloneDX"
        assert cdx["specVersion"] == "1.5"
        assert "serialNumber" in cdx
        assert "metadata" in cdx
        assert "components" in cdx
        assert "extensions" in cdx

    def test_cyclonedx_metadata(self, sample_inventory):
        """Test CycloneDX metadata properties."""
        cbom = cbom_service.generate_cbom(sample_inventory)
        cdx = cbom_service.to_cyclonedx(cbom)

        metadata = cdx["metadata"]
        assert metadata["component"]["name"] == "Test Application"

        props = {p["name"]: p["value"] for p in metadata["properties"]}
        assert "cbom:version" in props
        assert "cbom:id" in props
        assert "cbom:content-hash" in props
        assert "cbom:quantum-readiness-score" in props

    def test_cyclonedx_components(self, sample_inventory):
        """Test CycloneDX components include crypto properties."""
        cbom = cbom_service.generate_cbom(sample_inventory)
        cdx = cbom_service.to_cyclonedx(cbom)

        # Only library components are included in CycloneDX
        assert len(cdx["components"]) == 3

        crypto_comp = next(c for c in cdx["components"] if c["name"] == "cryptography")
        assert crypto_comp["type"] == "library"
        assert crypto_comp["purl"] == "pkg:pypi/cryptography@41.0.0"

        props = {p["name"]: p["value"] for p in crypto_comp["properties"]}
        assert props["crypto:category"] == "general"
        assert props["crypto:quantum-risk"] == "high"

    def test_cyclonedx_cbom_extension(self, sample_inventory):
        """Test CycloneDX includes full CBOM as extension."""
        cbom = cbom_service.generate_cbom(sample_inventory)
        cdx = cbom_service.to_cyclonedx(cbom)

        assert "cbom" in cdx["extensions"]
        assert cdx["extensions"]["cbom"]["identity_id"] == "test-app-123"

    def test_cyclonedx_with_git_info(self, sample_inventory):
        """Test CycloneDX includes git info when provided."""
        cbom = cbom_service.generate_cbom(
            sample_inventory,
            git_info={"commit": "abc123", "branch": "main", "repo": "org/repo"},
        )
        cdx = cbom_service.to_cyclonedx(cbom)

        props = {p["name"]: p["value"] for p in cdx["metadata"]["properties"]}
        assert props["git:commit"] == "abc123"
        assert props["git:branch"] == "main"
        assert props["git:repo"] == "org/repo"


class TestSPDXExport:
    """Tests for SPDX export format."""

    def test_spdx_structure(self, sample_inventory):
        """Test SPDX export has correct structure."""
        cbom = cbom_service.generate_cbom(sample_inventory)
        spdx = cbom_service.to_spdx(cbom)

        assert spdx["spdxVersion"] == "SPDX-2.3"
        assert spdx["dataLicense"] == "CC0-1.0"
        assert "SPDXID" in spdx
        assert "packages" in spdx
        assert "relationships" in spdx
        assert "annotations" in spdx

    def test_spdx_namespace(self, sample_inventory):
        """Test SPDX document namespace uses cbom.csnp.org."""
        cbom = cbom_service.generate_cbom(sample_inventory)
        spdx = cbom_service.to_spdx(cbom)

        assert "cbom.csnp.org" in spdx["documentNamespace"]

    def test_spdx_packages(self, sample_inventory):
        """Test SPDX includes packages for libraries."""
        cbom = cbom_service.generate_cbom(sample_inventory)
        spdx = cbom_service.to_spdx(cbom)

        # 1 main application + 3 library packages
        assert len(spdx["packages"]) == 4

        app_pkg = next(p for p in spdx["packages"] if "Application" in p["SPDXID"])
        assert app_pkg["name"] == "Test Application"

    def test_spdx_relationships(self, sample_inventory):
        """Test SPDX includes DEPENDS_ON relationships."""
        cbom = cbom_service.generate_cbom(sample_inventory)
        spdx = cbom_service.to_spdx(cbom)

        depends_on = [r for r in spdx["relationships"] if r["relationshipType"] == "DEPENDS_ON"]
        assert len(depends_on) == 3  # 3 library dependencies

    def test_spdx_cbom_annotation(self, sample_inventory):
        """Test SPDX includes CBOM data in annotations."""
        cbom = cbom_service.generate_cbom(sample_inventory)
        spdx = cbom_service.to_spdx(cbom)

        assert len(spdx["annotations"]) == 1
        assert "CBOM Data (JSON):" in spdx["annotations"][0]["comment"]


class TestJSONExport:
    """Tests for native JSON export."""

    def test_json_export(self, sample_inventory):
        """Test native JSON export returns full CBOM."""
        cbom = cbom_service.generate_cbom(sample_inventory)
        json_data = cbom_service.to_json(cbom)

        assert json_data["id"] == cbom.id
        assert json_data["identity_id"] == "test-app-123"
        assert len(json_data["components"]) == 5
        assert "quantum_readiness" in json_data


class TestContentHash:
    """Tests for content hash calculation."""

    def test_content_hash_deterministic(self, sample_inventory):
        """Test that content hash is deterministic."""
        cbom1 = cbom_service.generate_cbom(sample_inventory)
        cbom2 = cbom_service.generate_cbom(sample_inventory)

        # IDs will be different, but content hash should be same
        assert cbom1.id != cbom2.id
        assert cbom1.content_hash == cbom2.content_hash

    def test_content_hash_changes_with_content(self, sample_inventory):
        """Test that content hash changes when content changes."""
        cbom1 = cbom_service.generate_cbom(sample_inventory)

        # Modify inventory
        sample_inventory.libraries[0].version = "42.0.0"
        cbom2 = cbom_service.generate_cbom(sample_inventory)

        assert cbom1.content_hash != cbom2.content_hash
