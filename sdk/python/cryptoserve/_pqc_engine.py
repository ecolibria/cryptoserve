"""Offline PQC analysis engine.

Ports the backend's PQC recommendation intelligence into the SDK so that
air-gapped and offline environments get the same quality analysis as
server-connected environments.

Data sourced from backend/app/core/pqc_recommendations.py and expanded
with compliance framework references and algorithm-specific threat timelines.
"""

from __future__ import annotations

import datetime

# ---------------------------------------------------------------------------
# Embedded intelligence data
# ---------------------------------------------------------------------------

QUANTUM_THREAT_TIMELINE: dict[str, dict[str, int]] = {
    "rsa_2048":   {"min": 10, "median": 15, "max": 25},
    "rsa_4096":   {"min": 15, "median": 20, "max": 30},
    "ecdsa_p256": {"min": 10, "median": 15, "max": 25},
    "ecdsa_p384": {"min": 12, "median": 17, "max": 27},
    "ed25519":    {"min": 10, "median": 15, "max": 25},
    "x25519":     {"min": 10, "median": 15, "max": 25},
    "dh_2048":    {"min": 10, "median": 15, "max": 25},
    "aes_128":    {"min": 15, "median": 25, "max": 50},
    "aes_256":    {"min": 30, "median": 50, "max": 100},
    "sha_256":    {"min": 30, "median": 50, "max": 100},
    "chacha20":   {"min": 30, "median": 50, "max": 100},
}

DATA_PROFILES: dict[str, dict] = {
    "national_security": {
        "name": "National Security Data",
        "lifespan_years": 75,
        "urgency": "critical",
        "crypto_needs": ["kem", "signature"],
    },
    "healthcare": {
        "name": "Healthcare Records",
        "lifespan_years": 100,
        "urgency": "critical",
        "crypto_needs": ["kem"],
    },
    "financial": {
        "name": "Long-term Financial Data",
        "lifespan_years": 25,
        "urgency": "high",
        "crypto_needs": ["kem", "signature"],
    },
    "intellectual_property": {
        "name": "Intellectual Property",
        "lifespan_years": 20,
        "urgency": "high",
        "crypto_needs": ["kem"],
    },
    "legal": {
        "name": "Legal Documents",
        "lifespan_years": 30,
        "urgency": "high",
        "crypto_needs": ["kem", "signature"],
    },
    "general": {
        "name": "Personal Data / General",
        "lifespan_years": 10,
        "urgency": "medium",
        "crypto_needs": ["kem"],
    },
    "authentication": {
        "name": "Authentication Credentials",
        "lifespan_years": 1,
        "urgency": "medium",
        "crypto_needs": ["kem", "signature"],
    },
    "session_tokens": {
        "name": "Session Tokens",
        "lifespan_years": 0,
        "urgency": "low",
        "crypto_needs": ["signature"],
    },
    "ephemeral": {
        "name": "Ephemeral Communications",
        "lifespan_years": 1,
        "urgency": "low",
        "crypto_needs": ["kem"],
    },
    # Backward-compat alias
    "short_lived": {
        "name": "Session Tokens",
        "lifespan_years": 0,
        "urgency": "low",
        "crypto_needs": ["signature"],
    },
}

PQC_ALGORITHMS: dict[str, list[dict]] = {
    "kem": [
        {
            "id": "ml-kem-768",
            "name": "ML-KEM-768",
            "fips": "FIPS 203",
            "security_level": 3,
            "status": "standardized",
            "description": "Primary NIST KEM standard, balanced security/performance",
            "hybrid_with": "X25519Kyber768",
        },
        {
            "id": "ml-kem-1024",
            "name": "ML-KEM-1024",
            "fips": "FIPS 203",
            "security_level": 5,
            "status": "standardized",
            "description": "Highest security KEM for long-term protection",
            "hybrid_with": "X25519Kyber1024",
        },
        {
            "id": "ml-kem-512",
            "name": "ML-KEM-512",
            "fips": "FIPS 203",
            "security_level": 1,
            "status": "standardized",
            "description": "Smallest/fastest KEM for constrained environments",
            "hybrid_with": "X25519Kyber512",
        },
    ],
    "signature": [
        {
            "id": "ml-dsa-65",
            "name": "ML-DSA-65",
            "fips": "FIPS 204",
            "security_level": 3,
            "status": "standardized",
            "description": "Primary NIST signature standard, balanced approach",
        },
        {
            "id": "ml-dsa-87",
            "name": "ML-DSA-87",
            "fips": "FIPS 204",
            "security_level": 5,
            "status": "standardized",
            "description": "Highest security signatures for critical applications",
        },
        {
            "id": "slh-dsa-128f",
            "name": "SLH-DSA-128f",
            "fips": "FIPS 205",
            "security_level": 1,
            "status": "standardized",
            "description": "Hash-based signatures, conservative security assumptions",
        },
    ],
}

COMPLIANCE_FRAMEWORKS: dict[str, dict[str, str]] = {
    "cnsa_2_0": {
        "name": "CNSA 2.0",
        "authority": "NSA",
        "kem": "ML-KEM-1024 required by 2030",
        "sig": "ML-DSA-87 required by 2033",
    },
    "nist_sp_800_208": {
        "name": "NIST SP 800-208",
        "authority": "NIST",
        "sig": "LMS/XMSS/SLH-DSA for firmware signing",
    },
    "bsi": {
        "name": "BSI TR-02102",
        "authority": "BSI (Germany)",
        "note": "Hybrid mode recommended until 2030",
    },
    "anssi": {
        "name": "ANSSI Guidelines",
        "authority": "ANSSI (France)",
        "note": "Hybrid classical+PQC mandated through 2030",
    },
}

# ---------------------------------------------------------------------------
# Algorithm classification
# ---------------------------------------------------------------------------

# Maps substrings found in detected algorithm names to timeline keys and
# categories.  Order matters: first match wins.
_ALGO_CLASSIFICATION_RULES: list[tuple[str, str, str]] = [
    # PQC algorithms (safe)
    ("Kyber",    "pqc",        "pqc"),
    ("ML-KEM",   "pqc",        "pqc"),
    ("Dilithium","pqc",        "pqc"),
    ("ML-DSA",   "pqc",        "pqc"),
    ("Falcon",   "pqc",        "pqc"),
    ("SPHINCS",  "pqc",        "pqc"),
    ("SLH-DSA",  "pqc",        "pqc"),
    # Asymmetric (quantum-vulnerable via Shor's)
    ("RSA",      "rsa_2048",   "asymmetric"),
    ("ECDSA",    "ecdsa_p256", "asymmetric"),
    ("ECDHE",    "ecdsa_p256", "asymmetric"),
    ("ECC",      "ecdsa_p256", "asymmetric"),
    ("Ed25519",  "ed25519",    "asymmetric"),
    ("EdDSA",    "ed25519",    "asymmetric"),
    ("Curve25519","x25519",    "asymmetric"),
    ("X25519",   "x25519",     "asymmetric"),
    ("DH",       "dh_2048",    "asymmetric"),
    # Symmetric (Grover's — key-doubling sufficient)
    ("AES",      "aes_256",    "symmetric"),
    ("ChaCha20", "chacha20",   "symmetric"),
    ("3DES",     "aes_128",    "symmetric"),
    ("DES",      "aes_128",    "symmetric"),
    ("XSalsa20", "chacha20",   "symmetric"),
    # Hashing
    ("SHA-256",  "sha_256",    "hash"),
    ("SHA-512",  "sha_256",    "hash"),
    ("SHA-1",    "sha_256",    "hash"),
    ("SHA3",     "sha_256",    "hash"),
    ("Blake2",   "sha_256",    "hash"),
    ("MD5",      "sha_256",    "hash"),
    # KDF / MAC / CSPRNG — not quantum-relevant
    ("HMAC",     "sha_256",    "hash"),
    ("bcrypt",   None,         "kdf"),
    ("Argon2",   None,         "kdf"),
    ("PBKDF2",   None,         "kdf"),
    ("scrypt",   None,         "kdf"),
    ("CSPRNG",   None,         "random"),
    ("Poly1305", None,         "mac"),
    # Token / TLS wrappers classified by their inner algorithms above
    ("TLS",      "rsa_2048",   "asymmetric"),
    ("JWS",      "rsa_2048",   "asymmetric"),
    ("JWE",      "rsa_2048",   "asymmetric"),
    ("JWK",      "rsa_2048",   "asymmetric"),
    ("RS256",    "rsa_2048",   "asymmetric"),
    ("ES256",    "ecdsa_p256", "asymmetric"),
    ("HS256",    "sha_256",    "hash"),
]


def _classify_algorithms(libraries: list[dict]) -> list[dict]:
    """Classify every algorithm from detected libraries.

    Returns a list of dicts:
        {"algo": <name>, "timeline_key": <key|None>, "category": <str>}
    """
    seen: set[str] = set()
    results: list[dict] = []

    for lib in libraries:
        for algo_name in lib.get("algorithms", []):
            if algo_name in seen:
                continue
            seen.add(algo_name)

            matched = False
            for pattern, timeline_key, category in _ALGO_CLASSIFICATION_RULES:
                if pattern.upper() in algo_name.upper():
                    results.append({
                        "algo": algo_name,
                        "timeline_key": timeline_key,
                        "category": category,
                    })
                    matched = True
                    break

            if not matched:
                results.append({
                    "algo": algo_name,
                    "timeline_key": None,
                    "category": "unknown",
                })

    return results


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def _assess_sndl(
    classifications: list[dict],
    profile: dict,
    libraries: list[dict],
) -> dict:
    """Algorithm-specific SNDL risk using the shortest asymmetric timeline."""
    lifespan = profile["lifespan_years"]
    migration_years = 2

    # Find shortest asymmetric threat median
    asymmetric_timelines = [
        QUANTUM_THREAT_TIMELINE[c["timeline_key"]]
        for c in classifications
        if c["category"] == "asymmetric" and c["timeline_key"] in QUANTUM_THREAT_TIMELINE
    ]

    if asymmetric_timelines:
        min_median = min(t["median"] for t in asymmetric_timelines)
        min_min = min(t["min"] for t in asymmetric_timelines)
        min_max = min(t["max"] for t in asymmetric_timelines)
    else:
        min_median = 50
        min_min = 30
        min_max = 100

    risk_window = min_median - (lifespan + migration_years)
    is_vulnerable = risk_window < 0

    has_deprecated = any(lib.get("is_deprecated", False) for lib in libraries)
    has_pqc = any(c["category"] == "pqc" for c in classifications)
    has_asymmetric = any(c["category"] == "asymmetric" for c in classifications)

    if has_deprecated:
        risk_level = "critical"
    elif is_vulnerable and has_asymmetric and not has_pqc:
        risk_level = "critical"
    elif is_vulnerable:
        risk_level = "high"
    elif risk_window < 5 and has_asymmetric:
        risk_level = "medium"
    elif has_asymmetric:
        risk_level = "low"
    else:
        risk_level = "low"

    if is_vulnerable:
        explanation = (
            f"Your data ({profile['name']}) with {lifespan}-year lifespan "
            f"is at risk. Quantum computers (est. {min_min}-{min_max} years) may "
            f"decrypt this data before its confidentiality period expires."
        )
    elif risk_window < 5:
        explanation = (
            f"Only {risk_window} years margin before SNDL risk. "
            f"Data encrypted today may be vulnerable before expiration."
        )
    elif risk_window < 10:
        explanation = f"{risk_window} years margin. Time to plan migration."
    else:
        explanation = f"{risk_window} years margin. Monitor quantum developments."

    return {
        "vulnerable": is_vulnerable,
        "protection_years_required": lifespan,
        "estimated_quantum_years_min": min_min,
        "estimated_quantum_years_median": min_median,
        "estimated_quantum_years_max": min_max,
        "risk_window_years": risk_window,
        "risk_level": risk_level,
        "explanation": explanation,
    }


def _score_algorithm(algo: dict, has_critical: bool) -> float:
    """Score a PQC algorithm candidate."""
    score = 50.0
    if algo.get("status") == "standardized":
        score += 25
    if has_critical and algo["security_level"] >= 3:
        score += 15
    elif algo["security_level"] == 3:
        score += 10
    if algo["id"] in ("ml-kem-768", "ml-dsa-65"):
        score += 10
    return min(100.0, score)


def _recommend_kem(
    classifications: list[dict],
    profile: dict,
    libraries: list[dict],
) -> list[dict]:
    """Score and return KEM recommendations."""
    has_asymmetric = any(
        c["category"] == "asymmetric" for c in classifications
    )
    if not has_asymmetric and "kem" not in profile.get("crypto_needs", []):
        return []

    has_critical = any(lib.get("quantum_risk") in ("high", "critical") for lib in libraries)

    # Build current algorithm list for display
    current_algos = sorted({
        c["algo"] for c in classifications if c["category"] == "asymmetric"
    })
    current_display = ", ".join(current_algos) if current_algos else "classical algorithms"

    results = []
    for algo in PQC_ALGORITHMS["kem"]:
        score = _score_algorithm(algo, has_critical)
        results.append({
            "current_algorithm": current_display,
            "recommended_algorithm": algo["name"],
            "fips_standard": algo["fips"],
            "security_level": f"NIST Level {algo['security_level']}",
            "description": algo["description"],
            "hybrid_option": algo.get("hybrid_with"),
            "score": score,
            "rationale": f"Replaces quantum-vulnerable key exchange with {algo['fips']}-standardized KEM",
            "migration_complexity": "medium",
        })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


def _recommend_signatures(
    classifications: list[dict],
    profile: dict,
    libraries: list[dict],
) -> list[dict]:
    """Score and return signature recommendations."""
    has_signing_algo = any(
        c["algo"] in ("RSA", "ECDSA", "Ed25519", "EdDSA", "RS256", "ES256")
        or c["category"] == "asymmetric"
        for c in classifications
    )
    if not has_signing_algo and "signature" not in profile.get("crypto_needs", []):
        return []

    has_critical = any(lib.get("quantum_risk") in ("high", "critical") for lib in libraries)

    current_algos = sorted({
        c["algo"] for c in classifications if c["category"] == "asymmetric"
    })
    current_display = ", ".join(current_algos) if current_algos else "classical signatures"

    results = []
    for algo in PQC_ALGORITHMS["signature"]:
        score = _score_algorithm(algo, has_critical)
        results.append({
            "current_algorithm": current_display,
            "recommended_algorithm": algo["name"],
            "fips_standard": algo["fips"],
            "security_level": f"NIST Level {algo['security_level']}",
            "description": algo["description"],
            "score": score,
            "rationale": f"Replaces quantum-vulnerable signatures with {algo['fips']}-standardized scheme",
            "migration_complexity": "medium",
        })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results


def _generate_migration_plan(
    libraries: list[dict],
    classifications: list[dict],
    sndl: dict,
) -> list[dict]:
    """Generate a 5-step migration plan."""
    steps: list[dict] = []
    step_order = 1

    deprecated = [lib for lib in libraries if lib.get("is_deprecated", False)]
    if deprecated:
        steps.append({
            "step": step_order,
            "action": "Replace deprecated libraries",
            "description": f"Remove {', '.join(lib['name'] for lib in deprecated)} — known vulnerabilities",
            "priority": "CRITICAL",
            "effort": "medium",
            "affected": [lib["name"] for lib in deprecated],
        })
        step_order += 1

    has_pqc = any(c["category"] == "pqc" for c in classifications)
    if not has_pqc:
        steps.append({
            "step": step_order,
            "action": "Enable cryptographic agility",
            "description": "Refactor to support algorithm negotiation and easy swapping",
            "priority": "HIGH" if sndl.get("risk_level") in ("critical", "high") else "MEDIUM",
            "effort": "high",
            "affected": [],
        })
        step_order += 1

    has_asymmetric = any(c["category"] == "asymmetric" for c in classifications)
    if has_asymmetric:
        steps.append({
            "step": step_order,
            "action": "Deploy hybrid key exchange",
            "description": "Implement X25519Kyber768 for TLS and key exchange",
            "priority": "HIGH" if sndl.get("vulnerable") else "MEDIUM",
            "effort": "medium",
            "affected": [lib["name"] for lib in libraries if lib.get("category") == "tls"],
            "target_algorithm": "X25519Kyber768",
        })
        step_order += 1

    has_signing = any(
        c["algo"] in ("RSA", "ECDSA", "Ed25519", "EdDSA", "RS256", "ES256")
        for c in classifications
    )
    if has_signing:
        steps.append({
            "step": step_order,
            "action": "Migrate to PQC signatures",
            "description": "Replace RSA/ECDSA signatures with ML-DSA-65",
            "priority": "MEDIUM",
            "effort": "medium",
            "affected": [lib["name"] for lib in libraries if lib.get("category") == "token"],
            "target_algorithm": "ML-DSA-65",
        })
        step_order += 1

    steps.append({
        "step": step_order,
        "action": "Complete PQC migration",
        "description": "Remove classical-only crypto, verify quantum resistance",
        "priority": "LOW",
        "effort": "low",
        "affected": [],
    })

    return steps


def _calculate_quantum_score(
    libraries: list[dict],
    classifications: list[dict],
) -> float:
    """Weighted quantum readiness score (0-100)."""
    if not libraries:
        return 100.0

    safe = sum(1 for lib in libraries if lib.get("quantum_risk", "").lower() in ("none", "low"))
    vulnerable = sum(1 for lib in libraries if lib.get("quantum_risk", "").lower() in ("high", "critical"))
    total = safe + vulnerable

    if total == 0:
        return 100.0

    score = (safe / total) * 100
    if any(c["category"] == "pqc" for c in classifications):
        score = min(100, score + 20)
    deprecated = sum(1 for lib in libraries if lib.get("is_deprecated", False))
    if deprecated > 0:
        score = max(0, score - deprecated * 10)

    return round(score, 1)


def _get_compliance_references(urgency: str) -> list[dict]:
    """Return compliance frameworks relevant for the given urgency."""
    refs: list[dict] = []
    if urgency in ("critical", "high"):
        for key in ("cnsa_2_0", "nist_sp_800_208", "bsi", "anssi"):
            fw = COMPLIANCE_FRAMEWORKS[key]
            detail = fw.get("kem") or fw.get("sig") or fw.get("note", "")
            refs.append({
                "framework": fw["name"],
                "authority": fw["authority"],
                "detail": detail,
            })
    elif urgency == "medium":
        for key in ("cnsa_2_0", "bsi"):
            fw = COMPLIANCE_FRAMEWORKS[key]
            detail = fw.get("kem") or fw.get("note", "")
            refs.append({
                "framework": fw["name"],
                "authority": fw["authority"],
                "detail": detail,
            })
    return refs


def _generate_findings(
    libraries: list[dict],
    classifications: list[dict],
    sndl: dict,
    profile: dict,
) -> list[str]:
    """Contextual key findings."""
    findings: list[str] = []

    vulnerable_count = sum(1 for lib in libraries if lib.get("quantum_risk") in ("high", "critical"))
    if vulnerable_count > 0:
        findings.append(f"Found {vulnerable_count} quantum-vulnerable libraries")

    deprecated_count = sum(1 for lib in libraries if lib.get("is_deprecated", False))
    if deprecated_count > 0:
        findings.append(f"Found {deprecated_count} deprecated libraries requiring immediate attention")

    findings.append(
        f"Data profile '{profile['name']}' requires {profile['lifespan_years']}-year protection"
    )

    if sndl.get("vulnerable"):
        findings.append("SNDL risk: Data may be decryptable before confidentiality period expires")

    if any(c["category"] == "pqc" for c in classifications):
        findings.append("Post-quantum cryptography already in use")
    else:
        findings.append("No post-quantum cryptography detected")

    return findings


def _generate_next_steps(
    urgency: str,
    migration_plan: list[dict],
    sndl: dict,
) -> list[str]:
    """Priority-ordered actions."""
    steps: list[str] = []

    if migration_plan:
        steps.append(f"Priority: {migration_plan[0]['action']}")

    if urgency == "critical":
        steps.append("Deploy hybrid crypto (X25519Kyber768) within 90 days")
        steps.append("Identify and re-encrypt sensitive long-term data")
    elif urgency == "high":
        steps.append("Begin PQC pilot project within 6 months")
        steps.append("Evaluate liboqs or pqcrypto for Python integration")
    elif urgency == "medium":
        steps.append("Include PQC migration in next architecture review")
        steps.append("Train development team on PQC concepts")
    else:
        steps.append("Monitor NIST PQC standardization updates")
        steps.append("Evaluate crypto agility improvements")

    return steps


def _build_threat_timelines(classifications: list[dict]) -> dict[str, dict]:
    """Build per-algorithm threat timelines for detected algorithms."""
    timelines: dict[str, dict] = {}
    for c in classifications:
        key = c["timeline_key"]
        if key and key in QUANTUM_THREAT_TIMELINE and key not in timelines:
            t = QUANTUM_THREAT_TIMELINE[key]
            timelines[key] = {
                "algorithm": c["algo"],
                "timeline_key": key,
                "min_years": t["min"],
                "median_years": t["median"],
                "max_years": t["max"],
                "status": "AT RISK" if t["median"] <= 25 else "SAFE",
                "category": c["category"],
            }
    return timelines


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_offline(
    libraries: list[dict],
    data_profile: str | None = None,
) -> dict:
    """Run full offline PQC analysis.

    Args:
        libraries: Detected crypto libraries from init().
        data_profile: One of the DATA_PROFILES keys.

    Returns:
        Dict matching PQCRecommendationResult._data shape with additional
        keys: compliance_references, threat_timelines, data_profile.
    """
    profile_key = data_profile or "general"
    profile = DATA_PROFILES.get(profile_key, DATA_PROFILES["general"])

    classifications = _classify_algorithms(libraries)
    sndl = _assess_sndl(classifications, profile, libraries)
    kem_recs = _recommend_kem(classifications, profile, libraries)
    sig_recs = _recommend_signatures(classifications, profile, libraries)
    migration_plan = _generate_migration_plan(libraries, classifications, sndl)
    quantum_score = _calculate_quantum_score(libraries, classifications)

    urgency = sndl["risk_level"]
    compliance_refs = _get_compliance_references(urgency)
    findings = _generate_findings(libraries, classifications, sndl, profile)
    next_steps = _generate_next_steps(urgency, migration_plan, sndl)
    threat_timelines = _build_threat_timelines(classifications)

    return {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "analysis_mode": "offline",
        "sndl_assessment": sndl,
        "kem_recommendations": kem_recs,
        "signature_recommendations": sig_recs,
        "migration_plan": migration_plan,
        "overall_urgency": urgency,
        "quantum_readiness_score": quantum_score,
        "key_findings": findings,
        "next_steps": next_steps,
        "compliance_references": compliance_refs,
        "threat_timelines": threat_timelines,
        "data_profile": {
            "key": profile_key,
            "name": profile["name"],
            "lifespan_years": profile["lifespan_years"],
            "urgency": profile["urgency"],
        },
    }
