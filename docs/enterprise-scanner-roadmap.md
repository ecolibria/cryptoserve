# Enterprise Scanner Roadmap

Planning document for enterprise-grade CryptoServe scanner features.
Status: design phase only. No enterprise features are built or gated yet.
All current capabilities remain free and open source (Apache-2.0).

Monetization target: 2027+. The free CLI is the distribution channel.
Enterprise features will be a configuration change, not a rewrite --
architectural hooks are baked in now.

---

## Current Scanner Capabilities (Free, Open Source)

### Source Code Scanning (6 Languages)
- Deep source code pattern matching for Go, Python, Java/Kotlin, Rust, C/C++, and JavaScript/TypeScript
- Regex-based algorithm detection: AES, RSA, ECDSA, Ed25519, X25519, ChaCha20, SHA family, MD5, DES, RC4, HMAC, KDFs, TLS config, and PQC algorithms (Kyber/Dilithium via circl)
- Weak pattern detection: createCipher without IV, MD5 usage, DES, RC4, ECB mode, CBC mode
- Multi-language import/library tracking: node:crypto, crypto-js, node-forge, tweetnacl, jsonwebtoken, hashlib, pycryptodome, cryptography, bcrypt, pynacl, golang.org/x/crypto, Java Cipher.getInstance, Rust ring/RustCrypto

### Dependency Manifest Analysis
- Scans package.json (including monorepo workspaces), go.mod, requirements.txt, Cargo.toml, pom.xml, build.gradle
- Maps known crypto libraries to algorithm sets via built-in crypto-registry

### Secret Detection
- 12 hardcoded secret patterns (Anthropic, OpenAI, AWS, GitHub, Slack, Google, Stripe, SendGrid, npm, private keys)
- Certificate/key file discovery (.pem, .key, .crt, .p12, .pfx, .jks, .keystore)

### TLS Configuration Scanning
- Detects TLS version settings in config files
- Flags outdated TLS versions

### Binary Scanning (Optional)
- Crypto signature detection in compiled binaries via --binary flag

### PQC Readiness Analysis
- Offline quantum threat assessment with embedded intelligence data
- Quantum threat timeline modeling for each algorithm family (RSA, ECDSA, Ed25519, X25519, DH, AES, SHA, ChaCha20)
- 9 data sensitivity profiles: national_security, healthcare, financial, intellectual_property, legal, general, authentication, session_tokens, ephemeral
- NIST FIPS 203/204/205 PQC algorithm recommendations (ML-KEM-512/768/1024, ML-DSA-65/87, SLH-DSA-128f)
- Compliance framework mapping: CNSA 2.0, NIST SP 800-208, BSI TR-02102, ANSSI guidelines

### CBOM Generation
- CycloneDX 1.5 JSON output
- SPDX 2.3 JSON output
- Native JSON with quantum readiness annotations
- Package URL (purl) generation for npm, Go, PyPI, Cargo, Maven ecosystems
- Git metadata embedding (commit, branch, remote)

### CI/CD Gate
- Exit code 0/1 for pass/fail in pipelines
- Configurable thresholds: --max-risk, --min-score, --fail-on-weak
- JSON output for machine consumption

### Algorithm Database
- 80+ algorithm entries with quantum risk classification (none, low, high, critical)
- Weakness tracking with CWE identifiers (CWE-326, CWE-327)
- Category taxonomy: encryption, signing, key_exchange, kdf, mac, hashing, protocol

### Crypto Census
- Live ecosystem scanning across 11 package registries (npm, PyPI, crates.io, Maven, NuGet, RubyGems, Hex, Pub, CocoaPods, Packagist, Go)
- NVD CVE correlation
- GitHub advisory enrichment
- Download/adoption statistics per ecosystem
- HTML and JSON report generation

### Proven Deep Scan Advantage
Validated against 20 major OSS projects (Kubernetes, Grafana, Vault, Django, Spring Boot, Terraform, go-ethereum, Next.js, etc.):
- 167 deep scan findings vs 42 dependency-only findings (4x multiplier)
- 6 projects where deep scan found crypto that dependency analysis completely missed
- 114 source-level algorithm detections, 9 weak patterns, 17 TLS findings
- 47,509 files scanned across 6 languages

---

## Enterprise Scanner Features (Planned)

### Tier 1: Fleet Scanning (Team/Org Level)

**What:** Scan all repositories in a GitHub/GitLab/Bitbucket organization with a single command. Aggregate findings into an org-level cryptographic posture report.

**Why CISOs care:** A CISO inheriting 500 repositories has no way to answer "what is our quantum exposure?" today. Snyk tells them about CVEs. CryptoServe tells them which repos use RSA-2048, which use MD5 for anything beyond checksums, and which have zero PQC readiness -- across every repo, in every language.

**Capabilities:**
- `cryptoserve scan --org mycompany --provider github` -- scan all repos (respects .gitignore, skips archived/forked by default)
- `cryptoserve scan --org mycompany --provider gitlab --group backend` -- scan a specific group
- Parallel scanning with configurable concurrency (default: 5 repos)
- Incremental mode: only re-scan repos with commits since last scan
- Per-repo CBOM generation with org-level aggregation
- Output: org-level summary JSON with per-repo drill-down
- Filters: `--language go,python`, `--min-risk high`, `--team platform-engineering`

**Example output structure:**
```json
{
  "orgId": "mycompany",
  "scanTimestamp": "2026-03-18T00:00:00Z",
  "repoCount": 247,
  "reposScanned": 247,
  "aggregateFindings": {
    "totalAlgorithms": 1847,
    "quantumVulnerable": 312,
    "weakCrypto": 47,
    "secretsExposed": 3,
    "pqcReadinessScore": 34
  },
  "byRepo": [ ... ],
  "byAlgorithm": { "rsa": { "repoCount": 89, "instanceCount": 234 }, ... },
  "byTeam": { ... }
}
```

**Architecture hooks needed now:**
- Scan result schema must include optional `orgId`, `teamId`, `repoUrl` fields (empty strings in free tier)
- JSON output must be stable and versioned (add `schemaVersion` field to scan output)
- Walker must support cloning repos to temp directories with depth-1 shallow clone
- Scan function must accept a `scanId` parameter for correlation across fleet scans

---

### Tier 2: Continuous Monitoring and Drift Detection

**What:** Run CryptoServe on every PR/commit via GitHub Actions (already exists), store results over time, and alert when cryptographic posture degrades.

**Why CISOs care:** Point-in-time scans are insufficient for compliance. Auditors ask "when was this weakness introduced?" and "who approved it?" CISOs need trend data: is our PQC readiness improving or degrading? Is new RSA usage still being introduced?

**Capabilities:**
- GitHub Action (already exists) enhanced with:
  - PR comment with crypto diff ("This PR introduces 2 new RSA usages, removes 1 MD5 usage")
  - Block merge if crypto policy violated
  - CBOM diff between base and head
- Drift detection: compare current scan against baseline, alert on:
  - New quantum-vulnerable algorithm introduced
  - PQC readiness score decrease
  - New weak crypto pattern
  - New secret exposure
- Time-series storage of scan results (local SQLite in free tier, API in enterprise)
- Weekly/monthly crypto posture reports
- Slack/Teams/PagerDuty integration for alerts

**Example alert:**
```
CryptoServe Drift Alert: mycompany/payment-service
PQC readiness score dropped from 72 to 65 this week.
Changes: +3 RSA usages (PR #847, #852), -1 ECDSA replaced with ML-DSA (PR #849)
Action: Review PRs #847 and #852 for RSA justification.
```

**Architecture hooks needed now:**
- Scan results must include a `timestamp` field (ISO 8601)
- Scan results must be deterministic given the same source (no random UUIDs in comparison-critical fields)
- CBOM must support diffing: two CBOMs in, delta out
- Gate command must accept a `--baseline` flag pointing to a previous scan result
- Event schema for findings: `{ eventType, scanId, repoUrl, finding, timestamp, prNumber?, commitSha? }`

---

### Tier 3: CBOM Registry

**What:** Central, queryable registry of all Crypto Bills of Materials across the organization. Compliance teams can search, filter, and report on cryptographic usage across the entire software portfolio.

**Why CISOs care:** When NIST announces "RSA-2048 deprecated for all federal use by 2030," the CISO needs to answer within hours: "Which of our 500 services use RSA-2048, and what data do they protect?" Today that requires manually scanning each repo. A CBOM registry answers this query in seconds.

**Capabilities:**
- Central CBOM storage with full-text search
- Query API: "which repos use RSA-2048?" "which repos have no PQC algorithms?" "show me all repos with critical quantum risk"
- CBOM versioning: track how each repo's crypto profile changes over time
- Compliance dashboards: aggregate views by algorithm, risk level, team, language
- CBOM export for auditors: filtered, formatted, with provenance chain
- Federation: merge CBOMs from multiple orgs (M&A, multi-subsidiary)
- Retention policies: configurable CBOM history retention

**Query examples:**
```
GET /api/v1/cbom/search?algorithm=rsa&quantumRisk=high
GET /api/v1/cbom/search?team=payments&hasWeakCrypto=true
GET /api/v1/cbom/repos/payment-service/history?since=2025-01-01
GET /api/v1/cbom/aggregate?groupBy=algorithm&metric=repoCount
```

**Architecture hooks needed now:**
- CBOM schema must be stable, versioned, and self-describing (add `cbomVersion` field)
- Every CBOM must include a unique `cbomId` (deterministic hash of repo+commit+timestamp)
- CBOM must include `orgId`, `teamId` fields (optional, empty in free tier)
- Storage abstraction: current file-based output must work through an interface that can be swapped for HTTP/database backends
- CycloneDX and SPDX output must be fully standards-compliant (test against official validators)

---

### Tier 4: Policy-as-Code

**What:** Declarative cryptographic policies expressed as YAML/JSON that gate CI/CD pipelines. Organization-wide policies with per-team overrides. Integration with OPA/Rego for organizations already using policy frameworks.

**Why CISOs care:** Without enforceable policy, crypto standards are aspirational documents that developers ignore. Policy-as-code turns "no new RSA after 2027" from a memo into a build failure.

**Capabilities:**
- Policy definition in YAML:
```yaml
# .cryptoserve-policy.yaml
version: 1
policies:
  - id: no-new-rsa
    description: "No new RSA usage after 2027-01-01"
    match:
      algorithm: rsa
      dateIntroduced: { after: "2027-01-01" }
    action: block
    severity: high

  - id: require-pqc-kem
    description: "All new key exchange must use ML-KEM"
    match:
      category: key_exchange
      algorithm: { not: ["ml-kem-768", "ml-kem-1024", "ml-kem-512"] }
      dateIntroduced: { after: "2027-06-01" }
    action: block
    severity: critical

  - id: warn-md5
    description: "MD5 usage should be reviewed"
    match:
      algorithm: md5
    action: warn
    severity: medium
    exemptions:
      - path: "tests/**"
      - path: "vendor/**"
```
- Policy inheritance: org-level policy applies to all repos, team-level can add (not remove) restrictions
- Exemption mechanism: specific files/paths can be exempted with documented justification
- Policy evaluation in gate command: `cryptoserve gate --policy .cryptoserve-policy.yaml`
- OPA/Rego integration: export findings as OPA-compatible input, evaluate against Rego policies
- Policy violation reporting: which PRs violated which policies, who approved exemptions
- Policy dry-run mode: evaluate policy against existing codebase without blocking

**Architecture hooks needed now:**
- Gate command already accepts --max-risk, --min-score, --fail-on-weak -- extend to accept --policy <file>
- Scan results must include file paths for every finding (already present for some finding types, missing for others)
- Finding schema must include `dateIntroduced` field (requires git blame integration or baseline comparison)
- Policy evaluation must be a separate module that takes scan results + policy definition as input and produces pass/fail + violations as output
- Policy files must be loadable from local file, URL, or org-level registry

---

### Tier 5: Migration Planner

**What:** Given the current cryptographic inventory and target policy, generate a prioritized migration plan with estimated effort, risk assessment, and optionally auto-generated PRs.

**Why CISOs care:** Knowing you have 312 quantum-vulnerable algorithms across 89 repos is step one. Step two is: "How do we fix this, in what order, and how long will it take?" No existing tool answers this. CryptoServe can because it understands both the source code patterns and the PQC replacement algorithms.

**Capabilities:**
- Migration path generation per algorithm:
  - RSA -> ML-KEM-768 (for key exchange) or ML-DSA-65 (for signing)
  - ECDSA -> ML-DSA-65
  - X25519 -> ML-KEM-768
  - DES/RC4/MD5 -> AES-256-GCM/SHA-256 (immediate, non-quantum-related)
- Library-specific migration guidance:
  - "Replace crypto-js AES-CBC with @noble/ciphers AES-256-GCM in 47 files across 12 repos"
  - "Replace golang.org/x/crypto/ed25519 with circl ML-DSA-65 in 23 files across 8 repos"
- SNDL (Store Now, Decrypt Later) risk prioritization:
  - Data classified as healthcare/financial/national_security migrated first
  - Session tokens and ephemeral data migrated last
  - Priority score = (data sensitivity lifespan in years) * (quantum risk level)
- Effort estimation:
  - Per-file change complexity (trivial: drop-in replacement, moderate: API change, complex: protocol change)
  - Per-repo estimated hours based on finding count and complexity
  - Org-level migration timeline projection
- PR generation (enterprise):
  - Auto-create migration PRs for trivial replacements (e.g., hashlib.md5 -> hashlib.sha256)
  - Draft PRs with human review required for moderate/complex changes
  - Batch PRs by team/repo with migration instructions in PR description
- Migration tracking dashboard:
  - Progress by repo, team, algorithm, risk level
  - Burndown chart: quantum-vulnerable findings over time
  - Blocker identification: which repos are stuck and why

**Architecture hooks needed now:**
- Algorithm database must include a `migrateTo` field for each algorithm (e.g., rsa -> ml-kem-768)
- Scan results must include enough file/line context to generate meaningful diffs
- PQC engine data profiles must be linkable to repos (which repos handle healthcare data?)
- Migration complexity classification must be computable from the algorithm + library + language

---

### Tier 6: Supply Chain Crypto Audit

**What:** Trace cryptographic algorithm usage through the entire transitive dependency tree, not just direct dependencies. Combine SBOM (Software Bill of Materials) with CBOM for full supply chain crypto visibility.

**Why CISOs care:** The deep scan comparison proves this is where the real risk hides. Direct dependency analysis found 42 crypto findings; deep source scanning found 167 (4x multiplier). Six major projects (aws-sdk-go-v2, axios, Next.js, node-jsonwebtoken, Spring Boot, stripe-python) had zero dependency matches but real crypto in source. Transitive dependencies are even worse -- your app depends on express, which depends on cookie-signature, which uses SHA-1 HMAC. You never see it.

**Capabilities:**
- Transitive dependency resolution:
  - npm: parse package-lock.json / yarn.lock / pnpm-lock.yaml for full dependency tree
  - Go: parse go.sum for complete module graph
  - Python: parse Pipfile.lock / poetry.lock for pinned transitive deps
  - Java: parse gradle.lockfile / effective POM for full dependency tree
  - Rust: parse Cargo.lock for complete crate graph
- Deep transitive scanning:
  - Download and scan source of transitive dependencies (configurable depth)
  - Cache scanned dependency results to avoid redundant work
  - Map crypto findings to dependency path (your-app -> express -> cookie-signature -> SHA-1)
- SBOM + CBOM integration:
  - Generate combined SBOM+CBOM that shows both "what software" and "what crypto"
  - Import existing SBOMs (CycloneDX, SPDX) and enrich with crypto findings
  - Export enriched SBOM+CBOM for compliance tooling
- Supply chain risk scoring:
  - Per-dependency quantum risk based on its crypto usage
  - Dependency freshness: is the crypto library actively maintained?
  - Known vulnerability correlation: map crypto findings to NVD/GitHub advisories
  - Dependency substitution recommendations: "Replace tweetnacl (unmaintained) with @noble/ed25519 (active, audited)"

**Evidence from deep scan comparison:**
| Metric | Dependency-only | Deep Source Scan | Multiplier |
|--------|----------------|------------------|------------|
| Total findings across 20 projects | 42 | 167 | 4x |
| Projects with findings | 13 | 18 | 1.4x |
| Projects where deep scan found crypto missed by deps | -- | 6 | -- |
| Kubernetes findings | 2 (libs) | 11 (10 source algorithms) | 5.5x |
| Grafana findings | 7 (libs) | 28 (9 algorithms + 16 TLS + 2 secrets) | 4x |
| Vault findings | 8 (libs) | 30 (17 algorithms + 11 secrets) | 3.8x |

**Architecture hooks needed now:**
- Scanner must accept a `--depth` flag for transitive scanning (default 0 = direct only)
- Scan results must include a `dependencyPath` field (array of package names from root to finding)
- CBOM generation must support merging multiple scan results into a single CBOM
- Lock file parsers must be modular (one per ecosystem, loaded on demand)
- Dependency cache must use content-addressable storage (hash of package name + version)

---

### Tier 7: Quantum Risk Scoring and Executive Dashboard

**What:** Organization-wide quantum risk score that combines data sensitivity, protection lifetime, current crypto algorithms, PQC readiness, and migration velocity into a single metric. Executive dashboard for board-level reporting.

**Why CISOs care:** Boards ask "are we ready for quantum?" The CISO needs a number, a trend, and a plan -- not a 200-page technical report. A risk score that maps to QRAMM maturity levels gives CISOs a defensible answer and a framework for budget justification.

**Capabilities:**
- Quantum Risk Score (0-100):
  - Inputs: algorithm inventory, data classification, protection lifetimes, PQC adoption rate, migration velocity
  - Formula: weighted combination of exposure (what crypto is in use), impact (what data it protects), readiness (PQC adoption), and velocity (migration trend)
  - Benchmarking: compare score against industry peers (anonymized, opt-in)
- QRAMM (Quantum Risk Assessment Maturity Model) mapping:
  - Level 1: No quantum awareness
  - Level 2: Inventory complete (you know what crypto you use)
  - Level 3: Risk assessed (you know which crypto is quantum-vulnerable)
  - Level 4: Migration planned (you have a prioritized plan)
  - Level 5: PQC adopted (quantum-safe algorithms deployed)
  - Level 6: Crypto agile (can swap algorithms without code changes)
- Executive dashboard:
  - Single-page quantum readiness summary
  - Trend charts: risk score over time, PQC adoption rate, migration burndown
  - Compliance status: CNSA 2.0 readiness, NIST timeline alignment
  - Top 10 riskiest repos/services
  - Migration ROI: cost of migration vs cost of breach (industry data)
- Board report generation:
  - One-page PDF/HTML summary suitable for board presentation
  - Risk framed in business terms, not technical jargon
  - Comparison against NIST deadlines (2030 for KEM, 2035 for signatures)
  - Action items with owners and deadlines

**Architecture hooks needed now:**
- PQC engine already has data profiles and threat timelines -- expose these as a scoring API
- Scan results must include a `pqcReadinessScore` field (already partially present)
- Score calculation must be deterministic and documented (no black box)
- Time-series data model for tracking score changes (needed for Tier 2 as well)
- Data classification must be linkable to repos (which repos handle which data types?)

---

## Differentiation from Snyk/Sonatype/Checkmarx

### What they do well (and CryptoServe does not compete on)
- CVE/vulnerability database matching (Snyk has 200K+ vulns)
- License compliance scanning
- Container image scanning
- Real-time patching recommendations for known CVEs
- Developer workflow integrations (IDE plugins, PR decorations)

### What CryptoServe does that they cannot

| Capability | Snyk/Sonatype/Checkmarx | CryptoServe |
|-----------|------------------------|-------------|
| **Scan focus** | Known CVEs in dependencies | Algorithmic risk in source code |
| **Scan depth** | Dependency manifests only | Source code, manifests, binaries, TLS configs, secrets |
| **Finding multiplier** | 1x (deps only) | 4x (source + deps, validated across 20 OSS projects) |
| **Quantum risk** | Not assessed | Every finding classified: none/low/high/critical quantum risk |
| **PQC readiness** | Not supported | FIPS 203/204/205 algorithm recommendations with migration paths |
| **CBOM generation** | Not supported | CycloneDX 1.5 + SPDX 2.3 + native JSON with quantum annotations |
| **NIST deadline mapping** | Not supported | Every finding mapped to 2030/2035 NIST transition deadlines |
| **Data sensitivity** | Not considered | 9 data profiles with protection lifetime modeling |
| **Compliance frameworks** | General (SOC2, ISO 27001) | Crypto-specific (CNSA 2.0, NIST SP 800-208, BSI, ANSSI) |
| **Languages scanned** | Varies by tool | 6 languages with unified algorithm taxonomy |
| **Threat timeline** | Static (known vuln = urgent) | Dynamic (quantum threat modeled with min/median/max timelines) |

### The core insight
Existing SCA tools answer: "Do you have a known vulnerability in your dependencies?"
CryptoServe answers: "Is your cryptography ready for a post-quantum world?"

These are fundamentally different questions. A project can have zero CVEs and still be entirely quantum-vulnerable. Every RSA-2048 key, every ECDSA signature, every X25519 key exchange will break when cryptographically relevant quantum computers arrive. No existing SCA tool tracks this.

### Positioning
CryptoServe is not a replacement for Snyk/Sonatype. It is a complementary tool that covers a blind spot in every existing security toolchain: cryptographic algorithm risk. The enterprise play is: "You already run Snyk for CVEs. Run CryptoServe for crypto."

---

## Revenue Model

All current CLI capabilities remain free and open source. Enterprise features are additive layers that require centralized infrastructure (registries, dashboards, APIs).

| Tier | Target | Capabilities | Pricing Model |
|------|--------|-------------|---------------|
| **Free** | Individual developers, small teams | CLI scanning, PQC readiness, CBOM generation, CI/CD gate, crypto census (single repo) | Free forever (Apache-2.0) |
| **Team** | Engineering teams (5-50 devs) | Fleet scanning, continuous monitoring, drift alerts, team-level aggregation | Per-seat/month |
| **Enterprise** | Organizations (50+ devs) | CBOM registry, policy-as-code, migration planner, org-level dashboard | Annual contract |
| **Compliance** | Regulated industries | Automated NIST/CNSA 2.0/HIPAA/PCI-DSS crypto compliance reporting, auditor-ready exports, executive dashboard, board reports | Annual contract, premium |

### Conversion funnel (bottom-up PLG)
1. Developer installs free CLI, scans their project, sees quantum risk findings
2. Developer uses `cryptoserve gate` in CI/CD to prevent crypto regression
3. Team lead discovers 5+ developers using CryptoServe, wants fleet scanning
4. CISO discovers org-wide usage, needs centralized visibility and policy enforcement
5. Compliance team needs audit-ready CBOM registry and NIST timeline reporting

### Key metrics to track for monetization readiness
- CLI installs (npm, Homebrew)
- Active weekly scans
- CI/CD integrations (GitHub Action installs)
- Repos scanned per organization
- Conversion from free to team tier (when available)

---

## Architecture Hooks to Add Now

These are specific code changes that make enterprise features achievable through configuration rather than rewrite. None of these changes affect the free tier user experience.

### 1. Structured Event Schema

Add a `schemaVersion` field to all scan output and a stable event format for every finding.

```javascript
// In scanner.mjs scanProject() result:
{
  schemaVersion: "1.0.0",
  scanId: "<deterministic-hash>",
  orgId: "",          // empty in free tier
  teamId: "",         // empty in free tier
  repoUrl: "",        // populated when available from git remote
  timestamp: "<ISO-8601>",
  // ... existing fields
}
```

**Files to modify:** `scanner.mjs` (output schema), `cbom.mjs` (CBOM schema), `pqc-engine.mjs` (analysis output)

### 2. Org/Team Identity Fields

Add optional `orgId` and `teamId` to scan results, CBOM, and gate output. These fields are empty strings in the free tier and populated by fleet scanning or configuration.

```javascript
// In .cryptoserve.yaml (existing config system):
org:
  id: "mycompany"
  team: "platform-engineering"
```

**Files to modify:** `config.mjs` (parse org config), `scanner.mjs` (include in output), `cbom.mjs` (include in CBOM)

### 3. Policy-as-Data Foundation

The gate command currently uses flag-based thresholds (--max-risk, --min-score, --fail-on-weak). Extend it to accept a YAML/JSON policy file.

**Current gate interface:**
```bash
cryptoserve gate --max-risk high --min-score 50 --fail-on-weak
```

**Extended interface:**
```bash
cryptoserve gate --policy .cryptoserve-policy.yaml
```

Policy evaluation should be a separate module (policy-engine.mjs) that takes scan results + policy as input and returns pass/fail + violations. This module is reusable by fleet scanning and continuous monitoring.

**Files to create:** `policy-engine.mjs` (new module)
**Files to modify:** gate command in `cryptoserve.mjs`

### 4. Deterministic Scan IDs

Generate a deterministic scan ID from the combination of repo URL + commit SHA + scan timestamp. This enables correlation across fleet scans and time-series tracking.

```javascript
import { createHash } from 'node:crypto';
function generateScanId(repoUrl, commitSha, timestamp) {
  return createHash('sha256')
    .update(`${repoUrl}:${commitSha}:${timestamp}`)
    .digest('hex')
    .slice(0, 16);
}
```

**Files to modify:** `scanner.mjs` (generate scan ID), `cbom.mjs` (include scan ID reference)

### 5. Finding-Level File Paths

Ensure every finding type includes the source file path. Currently, sourceAlgorithms include file paths inconsistently. Every finding (library, algorithm, weak pattern, secret, TLS issue) must include `filePath` and optionally `lineNumber`.

**Files to modify:** `scanner.mjs` (ensure file paths on all finding types), `scanner-languages.mjs` (return file paths from pattern matches)

### 6. CBOM Diffing Support

Add a `cbomDiff(oldCbom, newCbom)` function that computes the delta between two CBOMs. This is required for PR-level crypto change detection and drift alerts.

**Files to create:** `cbom-diff.mjs` (new module)
**Interface:**
```javascript
export function cbomDiff(oldCbom, newCbom) {
  return {
    added: [],      // new crypto components
    removed: [],    // removed crypto components
    changed: [],    // components with changed properties
    riskDelta: 0,   // change in aggregate risk score
  };
}
```

### 7. Storage Abstraction

Current output goes to stdout or --output file. Add a storage interface that can be implemented for file (free), SQLite (team), or HTTP API (enterprise).

```javascript
// storage.mjs
export class FileStorage { async store(scanResult) { ... } }
export class ApiStorage  { async store(scanResult) { ... } }  // enterprise
```

**Files to create:** `storage.mjs` (interface + file implementation)

### 8. API Versioning for Fleet Operations

When fleet scanning is implemented, it will expose an HTTP API. Version it from day one.

**Convention:** `/api/v1/scan`, `/api/v1/cbom`, `/api/v1/policy`
**Transport:** JSON over HTTP, with JSON-LD context for semantic interop
**Auth:** Bearer token (integrate with existing `cryptoserve login` flow)

### 9. Algorithm Migration Mapping

Add a `migrateTo` field to algorithm-db.mjs entries. This is the foundation for the migration planner.

```javascript
// In ALGORITHM_DB:
'rsa':      { category: 'encryption', quantumRisk: 'high', isWeak: false, migrateTo: ['ml-kem-768'] },
'ecdsa':    { category: 'signing', quantumRisk: 'high', isWeak: false, migrateTo: ['ml-dsa-65'] },
'x25519':   { category: 'key_exchange', quantumRisk: 'high', isWeak: false, migrateTo: ['ml-kem-768'] },
'ed25519':  { category: 'signing', quantumRisk: 'high', isWeak: false, migrateTo: ['ml-dsa-65'] },
'md5':      { category: 'hashing', quantumRisk: 'critical', isWeak: true, migrateTo: ['sha-256'] },
'des':      { category: 'encryption', quantumRisk: 'critical', isWeak: true, migrateTo: ['aes-256-gcm'] },
```

**Files to modify:** `algorithm-db.mjs` (add migrateTo field to relevant entries)

### 10. Data Classification Linkage

Allow repos to declare their data sensitivity profile in .cryptoserve.yaml. This links the PQC engine's data profiles to specific repositories for accurate risk scoring.

```yaml
# .cryptoserve.yaml
dataProfile: financial    # maps to DATA_PROFILES in pqc-engine.mjs
```

**Files to modify:** `config.mjs` (parse dataProfile), `pqc-engine.mjs` (use repo-level profile in analysis)

---

## Implementation Priority

Hooks are ordered by dependency (later tiers depend on earlier hooks being in place) and by enterprise value.

| Priority | Hook | Enables | Effort |
|----------|------|---------|--------|
| P0 | Schema version + timestamp | All tiers | Small |
| P0 | Finding-level file paths | Tiers 2, 4, 5 | Small |
| P1 | Deterministic scan IDs | Tiers 1, 2, 3 | Small |
| P1 | Org/team identity fields | Tiers 1, 3, 7 | Small |
| P1 | Algorithm migration mapping | Tier 5 | Small |
| P2 | Data classification linkage | Tiers 5, 7 | Small |
| P2 | Policy-as-data foundation | Tier 4 | Medium |
| P2 | CBOM diffing | Tier 2 | Medium |
| P3 | Storage abstraction | Tiers 2, 3 | Medium |
| P3 | API versioning design | Tiers 1, 3 | Design only |

---

## Open Questions

1. **Pricing research:** What do security teams pay for crypto-specific tooling? Benchmark against Snyk Team ($25/dev/mo) and Snyk Enterprise ($100+/dev/mo). CryptoServe provides narrower but deeper value -- price accordingly.

2. **Self-hosted vs SaaS:** Should the CBOM registry be self-hosted (on-prem install) or SaaS? Regulated industries (healthcare, finance, defense) will demand self-hosted. Start with self-hosted, add SaaS later.

3. **Competitive moat:** The 4x deep scan multiplier is defensible because it requires per-language regex engineering. Snyk/Sonatype would need to build this from scratch. The PQC knowledge base (FIPS 203/204/205, CNSA 2.0, QRAMM) is another moat -- it requires domain expertise they lack.

4. **Certification:** Should CryptoServe itself be FIPS-validated? This would add credibility for federal/defense customers but is expensive (6-12 months, $50K+).

5. **Partner integrations:** Which existing security platforms should CryptoServe integrate with? Candidates: ServiceNow, Jira, Splunk, Datadog, PagerDuty, Terraform Cloud, AWS Security Hub, Azure Defender.
