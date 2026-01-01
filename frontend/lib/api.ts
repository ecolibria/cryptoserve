// Use relative URLs to leverage Next.js rewrites/proxy for same-origin requests
// This avoids cross-origin cookie issues with SameSite=lax
const API_URL = "";

async function fetchApi(endpoint: string, options: RequestInit = {}) {
  const response = await fetch(`${API_URL}${endpoint}`, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(error.detail || "Request failed");
  }

  // Handle empty responses (204 No Content, etc.)
  const contentLength = response.headers.get("content-length");
  if (response.status === 204 || contentLength === "0") {
    return null;
  }

  // Try to parse JSON, return null if empty
  const text = await response.text();
  if (!text) {
    return null;
  }

  return JSON.parse(text);
}

export interface User {
  id: string;
  github_username: string;
  email: string | null;
  avatar_url: string | null;
  is_admin?: boolean;
}

export interface Context {
  name: string;
  display_name: string;
  description: string;
  data_examples: string[] | null;
  compliance_tags: string[] | null;
  algorithm: string;
  sensitivity?: Sensitivity;
  quantum_resistant?: boolean;
}

// 5-Layer Context Model Types
export type Sensitivity = "critical" | "high" | "medium" | "low";
export type DataCategory = "personal_identifier" | "financial" | "health" | "authentication" | "business_confidential" | "general";
export type Adversary = "opportunistic_attacker" | "organized_crime" | "nation_state" | "insider_threat" | "quantum_computer";
export type AccessFrequency = "high" | "medium" | "low" | "rare";

// Encryption Context - Where/how the encryption is used
export type EncryptionUsageContext = "at_rest" | "in_transit" | "in_use" | "streaming" | "disk";

// Cipher modes for symmetric encryption
export type CipherMode = "gcm" | "gcm-siv" | "cbc" | "ctr" | "ccm" | "xts";

// Standard cryptographic key sizes in bits
export type KeySize = 128 | 192 | 256 | 2048 | 3072 | 4096 | 384 | 521;

// Algorithm override for advanced users
export interface AlgorithmOverride {
  cipher?: string | null;
  mode?: CipherMode | null;
  key_bits?: number | null;
}

// Alternative algorithm suggestion
export interface AlgorithmAlternative {
  algorithm: string;
  reason: string;
}

// Detailed explanation of algorithm selection
export interface AlgorithmRationale {
  summary: string;
  factors: string[];
  alternatives: AlgorithmAlternative[];
}

export interface DataIdentity {
  category: DataCategory;
  subcategory?: string | null;
  sensitivity: Sensitivity;
  usage_context: EncryptionUsageContext;
  pii: boolean;
  phi: boolean;
  pci: boolean;
  notification_required: boolean;
  examples: string[];
}

export interface RetentionPolicy {
  minimum_days?: number | null;
  maximum_days?: number | null;
  deletion_method: "crypto_shred" | "secure_delete" | "standard";
}

export interface DataResidency {
  allowed_regions: string[];
  prohibited_regions: string[];
}

export interface RegulatoryMapping {
  frameworks: string[];
  data_residency?: DataResidency | null;
  retention?: RetentionPolicy | null;
  cross_border_allowed: boolean;
}

export interface ThreatModel {
  adversaries: Adversary[];
  attack_vectors: string[];
  protection_lifetime_years: number;
  quantum_resistant_required?: boolean;
}

export interface AccessPatterns {
  frequency: AccessFrequency;
  operations_per_second?: number | null;
  latency_requirement_ms?: number | null;
  batch_operations: boolean;
  search_required: boolean;
}

export interface ContextConfig {
  data_identity: DataIdentity;
  regulatory: RegulatoryMapping;
  threat_model: ThreatModel;
  access_patterns: AccessPatterns;
}

export interface DerivedRequirements {
  minimum_security_bits: number;
  quantum_resistant: boolean;
  key_rotation_days: number;
  resolved_algorithm: string;
  resolved_mode: CipherMode;
  resolved_key_bits: number;
  audit_level: "full" | "detailed" | "standard" | "minimal";
  hardware_acceleration: boolean;
  rationale: string[];
  detailed_rationale?: AlgorithmRationale | null;
}

export interface ContextFullResponse {
  name: string;
  display_name: string;
  description: string;
  config: ContextConfig | null;
  derived: DerivedRequirements | null;
  data_examples: string[] | null;
  compliance_tags: string[] | null;
  algorithm: string;
  sensitivity?: string;
  quantum_resistant?: boolean;
  created_at: string;
  updated_at: string | null;
}

// Algorithm Types
export interface AlgorithmInfo {
  name: string;
  family: string;
  variant: string | null;
  aliases: string[];
  type: string;
  use_cases: string[];
  security_bits: number;
  key_sizes: number[];
  quantum_resistant: boolean;
  status: string;
  replacement: string | null;
  standards: string[];
  hardware_acceleration: boolean;
}

export interface AlgorithmDetail extends AlgorithmInfo {
  block_size: number | null;
  output_size: number | null;
  quantum_security_bits: number | null;
  deprecated_date: string | null;
  vulnerabilities: string[];
  compliance_frameworks: string[];
  relative_speed: string;
  memory_usage: string;
  implementation_notes: string[];
  common_mistakes: string[];
}

export interface AlgorithmTypeInfo {
  value: string;
  label: string;
  description: string;
  count: number;
}

export interface Identity {
  id: string;
  type: "developer" | "service";
  name: string;
  team: string;
  environment: string;
  allowed_contexts: string[];
  status: "active" | "expired" | "revoked";
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
}

export interface IdentityCreateResponse {
  identity: Identity;
  token: string;
  sdk_download_url: string;
}

// New Application model (replaces Identity)
export interface Application {
  id: string;
  name: string;
  description: string | null;
  team: string;
  environment: string;
  allowed_contexts: string[];
  status: "active" | "expired" | "revoked";
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
  key_created_at: string;
  has_refresh_token: boolean;
  refresh_token_expires_at: string | null;
}

export interface ApplicationCreateResponse {
  application: Application;
  access_token: string;
  refresh_token: string;
  setup_instructions: {
    step1: { title: string; command: string; note: string };
    step2: { title: string; command: string };
    step3: { title: string; code: string };
  };
}

export interface TokenInfo {
  access_token_algorithm: string;
  access_token_lifetime_seconds: number;
  refresh_token_active: boolean;
  refresh_token_expires_at: string | null;
  refresh_token_rotated_at: string | null;
  last_used_at: string | null;
}

export interface TokenRotateResponse {
  refresh_token: string;
  expires_at: string;
  message: string;
}

export interface TokenRefreshResponse {
  access_token: string;
  expires_at: string;
  token_type: string;
}

export interface TokenVerifyResponse {
  valid: boolean;
  error?: string;
  app_id?: string;
  app_name?: string;
  team?: string;
  environment?: string;
  contexts?: string[];
  expires_at?: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  operation: string;
  context: string;
  success: boolean;
  error_message: string | null;
  identity_id: string;
  identity_name: string | null;
  team: string | null;
  input_size_bytes: number | null;
  output_size_bytes: number | null;
  latency_ms: number | null;
}

export interface AuditStats {
  total_operations: number;
  successful_operations: number;
  failed_operations: number;
  operations_by_context: Record<string, number>;
  operations_by_identity: Record<string, number>;
}

// Dashboard Metrics Types
export interface AlgorithmUsage {
  algorithm: string;
  count: number;
  category: string;
  quantum_safe: boolean;
}

export interface SecurityPosture {
  overall_score: number;
  quantum_readiness: number;
  deprecated_usage: number;
  weak_algorithms: number;
  recommendations: string[];
}

export interface RecentActivity {
  total_operations_24h: number;
  successful_24h: number;
  failed_24h: number;
  most_used_context: string | null;
  most_used_algorithm: string | null;
}

// Promotion Metrics Types
export interface AppPromotionStatus {
  app_id: string;
  app_name: string;
  environment: string;
  is_ready: boolean;
  ready_count: number;
  total_count: number;
  blocking_contexts: string[];
  estimated_ready_at: string | null;
  requires_approval: boolean;
}

export interface PromotionMetrics {
  apps_ready_for_promotion: number;
  apps_blocking: number;
  total_dev_apps: number;
  tier_distribution: Record<string, number>;
  app_statuses: AppPromotionStatus[];
}

export interface DashboardMetrics {
  security_posture: SecurityPosture;
  recent_activity: RecentActivity;
  algorithm_distribution: AlgorithmUsage[];
  quantum_vulnerable_count: number;
  pqc_ready_count: number;
  active_identities: number;
  total_contexts: number;
  last_scan_date: string | null;
  warnings: string[];
  promotion_metrics: PromotionMetrics | null;
}

// Admin Types
export interface AdminDashboardStats {
  total_users: number;
  new_users_today: number;
  total_identities: number;
  active_identities: number;
  expiring_soon: number;
  total_operations: number;
  operations_today: number;
  operations_yesterday: number;
  successful_operations: number;
  failed_operations: number;
  avg_latency_ms: number;
  total_data_bytes: number;
  contexts_count: number;
}

export interface AdminUserSummary {
  id: string;
  github_username: string;
  email: string | null;
  avatar_url: string | null;
  created_at: string;
  last_login_at: string | null;
  is_admin: boolean;
  identity_count: number;
  operation_count: number;
}

export interface AdminIdentitySummary {
  id: string;
  name: string;
  team: string;
  environment: string;
  type: string;
  status: string;
  allowed_contexts: string[];
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
  user_id: string;
  user_name: string;
  operation_count: number;
}

export interface AdminContextStats {
  name: string;
  display_name: string;
  description: string;
  algorithm: string;
  compliance_tags: string[];
  data_examples: string[];
  created_at: string;
  operation_count: number;
  identity_count: number;
  last_key_rotation: string | null;
  key_version: number;
}

export interface TrendDataPoint {
  date: string;
  encrypt_count: number;
  decrypt_count: number;
  success_count: number;
  failed_count: number;
}

export interface TeamUsage {
  team: string;
  operation_count: number;
  identity_count: number;
}

// Code Analysis Types
export interface CryptoUsage {
  algorithm: string;
  category: string;
  library: string;
  line_number: number;
  context: string;
  is_weak: boolean;
  weakness_reason: string | null;
  quantum_risk: string;
  recommendation: string | null;
}

export interface CryptoFinding {
  severity: string;
  category: string;
  message: string;
  line_number: number | null;
  algorithm: string | null;
  recommendation: string;
}

export interface CBOMResponse {
  version: string;
  algorithms: { name: string; category: string; count: number; quantum_risk: string }[];
  libraries: string[];
  quantum_summary: { vulnerable: number; safe: number; unknown: number };
  findings_summary: { critical: number; high: number; medium: number; low: number; info: number };
}

export interface CodeScanResponse {
  usages: CryptoUsage[];
  findings: CryptoFinding[];
  language: string;
  lines_scanned: number;
  cbom: CBOMResponse;
}

export interface CodeScanQuickResponse {
  has_crypto: boolean;
  algorithms: string[];
  weak_algorithms: string[];
  quantum_vulnerable: string[];
  risk_level: string;
  recommendation: string;
}

export interface SupportedLanguage {
  language: string;
  extensions: string[];
  ast_supported: boolean;
}

export interface AlgorithmProperties {
  category: string;
  quantum_risk: string;
  is_weak: boolean;
  weakness_reason: string | null;
}

// Dependency Types
export interface CryptoDependency {
  name: string;
  version: string | null;
  package_type: string;
  category: string;
  algorithms: string[];
  quantum_risk: string;
  is_deprecated: boolean;
  deprecation_reason: string | null;
  recommended_replacement: string | null;
  description: string | null;
}

export interface DependencyScanResponse {
  dependencies: CryptoDependency[];
  package_type: string;
  total_packages: number;
  crypto_packages: number;
  quantum_vulnerable_count: number;
  deprecated_count: number;
  recommendations: string[];
}

export interface DependencyScanQuickResponse {
  has_crypto: boolean;
  crypto_count: number;
  quantum_vulnerable: boolean;
  deprecated_present: boolean;
  risk_level: string;
  top_algorithms: string[];
  recommendation: string;
}

export interface KnownPackage {
  name: string;
  category: string;
  algorithms: string[];
  quantum_risk: string;
  is_deprecated: boolean;
}

export interface SupportedFormatsResponse {
  formats: { filename: string; ecosystem: string; language: string }[];
}

// CBOM Report Types (CLI uploads)
export interface CBOMReport {
  id: number;
  scannedAt: string;
  scanName: string | null;
  scanPath: string | null;
  libraryCount: number;
  algorithmCount: number;
  quantumReadinessScore: number;
  hasPqc: boolean;
  gitCommit: string | null;
  gitBranch: string | null;
  gitRepo: string | null;
}

export interface CBOMReportDetail {
  id: number;
  scannedAt: string;
  scanName: string | null;
  scanPath: string | null;
  scanSource: string;
  quantumReadinessScore: number;
  metrics: {
    libraryCount: number;
    algorithmCount: number;
    quantumSafeCount: number;
    quantumVulnerableCount: number;
    hasPqc: boolean;
    deprecatedCount: number;
  };
  libraries: {
    name: string;
    version?: string;
    category: string;
    algorithms?: string[];
    quantumRisk?: string;
    isDeprecated?: boolean;
  }[];
  algorithms: {
    name: string;
    category: string;
    library?: string;
  }[];
  cbomData: Record<string, unknown> | null;
  git: {
    commit: string | null;
    branch: string | null;
    repo: string | null;
  };
}

// PQC Recommendations Types
export interface SNDLAssessment {
  vulnerable: boolean;
  protection_years_required: number;
  estimated_quantum_years: number;
  risk_window_years: number;
  risk_level: string;
  explanation: string;
}

export interface AlgorithmRecommendation {
  current_algorithm: string;
  recommended_algorithm: string;
  fips_standard: string;
  security_level: string;
  rationale: string;
  migration_complexity: string;
  library_support: string[];
}

export interface MigrationStep {
  priority: number;
  phase: string;
  action: string;
  algorithms_affected: string[];
  estimated_effort: string;
  dependencies: string[];
}

export interface PQCRecommendationResponse {
  sndl_assessment: SNDLAssessment;
  kem_recommendations: AlgorithmRecommendation[];
  signature_recommendations: AlgorithmRecommendation[];
  migration_plan: MigrationStep[];
  overall_urgency: string;
  quantum_readiness_score: number;
  key_findings: string[];
  next_steps: string[];
}

// Certificate Types
export interface CSRResponse {
  csr_pem: string;
  private_key_pem: string;
  public_key_pem: string;
}

export interface SelfSignedCertResponse {
  certificate_pem: string;
  private_key_pem: string;
}

export interface CertificateInfo {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  serial_number: string;
  not_before: string;
  not_after: string;
  days_until_expiry: number;
  is_ca: boolean;
  signature_algorithm: string;
  key_type: string;
  key_size: number | null;
  key_usage: string[];
  extended_key_usage: string[];
  san: string[];
  fingerprint_sha256: string;
  fingerprint_sha1: string;
}

export interface CertificateVerifyResponse {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export interface ChainVerifyResponse {
  valid: boolean;
  errors: string[];
  chain_length: number;
}

// =============================================================================
// Cryptographic Operations Types (Hash, MAC, Signatures, Key Exchange, Secrets)
// =============================================================================

// Hash Algorithms supported
export type HashAlgorithm = "sha256" | "sha384" | "sha512" | "sha3-256" | "sha3-384" | "sha3-512" | "blake2b" | "blake2s" | "blake3" | "shake128" | "shake256";

// MAC Algorithms supported
export type MACAlgorithm = "hmac-sha256" | "hmac-sha384" | "hmac-sha512" | "hmac-sha3-256" | "hmac-blake2b" | "kmac128" | "kmac256";

// Signature Algorithms supported
export type SignatureAlgorithm = "ed25519" | "ed448" | "ecdsa-p256" | "ecdsa-p384" | "ml-dsa-65" | "slh-dsa-128f";

// Signature output formats
export type SignatureFormat = "raw" | "base64" | "der" | "jws";

// Key Exchange Algorithms
export type KeyExchangeAlgorithm = "x25519" | "ecdh-p256" | "ecdh-p384" | "ecdh-p521";

// Password Hash Algorithms
export type PasswordHashAlgorithm = "argon2id" | "argon2i" | "argon2d" | "bcrypt" | "scrypt" | "pbkdf2-sha256";

// Hash Request/Response
export interface HashRequest {
  data: string; // base64 encoded
  algorithm: HashAlgorithm;
  output_length?: number; // for variable output (SHAKE, BLAKE)
}

export interface HashResponse {
  digest: string; // base64
  hex: string;
  algorithm: string;
  length_bits: number;
}

// MAC Request/Response
export interface MACRequest {
  data: string; // base64
  key: string; // base64
  algorithm: MACAlgorithm;
  output_length?: number;
}

export interface MACResponse {
  tag: string; // base64
  hex: string;
  algorithm: string;
  length_bits: number;
}

// Signature Types
export interface SigningKeyResponse {
  key_id: string;
  algorithm: string;
  public_key_jwk: Record<string, unknown>;
  public_key_pem: string;
  created_at: string;
}

export interface SignRequest {
  message: string; // base64
  key_id: string;
  output_format?: SignatureFormat;
}

export interface SignResponse {
  signature: string;
  algorithm: string;
  key_id: string;
  format: string;
}

export interface VerifyRequest {
  message: string; // base64
  signature: string;
  key_id?: string;
  public_key?: string;
  signature_format?: SignatureFormat;
}

export interface VerifyResponse {
  valid: boolean;
  algorithm: string;
  message?: string;
}

// Key Exchange Types
export interface KeyExchangeKeysResponse {
  private_key: string; // base64
  public_key: string; // base64
  algorithm: string;
}

export interface DeriveSecretRequest {
  private_key: string; // base64
  peer_public_key: string; // base64
  algorithm: KeyExchangeAlgorithm;
  key_length?: number;
  info?: string; // base64
}

export interface DeriveSecretResponse {
  shared_secret: string; // base64
  algorithm: string;
  length_bytes: number;
}

// Password Hashing Types
export interface PasswordHashRequest {
  password: string;
  algorithm?: PasswordHashAlgorithm;
}

export interface PasswordHashResponse {
  hash: string; // PHC format
  algorithm: string;
  params: Record<string, unknown>;
}

export interface PasswordVerifyRequest {
  password: string;
  hash: string;
}

export interface PasswordVerifyResponse {
  valid: boolean;
  needs_rehash: boolean;
  algorithm: string;
}

export interface PasswordStrengthResponse {
  score: number; // 0-100
  strength: "weak" | "fair" | "good" | "strong";
  length: number;
  entropy_bits: number;
  has_uppercase: boolean;
  has_lowercase: boolean;
  has_digits: boolean;
  has_symbols: boolean;
  suggestions: string[];
}

// Shamir Secret Sharing Types
export interface ShamirShare {
  index: number;
  value: string; // base64
}

export interface ShamirSplitRequest {
  secret: string; // base64
  threshold: number; // 2-255
  total_shares: number; // 2-255
}

export interface ShamirSplitResponse {
  shares: ShamirShare[];
  threshold: number;
  total_shares: number;
}

export interface ShamirCombineRequest {
  shares: ShamirShare[];
}

export interface ShamirCombineResponse {
  secret: string; // base64
}

// Lease Management Types
export interface LeaseGrantRequest {
  resource_type: string;
  resource_id: string;
  identity: string;
  expiry_seconds: number;
  permissions: string[];
}

export interface LeaseResponse {
  lease_id: string;
  token: string;
  expiry: string;
}

export interface LeaseRenewResponse {
  new_expiry: string;
}

// Encryption with Algorithm Details
export interface EncryptRequest {
  plaintext: string; // base64
  context: string;
  algorithm_override?: {
    cipher?: string;
    mode?: CipherMode;
    key_bits?: number;
  };
  associated_data?: string; // base64 AAD
}

export interface EncryptResponse {
  ciphertext: string; // base64
  algorithm: {
    name: string;
    mode: CipherMode;
    key_bits: number;
    description: string;
  };
  warnings: string[];
}

export interface DecryptRequest {
  ciphertext: string; // base64
  context: string;
  associated_data?: string; // base64 AAD
}

export interface DecryptResponse {
  plaintext: string; // base64
}

// Algorithm Details for UI display
export interface AlgorithmParameters {
  nonce_size_bytes: number;
  tag_size_bytes: number;
  block_size_bytes: number;
  min_key_bits: number;
  max_key_bits: number;
  supports_aad: boolean;
  requires_padding: boolean;
  hardware_accelerated: boolean;
}

export interface HealthStatus {
  database: string;
  encryption_service: string;
  expiring_identities: number;
  failed_operations_last_hour: number;
  avg_latency_last_hour: number;
}

// Security Command Center Types
export interface SecurityAlert {
  id: string;
  severity: "critical" | "warning" | "info";
  category: "key" | "identity" | "operation" | "compliance";
  title: string;
  description: string;
  affected_count: number;
  timestamp: string;
  action_url: string | null;
  auto_resolvable: boolean;
}

export interface SecurityMetrics {
  operations_per_minute: number;
  encryption_rate: number;
  success_rate: number;
  avg_latency_ms: number;
  active_identities: number;
  contexts_in_use: number;
  data_processed_mb: number;
}

export interface BlastRadiusItem {
  context_name: string;
  key_version: number;
  identities_affected: number;
  operations_count: number;
  data_size_bytes: number;
  teams: string[];
  last_used: string | null;
}

export interface PlaygroundRequest {
  operation: "encrypt" | "decrypt";
  data: string;
  context: string;
}

export interface PlaygroundResponse {
  success: boolean;
  result: string | null;
  algorithm: string;
  latency_ms: number;
  error: string | null;
}

// Premium Feature Types
export interface RiskScoreFactor {
  name: string;
  category: string;
}

export interface RiskScoreResponse {
  score: number;
  grade: string;
  trend: string;
  factors: RiskScoreFactor[];
  premium_required: boolean;
}

export interface QuantumReadinessResponse {
  readiness_percent: number;
  classical_contexts: number;
  quantum_ready_contexts: number;
  hybrid_contexts: number;
  migration_status: string;
  estimated_completion: string | null;
  premium_required: boolean;
}

export interface ComplianceFramework {
  name: string;
  status: string;
  coverage_percent: number;
  issues: number;
  last_audit: string | null;
}

export interface ComplianceStatusResponse {
  frameworks: ComplianceFramework[];
  overall_score: number;
  export_available: boolean;
  premium_required: boolean;
}

// Organization Settings Types
export interface OrganizationSettingsResponse {
  allowed_domains: string[];
  require_domain_match: boolean;
  allow_any_github_user: boolean;
  organization_name: string | null;
  admin_email: string | null;
  created_at: string;
  updated_at: string;
}

// Policy Types
export interface Policy {
  name: string;
  description: string;
  rule: string;
  severity: "block" | "warn" | "info";
  message: string;
  enabled: boolean;
  contexts: string[];
  operations: string[];
}

export interface PolicyEvaluationRequest {
  algorithm: string;
  context_name: string;
  sensitivity: "low" | "medium" | "high" | "critical";
  pii?: boolean;
  phi?: boolean;
  pci?: boolean;
  frameworks?: string[];
  protection_lifetime_years?: number;
  team?: string;
  operation?: "encrypt" | "decrypt";
}

export interface PolicyEvaluationResult {
  policy_name: string;
  passed: boolean;
  severity: string;
  message: string;
  rule: string;
}

export interface PolicyEvaluationResponse {
  algorithm: string;
  context: string;
  allowed: boolean;
  blocking_violations: number;
  warning_violations: number;
  info_violations: number;
  results: PolicyEvaluationResult[];
}

export const api = {
  // User
  getCurrentUser: () => fetchApi("/api/users/me") as Promise<User>,

  // Contexts
  listContexts: () => fetchApi("/api/contexts") as Promise<Context[]>,

  // Algorithms
  listAlgorithms: (params?: {
    type?: string;
    quantum_resistant?: boolean;
    status?: string;
    min_security_bits?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.type) query.set("type", params.type);
    if (params?.quantum_resistant !== undefined)
      query.set("quantum_resistant", String(params.quantum_resistant));
    if (params?.status) query.set("status", params.status);
    if (params?.min_security_bits)
      query.set("min_security_bits", String(params.min_security_bits));
    return fetchApi(`/api/algorithms?${query}`) as Promise<AlgorithmInfo[]>;
  },
  getAlgorithmTypes: () =>
    fetchApi("/api/algorithms/types") as Promise<AlgorithmTypeInfo[]>,
  getRecommendedAlgorithms: (type?: string) => {
    const query = type ? `?type=${type}` : "";
    return fetchApi(`/api/algorithms/recommended${query}`) as Promise<AlgorithmInfo[]>;
  },
  getQuantumResistantAlgorithms: () =>
    fetchApi("/api/algorithms/quantum-resistant") as Promise<AlgorithmInfo[]>,
  getDeprecatedAlgorithms: () =>
    fetchApi("/api/algorithms/deprecated") as Promise<AlgorithmInfo[]>,
  getAlgorithm: (name: string) =>
    fetchApi(`/api/algorithms/${encodeURIComponent(name)}`) as Promise<AlgorithmDetail>,

  // Identities (legacy - kept for backward compatibility)
  listIdentities: () => fetchApi("/api/identities") as Promise<Identity[]>,
  createIdentity: (data: {
    name: string;
    type: "developer" | "service";
    team: string;
    environment: string;
    allowed_contexts: string[];
    expires_in_days: number;
  }) =>
    fetchApi("/api/identities", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<IdentityCreateResponse>,
  revokeIdentity: (id: string) =>
    fetchApi(`/api/identities/${id}`, { method: "DELETE" }),

  // Applications (new - replaces Identities)
  listApplications: () =>
    fetchApi("/api/v1/applications") as Promise<Application[]>,
  createApplication: (data: {
    name: string;
    description?: string;
    team: string;
    environment: string;
    allowed_contexts: string[];
    expires_in_days?: number;
  }) =>
    fetchApi("/api/v1/applications", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<ApplicationCreateResponse>,
  getApplication: (id: string) =>
    fetchApi(`/api/v1/applications/${id}`) as Promise<Application>,
  updateApplication: (id: string, data: {
    name?: string;
    description?: string;
    allowed_contexts?: string[];
  }) =>
    fetchApi(`/api/v1/applications/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }) as Promise<Application>,
  deleteApplication: (id: string) =>
    fetchApi(`/api/v1/applications/${id}`, { method: "DELETE" }),

  // Application Token Management
  getTokenInfo: (appId: string) =>
    fetchApi(`/api/v1/applications/${appId}/tokens`) as Promise<TokenInfo>,
  rotateTokens: (appId: string) =>
    fetchApi(`/api/v1/applications/${appId}/tokens/rotate`, {
      method: "POST",
    }) as Promise<TokenRotateResponse>,
  revokeTokens: (appId: string) =>
    fetchApi(`/api/v1/applications/${appId}/tokens/revoke`, {
      method: "POST",
    }),

  // Token Refresh (for SDK)
  refreshAccessToken: (refreshToken: string) =>
    fetchApi("/api/v1/auth/refresh", {
      method: "POST",
      body: JSON.stringify({ refresh_token: refreshToken }),
    }) as Promise<TokenRefreshResponse>,

  // Token Verification (for debugging)
  verifyToken: (accessToken: string) =>
    fetchApi("/api/v1/auth/verify", {
      method: "POST",
      body: JSON.stringify({ access_token: accessToken }),
    }) as Promise<TokenVerifyResponse>,

  // Audit
  listAuditLogs: (params?: {
    identity_id?: string;
    context?: string;
    success?: boolean;
    limit?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.identity_id) query.set("identity_id", params.identity_id);
    if (params?.context) query.set("context", params.context);
    if (params?.success !== undefined)
      query.set("success", String(params.success));
    if (params?.limit) query.set("limit", String(params.limit));
    return fetchApi(`/api/audit?${query}`) as Promise<AuditLog[]>;
  },
  getAuditStats: () => fetchApi("/api/audit/stats") as Promise<AuditStats>,

  // Dashboard Metrics
  getDashboardMetrics: () =>
    fetchApi("/api/v1/dashboard/metrics") as Promise<DashboardMetrics>,

  // Auth
  getLoginUrl: () => `${API_URL}/auth/github`,
  logout: () => fetchApi("/auth/logout", { method: "POST" }),

  // Admin - Dashboard
  getAdminDashboard: () =>
    fetchApi("/api/admin/dashboard") as Promise<AdminDashboardStats>,

  // Admin - Users
  listAllUsers: (params?: { search?: string; limit?: number; offset?: number }) => {
    const query = new URLSearchParams();
    if (params?.search) query.set("search", params.search);
    if (params?.limit) query.set("limit", String(params.limit));
    if (params?.offset) query.set("offset", String(params.offset));
    return fetchApi(`/api/admin/users?${query}`) as Promise<AdminUserSummary[]>;
  },
  getUserDetails: (userId: string) => fetchApi(`/api/admin/users/${userId}`),

  // Admin - Identities
  listAllIdentities: (params?: {
    search?: string;
    status?: string;
    team?: string;
    environment?: string;
    limit?: number;
    offset?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.search) query.set("search", params.search);
    if (params?.status) query.set("status", params.status);
    if (params?.team) query.set("team", params.team);
    if (params?.environment) query.set("environment", params.environment);
    if (params?.limit) query.set("limit", String(params.limit));
    if (params?.offset) query.set("offset", String(params.offset));
    return fetchApi(`/api/admin/identities?${query}`) as Promise<AdminIdentitySummary[]>;
  },
  adminRevokeIdentity: (identityId: string) =>
    fetchApi(`/api/admin/identities/${identityId}`, { method: "DELETE" }),

  // Admin - Audit
  getGlobalAuditLogs: (params?: {
    identity_id?: string;
    context?: string;
    operation?: string;
    success?: boolean;
    start_date?: string;
    end_date?: string;
    limit?: number;
    offset?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.identity_id) query.set("identity_id", params.identity_id);
    if (params?.context) query.set("context", params.context);
    if (params?.operation) query.set("operation", params.operation);
    if (params?.success !== undefined) query.set("success", String(params.success));
    if (params?.start_date) query.set("start_date", params.start_date);
    if (params?.end_date) query.set("end_date", params.end_date);
    if (params?.limit) query.set("limit", String(params.limit));
    if (params?.offset) query.set("offset", String(params.offset));
    return fetchApi(`/api/admin/audit/global?${query}`) as Promise<AuditLog[]>;
  },
  exportAuditLogs: (format: "csv" | "json", params?: { start_date?: string; end_date?: string }) => {
    const query = new URLSearchParams();
    query.set("format", format);
    if (params?.start_date) query.set("start_date", params.start_date);
    if (params?.end_date) query.set("end_date", params.end_date);
    return `${API_URL}/api/admin/audit/export?${query}`;
  },

  // Admin - Contexts
  getContextsWithStats: () =>
    fetchApi("/api/admin/contexts") as Promise<AdminContextStats[]>,
  rotateContextKey: (contextName: string) =>
    fetchApi(`/api/admin/contexts/${contextName}/rotate-key`, { method: "POST" }),

  // Admin - Key Usage
  getKeyUsage: (contextName: string) =>
    fetchApi(`/api/admin/keys/${contextName}/usage`) as Promise<{
      context: string;
      active_key_version: number;
      total_keys: number;
      keys: {
        key_id: string;
        context: string;
        version: number;
        status: string;
        created_at: string;
        encrypt_count: number;
        decrypt_count: number;
        total_operations: number;
        total_bytes_processed: number;
        last_used: string | null;
      }[];
    }>,

  // Admin - Cryptographic Bill of Materials
  getCBOM: () =>
    fetchApi("/api/admin/cbom") as Promise<{
      generated_at: string;
      total_contexts: number;
      total_algorithms: number;
      quantum_ready_percent: number;
      algorithms: {
        algorithm: string;
        family: string;
        mode: string;
        key_bits: number;
        context_count: number;
        contexts: string[];
        quantum_resistant: boolean;
        deprecated: boolean;
        standards: string[];
      }[];
      by_family: Record<string, number>;
      by_mode: Record<string, number>;
      by_security_level: Record<string, number>;
      recommendations: string[];
    }>,

  // Context CRUD (5-layer model)
  getContextDetail: (name: string) =>
    fetchApi(`/api/contexts/${name}`) as Promise<ContextFullResponse>,

  createContext: (data: {
    name: string;
    display_name: string;
    description: string;
    config: ContextConfig;
  }) =>
    fetchApi("/api/contexts", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<ContextFullResponse>,

  updateContext: (name: string, data: {
    name: string;
    display_name: string;
    description: string;
    config: ContextConfig;
  }) =>
    fetchApi(`/api/contexts/${name}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }) as Promise<ContextFullResponse>,

  resolveContextAlgorithm: (name: string) =>
    fetchApi(`/api/contexts/${name}/resolve`) as Promise<DerivedRequirements>,

  // Admin - Analytics
  getOperationTrends: (days: number = 30) =>
    fetchApi(`/api/admin/analytics/trends?days=${days}`) as Promise<TrendDataPoint[]>,
  getTeamUsage: (limit: number = 10) =>
    fetchApi(`/api/admin/analytics/teams?limit=${limit}`) as Promise<TeamUsage[]>,

  // Admin - Health
  getSystemHealth: () => fetchApi("/api/admin/health") as Promise<HealthStatus>,

  // Admin - Premium Features (OSS Preview)
  getRiskScore: () => fetchApi("/api/admin/risk-score") as Promise<RiskScoreResponse>,
  getQuantumReadiness: () => fetchApi("/api/admin/quantum-readiness") as Promise<QuantumReadinessResponse>,
  getComplianceStatus: () => fetchApi("/api/admin/compliance-status") as Promise<ComplianceStatusResponse>,

  // Admin - Security Command Center
  getSecurityAlerts: () =>
    fetchApi("/api/admin/security/alerts") as Promise<SecurityAlert[]>,
  getSecurityMetrics: () =>
    fetchApi("/api/admin/security/metrics") as Promise<SecurityMetrics>,
  getBlastRadius: () =>
    fetchApi("/api/admin/security/blast-radius") as Promise<BlastRadiusItem[]>,

  // Playground
  playground: (data: PlaygroundRequest) =>
    fetchApi("/api/admin/playground", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<PlaygroundResponse>,

  // Policies
  listPolicies: (params?: { enabled_only?: boolean; severity?: string }) => {
    const query = new URLSearchParams();
    if (params?.enabled_only) query.set("enabled_only", "true");
    if (params?.severity) query.set("severity", params.severity);
    return fetchApi(`/api/policies?${query}`) as Promise<Policy[]>;
  },
  getDefaultPolicies: () => fetchApi("/api/policies/defaults") as Promise<Policy[]>,
  getPolicy: (name: string) => fetchApi(`/api/policies/${name}`) as Promise<Policy>,
  evaluatePolicies: (data: PolicyEvaluationRequest) =>
    fetchApi("/api/policies/evaluate", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<PolicyEvaluationResponse>,

  // Policy CRUD (Admin only)
  createPolicy: (data: {
    name: string;
    description: string;
    rule: string;
    severity: "block" | "warn" | "info";
    message?: string;
    enabled?: boolean;
    contexts?: string[];
  }) =>
    fetchApi("/api/policies", {
      method: "POST",
      body: JSON.stringify({
        ...data,
        message: data.message || data.description,
        enabled: data.enabled ?? true,
        contexts: data.contexts || [],
        operations: [],
      }),
    }) as Promise<Policy>,

  updatePolicy: (name: string, data: {
    description?: string;
    rule?: string;
    severity?: "block" | "warn" | "info";
    message?: string;
    enabled?: boolean;
    contexts?: string[];
  }) =>
    fetchApi(`/api/policies/${name}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }) as Promise<Policy>,

  deletePolicy: (name: string) =>
    fetchApi(`/api/policies/${name}`, {
      method: "DELETE",
    }),

  // Policy Wizard (Admin)
  publishWizardPolicy: (data: {
    data_type: string;
    compliance: string[];
    threat_level: string;
    access_pattern: string;
    policy_name: string;
    context_name: string;
  }) =>
    fetchApi("/api/admin/wizard/publish", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<{
      success: boolean;
      context_name: string;
      policy_name: string;
      algorithm: string;
      message: string;
    }>,

  listPublishedPolicies: () =>
    fetchApi("/api/admin/policies/published") as Promise<{
      name: string;
      description: string;
      linked_context: string | null;
      created_at: string | null;
      created_by: string | null;
      metadata: Record<string, unknown> | null;
    }[]>,

  // Code Analysis
  scanCode: (data: { code: string; language?: string; filename?: string }) =>
    fetchApi("/api/v1/code/scan", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<CodeScanResponse>,

  scanCodeQuick: (data: { code: string; language?: string }) =>
    fetchApi("/api/v1/code/scan/quick", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<CodeScanQuickResponse>,

  generateCBOM: (data: { code: string; language?: string; filename?: string }) =>
    fetchApi("/api/v1/code/cbom", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<CBOMResponse>,

  exportCBOM: (data: {
    code: string;
    language?: string;
    filename?: string;
    format: "json" | "cyclonedx" | "spdx";
    identity_name?: string;
  }) =>
    fetchApi("/api/v1/code/cbom/export", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<Record<string, unknown>>,

  getPQCRecommendations: (data: {
    code: string;
    language?: string;
    data_profile?: "healthcare" | "national_security" | "financial" | "general" | "short_lived";
  }) =>
    fetchApi("/api/v1/code/recommendations", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<PQCRecommendationResponse>,

  getSupportedLanguages: () =>
    fetchApi("/api/v1/code/languages") as Promise<SupportedLanguage[]>,

  getDetectableAlgorithms: () =>
    fetchApi("/api/v1/code/algorithms") as Promise<Record<string, AlgorithmProperties>>,

  // Dependencies
  scanDependencies: (data: { content: string; filename?: string }) =>
    fetchApi("/api/v1/dependencies/scan", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<DependencyScanResponse>,

  scanDependenciesQuick: (data: { content: string; filename?: string }) =>
    fetchApi("/api/v1/dependencies/scan/quick", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<DependencyScanQuickResponse>,

  getKnownPackages: (packageType?: string) => {
    const query = packageType ? `?package_type=${packageType}` : "";
    return fetchApi(`/api/v1/dependencies/known-packages${query}`) as Promise<Record<string, KnownPackage[]>>;
  },

  getSupportedFormats: () =>
    fetchApi("/api/v1/dependencies/supported-formats") as Promise<SupportedFormatsResponse>,

  // Certificates
  generateCSR: (data: {
    subject: { common_name: string; organization?: string; country?: string };
    key_type?: string;
    key_size?: number;
    san_domains?: string[];
  }) =>
    fetchApi("/api/v1/certificates/csr/generate", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<CSRResponse>,

  generateSelfSignedCert: (data: {
    subject: { common_name: string; organization?: string; country?: string };
    validity_days?: number;
    is_ca?: boolean;
    san_domains?: string[];
  }) =>
    fetchApi("/api/v1/certificates/self-signed/generate", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<SelfSignedCertResponse>,

  parseCertificate: (data: { certificate: string }) =>
    fetchApi("/api/v1/certificates/parse", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<CertificateInfo>,

  verifyCertificate: (data: {
    certificate: string;
    issuer_certificate?: string;
    check_expiry?: boolean;
  }) =>
    fetchApi("/api/v1/certificates/verify", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<CertificateVerifyResponse>,

  verifyCertificateChain: (data: { certificates: string[]; check_expiry?: boolean }) =>
    fetchApi("/api/v1/certificates/verify-chain", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<ChainVerifyResponse>,

  // =============================================================================
  // Cryptographic Operations API
  // =============================================================================

  // Hashing
  hash: (data: { data: string; algorithm: HashAlgorithm; output_length?: number }) =>
    fetchApi("/api/v1/crypto/hash", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<HashResponse>,

  hashVerify: (data: { data: string; expected_digest: string; algorithm: HashAlgorithm }) =>
    fetchApi("/api/v1/crypto/hash/verify", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<{ valid: boolean }>,

  // MAC
  mac: (data: { data: string; key: string; algorithm: MACAlgorithm; output_length?: number }) =>
    fetchApi("/api/v1/crypto/mac", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<MACResponse>,

  macVerify: (data: { data: string; key: string; expected_tag: string; algorithm: MACAlgorithm }) =>
    fetchApi("/api/v1/crypto/mac/verify", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<{ valid: boolean }>,

  // Signatures
  generateSigningKey: (data: { algorithm?: SignatureAlgorithm; context?: string }) =>
    fetchApi("/api/v1/signatures/generate-key", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<SigningKeyResponse>,

  sign: (data: { message: string; key_id: string; output_format?: SignatureFormat }) =>
    fetchApi("/api/v1/signatures/sign", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<SignResponse>,

  verifySignature: (data: VerifyRequest) =>
    fetchApi("/api/v1/signatures/verify", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<VerifyResponse>,

  // Key Exchange
  generateKeyExchangeKeys: (algorithm: KeyExchangeAlgorithm = "x25519") =>
    fetchApi("/api/v1/crypto/key-exchange/generate", {
      method: "POST",
      body: JSON.stringify({ algorithm }),
    }) as Promise<KeyExchangeKeysResponse>,

  deriveSharedSecret: (data: DeriveSecretRequest) =>
    fetchApi("/api/v1/crypto/key-exchange/derive", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<DeriveSecretResponse>,

  // Password Hashing
  hashPassword: (data: { password: string; algorithm?: PasswordHashAlgorithm }) =>
    fetchApi("/api/v1/crypto/password/hash", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<PasswordHashResponse>,

  verifyPassword: (data: { password: string; hash: string }) =>
    fetchApi("/api/v1/crypto/password/verify", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<PasswordVerifyResponse>,

  checkPasswordStrength: (password: string) =>
    fetchApi("/api/v1/crypto/password/strength", {
      method: "POST",
      body: JSON.stringify({ password }),
    }) as Promise<PasswordStrengthResponse>,

  // Shamir Secret Sharing
  splitSecret: (data: { secret: string; threshold: number; total_shares: number }) =>
    fetchApi("/api/v1/secrets/shamir/split", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<ShamirSplitResponse>,

  combineShares: (shares: ShamirShare[]) =>
    fetchApi("/api/v1/secrets/shamir/combine", {
      method: "POST",
      body: JSON.stringify({ shares }),
    }) as Promise<ShamirCombineResponse>,

  // Encryption with AAD and Algorithm Override
  encrypt: (data: EncryptRequest) =>
    fetchApi("/api/v1/crypto/encrypt", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<EncryptResponse>,

  decrypt: (data: DecryptRequest) =>
    fetchApi("/api/v1/crypto/decrypt", {
      method: "POST",
      body: JSON.stringify(data),
    }) as Promise<DecryptResponse>,

  // CBOM Reports (CLI uploads)
  listCBOMReports: (limit: number = 20) =>
    fetchApi(`/api/v1/cbom?limit=${limit}`) as Promise<CBOMReport[]>,

  getCBOMReport: (reportId: number) =>
    fetchApi(`/api/v1/cbom/${reportId}`) as Promise<CBOMReportDetail>,

  // =============================================================================
  // Organization Settings & Domain Management (Admin)
  // =============================================================================

  getOrgSettings: () =>
    fetchApi("/api/admin/settings") as Promise<OrganizationSettingsResponse>,

  updateOrgSettings: (data: {
    require_domain_match?: boolean;
    allow_any_github_user?: boolean;
    organization_name?: string;
  }) =>
    fetchApi("/api/admin/settings", {
      method: "PATCH",
      body: JSON.stringify(data),
    }) as Promise<OrganizationSettingsResponse>,

  getAllowedDomains: () =>
    fetchApi("/api/admin/settings/domains") as Promise<{ domains: string[] }>,

  addAllowedDomain: (domain: string) =>
    fetchApi("/api/admin/settings/domains", {
      method: "POST",
      body: JSON.stringify({ domain }),
    }) as Promise<{ message: string; domains: string[] }>,

  removeAllowedDomain: (domain: string) =>
    fetchApi(`/api/admin/settings/domains/${encodeURIComponent(domain)}`, {
      method: "DELETE",
    }) as Promise<{ message: string; domains: string[] }>,

  toggleUserAdmin: (userId: string) =>
    fetchApi(`/api/admin/users/${userId}/toggle-admin`, {
      method: "POST",
    }) as Promise<{
      user_id: string;
      github_username: string;
      is_admin: boolean;
      message: string;
    }>,
};
