const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";

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
}

// 5-Layer Context Model Types
export type Sensitivity = "critical" | "high" | "medium" | "low";
export type DataCategory = "personal_identifier" | "financial" | "health" | "authentication" | "business_confidential" | "general";
export type Adversary = "opportunistic_attacker" | "organized_crime" | "nation_state" | "insider_threat" | "quantum_computer";
export type AccessFrequency = "high" | "medium" | "low" | "rare";

export interface DataIdentity {
  category: DataCategory;
  subcategory?: string | null;
  sensitivity: Sensitivity;
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
  audit_level: "full" | "detailed" | "standard" | "minimal";
  hardware_acceleration: boolean;
  rationale: string[];
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

  // Identities
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
};
