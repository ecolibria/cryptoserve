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

  return response.json();
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

  // Admin - Analytics
  getOperationTrends: (days: number = 30) =>
    fetchApi(`/api/admin/analytics/trends?days=${days}`) as Promise<TrendDataPoint[]>,
  getTeamUsage: (limit: number = 10) =>
    fetchApi(`/api/admin/analytics/teams?limit=${limit}`) as Promise<TeamUsage[]>,

  // Admin - Health
  getSystemHealth: () => fetchApi("/api/admin/health") as Promise<HealthStatus>,

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
};
