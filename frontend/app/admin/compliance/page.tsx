"use client";

import { useState, useEffect } from "react";
import {
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  MinusCircle,
  FileText,
  Download,
  Clock,
  Target,
  Lock,
  Globe,
  Building2,
  Activity,
  ChevronRight,
  Info,
  TrendingUp,
  RefreshCw,
} from "lucide-react";
import { api, ComplianceStatusResponse, Context, AdminContextStats } from "@/lib/api";
import Link from "next/link";

interface FrameworkDetail {
  name: string;
  fullName: string;
  description: string;
  icon: React.ReactNode;
  requirements: string[];
}

const FRAMEWORK_DETAILS: Record<string, FrameworkDetail> = {
  SOC2: {
    name: "SOC2",
    fullName: "SOC 2 Type II",
    description: "Service Organization Control report for trust service criteria",
    icon: <Shield className="h-6 w-6" />,
    requirements: [
      "Encrypt PII data at rest",
      "Use AES-256 or stronger",
      "Key rotation every 90 days",
      "Audit logging enabled",
      "Access control enforcement",
    ],
  },
  HIPAA: {
    name: "HIPAA",
    fullName: "Health Insurance Portability and Accountability Act",
    description: "U.S. regulation for protecting health information",
    icon: <Activity className="h-6 w-6" />,
    requirements: [
      "PHI encryption required",
      "Strong key management",
      "Audit trails for PHI access",
      "Minimum necessary access",
      "BAA compliance verification",
    ],
  },
  GDPR: {
    name: "GDPR",
    fullName: "General Data Protection Regulation",
    description: "EU regulation on data protection and privacy",
    icon: <Globe className="h-6 w-6" />,
    requirements: [
      "Data encryption at rest",
      "Right to erasure support",
      "Data minimization",
      "Cross-border transfer controls",
      "Breach notification capability",
    ],
  },
  "PCI-DSS": {
    name: "PCI-DSS",
    fullName: "Payment Card Industry Data Security Standard",
    description: "Security standard for card payment processing",
    icon: <Lock className="h-6 w-6" />,
    requirements: [
      "Encrypt cardholder data",
      "Strong cryptography (AES-256)",
      "Key management procedures",
      "Network segmentation",
      "Regular security testing",
    ],
  },
  CCPA: {
    name: "CCPA",
    fullName: "California Consumer Privacy Act",
    description: "California privacy rights and consumer protection",
    icon: <Building2 className="h-6 w-6" />,
    requirements: [
      "Consumer data protection",
      "Opt-out mechanisms",
      "Data deletion support",
      "Disclosure requirements",
      "Security safeguards",
    ],
  },
};

export default function CompliancePage() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [compliance, setCompliance] = useState<ComplianceStatusResponse | null>(null);
  const [contexts, setContexts] = useState<AdminContextStats[]>([]);
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);

  const loadData = async (showRefresh = false) => {
    if (showRefresh) setRefreshing(true);
    try {
      const [complianceData, contextData] = await Promise.all([
        api.getComplianceStatus(),
        api.getContextsWithStats(),
      ]);
      setCompliance(complianceData);
      setContexts(contextData);
    } catch (error) {
      console.error("Failed to load compliance data:", error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "compliant":
        return <CheckCircle2 className="h-5 w-5 text-green-500" />;
      case "partial":
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      case "non_compliant":
        return <XCircle className="h-5 w-5 text-red-500" />;
      default:
        return <MinusCircle className="h-5 w-5 text-gray-400" />;
    }
  };

  const getStatusBg = (status: string) => {
    switch (status) {
      case "compliant":
        return "bg-green-500/10 border-green-500/30";
      case "partial":
        return "bg-yellow-500/10 border-yellow-500/30";
      case "non_compliant":
        return "bg-red-500/10 border-red-500/30";
      default:
        return "bg-gray-500/10 border-gray-500/30";
    }
  };

  const getStatusLabel = (status: string) => {
    switch (status) {
      case "compliant":
        return "Compliant";
      case "partial":
        return "Partially Compliant";
      case "non_compliant":
        return "Non-Compliant";
      default:
        return "Not Applicable";
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return "text-green-500";
    if (score >= 70) return "text-yellow-500";
    if (score >= 50) return "text-orange-500";
    return "text-red-500";
  };

  const getContextsForFramework = (frameworkName: string) => {
    return contexts.filter((ctx) =>
      ctx.compliance_tags?.includes(frameworkName)
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-gradient-to-br from-emerald-500 to-teal-600 rounded-xl shadow-lg shadow-emerald-500/20">
            <FileText className="h-8 w-8" />
          </div>
          <div>
            <h1 className="text-3xl font-bold bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
              Compliance Dashboard
            </h1>
            <p className="text-slate-400">
              Real-time compliance monitoring across frameworks
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => loadData(true)}
            disabled={refreshing}
            className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
            Refresh
          </button>
          {compliance?.export_available ? (
            <button className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 rounded-lg transition-colors">
              <Download className="h-4 w-4" />
              Export Report
            </button>
          ) : (
            <div className="flex items-center gap-2 px-4 py-2 bg-slate-700/50 rounded-lg text-slate-400">
              <Lock className="h-4 w-4" />
              Export (Premium)
            </div>
          )}
        </div>
      </div>

      {/* Overall Score Banner */}
      {compliance && (
        <div className="mb-8 p-6 bg-slate-800/50 rounded-xl border border-slate-700">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-slate-300 mb-1">
                Overall Compliance Score
              </h2>
              <p className="text-slate-400 text-sm">
                Based on {compliance.frameworks.length} active frameworks
              </p>
            </div>
            <div className="text-right">
              <div className={`text-6xl font-bold ${getScoreColor(compliance.overall_score)}`}>
                {compliance.overall_score}%
              </div>
              <div className="flex items-center gap-2 text-sm text-slate-400 mt-1">
                <TrendingUp className="h-4 w-4 text-green-500" />
                Trending positive
              </div>
            </div>
          </div>

          {/* Progress bar */}
          <div className="mt-4 h-2 bg-slate-700 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full ${
                compliance.overall_score >= 90
                  ? "bg-green-500"
                  : compliance.overall_score >= 70
                  ? "bg-yellow-500"
                  : compliance.overall_score >= 50
                  ? "bg-orange-500"
                  : "bg-red-500"
              }`}
              style={{ width: `${compliance.overall_score}%` }}
            />
          </div>
        </div>
      )}

      {/* Framework Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
        {compliance?.frameworks.map((framework) => {
          const details = FRAMEWORK_DETAILS[framework.name];
          const relatedContexts = getContextsForFramework(framework.name);

          return (
            <div
              key={framework.name}
              onClick={() =>
                setSelectedFramework(
                  selectedFramework === framework.name ? null : framework.name
                )
              }
              className={`p-6 rounded-xl border cursor-pointer transition-all hover:scale-[1.02] ${getStatusBg(
                framework.status
              )} ${
                selectedFramework === framework.name
                  ? "ring-2 ring-blue-500"
                  : ""
              }`}
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-slate-700/50 rounded-lg">
                    {details?.icon || <Shield className="h-6 w-6" />}
                  </div>
                  <div>
                    <h3 className="font-semibold text-lg">{framework.name}</h3>
                    <p className="text-xs text-slate-400">
                      {details?.fullName || framework.name}
                    </p>
                  </div>
                </div>
                {getStatusIcon(framework.status)}
              </div>

              <p className="text-sm text-slate-400 mb-4">
                {details?.description || "Compliance framework"}
              </p>

              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-400">Coverage</span>
                  <span className="font-semibold">{framework.coverage_percent}%</span>
                </div>
                <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${
                      framework.coverage_percent >= 90
                        ? "bg-green-500"
                        : framework.coverage_percent >= 70
                        ? "bg-yellow-500"
                        : "bg-red-500"
                    }`}
                    style={{ width: `${framework.coverage_percent}%` }}
                  />
                </div>

                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-400">Status</span>
                  <span
                    className={`px-2 py-0.5 rounded ${
                      framework.status === "compliant"
                        ? "bg-green-500/20 text-green-400"
                        : framework.status === "partial"
                        ? "bg-yellow-500/20 text-yellow-400"
                        : framework.status === "non_compliant"
                        ? "bg-red-500/20 text-red-400"
                        : "bg-gray-500/20 text-gray-400"
                    }`}
                  >
                    {getStatusLabel(framework.status)}
                  </span>
                </div>

                {framework.issues > 0 && (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-slate-400">Issues</span>
                    <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded">
                      {framework.issues} issue{framework.issues > 1 ? "s" : ""}
                    </span>
                  </div>
                )}

                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-400">Contexts</span>
                  <span className="text-slate-300">{relatedContexts.length} linked</span>
                </div>

                {framework.last_audit && (
                  <div className="flex items-center gap-1 text-xs text-slate-500 mt-2">
                    <Clock className="h-3 w-3" />
                    Last audit: {new Date(framework.last_audit).toLocaleDateString()}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Selected Framework Details */}
      {selectedFramework && (
        <div className="mb-8 p-6 bg-slate-800/50 rounded-xl border border-slate-700">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Target className="h-5 w-5 text-blue-400" />
            {FRAMEWORK_DETAILS[selectedFramework]?.fullName || selectedFramework} Requirements
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Requirements Checklist */}
            <div>
              <h4 className="text-sm font-medium text-slate-400 mb-3">Key Requirements</h4>
              <div className="space-y-2">
                {FRAMEWORK_DETAILS[selectedFramework]?.requirements.map((req, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-2 text-sm p-2 bg-slate-700/30 rounded"
                  >
                    <CheckCircle2 className="h-4 w-4 text-green-500" />
                    <span>{req}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Linked Contexts */}
            <div>
              <h4 className="text-sm font-medium text-slate-400 mb-3">Linked Contexts</h4>
              <div className="space-y-2">
                {getContextsForFramework(selectedFramework).map((ctx) => (
                  <Link
                    key={ctx.name}
                    href={`/admin/contexts`}
                    className="flex items-center justify-between p-3 bg-slate-700/30 rounded hover:bg-slate-700/50 transition-colors"
                  >
                    <div>
                      <div className="font-medium">{ctx.display_name}</div>
                      <div className="text-xs text-slate-400">{ctx.name}</div>
                    </div>
                    <div className="flex items-center gap-2 text-sm text-slate-400">
                      <span>{ctx.algorithm}</span>
                      <ChevronRight className="h-4 w-4" />
                    </div>
                  </Link>
                ))}
                {getContextsForFramework(selectedFramework).length === 0 && (
                  <div className="text-center py-4 text-slate-500">
                    <Info className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">No contexts linked to this framework</p>
                    <p className="text-xs mt-1">Create a context with {selectedFramework} compliance tag</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* All Contexts with Compliance Tags */}
      <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Lock className="h-5 w-5 text-purple-400" />
          Contexts by Compliance Coverage
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="text-left py-3 px-4 font-medium text-slate-400">Context</th>
                <th className="text-left py-3 px-4 font-medium text-slate-400">Algorithm</th>
                <th className="text-left py-3 px-4 font-medium text-slate-400">Compliance Tags</th>
                <th className="text-right py-3 px-4 font-medium text-slate-400">Operations</th>
                <th className="text-right py-3 px-4 font-medium text-slate-400">Key Version</th>
              </tr>
            </thead>
            <tbody>
              {contexts.map((ctx) => (
                <tr
                  key={ctx.name}
                  className="border-b border-slate-700/50 hover:bg-slate-700/30"
                >
                  <td className="py-3 px-4">
                    <div className="font-medium text-slate-200">{ctx.display_name}</div>
                    <div className="text-xs text-slate-500">{ctx.name}</div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 bg-slate-700 rounded text-xs">
                      {ctx.algorithm}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex flex-wrap gap-1">
                      {ctx.compliance_tags?.length > 0 ? (
                        ctx.compliance_tags.map((tag) => (
                          <span
                            key={tag}
                            className={`px-2 py-0.5 rounded text-xs ${
                              compliance?.frameworks.find(
                                (f) => f.name === tag && f.status === "compliant"
                              )
                                ? "bg-green-500/20 text-green-400"
                                : "bg-blue-500/20 text-blue-400"
                            }`}
                          >
                            {tag}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-500 text-xs">No tags</span>
                      )}
                    </div>
                  </td>
                  <td className="text-right py-3 px-4 text-slate-300">
                    {ctx.operation_count.toLocaleString()}
                  </td>
                  <td className="text-right py-3 px-4 text-slate-400">
                    v{ctx.key_version}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {contexts.length === 0 && (
          <div className="text-center py-8 text-slate-500">
            <Lock className="h-12 w-12 mx-auto mb-2 opacity-50" />
            <p>No contexts configured yet</p>
            <Link
              href="/admin/contexts"
              className="text-blue-400 hover:text-blue-300 text-sm mt-2 inline-block"
            >
              Create your first context
            </Link>
          </div>
        )}
      </div>

      {/* Premium Banner */}
      {compliance?.premium_required && (
        <div className="mt-6 p-4 bg-gradient-to-r from-purple-500/10 to-blue-500/10 border border-purple-500/30 rounded-xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-purple-400" />
              <div>
                <h4 className="font-semibold">Unlock Advanced Compliance Features</h4>
                <p className="text-sm text-slate-400">
                  Export reports, automated audits, remediation tracking, and more
                </p>
              </div>
            </div>
            <button className="px-4 py-2 bg-purple-600 hover:bg-purple-700 rounded-lg transition-colors">
              Upgrade to Premium
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
