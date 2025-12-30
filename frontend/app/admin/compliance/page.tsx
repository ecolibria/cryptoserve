"use client";

import { useState, useEffect, useCallback } from "react";
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
  Sparkles,
  Crown,
  BarChart3,
  FileCheck,
  Bell,
  RefreshCw,
  Zap,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AdminLayout } from "@/components/admin-layout";
import { api, ComplianceStatusResponse, AdminContextStats } from "@/lib/api";
import { cn } from "@/lib/utils";
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

// Premium features with descriptions
const PREMIUM_FEATURES = [
  {
    icon: <FileCheck className="h-5 w-5 text-purple-600" />,
    title: "Automated Audit Reports",
    description: "Generate SOC2, HIPAA, and GDPR audit reports on-demand with one click",
  },
  {
    icon: <Bell className="h-5 w-5 text-purple-600" />,
    title: "Compliance Alerts",
    description: "Real-time notifications when your systems drift from compliance requirements",
  },
  {
    icon: <BarChart3 className="h-5 w-5 text-purple-600" />,
    title: "Trend Analysis",
    description: "Historical compliance trends and predictive risk scoring",
  },
  {
    icon: <RefreshCw className="h-5 w-5 text-purple-600" />,
    title: "Remediation Tracking",
    description: "Track and manage compliance issues from detection to resolution",
  },
  {
    icon: <Zap className="h-5 w-5 text-purple-600" />,
    title: "Policy Engine",
    description: "Define custom compliance policies and automated enforcement rules",
  },
  {
    icon: <Globe className="h-5 w-5 text-purple-600" />,
    title: "Multi-Region Compliance",
    description: "Manage data residency and cross-border transfer compliance globally",
  },
];

export default function CompliancePage() {
  const [loading, setLoading] = useState(true);
  const [compliance, setCompliance] = useState<ComplianceStatusResponse | null>(null);
  const [contexts, setContexts] = useState<AdminContextStats[]>([]);
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);

  const loadData = useCallback(async () => {
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
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "compliant":
        return <CheckCircle2 className="h-5 w-5 text-green-500" />;
      case "partial":
        return <AlertTriangle className="h-5 w-5 text-amber-500" />;
      case "non_compliant":
        return <XCircle className="h-5 w-5 text-red-500" />;
      default:
        return <MinusCircle className="h-5 w-5 text-slate-400" />;
    }
  };

  const getStatusBg = (status: string) => {
    switch (status) {
      case "compliant":
        return "bg-green-50 border-green-200";
      case "partial":
        return "bg-amber-50 border-amber-200";
      case "non_compliant":
        return "bg-red-50 border-red-200";
      default:
        return "bg-slate-50 border-slate-200";
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
    if (score >= 90) return "text-green-600";
    if (score >= 70) return "text-amber-600";
    if (score >= 50) return "text-orange-600";
    return "text-red-600";
  };

  const getScoreBg = (score: number) => {
    if (score >= 90) return "bg-green-100";
    if (score >= 70) return "bg-amber-100";
    if (score >= 50) return "bg-orange-100";
    return "bg-red-100";
  };

  const getContextsForFramework = (frameworkName: string) => {
    return contexts.filter((ctx) => ctx.compliance_tags?.includes(frameworkName));
  };

  if (loading) {
    return (
      <AdminLayout title="Compliance Dashboard" subtitle="Loading...">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </AdminLayout>
    );
  }

  return (
    <AdminLayout
      title="Compliance Dashboard"
      subtitle="Real-time compliance monitoring across frameworks"
      onRefresh={loadData}
      actions={
        compliance?.export_available ? (
          <Button variant="outline" size="sm">
            <Download className="h-4 w-4 mr-2" />
            Export Report
          </Button>
        ) : (
          <Button variant="outline" size="sm" disabled className="opacity-50">
            <Lock className="h-4 w-4 mr-2" />
            Export (Premium)
          </Button>
        )
      }
    >
      {/* Overall Score Banner */}
      {compliance && (
        <Card className="mb-6">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold text-slate-900 mb-1">
                  Overall Compliance Score
                </h2>
                <p className="text-sm text-slate-500">
                  Based on {compliance.frameworks.length} active frameworks
                </p>
              </div>
              <div className="text-right">
                <div
                  className={cn(
                    "inline-flex items-center justify-center w-20 h-20 rounded-full",
                    getScoreBg(compliance.overall_score)
                  )}
                >
                  <span className={cn("text-3xl font-bold", getScoreColor(compliance.overall_score))}>
                    {compliance.overall_score}%
                  </span>
                </div>
                <div className="flex items-center justify-end gap-1 text-sm text-slate-500 mt-2">
                  <TrendingUp className="h-4 w-4 text-green-500" />
                  Trending positive
                </div>
              </div>
            </div>

            {/* Progress bar */}
            <div className="mt-4 h-2 bg-slate-100 rounded-full overflow-hidden">
              <div
                className={cn(
                  "h-full rounded-full transition-all",
                  compliance.overall_score >= 90
                    ? "bg-green-500"
                    : compliance.overall_score >= 70
                    ? "bg-amber-500"
                    : compliance.overall_score >= 50
                    ? "bg-orange-500"
                    : "bg-red-500"
                )}
                style={{ width: `${compliance.overall_score}%` }}
              />
            </div>
          </CardContent>
        </Card>
      )}

      {/* Framework Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
        {compliance?.frameworks.map((framework) => {
          const details = FRAMEWORK_DETAILS[framework.name];
          const relatedContexts = getContextsForFramework(framework.name);

          return (
            <Card
              key={framework.name}
              className={cn(
                "cursor-pointer transition-all hover:shadow-md",
                selectedFramework === framework.name && "ring-2 ring-blue-500"
              )}
              onClick={() =>
                setSelectedFramework(selectedFramework === framework.name ? null : framework.name)
              }
            >
              <CardContent className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-slate-100 rounded-lg">
                      {details?.icon || <Shield className="h-6 w-6" />}
                    </div>
                    <div>
                      <h3 className="font-semibold text-lg text-slate-900">{framework.name}</h3>
                      <p className="text-xs text-slate-500">{details?.fullName || framework.name}</p>
                    </div>
                  </div>
                  {getStatusIcon(framework.status)}
                </div>

                <p className="text-sm text-slate-600 mb-4">
                  {details?.description || "Compliance framework"}
                </p>

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-500">Coverage</span>
                    <span className="font-semibold text-slate-900">{framework.coverage_percent}%</span>
                  </div>
                  <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
                    <div
                      className={cn(
                        "h-full rounded-full",
                        framework.coverage_percent >= 90
                          ? "bg-green-500"
                          : framework.coverage_percent >= 70
                          ? "bg-amber-500"
                          : "bg-red-500"
                      )}
                      style={{ width: `${framework.coverage_percent}%` }}
                    />
                  </div>

                  <div className="flex items-center justify-between text-sm">
                    <span className="text-slate-500">Status</span>
                    <span
                      className={cn(
                        "px-2 py-0.5 rounded text-xs font-medium",
                        framework.status === "compliant"
                          ? "bg-green-100 text-green-700"
                          : framework.status === "partial"
                          ? "bg-amber-100 text-amber-700"
                          : framework.status === "non_compliant"
                          ? "bg-red-100 text-red-700"
                          : "bg-slate-100 text-slate-700"
                      )}
                    >
                      {getStatusLabel(framework.status)}
                    </span>
                  </div>

                  {framework.issues > 0 && (
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-slate-500">Issues</span>
                      <span className="px-2 py-0.5 bg-red-100 text-red-700 rounded text-xs font-medium">
                        {framework.issues} issue{framework.issues > 1 ? "s" : ""}
                      </span>
                    </div>
                  )}

                  <div className="flex items-center justify-between text-sm">
                    <span className="text-slate-500">Contexts</span>
                    <span className="text-slate-700">{relatedContexts.length} linked</span>
                  </div>

                  {framework.last_audit && (
                    <div className="flex items-center gap-1 text-xs text-slate-500 mt-2 pt-2 border-t">
                      <Clock className="h-3 w-3" />
                      Last audit: {new Date(framework.last_audit).toLocaleDateString()}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Selected Framework Details */}
      {selectedFramework && (
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Target className="h-5 w-5 text-blue-500" />
              {FRAMEWORK_DETAILS[selectedFramework]?.fullName || selectedFramework} Requirements
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Requirements Checklist */}
              <div>
                <h4 className="text-sm font-medium text-slate-700 mb-3">Key Requirements</h4>
                <div className="space-y-2">
                  {FRAMEWORK_DETAILS[selectedFramework]?.requirements.map((req, idx) => (
                    <div key={idx} className="flex items-center gap-2 text-sm p-2 bg-slate-50 rounded">
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                      <span className="text-slate-700">{req}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Linked Contexts */}
              <div>
                <h4 className="text-sm font-medium text-slate-700 mb-3">Linked Contexts</h4>
                <div className="space-y-2">
                  {getContextsForFramework(selectedFramework).map((ctx) => (
                    <Link
                      key={ctx.name}
                      href="/admin/contexts"
                      className="flex items-center justify-between p-3 bg-slate-50 rounded hover:bg-slate-100 transition-colors"
                    >
                      <div>
                        <div className="font-medium text-slate-900">{ctx.display_name}</div>
                        <div className="text-xs text-slate-500">{ctx.name}</div>
                      </div>
                      <div className="flex items-center gap-2 text-sm text-slate-500">
                        <span className="px-2 py-0.5 bg-slate-200 rounded text-xs">{ctx.algorithm}</span>
                        <ChevronRight className="h-4 w-4" />
                      </div>
                    </Link>
                  ))}
                  {getContextsForFramework(selectedFramework).length === 0 && (
                    <div className="text-center py-4 text-slate-500">
                      <Info className="h-8 w-8 mx-auto mb-2 text-slate-300" />
                      <p className="text-sm">No contexts linked to this framework</p>
                      <p className="text-xs mt-1">Create a context with {selectedFramework} compliance tag</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* All Contexts with Compliance Tags */}
      <Card className="mb-8">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Lock className="h-5 w-5 text-purple-500" />
            Contexts by Compliance Coverage
          </CardTitle>
        </CardHeader>
        <CardContent>
          {contexts.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-3 px-4 font-medium text-slate-600">Context</th>
                    <th className="text-left py-3 px-4 font-medium text-slate-600">Algorithm</th>
                    <th className="text-left py-3 px-4 font-medium text-slate-600">Compliance Tags</th>
                    <th className="text-right py-3 px-4 font-medium text-slate-600">Operations</th>
                    <th className="text-right py-3 px-4 font-medium text-slate-600">Key Version</th>
                  </tr>
                </thead>
                <tbody>
                  {contexts.map((ctx) => (
                    <tr key={ctx.name} className="border-b last:border-0 hover:bg-slate-50">
                      <td className="py-3 px-4">
                        <div className="font-medium text-slate-900">{ctx.display_name}</div>
                        <div className="text-xs text-slate-500">{ctx.name}</div>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 bg-slate-100 rounded text-xs">{ctx.algorithm}</span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {ctx.compliance_tags?.length > 0 ? (
                            ctx.compliance_tags.map((tag) => (
                              <span
                                key={tag}
                                className={cn(
                                  "px-2 py-0.5 rounded text-xs font-medium",
                                  compliance?.frameworks.find((f) => f.name === tag && f.status === "compliant")
                                    ? "bg-green-100 text-green-700"
                                    : "bg-blue-100 text-blue-700"
                                )}
                              >
                                {tag}
                              </span>
                            ))
                          ) : (
                            <span className="text-slate-400 text-xs">No tags</span>
                          )}
                        </div>
                      </td>
                      <td className="text-right py-3 px-4 text-slate-900">
                        {ctx.operation_count.toLocaleString()}
                      </td>
                      <td className="text-right py-3 px-4 text-slate-600">v{ctx.key_version}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-8 text-slate-500">
              <Lock className="h-12 w-12 mx-auto mb-2 text-slate-300" />
              <p>No contexts configured yet</p>
              <Link href="/admin/contexts" className="text-blue-600 hover:text-blue-800 text-sm mt-2 inline-block">
                Create your first context
              </Link>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Premium Upsell Section */}
      <Card className="bg-gradient-to-br from-purple-50 to-blue-50 border-purple-200">
        <CardContent className="p-6">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-gradient-to-br from-purple-500 to-blue-500 rounded-lg">
              <Crown className="h-6 w-6 text-white" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-slate-900 flex items-center gap-2">
                Unlock Enterprise Compliance
                <Sparkles className="h-5 w-5 text-purple-500" />
              </h3>
              <p className="text-sm text-slate-600">
                Advanced compliance automation for enterprise teams
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
            {PREMIUM_FEATURES.map((feature, idx) => (
              <div key={idx} className="bg-white/70 rounded-lg p-4 border border-purple-100">
                <div className="flex items-center gap-3 mb-2">
                  {feature.icon}
                  <h4 className="font-medium text-slate-900">{feature.title}</h4>
                </div>
                <p className="text-sm text-slate-600">{feature.description}</p>
              </div>
            ))}
          </div>

          <div className="flex items-center justify-between pt-4 border-t border-purple-200">
            <div>
              <p className="text-sm text-slate-600">
                Starting at <span className="font-semibold text-slate-900">$499/month</span> for teams
              </p>
              <p className="text-xs text-slate-500 mt-0.5">14-day free trial included</p>
            </div>
            <div className="flex gap-3">
              <Button variant="outline" className="border-purple-300 text-purple-700 hover:bg-purple-50">
                Schedule Demo
              </Button>
              <Button className="bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 text-white">
                <Crown className="h-4 w-4 mr-2" />
                Upgrade to Premium
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </AdminLayout>
  );
}
