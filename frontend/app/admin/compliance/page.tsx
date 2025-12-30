"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  MinusCircle,
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
  TrendingDown,
  FileText,
  AlertCircle,
  BarChart3,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AdminLayout } from "@/components/admin-layout";
import { StatCard } from "@/components/ui/stat-card";
import { api, ComplianceStatusResponse, AdminContextStats } from "@/lib/api";
import { cn } from "@/lib/utils";
import Link from "next/link";
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

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

// Mock trend data for compliance score over time
const generateComplianceTrendData = () => {
  const data = [];
  const now = new Date();
  for (let i = 29; i >= 0; i--) {
    const date = new Date(now);
    date.setDate(date.getDate() - i);
    const baseScore = 78;
    const variation = Math.sin(i / 5) * 8 + Math.random() * 5;
    data.push({
      date: date.toLocaleDateString("en-US", { month: "short", day: "numeric" }),
      score: Math.min(100, Math.max(60, Math.round(baseScore + variation + (29 - i) * 0.3))),
    });
  }
  return data;
};

export default function CompliancePage() {
  const [loading, setLoading] = useState(true);
  const [compliance, setCompliance] = useState<ComplianceStatusResponse | null>(null);
  const [contexts, setContexts] = useState<AdminContextStats[]>([]);
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);
  const [complianceTrendData] = useState(generateComplianceTrendData);

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

  const getStatusLabel = (status: string) => {
    switch (status) {
      case "compliant":
        return "Compliant";
      case "partial":
        return "Partial";
      case "non_compliant":
        return "Non-Compliant";
      default:
        return "N/A";
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 90) return "#22c55e";
    if (score >= 70) return "#f59e0b";
    if (score >= 50) return "#f97316";
    return "#ef4444";
  };

  const getContextsForFramework = (frameworkName: string) => {
    return contexts.filter((ctx) => ctx.compliance_tags?.includes(frameworkName));
  };

  // Calculate metrics
  const totalFrameworks = compliance?.frameworks.length || 0;
  const compliantCount = compliance?.frameworks.filter((f) => f.status === "compliant").length || 0;
  const partialCount = compliance?.frameworks.filter((f) => f.status === "partial").length || 0;
  const nonCompliantCount = compliance?.frameworks.filter((f) => f.status === "non_compliant").length || 0;
  const totalIssues = compliance?.frameworks.reduce((sum, f) => sum + f.issues, 0) || 0;
  const avgCoverage = compliance?.frameworks.length
    ? Math.round(compliance.frameworks.reduce((sum, f) => sum + f.coverage_percent, 0) / compliance.frameworks.length)
    : 0;

  // Chart data for coverage by framework
  const coverageByFramework = compliance?.frameworks.map((f) => ({
    name: f.name,
    coverage: f.coverage_percent,
    issues: f.issues,
    status: f.status,
  })) || [];

  // Chart data for issues by framework
  const issuesByFramework = compliance?.frameworks
    .filter((f) => f.issues > 0)
    .map((f) => ({
      name: f.name,
      issues: f.issues,
    })) || [];

  if (loading) {
    return (
      <AdminLayout title="Compliance Dashboard" subtitle="Loading...">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </AdminLayout>
    );
  }

  const overallScore = compliance?.overall_score || 0;
  const scoreColor = getScoreColor(overallScore);
  const circumference = 2 * Math.PI * 54;
  const strokeDashoffset = circumference - (overallScore / 100) * circumference;

  return (
    <AdminLayout
      title="Compliance Dashboard"
      subtitle="Executive compliance overview and framework status"
      onRefresh={loadData}
      actions={
        <Button variant="outline" size="sm">
          <Download className="h-4 w-4 mr-2" />
          Export Report
        </Button>
      }
    >
      {/* Executive Summary Row */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-6">
        {/* Compliance Score Circle */}
        <Card className="lg:col-span-1">
          <CardContent className="p-6 flex flex-col items-center justify-center">
            <div className="relative w-32 h-32">
              <svg className="w-32 h-32 transform -rotate-90">
                <circle
                  cx="64"
                  cy="64"
                  r="54"
                  stroke="#e2e8f0"
                  strokeWidth="12"
                  fill="none"
                />
                <circle
                  cx="64"
                  cy="64"
                  r="54"
                  stroke={scoreColor}
                  strokeWidth="12"
                  fill="none"
                  strokeLinecap="round"
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  className="transition-all duration-1000"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-3xl font-bold" style={{ color: scoreColor }}>
                  {overallScore}%
                </span>
                <span className="text-xs text-slate-500">Score</span>
              </div>
            </div>
            <div className="mt-4 text-center">
              <div className="text-sm font-medium text-slate-900">Overall Compliance</div>
              <div className="flex items-center justify-center gap-1 text-xs text-green-600 mt-1">
                <TrendingUp className="h-3 w-3" />
                +3% vs last month
              </div>
            </div>
          </CardContent>
        </Card>

        {/* KPI Stats */}
        <div className="lg:col-span-3 grid grid-cols-2 md:grid-cols-3 gap-4">
          <StatCard
            title="Frameworks"
            value={totalFrameworks.toString()}
            subtitle="Active frameworks"
            icon={<FileText className="h-5 w-5 text-blue-500" />}
          />
          <StatCard
            title="Compliant"
            value={compliantCount.toString()}
            subtitle={`of ${totalFrameworks} frameworks`}
            icon={<CheckCircle2 className="h-5 w-5 text-green-500" />}
            trend={{ value: compliantCount > 0 ? Math.round((compliantCount / totalFrameworks) * 100) : 0, isPositive: true }}
          />
          <StatCard
            title="Partial"
            value={partialCount.toString()}
            subtitle="Need attention"
            icon={<AlertTriangle className="h-5 w-5 text-amber-500" />}
          />
          <StatCard
            title="Non-Compliant"
            value={nonCompliantCount.toString()}
            subtitle="Immediate action"
            icon={<XCircle className="h-5 w-5 text-red-500" />}
            trend={nonCompliantCount > 0 ? { value: nonCompliantCount, isPositive: false } : undefined}
          />
          <StatCard
            title="Open Issues"
            value={totalIssues.toString()}
            subtitle="Across all frameworks"
            icon={<AlertCircle className="h-5 w-5 text-orange-500" />}
            trend={totalIssues > 0 ? { value: totalIssues, isPositive: false } : undefined}
          />
          <StatCard
            title="Avg Coverage"
            value={`${avgCoverage}%`}
            subtitle="Requirement coverage"
            icon={<Target className="h-5 w-5 text-purple-500" />}
            trend={{ value: avgCoverage >= 80 ? 5 : -3, isPositive: avgCoverage >= 80 }}
          />
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Compliance Score Trend */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="h-5 w-5 text-blue-500" />
              Compliance Score Trend
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={complianceTrendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis
                    dataKey="date"
                    tick={{ fontSize: 11 }}
                    stroke="#94a3b8"
                    tickLine={false}
                  />
                  <YAxis
                    domain={[50, 100]}
                    tick={{ fontSize: 11 }}
                    stroke="#94a3b8"
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#1e293b",
                      border: "none",
                      borderRadius: "8px",
                      color: "#f8fafc",
                    }}
                    formatter={(value: number) => [`${value}%`, "Score"]}
                  />
                  <Line
                    type="monotone"
                    dataKey="score"
                    stroke="#3b82f6"
                    strokeWidth={2}
                    dot={false}
                    activeDot={{ r: 4, fill: "#3b82f6" }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Coverage by Framework */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-green-500" />
              Coverage by Framework
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={coverageByFramework} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" horizontal={true} vertical={false} />
                  <XAxis
                    type="number"
                    domain={[0, 100]}
                    tick={{ fontSize: 11 }}
                    stroke="#94a3b8"
                    tickLine={false}
                    tickFormatter={(v) => `${v}%`}
                  />
                  <YAxis
                    type="category"
                    dataKey="name"
                    tick={{ fontSize: 11 }}
                    stroke="#94a3b8"
                    tickLine={false}
                    axisLine={false}
                    width={70}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#1e293b",
                      border: "none",
                      borderRadius: "8px",
                      color: "#f8fafc",
                    }}
                    formatter={(value: number) => [`${value}%`, "Coverage"]}
                  />
                  <Bar dataKey="coverage" radius={[0, 4, 4, 0]}>
                    {coverageByFramework.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={
                          entry.coverage >= 90
                            ? "#22c55e"
                            : entry.coverage >= 70
                            ? "#f59e0b"
                            : "#ef4444"
                        }
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Issue Summary and Framework Status Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* Issue Summary */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-orange-500" />
              Issue Summary
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {compliance?.frameworks.map((framework) => (
                <div key={framework.name} className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div
                      className={cn(
                        "w-2 h-2 rounded-full",
                        framework.status === "compliant"
                          ? "bg-green-500"
                          : framework.status === "partial"
                          ? "bg-amber-500"
                          : "bg-red-500"
                      )}
                    />
                    <span className="text-sm text-slate-700">{framework.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {framework.issues > 0 ? (
                      <span className="px-2 py-0.5 bg-red-100 text-red-700 rounded text-xs font-medium">
                        {framework.issues} issue{framework.issues > 1 ? "s" : ""}
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 bg-green-100 text-green-700 rounded text-xs font-medium">
                        Clear
                      </span>
                    )}
                  </div>
                </div>
              ))}
              {(!compliance?.frameworks || compliance.frameworks.length === 0) && (
                <div className="text-center py-4 text-slate-500 text-sm">
                  No frameworks configured
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Framework Status Grid */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Shield className="h-5 w-5 text-blue-500" />
              Framework Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              {compliance?.frameworks.map((framework) => {
                const details = FRAMEWORK_DETAILS[framework.name];
                return (
                  <button
                    key={framework.name}
                    onClick={() =>
                      setSelectedFramework(selectedFramework === framework.name ? null : framework.name)
                    }
                    className={cn(
                      "p-4 rounded-lg border text-left transition-all hover:shadow-md",
                      selectedFramework === framework.name
                        ? "ring-2 ring-blue-500 bg-blue-50 border-blue-200"
                        : framework.status === "compliant"
                        ? "bg-green-50 border-green-200"
                        : framework.status === "partial"
                        ? "bg-amber-50 border-amber-200"
                        : "bg-red-50 border-red-200"
                    )}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="p-1.5 bg-white rounded">
                        {details?.icon || <Shield className="h-4 w-4" />}
                      </div>
                      {getStatusIcon(framework.status)}
                    </div>
                    <div className="font-semibold text-slate-900">{framework.name}</div>
                    <div className="text-xs text-slate-500 mt-0.5">{framework.coverage_percent}% coverage</div>
                  </button>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Selected Framework Details */}
      {selectedFramework && (
        <Card className="mb-6">
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

      {/* Contexts Compliance Table */}
      <Card>
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

      {/* Quick Action Cards */}
      <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link
          href="/admin/audit"
          className="block p-4 bg-white border rounded-lg hover:shadow-md transition-shadow cursor-pointer"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 rounded-lg">
              <FileText className="h-5 w-5 text-blue-600" />
            </div>
            <div className="flex-1">
              <div className="font-medium text-slate-900">Generate Audit Report</div>
              <div className="text-sm text-slate-500">Export compliance documentation</div>
            </div>
            <ChevronRight className="h-5 w-5 text-slate-400" />
          </div>
        </Link>
        <Link
          href="/admin/policies"
          className="block p-4 bg-white border rounded-lg hover:shadow-md transition-shadow cursor-pointer"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 bg-amber-100 rounded-lg">
              <AlertTriangle className="h-5 w-5 text-amber-600" />
            </div>
            <div className="flex-1">
              <div className="font-medium text-slate-900">Review Open Issues</div>
              <div className="text-sm text-slate-500">{totalIssues} issues need attention</div>
            </div>
            <ChevronRight className="h-5 w-5 text-slate-400" />
          </div>
        </Link>
        <Link
          href="/admin/contexts"
          className="block p-4 bg-white border rounded-lg hover:shadow-md transition-shadow cursor-pointer"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-100 rounded-lg">
              <Target className="h-5 w-5 text-green-600" />
            </div>
            <div className="flex-1">
              <div className="font-medium text-slate-900">Set Compliance Goals</div>
              <div className="text-sm text-slate-500">Define framework targets</div>
            </div>
            <ChevronRight className="h-5 w-5 text-slate-400" />
          </div>
        </Link>
      </div>
    </AdminLayout>
  );
}
