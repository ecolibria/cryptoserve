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
  Database,
  Atom,
  Sparkles,
  Crown,
  Zap,
  ShieldAlert,
  Trash2,
  Bell,
  LineChart as LineChartIcon,
  Package,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AdminLayout } from "@/components/admin-layout";
import { StatCard } from "@/components/ui/stat-card";
import {
  api,
  ComplianceStatusResponse,
  AdminContextStats,
  DataInventorySummary,
  RiskScoreSummary,
  PremiumFeaturesResponse,
} from "@/lib/api";
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

  // New OSS compliance features
  const [dataInventory, setDataInventory] = useState<DataInventorySummary | null>(null);
  const [riskScore, setRiskScore] = useState<RiskScoreSummary | null>(null);
  const [premiumFeatures, setPremiumFeatures] = useState<PremiumFeaturesResponse | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "inventory" | "risk" | "premium">("overview");

  const loadData = useCallback(async () => {
    try {
      const [complianceData, contextData, inventoryData, riskData, premiumData] = await Promise.all([
        api.getComplianceStatus(),
        api.getContextsWithStats(),
        api.getDataInventory().catch(() => null),
        api.getComplianceRiskScore().catch(() => null),
        api.getPremiumFeatures().catch(() => null),
      ]);
      setCompliance(complianceData);
      setContexts(contextData);
      setDataInventory(inventoryData);
      setRiskScore(riskData);
      setPremiumFeatures(premiumData);
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

  const getRiskColor = (level: string) => {
    switch (level) {
      case "low": return { bg: "bg-green-100", text: "text-green-700", border: "border-green-200" };
      case "medium": return { bg: "bg-amber-100", text: "text-amber-700", border: "border-amber-200" };
      case "high": return { bg: "bg-orange-100", text: "text-orange-700", border: "border-orange-200" };
      case "critical": return { bg: "bg-red-100", text: "text-red-700", border: "border-red-200" };
      default: return { bg: "bg-slate-100", text: "text-slate-700", border: "border-slate-200" };
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score <= 15) return "#22c55e";  // Low risk = green
    if (score <= 30) return "#f59e0b";  // Medium = amber
    if (score <= 50) return "#f97316";  // High = orange
    return "#ef4444";  // Critical = red
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
      {/* Navigation Tabs */}
      <div className="flex gap-2 mb-6 border-b border-slate-200 pb-4">
        <button
          onClick={() => setActiveTab("overview")}
          className={cn(
            "px-4 py-2 rounded-lg text-sm font-medium transition-all",
            activeTab === "overview"
              ? "bg-blue-100 text-blue-700"
              : "text-slate-600 hover:bg-slate-100"
          )}
        >
          <Shield className="h-4 w-4 inline mr-2" />
          Overview
        </button>
        <button
          onClick={() => setActiveTab("inventory")}
          className={cn(
            "px-4 py-2 rounded-lg text-sm font-medium transition-all",
            activeTab === "inventory"
              ? "bg-purple-100 text-purple-700"
              : "text-slate-600 hover:bg-slate-100"
          )}
        >
          <Database className="h-4 w-4 inline mr-2" />
          Data Inventory
        </button>
        <button
          onClick={() => setActiveTab("risk")}
          className={cn(
            "px-4 py-2 rounded-lg text-sm font-medium transition-all",
            activeTab === "risk"
              ? "bg-orange-100 text-orange-700"
              : "text-slate-600 hover:bg-slate-100"
          )}
        >
          <ShieldAlert className="h-4 w-4 inline mr-2" />
          Risk Assessment
        </button>
        <button
          onClick={() => setActiveTab("premium")}
          className={cn(
            "px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2",
            activeTab === "premium"
              ? "bg-amber-100 text-amber-700"
              : "text-slate-600 hover:bg-slate-100"
          )}
        >
          <Crown className="h-4 w-4" />
          Premium Features
          <Badge className="bg-gradient-to-r from-amber-500 to-orange-500 text-white text-[10px] px-1.5">
            PRO
          </Badge>
        </button>
      </div>

      {/* Overview Tab */}
      {activeTab === "overview" && (
        <>
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
            trend={{ value: compliantCount > 0 ? Math.round((compliantCount / totalFrameworks) * 100) : 0, label: "% compliant" }}
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
            trend={nonCompliantCount > 0 ? { value: nonCompliantCount, label: "issues" } : undefined}
          />
          <StatCard
            title="Open Issues"
            value={totalIssues.toString()}
            subtitle="Across all frameworks"
            icon={<AlertCircle className="h-5 w-5 text-orange-500" />}
            trend={totalIssues > 0 ? { value: totalIssues, label: "to resolve" } : undefined}
          />
          <StatCard
            title="Avg Coverage"
            value={`${avgCoverage}%`}
            subtitle="Requirement coverage"
            icon={<Target className="h-5 w-5 text-purple-500" />}
            trend={{ value: avgCoverage >= 80 ? 5 : -3, label: avgCoverage >= 80 ? "good" : "needs work" }}
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
                    formatter={(value) => [`${value ?? 0}%`, "Score"]}
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
                    formatter={(value) => [`${value ?? 0}%`, "Coverage"]}
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
        </>
      )}

      {/* Data Inventory Tab */}
      {activeTab === "inventory" && (
        <div className="space-y-6">
          {/* Inventory Stats */}
          <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
            <StatCard
              title="Total Contexts"
              value={dataInventory?.total_contexts.toString() || "0"}
              icon={<Database className="h-5 w-5 text-blue-500" />}
            />
            <StatCard
              title="PII Data"
              value={dataInventory?.pii_count.toString() || "0"}
              subtitle="Personal data"
              icon={<Lock className="h-5 w-5 text-purple-500" />}
            />
            <StatCard
              title="PHI Data"
              value={dataInventory?.phi_count.toString() || "0"}
              subtitle="Health data"
              icon={<Activity className="h-5 w-5 text-red-500" />}
            />
            <StatCard
              title="PCI Data"
              value={dataInventory?.pci_count.toString() || "0"}
              subtitle="Payment data"
              icon={<Lock className="h-5 w-5 text-amber-500" />}
            />
            <StatCard
              title="Quantum Safe"
              value={dataInventory?.quantum_safe_count.toString() || "0"}
              subtitle="PQC-protected"
              icon={<Atom className="h-5 w-5 text-green-500" />}
            />
            <StatCard
              title="Data Types"
              value={dataInventory?.total_data_types.toString() || "0"}
              icon={<FileText className="h-5 w-5 text-slate-500" />}
            />
          </div>

          {/* Inventory Table */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Database className="h-5 w-5 text-purple-500" />
                Data Inventory
              </CardTitle>
            </CardHeader>
            <CardContent>
              {dataInventory?.items && dataInventory.items.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b">
                        <th className="text-left py-3 px-4 font-medium text-slate-600">Context</th>
                        <th className="text-left py-3 px-4 font-medium text-slate-600">Classification</th>
                        <th className="text-left py-3 px-4 font-medium text-slate-600">Frameworks</th>
                        <th className="text-left py-3 px-4 font-medium text-slate-600">Algorithm</th>
                        <th className="text-center py-3 px-4 font-medium text-slate-600">Quantum Safe</th>
                        <th className="text-right py-3 px-4 font-medium text-slate-600">Ops (30d)</th>
                      </tr>
                    </thead>
                    <tbody>
                      {dataInventory.items.map((item) => (
                        <tr key={item.context_name} className="border-b last:border-0 hover:bg-slate-50">
                          <td className="py-3 px-4 font-medium text-slate-900">{item.context_name}</td>
                          <td className="py-3 px-4">
                            <div className="flex flex-wrap gap-1">
                              {item.data_classification.map((cls) => (
                                <span
                                  key={cls}
                                  className={cn(
                                    "px-2 py-0.5 rounded text-xs font-medium uppercase",
                                    cls === "pii" ? "bg-purple-100 text-purple-700" :
                                    cls === "phi" ? "bg-red-100 text-red-700" :
                                    cls === "pci" ? "bg-amber-100 text-amber-700" :
                                    "bg-slate-100 text-slate-700"
                                  )}
                                >
                                  {cls}
                                </span>
                              ))}
                              {item.data_classification.length === 0 && (
                                <span className="text-slate-400 text-xs">None</span>
                              )}
                            </div>
                          </td>
                          <td className="py-3 px-4">
                            <div className="flex flex-wrap gap-1">
                              {item.frameworks.map((fw) => (
                                <span key={fw} className="px-2 py-0.5 bg-blue-100 text-blue-700 rounded text-xs">
                                  {fw}
                                </span>
                              ))}
                              {item.frameworks.length === 0 && (
                                <span className="text-slate-400 text-xs">None</span>
                              )}
                            </div>
                          </td>
                          <td className="py-3 px-4">
                            <span className="px-2 py-0.5 bg-slate-100 rounded text-xs font-mono">
                              {item.algorithm}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-center">
                            {item.quantum_safe ? (
                              <CheckCircle2 className="h-5 w-5 text-green-500 mx-auto" />
                            ) : (
                              <XCircle className="h-5 w-5 text-slate-300 mx-auto" />
                            )}
                          </td>
                          <td className="text-right py-3 px-4 text-slate-900">
                            {item.operations_30d.toLocaleString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-center py-8 text-slate-500">
                  <Database className="h-12 w-12 mx-auto mb-2 text-slate-300" />
                  <p>No data inventory available</p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Premium Features Available */}
          {dataInventory?.premium_features_available && (
            <Card className="border-amber-200 bg-gradient-to-r from-amber-50 to-orange-50">
              <CardContent className="p-4">
                <div className="flex items-start gap-3">
                  <div className="p-2 bg-amber-100 rounded-lg">
                    <Crown className="h-5 w-5 text-amber-600" />
                  </div>
                  <div className="flex-1">
                    <h4 className="font-medium text-amber-900">Unlock Premium Data Inventory Features</h4>
                    <ul className="mt-2 text-sm text-amber-700 space-y-1">
                      {dataInventory.premium_features_available.map((feature, i) => (
                        <li key={i} className="flex items-center gap-2">
                          <Sparkles className="h-3 w-3" />
                          {feature}
                        </li>
                      ))}
                    </ul>
                  </div>
                  <Button
                    size="sm"
                    className="bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-600 hover:to-orange-600 text-white"
                    onClick={() => setActiveTab("premium")}
                  >
                    Upgrade
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Risk Assessment Tab */}
      {activeTab === "risk" && (
        <div className="space-y-6">
          {/* Risk Score Overview */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Risk Score Gauge */}
            <Card>
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
                      stroke={getRiskScoreColor(riskScore?.overall_score || 0)}
                      strokeWidth="12"
                      fill="none"
                      strokeLinecap="round"
                      strokeDasharray={circumference}
                      strokeDashoffset={circumference - ((riskScore?.overall_score || 0) / 100) * circumference}
                      className="transition-all duration-1000"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span
                      className="text-3xl font-bold"
                      style={{ color: getRiskScoreColor(riskScore?.overall_score || 0) }}
                    >
                      {riskScore?.overall_score || 0}
                    </span>
                    <span className="text-xs text-slate-500">Risk Score</span>
                  </div>
                </div>
                <div className="mt-4 text-center">
                  <div
                    className={cn(
                      "inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm font-medium",
                      getRiskColor(riskScore?.risk_level || "low").bg,
                      getRiskColor(riskScore?.risk_level || "low").text
                    )}
                  >
                    <ShieldAlert className="h-4 w-4" />
                    {(riskScore?.risk_level || "unknown").toUpperCase()} RISK
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Risk Stats */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <AlertCircle className="h-5 w-5 text-orange-500" />
                  Key Findings
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {riskScore?.key_findings && riskScore.key_findings.length > 0 ? (
                    riskScore.key_findings.map((finding, i) => (
                      <div
                        key={i}
                        className="flex items-start gap-3 p-3 bg-orange-50 border border-orange-100 rounded-lg"
                      >
                        <AlertTriangle className="h-5 w-5 text-orange-500 mt-0.5 shrink-0" />
                        <span className="text-sm text-orange-800">{finding}</span>
                      </div>
                    ))
                  ) : (
                    <div className="flex items-center gap-3 p-3 bg-green-50 border border-green-100 rounded-lg">
                      <CheckCircle2 className="h-5 w-5 text-green-500" />
                      <span className="text-sm text-green-800">No significant risk findings</span>
                    </div>
                  )}
                </div>

                <div className="mt-4 pt-4 border-t border-slate-100">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-slate-500">High Risk Contexts</span>
                    <span className="font-medium text-slate-900">
                      {riskScore?.high_risk_contexts || 0}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-sm mt-2">
                    <span className="text-slate-500">Last Assessment</span>
                    <span className="font-medium text-slate-900">
                      {riskScore?.assessed_at
                        ? new Date(riskScore.assessed_at).toLocaleString()
                        : "Never"}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Premium Risk Features */}
          {riskScore?.premium_features_available && (
            <Card className="border-amber-200 bg-gradient-to-r from-amber-50 to-orange-50">
              <CardContent className="p-4">
                <div className="flex items-start gap-3">
                  <div className="p-2 bg-amber-100 rounded-lg">
                    <Crown className="h-5 w-5 text-amber-600" />
                  </div>
                  <div className="flex-1">
                    <h4 className="font-medium text-amber-900">Unlock Premium Risk Analysis</h4>
                    <ul className="mt-2 text-sm text-amber-700 space-y-1">
                      {riskScore.premium_features_available.map((feature, i) => (
                        <li key={i} className="flex items-center gap-2">
                          <Sparkles className="h-3 w-3" />
                          {feature}
                        </li>
                      ))}
                    </ul>
                  </div>
                  <Button
                    size="sm"
                    className="bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-600 hover:to-orange-600 text-white"
                    onClick={() => setActiveTab("premium")}
                  >
                    Upgrade
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Premium Features Tab */}
      {activeTab === "premium" && (
        <div className="space-y-6">
          {/* Premium Header */}
          <div className="bg-gradient-to-r from-amber-500 via-orange-500 to-rose-500 rounded-xl p-6 text-white">
            <div className="flex items-center gap-4">
              <div className="p-3 bg-white/20 rounded-xl">
                <Crown className="h-8 w-8" />
              </div>
              <div>
                <h2 className="text-2xl font-bold">Enterprise Compliance Features</h2>
                <p className="text-white/80 mt-1">
                  Unlock powerful compliance tools for auditors, regulators, and enterprise security teams
                </p>
              </div>
            </div>
          </div>

          {/* Feature Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* Evidence Packages */}
            <Card className="border-2 border-dashed border-amber-200 hover:border-amber-300 transition-colors">
              <CardContent className="p-5">
                <div className="flex items-start gap-3">
                  <div className="p-2 bg-blue-100 rounded-lg">
                    <Package className="h-5 w-5 text-blue-600" />
                  </div>
                  <div className="flex-1">
                    <h4 className="font-semibold text-slate-900">Evidence Packages</h4>
                    <p className="text-sm text-slate-500 mt-1">
                      Generate auditor-ready evidence packages with tamper-evident digital signatures
                    </p>
                    <Badge className="mt-3 bg-amber-100 text-amber-700 border-amber-200">
                      Enterprise
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Crypto-Shredding */}
            <Card className="border-2 border-dashed border-amber-200 hover:border-amber-300 transition-colors">
              <CardContent className="p-5">
                <div className="flex items-start gap-3">
                  <div className="p-2 bg-red-100 rounded-lg">
                    <Trash2 className="h-5 w-5 text-red-600" />
                  </div>
                  <div className="flex-1">
                    <h4 className="font-semibold text-slate-900">Crypto-Shredding</h4>
                    <p className="text-sm text-slate-500 mt-1">
                      Permanently destroy encryption keys for GDPR Article 17 compliance
                    </p>
                    <Badge className="mt-3 bg-amber-100 text-amber-700 border-amber-200">
                      Enterprise
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Detailed Risk Scoring */}
            <Card className="border-2 border-dashed border-amber-200 hover:border-amber-300 transition-colors">
              <CardContent className="p-5">
                <div className="flex items-start gap-3">
                  <div className="p-2 bg-orange-100 rounded-lg">
                    <ShieldAlert className="h-5 w-5 text-orange-600" />
                  </div>
                  <div className="flex-1">
                    <h4 className="font-semibold text-slate-900">Detailed Risk Scoring</h4>
                    <p className="text-sm text-slate-500 mt-1">
                      Per-context risk analysis with component breakdown and recommendations
                    </p>
                    <Badge className="mt-3 bg-amber-100 text-amber-700 border-amber-200">
                      Enterprise
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Compliance Alerting */}
            <Card className="border-2 border-dashed border-amber-200 hover:border-amber-300 transition-colors">
              <CardContent className="p-5">
                <div className="flex items-start gap-3">
                  <div className="p-2 bg-purple-100 rounded-lg">
                    <Bell className="h-5 w-5 text-purple-600" />
                  </div>
                  <div className="flex-1">
                    <h4 className="font-semibold text-slate-900">Compliance Alerting</h4>
                    <p className="text-sm text-slate-500 mt-1">
                      Real-time alerts for policy violations with webhook integrations
                    </p>
                    <Badge className="mt-3 bg-amber-100 text-amber-700 border-amber-200">
                      Enterprise
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Historical Trends */}
            <Card className="border-2 border-dashed border-amber-200 hover:border-amber-300 transition-colors">
              <CardContent className="p-5">
                <div className="flex items-start gap-3">
                  <div className="p-2 bg-green-100 rounded-lg">
                    <LineChartIcon className="h-5 w-5 text-green-600" />
                  </div>
                  <div className="flex-1">
                    <h4 className="font-semibold text-slate-900">Historical Trends</h4>
                    <p className="text-sm text-slate-500 mt-1">
                      Track compliance posture over time with trending analysis
                    </p>
                    <Badge className="mt-3 bg-amber-100 text-amber-700 border-amber-200">
                      Enterprise
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* PDF Reports */}
            <Card className="border-2 border-dashed border-amber-200 hover:border-amber-300 transition-colors">
              <CardContent className="p-5">
                <div className="flex items-start gap-3">
                  <div className="p-2 bg-slate-100 rounded-lg">
                    <FileText className="h-5 w-5 text-slate-600" />
                  </div>
                  <div className="flex-1">
                    <h4 className="font-semibold text-slate-900">PDF Reports</h4>
                    <p className="text-sm text-slate-500 mt-1">
                      Executive-ready compliance reports with visualizations
                    </p>
                    <Badge className="mt-3 bg-amber-100 text-amber-700 border-amber-200">
                      Enterprise
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* CTA */}
          <Card className="bg-slate-900 text-white">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-lg font-semibold">Ready to upgrade?</h3>
                  <p className="text-slate-400 mt-1">
                    Contact our sales team to learn more about enterprise features
                  </p>
                </div>
                <div className="flex gap-3">
                  <a
                    href="https://cryptoserve.io/pricing"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <Button variant="outline" className="border-slate-600 text-slate-300 hover:bg-slate-800">
                      View Pricing
                    </Button>
                  </a>
                  <a href="mailto:sales@cryptoserve.io">
                    <Button className="bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-600 hover:to-orange-600">
                      Contact Sales
                    </Button>
                  </a>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </AdminLayout>
  );
}
