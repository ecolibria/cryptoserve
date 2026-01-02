"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import Link from "next/link";
import {
  FileText,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  GitBranch,
  GitCommit,
  Package,
  ChevronRight,
  Download,
  XCircle,
  Search,
  Radar,
  ScanLine,
  FolderGit2,
  AlertOctagon,
  ShieldCheck,
  ShieldAlert,
  RefreshCw,
  ArrowUpRight,
  TrendingUp,
  Target,
  Zap,
  Building2,
  Users,
  BookOpen,
  ArrowRight,
  Timer,
  Lightbulb,
  Lock,
  ChevronDown,
  ChevronUp,
  BarChart3,
  PieChart,
} from "lucide-react";
import { AdminLayout } from "@/components/admin-layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api, CBOMReport } from "@/lib/api";
import { cn } from "@/lib/utils";

type StatusFilter = "all" | "critical" | "warning" | "passing";

// Admin-focused remediation priorities
interface RemediationPriority {
  category: string;
  severity: "critical" | "high" | "medium";
  affectedRepos: number;
  description: string;
  businessImpact: string;
  recommendation: string;
  complianceFrameworks: string[];
  estimatedEffort: string;
}

export default function AdminCBOMPage() {
  const [reports, setReports] = useState<CBOMReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [showAllPriorities, setShowAllPriorities] = useState(false);
  const [activeInsightTab, setActiveInsightTab] = useState<"priorities" | "compliance" | "trends">("priorities");
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    insights: false,  // Collapsed by default
    sidebar: true,
  });

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.listCBOMReports(100);
      setReports(data);
    } catch (error) {
      console.error("Failed to load CBOM reports:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Categorize scans by status
  const categorizedScans = useMemo(() => {
    const critical = reports.filter(r => r.quantumReadinessScore < 50);
    const warning = reports.filter(r => r.quantumReadinessScore >= 50 && r.quantumReadinessScore < 80);
    const passing = reports.filter(r => r.quantumReadinessScore >= 80);

    return { critical, warning, passing };
  }, [reports]);

  // Get unique repositories with latest scan
  const repositories = useMemo(() => {
    const repoMap: Record<string, CBOMReport & { scanCount: number }> = {};

    reports.forEach(report => {
      const repoName = report.gitRepo || report.scanName || `scan-${report.id}`;
      const existing = repoMap[repoName];

      if (!existing || new Date(report.scannedAt) > new Date(existing.scannedAt)) {
        repoMap[repoName] = { ...report, scanCount: (existing?.scanCount || 0) + 1 };
      } else if (existing) {
        existing.scanCount++;
      }
    });

    return Object.entries(repoMap)
      .map(([name, data]) => ({ name, ...data }))
      .sort((a, b) => a.quantumReadinessScore - b.quantumReadinessScore);
  }, [reports]);

  // Recent activity (last 10 scans)
  const recentScans = useMemo(() => {
    return [...reports]
      .sort((a, b) => new Date(b.scannedAt).getTime() - new Date(a.scannedAt).getTime())
      .slice(0, 8);
  }, [reports]);

  // Filter reports
  const filteredReports = useMemo(() => {
    return repositories.filter(repo => {
      const matchesSearch = searchQuery === "" ||
        repo.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (repo.gitBranch?.toLowerCase().includes(searchQuery.toLowerCase()));

      let matchesStatus = true;
      if (statusFilter === "critical") {
        matchesStatus = repo.quantumReadinessScore < 50;
      } else if (statusFilter === "warning") {
        matchesStatus = repo.quantumReadinessScore >= 50 && repo.quantumReadinessScore < 80;
      } else if (statusFilter === "passing") {
        matchesStatus = repo.quantumReadinessScore >= 80;
      }

      return matchesSearch && matchesStatus;
    });
  }, [repositories, searchQuery, statusFilter]);

  // Generate remediation priorities for admins
  const remediationPriorities = useMemo<RemediationPriority[]>(() => {
    const priorities: RemediationPriority[] = [];

    // Analyze based on scan results
    const criticalCount = categorizedScans.critical.length;
    const warningCount = categorizedScans.warning.length;
    const totalRepos = repositories.length;
    const pqcEnabled = reports.filter(r => r.hasPqc).length;

    if (criticalCount > 0) {
      priorities.push({
        category: "Quantum-Vulnerable Cryptography",
        severity: "critical",
        affectedRepos: criticalCount,
        description: `${criticalCount} repositories are using cryptographic algorithms vulnerable to quantum attacks (RSA, ECDSA, ECDH). These algorithms can be broken by Shor's algorithm on a sufficiently powerful quantum computer.`,
        businessImpact: "Data encrypted today with these algorithms could be decrypted in the future ('harvest now, decrypt later' attacks). This affects long-term data confidentiality and regulatory compliance.",
        recommendation: "Prioritize migration to hybrid cryptography (classical + PQC) starting with systems handling sensitive data with long retention periods. Begin with CRYSTALS-Kyber for key encapsulation and CRYSTALS-Dilithium for signatures.",
        complianceFrameworks: ["NIST SP 800-131A", "NSA CNSA 2.0", "PCI DSS 4.0", "HIPAA"],
        estimatedEffort: "3-6 months per application"
      });
    }

    if (pqcEnabled < totalRepos && totalRepos > 0) {
      priorities.push({
        category: "Post-Quantum Cryptography Adoption",
        severity: criticalCount > 0 ? "high" : "medium",
        affectedRepos: totalRepos - pqcEnabled,
        description: `Only ${pqcEnabled} of ${totalRepos} repositories have adopted post-quantum cryptography. The remaining ${totalRepos - pqcEnabled} repositories are not quantum-ready.`,
        businessImpact: "Organizations without PQC readiness will face increasing compliance pressure as NIST PQC standards become mandatory. Early adoption reduces migration risk and cost.",
        recommendation: "Establish a PQC adoption roadmap. Start with new applications and high-value assets. Use hybrid approaches to maintain backward compatibility while adding quantum resistance.",
        complianceFrameworks: ["NIST PQC Standards", "NSA CNSA 2.0", "CISA Quantum Readiness"],
        estimatedEffort: "6-12 months organization-wide"
      });
    }

    if (warningCount > 0) {
      priorities.push({
        category: "Cryptographic Hygiene Issues",
        severity: "medium",
        affectedRepos: warningCount,
        description: `${warningCount} repositories have cryptographic hygiene issues such as deprecated libraries, weak key sizes, or outdated algorithms that don't meet current best practices.`,
        businessImpact: "While not immediately exploitable, these issues increase attack surface and may indicate broader security debt. They also complicate future migrations.",
        recommendation: "Include cryptographic updates in regular maintenance cycles. Upgrade to AES-256, SHA-256+, and current library versions. Remove deprecated algorithms from codebases.",
        complianceFrameworks: ["SOC 2", "ISO 27001", "NIST Cybersecurity Framework"],
        estimatedEffort: "1-3 months per application"
      });
    }

    // Add scanning coverage recommendation if low
    if (totalRepos < 5) {
      priorities.push({
        category: "Limited Cryptographic Visibility",
        severity: "high",
        affectedRepos: 0,
        description: "Only a small number of repositories have been scanned. You may have undiscovered cryptographic vulnerabilities across your organization.",
        businessImpact: "Unknown cryptographic usage creates blind spots in your security posture and makes compliance attestation difficult.",
        recommendation: "Integrate CBOM scanning into CI/CD pipelines for all repositories. Prioritize scanning production applications first, then expand to development and internal tools.",
        complianceFrameworks: ["SBOM/CBOM Requirements", "Executive Order 14028", "NIST SSDF"],
        estimatedEffort: "2-4 weeks for CI/CD integration"
      });
    }

    return priorities.sort((a, b) => {
      const severityOrder = { critical: 0, high: 1, medium: 2 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });
  }, [categorizedScans, repositories, reports]);

  // Compliance framework impact analysis
  const complianceImpact = useMemo(() => {
    const criticalCount = categorizedScans.critical.length;
    const warningCount = categorizedScans.warning.length;
    const pqcEnabled = reports.filter(r => r.hasPqc).length;
    const totalRepos = repositories.length;

    return [
      {
        framework: "NIST PQC Standards",
        status: pqcEnabled > 0 ? (pqcEnabled === totalRepos ? "compliant" : "partial") : "at-risk",
        description: "NIST finalized ML-KEM, ML-DSA, SLH-DSA standards in 2024",
        action: pqcEnabled === totalRepos
          ? "Maintain PQC implementation across all systems"
          : `Adopt PQC in ${totalRepos - pqcEnabled} remaining repositories`,
        deadline: "Federal: 2035, Critical systems: 2030"
      },
      {
        framework: "NSA CNSA 2.0",
        status: criticalCount === 0 ? "compliant" : "at-risk",
        description: "Commercial National Security Algorithm Suite for quantum resistance",
        action: criticalCount > 0
          ? `Migrate ${criticalCount} repositories from vulnerable algorithms`
          : "Continue monitoring for algorithm updates",
        deadline: "Software: 2025, Firmware: 2027, Hardware: 2030"
      },
      {
        framework: "PCI DSS 4.0",
        status: criticalCount === 0 && warningCount === 0 ? "compliant" : (criticalCount > 0 ? "at-risk" : "partial"),
        description: "Payment Card Industry Data Security Standard",
        action: criticalCount > 0
          ? "Address cryptographic vulnerabilities before audit"
          : "Document cryptographic inventory for compliance",
        deadline: "Full enforcement: March 2025"
      },
      {
        framework: "HIPAA Security Rule",
        status: criticalCount === 0 ? "compliant" : "at-risk",
        description: "Healthcare data protection requirements",
        action: criticalCount > 0
          ? "Ensure PHI systems use approved encryption"
          : "Maintain encryption standards documentation",
        deadline: "Ongoing requirement"
      }
    ];
  }, [categorizedScans, repositories, reports]);

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  };

  const getStatusConfig = (score: number) => {
    if (score >= 80) return {
      label: "Passing",
      color: "text-emerald-600",
      bg: "bg-emerald-50",
      border: "border-emerald-200",
      icon: ShieldCheck,
      badge: "bg-emerald-100 text-emerald-700"
    };
    if (score >= 50) return {
      label: "Warning",
      color: "text-amber-600",
      bg: "bg-amber-50",
      border: "border-amber-200",
      icon: ShieldAlert,
      badge: "bg-amber-100 text-amber-700"
    };
    return {
      label: "Critical",
      color: "text-red-600",
      bg: "bg-red-50",
      border: "border-red-200",
      icon: AlertOctagon,
      badge: "bg-red-100 text-red-700"
    };
  };

  // Aggregated stats
  const stats = {
    totalScans: reports.length,
    totalRepos: repositories.length,
    critical: categorizedScans.critical.length,
    warning: categorizedScans.warning.length,
    passing: categorizedScans.passing.length,
    withPqc: reports.filter(r => r.hasPqc).length,
    avgScore: reports.length > 0
      ? Math.round(reports.reduce((sum, r) => sum + r.quantumReadinessScore, 0) / reports.length)
      : 0,
  };

  if (loading) {
    return (
      <AdminLayout title="Cryptographic Scanner" subtitle="Loading...">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      </AdminLayout>
    );
  }

  return (
    <AdminLayout
      title="Cryptographic Scanner"
      subtitle="Organization-wide CBOM analysis and quantum readiness assessment"
      onRefresh={loadData}
      actions={
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm">
            <Download className="h-4 w-4 mr-2" />
            Export Report
          </Button>
          <Button size="sm">
            <ScanLine className="h-4 w-4 mr-2" />
            New Scan
          </Button>
        </div>
      }
    >
      {/* Stats Overview - Clean Card Design */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
        <div className="bg-white border border-slate-200 rounded-xl p-4">
          <div className="text-sm text-slate-500 mb-1">Repositories</div>
          <div className="text-2xl font-bold text-slate-900">{stats.totalRepos}</div>
          <div className="text-xs text-slate-400 mt-1">scanned</div>
        </div>

        <button
          onClick={() => setStatusFilter(statusFilter === "critical" ? "all" : "critical")}
          className={cn(
            "bg-white border rounded-xl p-4 text-left transition-all hover:shadow-md",
            statusFilter === "critical" ? "ring-2 ring-rose-400 border-rose-300" : "border-slate-200"
          )}
        >
          <div className="text-sm text-slate-500 mb-1">Critical</div>
          <div className={cn("text-2xl font-bold", stats.critical > 0 ? "text-rose-600" : "text-slate-300")}>
            {stats.critical}
          </div>
          <div className="text-xs text-rose-500 mt-1">{stats.critical > 0 ? "needs action" : "none"}</div>
        </button>

        <button
          onClick={() => setStatusFilter(statusFilter === "warning" ? "all" : "warning")}
          className={cn(
            "bg-white border rounded-xl p-4 text-left transition-all hover:shadow-md",
            statusFilter === "warning" ? "ring-2 ring-amber-400 border-amber-300" : "border-slate-200"
          )}
        >
          <div className="text-sm text-slate-500 mb-1">Warnings</div>
          <div className={cn("text-2xl font-bold", stats.warning > 0 ? "text-amber-600" : "text-slate-300")}>
            {stats.warning}
          </div>
          <div className="text-xs text-amber-500 mt-1">{stats.warning > 0 ? "review soon" : "none"}</div>
        </button>

        <button
          onClick={() => setStatusFilter(statusFilter === "passing" ? "all" : "passing")}
          className={cn(
            "bg-white border rounded-xl p-4 text-left transition-all hover:shadow-md",
            statusFilter === "passing" ? "ring-2 ring-green-400 border-green-300" : "border-slate-200"
          )}
        >
          <div className="text-sm text-slate-500 mb-1">Passing</div>
          <div className={cn("text-2xl font-bold", stats.passing > 0 ? "text-green-600" : "text-slate-300")}>
            {stats.passing}
          </div>
          <div className="text-xs text-green-500 mt-1">quantum-ready</div>
        </button>

        <div className="bg-white border border-slate-200 rounded-xl p-4">
          <div className="text-sm text-slate-500 mb-1">Avg Score</div>
          <div className={cn(
            "text-2xl font-bold",
            stats.avgScore >= 80 ? "text-green-600" : stats.avgScore >= 50 ? "text-amber-600" : "text-rose-600"
          )}>{stats.avgScore}%</div>
          <div className="text-xs text-slate-400 mt-1">readiness</div>
        </div>
      </div>

      {/* Executive Summary - Compact */}
      {stats.totalRepos > 0 && (stats.critical > 0 || stats.warning > 0) && (
        <div className={cn(
          "rounded-xl border p-4 mb-6 flex items-center gap-4",
          stats.critical > 0
            ? "bg-rose-50 border-rose-200"
            : "bg-amber-50 border-amber-200"
        )}>
          <div className={cn(
            "p-3 rounded-xl shrink-0",
            stats.critical > 0 ? "bg-rose-100" : "bg-amber-100"
          )}>
            {stats.critical > 0 ? (
              <AlertOctagon className="h-6 w-6 text-rose-600" />
            ) : (
              <ShieldAlert className="h-6 w-6 text-amber-600" />
            )}
          </div>
          <div className="flex-1 min-w-0">
            <h3 className={cn(
              "font-semibold",
              stats.critical > 0 ? "text-rose-900" : "text-amber-900"
            )}>
              {stats.critical > 0 ? "Immediate Action Required" : "Attention Needed"}
            </h3>
            <p className="text-sm text-slate-600">
              {stats.critical > 0
                ? `${stats.critical} repositories contain cryptographic vulnerabilities requiring immediate remediation.`
                : `${stats.warning} repositories have hygiene issues that should be addressed.`}
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => toggleSection("insights")}
            className="shrink-0"
          >
            {expandedSections.insights ? "Hide Details" : "View Details"}
            {expandedSections.insights ? <ChevronUp className="h-4 w-4 ml-1" /> : <ChevronDown className="h-4 w-4 ml-1" />}
          </Button>
        </div>
      )}

      {/* Admin Insights Section - Collapsible */}
      {stats.totalRepos > 0 && remediationPriorities.length > 0 && expandedSections.insights && (
        <div className="mb-6 bg-white border border-slate-200 rounded-xl overflow-hidden">
          {/* Section Header */}
          <div className="flex items-center justify-between p-4 border-b border-slate-100 bg-slate-50">
            <h3 className="font-semibold text-slate-900 flex items-center gap-2">
              <Lightbulb className="h-5 w-5 text-amber-500" />
              Detailed Analysis & Recommendations
            </h3>
            <button
              onClick={() => toggleSection("insights")}
              className="text-sm text-slate-500 hover:text-slate-700 flex items-center gap-1"
            >
              Collapse <ChevronUp className="h-4 w-4" />
            </button>
          </div>

          <div className="p-4">
            {/* Tab Navigation */}
            <div className="flex items-center gap-1 mb-4 bg-slate-100 rounded-lg p-1 w-fit">
              <button
                onClick={() => setActiveInsightTab("priorities")}
                className={cn(
                  "px-4 py-2 text-sm font-medium rounded-md transition-all",
                  activeInsightTab === "priorities"
                    ? "bg-white text-slate-900 shadow-sm"
                    : "text-slate-600 hover:text-slate-900"
                )}
              >
                <Target className="h-4 w-4 inline mr-2" />
                Remediation Priorities
              </button>
              <button
                onClick={() => setActiveInsightTab("compliance")}
                className={cn(
                  "px-4 py-2 text-sm font-medium rounded-md transition-all",
                  activeInsightTab === "compliance"
                    ? "bg-white text-slate-900 shadow-sm"
                    : "text-slate-600 hover:text-slate-900"
                )}
              >
                <Shield className="h-4 w-4 inline mr-2" />
                Compliance Impact
              </button>
              <button
                onClick={() => setActiveInsightTab("trends")}
                className={cn(
                  "px-4 py-2 text-sm font-medium rounded-md transition-all",
                  activeInsightTab === "trends"
                    ? "bg-white text-slate-900 shadow-sm"
                    : "text-slate-600 hover:text-slate-900"
                )}
              >
                <BarChart3 className="h-4 w-4 inline mr-2" />
                Risk Breakdown
              </button>
            </div>

          {/* Remediation Priorities Tab */}
          {activeInsightTab === "priorities" && (
            <div className="space-y-4">
              {remediationPriorities.slice(0, showAllPriorities ? undefined : 2).map((priority, idx) => (
                <div key={idx} className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
                  {/* Header */}
                  <div className={cn(
                    "p-5 border-b",
                    priority.severity === "critical"
                      ? "bg-rose-50/50 border-rose-100"
                      : priority.severity === "high"
                        ? "bg-amber-50/50 border-amber-100"
                        : "bg-blue-50/50 border-blue-100"
                  )}>
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <span className="text-lg font-semibold text-slate-900">{priority.category}</span>
                          <span className={cn(
                            "px-2 py-0.5 text-xs font-medium rounded border",
                            priority.severity === "critical"
                              ? "bg-rose-100 text-rose-700 border-rose-200"
                              : priority.severity === "high"
                                ? "bg-amber-100 text-amber-700 border-amber-200"
                                : "bg-blue-100 text-blue-700 border-blue-200"
                          )}>
                            {priority.severity === "critical" ? "Critical Priority" :
                             priority.severity === "high" ? "High Priority" : "Medium Priority"}
                          </span>
                          {priority.affectedRepos > 0 && (
                            <span className="px-2 py-0.5 text-xs font-medium rounded bg-slate-100 text-slate-600">
                              {priority.affectedRepos} {priority.affectedRepos === 1 ? "repository" : "repositories"} affected
                            </span>
                          )}
                        </div>
                        <p className="text-slate-600">{priority.description}</p>
                      </div>
                    </div>
                  </div>

                  {/* Content Grid */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-0 lg:divide-x divide-slate-100">
                    {/* Left: Business Impact */}
                    <div className="p-5 space-y-4">
                      <div>
                        <h4 className="text-sm font-semibold text-slate-700 mb-2 flex items-center gap-2">
                          <AlertTriangle className="h-4 w-4 text-amber-500" />
                          Business Impact
                        </h4>
                        <p className="text-sm text-slate-600 leading-relaxed">{priority.businessImpact}</p>
                      </div>
                      <div>
                        <h4 className="text-sm font-semibold text-slate-700 mb-2 flex items-center gap-2">
                          <Timer className="h-4 w-4 text-slate-400" />
                          Estimated Effort
                        </h4>
                        <p className="text-sm text-slate-600">{priority.estimatedEffort}</p>
                      </div>
                    </div>

                    {/* Right: Recommendation */}
                    <div className="p-5 bg-slate-50/50">
                      <h4 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
                        <Lightbulb className="h-4 w-4 text-green-500" />
                        Recommended Action
                      </h4>
                      <p className="text-sm text-slate-700 leading-relaxed mb-4">{priority.recommendation}</p>

                      <h4 className="text-sm font-semibold text-slate-700 mb-2 flex items-center gap-2">
                        <Shield className="h-4 w-4 text-blue-500" />
                        Affected Compliance Frameworks
                      </h4>
                      <div className="flex flex-wrap gap-2">
                        {priority.complianceFrameworks.map((framework, fIdx) => (
                          <span key={fIdx} className="px-2 py-1 text-xs bg-white border border-slate-200 rounded text-slate-600">
                            {framework}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              ))}

              {remediationPriorities.length > 2 && (
                <button
                  onClick={() => setShowAllPriorities(!showAllPriorities)}
                  className="flex items-center gap-2 text-sm text-blue-600 hover:text-blue-700 font-medium"
                >
                  {showAllPriorities ? (
                    <>
                      <ChevronUp className="h-4 w-4" />
                      Show fewer priorities
                    </>
                  ) : (
                    <>
                      <ChevronDown className="h-4 w-4" />
                      Show {remediationPriorities.length - 2} more priorities
                    </>
                  )}
                </button>
              )}
            </div>
          )}

          {/* Compliance Impact Tab */}
          {activeInsightTab === "compliance" && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {complianceImpact.map((item, idx) => (
                <div key={idx} className="bg-white border border-slate-200 rounded-xl p-5">
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <h4 className="font-semibold text-slate-900">{item.framework}</h4>
                      <p className="text-sm text-slate-500 mt-1">{item.description}</p>
                    </div>
                    <span className={cn(
                      "px-2 py-1 text-xs font-medium rounded",
                      item.status === "compliant"
                        ? "bg-green-100 text-green-700"
                        : item.status === "partial"
                          ? "bg-amber-100 text-amber-700"
                          : "bg-rose-100 text-rose-700"
                    )}>
                      {item.status === "compliant" ? "Compliant" : item.status === "partial" ? "Partial" : "At Risk"}
                    </span>
                  </div>
                  <div className="pt-3 border-t border-slate-100">
                    <div className="flex items-start gap-2 mb-2">
                      <ArrowRight className="h-4 w-4 text-blue-500 mt-0.5 shrink-0" />
                      <p className="text-sm text-slate-700">{item.action}</p>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-slate-500">
                      <Clock className="h-3 w-3" />
                      <span>{item.deadline}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Risk Breakdown Tab */}
          {activeInsightTab === "trends" && (
            <div className="bg-white border border-slate-200 rounded-xl p-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Risk Distribution */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-700 mb-4">Risk Distribution</h4>
                  <div className="space-y-3">
                    <div>
                      <div className="flex items-center justify-between text-sm mb-1">
                        <span className="text-rose-600 font-medium">Critical</span>
                        <span className="text-slate-600">{stats.critical} repos</span>
                      </div>
                      <div className="h-3 bg-slate-100 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-rose-500 rounded-full"
                          style={{ width: stats.totalRepos > 0 ? `${(stats.critical / stats.totalRepos) * 100}%` : "0%" }}
                        />
                      </div>
                    </div>
                    <div>
                      <div className="flex items-center justify-between text-sm mb-1">
                        <span className="text-amber-600 font-medium">Warning</span>
                        <span className="text-slate-600">{stats.warning} repos</span>
                      </div>
                      <div className="h-3 bg-slate-100 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-amber-500 rounded-full"
                          style={{ width: stats.totalRepos > 0 ? `${(stats.warning / stats.totalRepos) * 100}%` : "0%" }}
                        />
                      </div>
                    </div>
                    <div>
                      <div className="flex items-center justify-between text-sm mb-1">
                        <span className="text-green-600 font-medium">Passing</span>
                        <span className="text-slate-600">{stats.passing} repos</span>
                      </div>
                      <div className="h-3 bg-slate-100 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-green-500 rounded-full"
                          style={{ width: stats.totalRepos > 0 ? `${(stats.passing / stats.totalRepos) * 100}%` : "0%" }}
                        />
                      </div>
                    </div>
                  </div>
                </div>

                {/* PQC Adoption */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-700 mb-4">PQC Adoption Rate</h4>
                  <div className="flex items-center gap-4">
                    <div className="relative w-24 h-24">
                      <svg className="w-full h-full transform -rotate-90">
                        <circle
                          cx="48"
                          cy="48"
                          r="40"
                          fill="none"
                          stroke="#e2e8f0"
                          strokeWidth="8"
                        />
                        <circle
                          cx="48"
                          cy="48"
                          r="40"
                          fill="none"
                          stroke="#8b5cf6"
                          strokeWidth="8"
                          strokeDasharray={`${stats.totalRepos > 0 ? (stats.withPqc / stats.totalRepos) * 251.2 : 0} 251.2`}
                          strokeLinecap="round"
                        />
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center">
                        <span className="text-xl font-bold text-purple-600">
                          {stats.totalRepos > 0 ? Math.round((stats.withPqc / stats.totalRepos) * 100) : 0}%
                        </span>
                      </div>
                    </div>
                    <div>
                      <p className="text-2xl font-bold text-slate-900">{stats.withPqc}</p>
                      <p className="text-sm text-slate-500">of {stats.totalRepos} repos</p>
                      <p className="text-sm text-slate-500">with PQC enabled</p>
                    </div>
                  </div>
                </div>

                {/* Quick Metrics */}
                <div>
                  <h4 className="text-sm font-semibold text-slate-700 mb-4">Key Metrics</h4>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-slate-600">Total Scans</span>
                      <span className="text-lg font-semibold text-slate-900">{stats.totalScans}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-slate-600">Avg Readiness Score</span>
                      <span className={cn(
                        "text-lg font-semibold",
                        stats.avgScore >= 80 ? "text-green-600" : stats.avgScore >= 50 ? "text-amber-600" : "text-rose-600"
                      )}>{stats.avgScore}%</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-slate-600">Quantum Ready</span>
                      <span className="text-lg font-semibold text-green-600">
                        {stats.totalRepos > 0 ? Math.round((stats.passing / stats.totalRepos) * 100) : 0}%
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
          </div>
        </div>
      )}

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Repository List - 2 columns */}
        <div className="lg:col-span-2">
          {/* Toolbar */}
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search repositories..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9 pr-4 py-2 text-sm border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent w-64"
                />
              </div>
              {statusFilter !== "all" && (
                <button
                  onClick={() => setStatusFilter("all")}
                  className="flex items-center gap-1 px-2 py-1 text-xs bg-slate-100 text-slate-600 rounded-full hover:bg-slate-200"
                >
                  <XCircle className="h-3 w-3" />
                  Clear filter
                </button>
              )}
            </div>
            <div className="text-sm text-slate-500">
              {filteredReports.length} of {repositories.length} repositories
            </div>
          </div>

          {/* Repository Cards */}
          <div className="space-y-3">
            {filteredReports.length > 0 ? (
              filteredReports.map((repo) => {
                const status = getStatusConfig(repo.quantumReadinessScore);
                const StatusIcon = status.icon;

                return (
                  <Link
                    key={repo.id}
                    href={`/cbom/${repo.scanRef || repo.id}`}
                    className={cn(
                      "block p-4 bg-white border rounded-xl hover:shadow-md transition-all group",
                      status.border
                    )}
                  >
                    <div className="flex items-start gap-4">
                      {/* Status Icon */}
                      <div className={cn("p-3 rounded-xl", status.bg)}>
                        <StatusIcon className={cn("h-6 w-6", status.color)} />
                      </div>

                      {/* Main Content */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start justify-between">
                          <div>
                            <h3 className="font-semibold text-slate-900 group-hover:text-blue-600 transition-colors flex items-center gap-2">
                              <FolderGit2 className="h-4 w-4 text-slate-400" />
                              {repo.name}
                              {repo.hasPqc && (
                                <span className="px-1.5 py-0.5 text-[10px] font-medium bg-purple-100 text-purple-700 rounded">
                                  PQC
                                </span>
                              )}
                            </h3>
                            <div className="flex items-center gap-3 mt-1 text-sm text-slate-500">
                              {repo.gitBranch && (
                                <span className="flex items-center gap-1">
                                  <GitBranch className="h-3 w-3" />
                                  {repo.gitBranch}
                                </span>
                              )}
                              {repo.gitCommit && (
                                <span className="flex items-center gap-1 font-mono text-xs">
                                  <GitCommit className="h-3 w-3" />
                                  {repo.gitCommit.substring(0, 7)}
                                </span>
                              )}
                              <span className="flex items-center gap-1">
                                <Clock className="h-3 w-3" />
                                {formatDate(repo.scannedAt)}
                              </span>
                            </div>
                          </div>

                          {/* Score Badge */}
                          <div className="text-right">
                            <div
                              className={cn("text-2xl font-bold tabular-nums", status.color)}
                            >
                              {repo.quantumReadinessScore}%
                            </div>
                            <div className={cn("text-xs font-medium", status.color)}>
                              {status.label}
                            </div>
                          </div>
                        </div>

                        {/* Stats Row */}
                        <div className="flex items-center gap-6 mt-3 pt-3 border-t border-slate-100">
                          <div className="flex items-center gap-2 text-sm">
                            <Package className="h-4 w-4 text-slate-400" />
                            <span className="text-slate-600">{repo.libraryCount} libraries</span>
                          </div>
                          <div className="flex items-center gap-2 text-sm">
                            <Lock className="h-4 w-4 text-slate-400" />
                            <span className="text-slate-600">{repo.algorithmCount} algorithms</span>
                          </div>
                          {repo.scanCount > 1 && (
                            <div className="flex items-center gap-2 text-sm">
                              <RefreshCw className="h-4 w-4 text-slate-400" />
                              <span className="text-slate-600">{repo.scanCount} scans</span>
                            </div>
                          )}
                          <div className="ml-auto">
                            <span className="text-sm text-blue-600 font-medium flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                              View Details <ArrowUpRight className="h-3 w-3" />
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </Link>
                );
              })
            ) : (
              <div className="text-center py-16 bg-slate-50 rounded-xl border-2 border-dashed border-slate-200">
                <Radar className="h-12 w-12 text-slate-300 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-slate-900 mb-2">
                  {reports.length === 0 ? "No scans yet" : "No matching repositories"}
                </h3>
                <p className="text-slate-500 max-w-md mx-auto mb-6">
                  {reports.length === 0
                    ? "Run your first CBOM scan to discover cryptographic usage."
                    : "Try adjusting your search or filter."}
                </p>
                {reports.length === 0 && (
                  <div className="bg-slate-100 border border-slate-200 rounded-lg p-4 max-w-sm mx-auto text-left font-mono text-sm">
                    <div className="text-slate-500 text-xs mb-2"># Scan a project</div>
                    <div className="text-slate-700">cryptoserve scan ./my-project</div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Sidebar - 1 column */}
        <div className="space-y-6">
          {/* Quick Stats */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-slate-600">Overview</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500">Total Scans</span>
                <span className="text-lg font-semibold text-slate-900">{stats.totalScans}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500">Repositories</span>
                <span className="text-lg font-semibold text-slate-900">{stats.totalRepos}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500">PQC Enabled</span>
                <span className="text-lg font-semibold text-purple-600">{stats.withPqc}</span>
              </div>
              <div className="h-px bg-slate-100" />
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500">Quantum Ready</span>
                <span className="text-lg font-semibold text-emerald-600">
                  {stats.totalRepos > 0 ? Math.round((stats.passing / stats.totalRepos) * 100) : 0}%
                </span>
              </div>
            </CardContent>
          </Card>

          {/* Recent Activity */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-slate-600 flex items-center gap-2">
                <Clock className="h-4 w-4" />
                Recent Scans
              </CardTitle>
            </CardHeader>
            <CardContent>
              {recentScans.length > 0 ? (
                <div className="space-y-3">
                  {recentScans.map((scan) => {
                    const status = getStatusConfig(scan.quantumReadinessScore);
                    return (
                      <Link
                        key={scan.id}
                        href={`/cbom/${scan.scanRef || scan.id}`}
                        className="flex items-center gap-3 p-2 -mx-2 rounded-lg hover:bg-slate-50 transition-colors"
                      >
                        <div className={cn("w-2 h-2 rounded-full", status.bg.replace("bg-", "bg-").replace("50", "500"))} />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm font-medium text-slate-900 truncate">
                            {scan.scanRef || scan.scanName || scan.gitRepo || `Scan #${scan.id}`}
                          </div>
                          <div className="text-xs text-slate-500">
                            {formatDate(scan.scannedAt)}
                          </div>
                        </div>
                        <div className={cn("text-sm font-medium tabular-nums", status.color)}>
                          {scan.quantumReadinessScore}%
                        </div>
                      </Link>
                    );
                  })}
                </div>
              ) : (
                <div className="text-center py-6 text-slate-500 text-sm">
                  No recent scans
                </div>
              )}
            </CardContent>
          </Card>

          {/* Quick Actions */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium text-slate-600">Actions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <Link
                href="/admin/compliance"
                className="flex items-center gap-3 p-2 -mx-2 rounded-lg hover:bg-slate-50 transition-colors"
              >
                <div className="p-2 bg-blue-50 rounded-lg">
                  <Shield className="h-4 w-4 text-blue-600" />
                </div>
                <div className="flex-1">
                  <div className="text-sm font-medium text-slate-900">Compliance Report</div>
                  <div className="text-xs text-slate-500">Review framework status</div>
                </div>
                <ChevronRight className="h-4 w-4 text-slate-400" />
              </Link>
              <Link
                href="/admin/security"
                className="flex items-center gap-3 p-2 -mx-2 rounded-lg hover:bg-slate-50 transition-colors"
              >
                <div className="p-2 bg-amber-50 rounded-lg">
                  <AlertTriangle className="h-4 w-4 text-amber-600" />
                </div>
                <div className="flex-1">
                  <div className="text-sm font-medium text-slate-900">Security Center</div>
                  <div className="text-xs text-slate-500">View all vulnerabilities</div>
                </div>
                <ChevronRight className="h-4 w-4 text-slate-400" />
              </Link>
              <Link
                href="/admin/policies"
                className="flex items-center gap-3 p-2 -mx-2 rounded-lg hover:bg-slate-50 transition-colors"
              >
                <div className="p-2 bg-purple-50 rounded-lg">
                  <FileText className="h-4 w-4 text-purple-600" />
                </div>
                <div className="flex-1">
                  <div className="text-sm font-medium text-slate-900">Scan Policies</div>
                  <div className="text-xs text-slate-500">Configure requirements</div>
                </div>
                <ChevronRight className="h-4 w-4 text-slate-400" />
              </Link>
            </CardContent>
          </Card>
        </div>
      </div>
    </AdminLayout>
  );
}
