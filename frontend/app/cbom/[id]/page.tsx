"use client";

import { useEffect, useState, useMemo } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft, Shield, ShieldAlert, ShieldCheck, ShieldX,
  AlertTriangle, CheckCircle, XCircle, Package, Lock, Unlock,
  GitBranch, GitCommit, FileCode, Clock, Download, ExternalLink,
  ChevronDown, ChevronUp, Info, Zap, Target, TrendingUp,
  ArrowRight, BookOpen, Timer, Lightbulb, Copy, Check
} from "lucide-react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api, CBOMReportDetail } from "@/lib/api";

type FindingCategory = "critical" | "warning" | "info";

interface Finding {
  type: "library" | "algorithm";
  name: string;
  category: string;
  issue: string;
  severity: FindingCategory;
  recommendation?: string;
}

export default function CBOMDetailPage() {
  const params = useParams();
  const [report, setReport] = useState<CBOMReportDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    critical: true,
    warning: true,
    info: false,
    libraries: true,
    algorithms: false,
  });

  useEffect(() => {
    const reportIdOrRef = params.id as string;
    if (!reportIdOrRef) {
      setError("Invalid report ID");
      setLoading(false);
      return;
    }

    api.getCBOMReport(reportIdOrRef)
      .then(setReport)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, [params.id]);

  // Quantum remediation mappings - detailed guidance for each vulnerability type
  const quantumRemediationMap: Record<string, {
    issue: string;
    explanation: string;
    impact: string;
    steps: string[];
    alternatives: string[];
    resources?: string[];
    urgency: "immediate" | "short-term" | "medium-term";
  }> = {
    "RSA": {
      issue: "RSA encryption is vulnerable to Shor's algorithm",
      explanation: "RSA relies on the difficulty of factoring large prime numbers. Quantum computers running Shor's algorithm can factor these efficiently, breaking RSA encryption.",
      impact: "All data encrypted with RSA could be decrypted by a sufficiently powerful quantum computer. This affects key exchange, digital signatures, and data encryption.",
      steps: [
        "1. Inventory all systems using RSA encryption",
        "2. Prioritize migration based on data sensitivity and retention period",
        "3. Implement hybrid approach: RSA + PQC algorithm (e.g., Kyber)",
        "4. Update key sizes to 4096-bit minimum as interim measure",
        "5. Plan full migration to CRYSTALS-Kyber or CRYSTALS-Dilithium"
      ],
      alternatives: ["CRYSTALS-Kyber (key encapsulation)", "CRYSTALS-Dilithium (signatures)", "SPHINCS+ (stateless signatures)"],
      resources: ["NIST PQC Standards", "Open Quantum Safe (liboqs)", "AWS KMS PQC support"],
      urgency: "short-term"
    },
    "ECDSA": {
      issue: "ECDSA signatures are vulnerable to quantum attacks",
      explanation: "Elliptic Curve Digital Signature Algorithm is susceptible to Shor's algorithm, which can solve the discrete logarithm problem efficiently.",
      impact: "Digital signatures can be forged, compromising authentication, code signing, and document integrity verification.",
      steps: [
        "1. Identify all ECDSA signing operations in your codebase",
        "2. Implement hybrid signatures (ECDSA + Dilithium)",
        "3. Update certificate chains to support PQC signatures",
        "4. Migrate to CRYSTALS-Dilithium for new signatures"
      ],
      alternatives: ["CRYSTALS-Dilithium", "Falcon", "SPHINCS+"],
      urgency: "short-term"
    },
    "ECDH": {
      issue: "ECDH key exchange is quantum-vulnerable",
      explanation: "Elliptic Curve Diffie-Hellman is vulnerable to quantum attacks that can solve the discrete logarithm problem.",
      impact: "Key exchanges can be broken, allowing decryption of TLS sessions and other encrypted communications.",
      steps: [
        "1. Enable hybrid key exchange in TLS 1.3 (X25519Kyber768)",
        "2. Update TLS libraries to support PQC key encapsulation",
        "3. Configure servers to prefer hybrid cipher suites"
      ],
      alternatives: ["X25519Kyber768 (hybrid)", "CRYSTALS-Kyber", "SIKE"],
      urgency: "short-term"
    },
    "AES-128": {
      issue: "AES-128 has reduced security margin against Grover's algorithm",
      explanation: "Grover's algorithm can search unsorted databases in O(√N) time, effectively halving the security of symmetric keys.",
      impact: "128-bit keys provide only 64-bit security against quantum attacks. While not immediately broken, security margin is reduced.",
      steps: [
        "1. Upgrade to AES-256 for all new implementations",
        "2. Update existing systems during regular key rotation",
        "3. No immediate migration required for short-lived data"
      ],
      alternatives: ["AES-256", "ChaCha20-Poly1305"],
      urgency: "medium-term"
    },
    "SHA-1": {
      issue: "SHA-1 is cryptographically broken and quantum-vulnerable",
      explanation: "SHA-1 already has known collision attacks. Quantum computers further weaken its security using Grover's algorithm.",
      impact: "Hash collisions enable signature forgery, certificate spoofing, and data integrity attacks.",
      steps: [
        "1. Immediately migrate to SHA-256 or SHA-3",
        "2. Update all certificate chains to use SHA-256+",
        "3. Replace HMAC-SHA1 with HMAC-SHA256"
      ],
      alternatives: ["SHA-256", "SHA-384", "SHA-3", "BLAKE3"],
      urgency: "immediate"
    },
    "MD5": {
      issue: "MD5 is completely broken - do not use",
      explanation: "MD5 has been broken since 2004. Collisions can be generated in seconds. Quantum attacks make it even weaker.",
      impact: "Critical security vulnerability. Any use of MD5 for security purposes is exploitable today.",
      steps: [
        "1. IMMEDIATE: Replace all MD5 usage with SHA-256 minimum",
        "2. Audit codebase for hidden MD5 dependencies",
        "3. Update any legacy systems still using MD5"
      ],
      alternatives: ["SHA-256", "SHA-3", "BLAKE3"],
      urgency: "immediate"
    },
    "DES": {
      issue: "DES is obsolete and easily broken",
      explanation: "56-bit keys can be brute-forced in hours on modern hardware. Quantum computers break it instantly.",
      impact: "All DES-encrypted data should be considered unprotected.",
      steps: [
        "1. IMMEDIATE: Replace DES with AES-256",
        "2. Re-encrypt any sensitive data currently using DES",
        "3. Update legacy systems and protocols"
      ],
      alternatives: ["AES-256", "ChaCha20-Poly1305"],
      urgency: "immediate"
    },
    "3DES": {
      issue: "Triple DES is deprecated and quantum-vulnerable",
      explanation: "3DES has known weaknesses (Sweet32 attack) and only provides 112-bit security at best.",
      impact: "Should not be used for new systems. Existing usage should be migrated.",
      steps: [
        "1. Plan migration to AES-256 within 6 months",
        "2. Disable 3DES in TLS configurations",
        "3. Update payment systems (PCI DSS compliance)"
      ],
      alternatives: ["AES-256", "ChaCha20-Poly1305"],
      urgency: "short-term"
    },
    "default": {
      issue: "This cryptographic component may be vulnerable to quantum attacks",
      explanation: "Many classical cryptographic algorithms are vulnerable to attacks from quantum computers using Shor's or Grover's algorithms.",
      impact: "Data encrypted or signed with vulnerable algorithms may be at risk as quantum computing advances.",
      steps: [
        "1. Assess the algorithm's quantum vulnerability",
        "2. Check NIST recommendations for quantum-safe alternatives",
        "3. Plan migration to post-quantum cryptography"
      ],
      alternatives: ["CRYSTALS-Kyber", "CRYSTALS-Dilithium", "SPHINCS+", "AES-256"],
      resources: ["NIST Post-Quantum Cryptography", "Open Quantum Safe project"],
      urgency: "medium-term"
    }
  };

  // Helper to get remediation info
  const getRemediationInfo = (name: string, category: string): {
    info: typeof quantumRemediationMap["RSA"];
    isSpecific: boolean;
  } => {
    // Check for exact match first
    if (quantumRemediationMap[name]) {
      return { info: quantumRemediationMap[name], isSpecific: true };
    }
    // Check for category-based match
    if (name.includes("RSA")) return { info: quantumRemediationMap["RSA"], isSpecific: true };
    if (name.includes("ECDSA")) return { info: quantumRemediationMap["ECDSA"], isSpecific: true };
    if (name.includes("ECDH") || name.includes("Diffie")) return { info: quantumRemediationMap["ECDH"], isSpecific: true };
    if (name.includes("SHA-1") || name === "SHA1") return { info: quantumRemediationMap["SHA-1"], isSpecific: true };
    if (name.includes("MD5")) return { info: quantumRemediationMap["MD5"], isSpecific: true };
    if (name === "DES" || name.includes("DES-")) return { info: quantumRemediationMap["DES"], isSpecific: true };
    if (name.includes("3DES") || name.includes("Triple")) return { info: quantumRemediationMap["3DES"], isSpecific: true };
    if (name.includes("AES-128") || name.includes("AES128")) return { info: quantumRemediationMap["AES-128"], isSpecific: true };

    return { info: quantumRemediationMap["default"], isSpecific: false };
  };

  // Process findings from libraries and algorithms
  const findings = useMemo<Finding[]>(() => {
    if (!report) return [];

    const items: Finding[] = [];

    // Process libraries for issues
    for (const lib of report.libraries) {
      const libData = lib as Record<string, unknown>;
      const quantumRisk = (libData.quantumRisk || libData.quantum_risk || "none") as string;
      const isDeprecated = libData.isDeprecated || libData.is_deprecated;
      const libName = libData.name as string;
      const libCategory = libData.category as string;

      if (quantumRisk === "critical" || quantumRisk === "high") {
        const { info: remediation } = getRemediationInfo(libName, libCategory);
        items.push({
          type: "library",
          name: libName,
          category: libCategory,
          issue: remediation.issue,
          severity: "critical",
          recommendation: remediation.steps[0]
        });
      }

      if (isDeprecated) {
        items.push({
          type: "library",
          name: libName,
          category: libCategory,
          issue: "Deprecated library - may contain known vulnerabilities",
          severity: "warning",
          recommendation: "Update to latest version or replace with actively maintained alternative"
        });
      }
    }

    return items;
  }, [report]);

  const criticalFindings = findings.filter(f => f.severity === "critical");
  const warningFindings = findings.filter(f => f.severity === "warning");
  const infoFindings = findings.filter(f => f.severity === "info");

  // Calculate scan status
  const getStatus = () => {
    if (!report) return { label: "Unknown", color: "gray", icon: Shield };
    const score = report.quantumReadinessScore;
    if (score >= 80) return { label: "Passing", color: "emerald", icon: ShieldCheck };
    if (score >= 50) return { label: "Warning", color: "amber", icon: ShieldAlert };
    return { label: "Critical", color: "red", icon: ShieldX };
  };

  const status = getStatus();

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString("en-US", {
      weekday: "short",
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit"
    });
  };

  const toggleSection = (key: string) => {
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const handleDownloadCBOM = () => {
    if (!report?.cbomData) return;

    const blob = new Blob([JSON.stringify(report.cbomData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cbom-${report.id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="flex flex-col items-center justify-center py-24">
          <div className="relative">
            <div className="h-16 w-16 rounded-full border-4 border-slate-200"></div>
            <div className="absolute top-0 left-0 h-16 w-16 rounded-full border-4 border-transparent border-t-blue-500 animate-spin"></div>
          </div>
          <p className="mt-4 text-slate-500">Loading scan report...</p>
        </div>
      </DashboardLayout>
    );
  }

  if (error || !report) {
    return (
      <DashboardLayout>
        <div className="max-w-2xl mx-auto py-12">
          <Link href="/cbom" className="inline-flex items-center text-sm text-slate-600 hover:text-slate-900 mb-8">
            <ArrowLeft className="h-4 w-4 mr-1" />
            Back to scans
          </Link>
          <div className="bg-red-50 border border-red-200 rounded-lg p-8 text-center">
            <XCircle className="h-12 w-12 mx-auto text-red-400 mb-4" />
            <h3 className="text-lg font-medium text-red-900 mb-2">Scan Not Found</h3>
            <p className="text-red-700">{error || "The requested CBOM report could not be found."}</p>
          </div>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="max-w-7xl mx-auto px-2">
        {/* Back link */}
        <Link href="/cbom" className="inline-flex items-center text-sm text-slate-600 hover:text-slate-900 mb-6">
          <ArrowLeft className="h-4 w-4 mr-1" />
          Back to scans
        </Link>

        {/* Status Header */}
        <div className="rounded-xl border border-slate-200 bg-white mb-6">
          <div className="p-6">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-6">
              {/* Left: Status and Score */}
              <div className="flex items-center gap-6">
                <div className={`p-4 rounded-xl ${
                  status.color === "emerald" ? "bg-slate-100" :
                  status.color === "amber" ? "bg-slate-100" :
                  "bg-slate-100"
                }`}>
                  <status.icon className={`h-10 w-10 ${
                    status.color === "emerald" ? "text-green-600" :
                    status.color === "amber" ? "text-amber-600" :
                    "text-rose-600"
                  }`} />
                </div>
                <div>
                  <div className="flex items-center gap-3 mb-1">
                    <span className={`text-4xl font-bold ${
                      status.color === "emerald" ? "text-green-700" :
                      status.color === "amber" ? "text-amber-700" :
                      "text-rose-700"
                    }`}>
                      {report.quantumReadinessScore}%
                    </span>
                    <span className={`px-3 py-1 rounded-full text-sm font-medium border ${
                      status.color === "emerald" ? "border-green-200 text-green-700 bg-white" :
                      status.color === "amber" ? "border-amber-200 text-amber-700 bg-white" :
                      "border-rose-200 text-rose-700 bg-white"
                    }`}>
                      {status.label}
                    </span>
                  </div>
                  <p className="text-slate-500 text-sm">Quantum Readiness Score</p>
                </div>
              </div>

              {/* Right: Actions */}
              <div className="flex items-center gap-3">
                {report.cbomData && (
                  <Button
                    variant="outline"
                    onClick={handleDownloadCBOM}
                  >
                    <Download className="h-4 w-4 mr-2" />
                    Export CBOM
                  </Button>
                )}
              </div>
            </div>

            {/* Scan Info */}
            <div className="mt-6 pt-6 border-t border-slate-200">
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm text-slate-500">
                <div className="flex items-center gap-2">
                  <FileCode className="h-4 w-4" />
                  <span className="font-medium text-slate-700">
                    {report.scanName || report.scanPath || `Scan #${report.id}`}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <Clock className="h-4 w-4" />
                  <span>{formatDate(report.scannedAt)}</span>
                </div>
                {report.git.repo && (
                  <div className="flex items-center gap-2">
                    <GitBranch className="h-4 w-4" />
                    <span>{report.git.repo}</span>
                  </div>
                )}
                {report.git.branch && (
                  <span className="px-2 py-0.5 rounded bg-slate-100 font-mono text-xs text-slate-600">
                    {report.git.branch}
                  </span>
                )}
                {report.git.commit && (
                  <div className="flex items-center gap-1">
                    <GitCommit className="h-4 w-4" />
                    <span className="font-mono text-xs">{report.git.commit.slice(0, 7)}</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Metrics Row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-white rounded-lg border border-slate-200 p-4">
            <div className="flex items-center justify-between mb-2">
              <Package className="h-5 w-5 text-slate-400" />
              <span className="text-2xl font-bold text-slate-900">{report.metrics.libraryCount}</span>
            </div>
            <p className="text-sm text-slate-600">Libraries Detected</p>
          </div>
          <div className="bg-white rounded-lg border border-slate-200 p-4">
            <div className="flex items-center justify-between mb-2">
              <Lock className="h-5 w-5 text-slate-400" />
              <span className="text-2xl font-bold text-slate-900">{report.metrics.algorithmCount}</span>
            </div>
            <p className="text-sm text-slate-600">Algorithms Found</p>
          </div>
          <div className="bg-white rounded-lg border border-slate-200 p-4 group relative">
            <div className="flex items-center justify-between mb-2">
              <ShieldCheck className="h-5 w-5 text-emerald-500" />
              <span className="text-2xl font-bold text-emerald-600">{report.metrics.quantumSafeCount}</span>
            </div>
            <p className="text-sm text-slate-600">Quantum Safe</p>
            <p className="text-xs text-slate-400 mt-1">Libraries resistant to quantum attacks</p>
          </div>
          <div className="bg-white rounded-lg border border-slate-200 p-4 group relative">
            <div className="flex items-center justify-between mb-2">
              <ShieldX className="h-5 w-5 text-red-500" />
              <span className="text-2xl font-bold text-red-600">{report.metrics.quantumVulnerableCount}</span>
            </div>
            <p className="text-sm text-slate-600">Quantum Vulnerable</p>
            <p className="text-xs text-slate-400 mt-1">Libraries at risk from quantum computers</p>
          </div>
        </div>

        {/* PQC Status */}
        <div className="rounded-lg border border-slate-200 p-4 mb-6 flex items-center gap-4 bg-white">
          {report.metrics.hasPqc ? (
            <>
              <div className="p-2 rounded-full bg-slate-100">
                <Zap className="h-5 w-5 text-emerald-600" />
              </div>
              <div>
                <p className="font-medium text-slate-900">Post-Quantum Cryptography Detected</p>
                <p className="text-sm text-slate-600">This codebase includes PQC libraries for quantum-resistant encryption.</p>
              </div>
            </>
          ) : (
            <>
              <div className="p-2 rounded-full bg-slate-100">
                <Target className="h-5 w-5 text-amber-600" />
              </div>
              <div>
                <p className="font-medium text-slate-900">No Post-Quantum Cryptography Found</p>
                <p className="text-sm text-slate-600">Consider adopting PQC libraries to prepare for quantum computing threats.</p>
              </div>
            </>
          )}
        </div>

        {/* Findings Sections */}
        {criticalFindings.length > 0 && (
          <div className="mb-6">
            <button
              onClick={() => toggleSection("critical")}
              className="w-full flex items-center justify-between p-4 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors"
            >
              <div className="flex items-center gap-3">
                <XCircle className="h-5 w-5 text-rose-600" />
                <span className="font-medium text-slate-900">
                  Critical Issues ({criticalFindings.length})
                </span>
              </div>
              {expandedSections.critical ? (
                <ChevronUp className="h-5 w-5 text-slate-500" />
              ) : (
                <ChevronDown className="h-5 w-5 text-slate-500" />
              )}
            </button>
            {expandedSections.critical && (
              <div className="mt-3 space-y-4">
                {criticalFindings.map((finding, idx) => {
                  const { info: remediation, isSpecific } = getRemediationInfo(finding.name, finding.category);
                  const urgencyColors = {
                    "immediate": "bg-rose-100 text-rose-700 border-rose-200",
                    "short-term": "bg-amber-100 text-amber-700 border-amber-200",
                    "medium-term": "bg-blue-100 text-blue-700 border-blue-200"
                  };

                  return (
                    <div key={idx} className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
                      {/* Header */}
                      <div className="p-5 border-b border-slate-100">
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1">
                            <div className="flex items-center gap-3 mb-2">
                              <span className="text-lg font-semibold text-slate-900">{finding.name}</span>
                              <Badge variant="outline" className="text-xs">{finding.category}</Badge>
                              <span className={`px-2 py-0.5 text-xs font-medium rounded border ${urgencyColors[remediation.urgency]}`}>
                                <Timer className="h-3 w-3 inline mr-1" />
                                {remediation.urgency === "immediate" ? "Fix Immediately" :
                                 remediation.urgency === "short-term" ? "Fix Within 3-6 Months" :
                                 "Plan Migration"}
                              </span>
                            </div>
                            <p className="text-rose-600 font-medium">{remediation.issue}</p>
                          </div>
                        </div>
                      </div>

                      {/* Content Grid */}
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-0 lg:divide-x divide-slate-100">
                        {/* Left: Why & Impact */}
                        <div className="p-5 space-y-4">
                          <div>
                            <h4 className="text-sm font-semibold text-slate-700 mb-2 flex items-center gap-2">
                              <BookOpen className="h-4 w-4 text-slate-400" />
                              Why is this vulnerable?
                            </h4>
                            <p className="text-sm text-slate-600 leading-relaxed">{remediation.explanation}</p>
                          </div>
                          <div>
                            <h4 className="text-sm font-semibold text-slate-700 mb-2 flex items-center gap-2">
                              <AlertTriangle className="h-4 w-4 text-amber-500" />
                              Security Impact
                            </h4>
                            <p className="text-sm text-slate-600 leading-relaxed">{remediation.impact}</p>
                          </div>
                        </div>

                        {/* Right: Migration Steps - only show if we have specific remediation */}
                        {isSpecific ? (
                          <div className="p-5 bg-slate-50/50">
                            <h4 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
                              <TrendingUp className="h-4 w-4 text-green-500" />
                              Migration Steps
                            </h4>
                            <ol className="space-y-2">
                              {remediation.steps.map((step, stepIdx) => (
                                <li key={stepIdx} className="flex items-start gap-3 text-sm">
                                  <span className="flex-shrink-0 w-5 h-5 rounded-full bg-green-100 text-green-700 flex items-center justify-center text-xs font-medium">
                                    {stepIdx + 1}
                                  </span>
                                  <span className="text-slate-700">{step.replace(/^\d+\.\s*/, "")}</span>
                                </li>
                              ))}
                            </ol>
                          </div>
                        ) : (
                          <div className="p-5 bg-slate-50/50">
                            <h4 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
                              <Info className="h-4 w-4 text-blue-500" />
                              Next Steps
                            </h4>
                            <p className="text-sm text-slate-600 mb-3">
                              This algorithm may be quantum-vulnerable. We recommend:
                            </p>
                            <ol className="space-y-2">
                              <li className="flex items-start gap-3 text-sm">
                                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center text-xs font-medium">1</span>
                                <span className="text-slate-700">Research this algorithm&apos;s quantum security status</span>
                              </li>
                              <li className="flex items-start gap-3 text-sm">
                                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-100 text-blue-700 flex items-center justify-center text-xs font-medium">2</span>
                                <span className="text-slate-700">Consult NIST PQC standards for approved alternatives</span>
                              </li>
                            </ol>
                          </div>
                        )}
                      </div>

                      {/* Footer: Recommended Alternatives */}
                      <div className="p-5 border-t border-slate-100 bg-white">
                        <h4 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
                          <Lightbulb className="h-4 w-4 text-slate-500" />
                          Recommended Alternatives
                        </h4>
                        <div className="flex flex-wrap gap-2">
                          {remediation.alternatives.map((alt, altIdx) => (
                            <span key={altIdx} className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-700 font-medium">
                              <ArrowRight className="h-3 w-3" />
                              {alt}
                            </span>
                          ))}
                        </div>
                        {remediation.resources && (
                          <div className="mt-3 flex flex-wrap gap-2">
                            {remediation.resources.map((resource, resIdx) => (
                              <span key={resIdx} className="text-xs text-slate-500 bg-white px-2 py-1 rounded border border-slate-200">
                                {resource}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {warningFindings.length > 0 && (
          <div className="mb-6">
            <button
              onClick={() => toggleSection("warning")}
              className="w-full flex items-center justify-between p-4 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition-colors"
            >
              <div className="flex items-center gap-3">
                <AlertTriangle className="h-5 w-5 text-amber-600" />
                <span className="font-medium text-slate-900">
                  Warnings ({warningFindings.length})
                </span>
              </div>
              {expandedSections.warning ? (
                <ChevronUp className="h-5 w-5 text-slate-500" />
              ) : (
                <ChevronDown className="h-5 w-5 text-slate-500" />
              )}
            </button>
            {expandedSections.warning && (
              <div className="mt-3 space-y-3">
                {warningFindings.map((finding, idx) => (
                  <div key={idx} className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <span className="text-lg font-semibold text-slate-900">{finding.name}</span>
                          <Badge variant="outline" className="text-xs">{finding.category}</Badge>
                          <span className="px-2 py-0.5 text-xs font-medium rounded border border-slate-200 text-slate-600 bg-slate-50">
                            <Timer className="h-3 w-3 inline mr-1" />
                            Review Recommended
                          </span>
                        </div>
                        <p className="text-slate-700 font-medium">{finding.issue}</p>
                      </div>
                    </div>
                    <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <div className="p-4 bg-slate-50 rounded-lg">
                        <h4 className="text-sm font-semibold text-slate-700 mb-2 flex items-center gap-2">
                          <AlertTriangle className="h-4 w-4 text-amber-500" />
                          Why This Matters
                        </h4>
                        <p className="text-sm text-slate-600">
                          Deprecated libraries may contain known security vulnerabilities and no longer receive security patches.
                          Using outdated dependencies increases your attack surface.
                        </p>
                      </div>
                      <div className="p-4 bg-green-50/50 rounded-lg">
                        <h4 className="text-sm font-semibold text-slate-700 mb-2 flex items-center gap-2">
                          <TrendingUp className="h-4 w-4 text-green-500" />
                          Recommended Action
                        </h4>
                        <ol className="space-y-1.5 text-sm text-slate-600">
                          <li className="flex items-start gap-2">
                            <span className="flex-shrink-0 w-4 h-4 rounded-full bg-green-100 text-green-700 flex items-center justify-center text-xs">1</span>
                            Check for a newer version of this library
                          </li>
                          <li className="flex items-start gap-2">
                            <span className="flex-shrink-0 w-4 h-4 rounded-full bg-green-100 text-green-700 flex items-center justify-center text-xs">2</span>
                            Review changelog for security fixes
                          </li>
                          <li className="flex items-start gap-2">
                            <span className="flex-shrink-0 w-4 h-4 rounded-full bg-green-100 text-green-700 flex items-center justify-center text-xs">3</span>
                            Update or replace with maintained alternative
                          </li>
                        </ol>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* All Libraries */}
        <div className="mb-4">
          <button
            onClick={() => toggleSection("libraries")}
            className="w-full flex items-center justify-between p-4 bg-slate-50 border border-slate-200 rounded-lg hover:bg-slate-100 transition-colors"
          >
            <div className="flex items-center gap-3">
              <Package className="h-5 w-5 text-slate-600" />
              <span className="font-medium text-slate-900">
                Cryptographic Libraries ({report.libraries.length})
              </span>
            </div>
            {expandedSections.libraries ? (
              <ChevronUp className="h-5 w-5 text-slate-500" />
            ) : (
              <ChevronDown className="h-5 w-5 text-slate-500" />
            )}
          </button>
          {expandedSections.libraries && (
            <div className="mt-2 bg-white border border-slate-200 rounded-lg overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="bg-slate-50 text-left text-sm font-medium text-slate-600">
                    <th className="px-4 py-3">Library</th>
                    <th className="px-4 py-3">Category</th>
                    <th className="px-4 py-3">Version</th>
                    <th className="px-4 py-3">Quantum Risk</th>
                    <th className="px-4 py-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {report.libraries.map((lib, idx) => {
                    const libData = lib as Record<string, unknown>;
                    const quantumRisk = (libData.quantumRisk || libData.quantum_risk || "none") as string;
                    const isDeprecated = libData.isDeprecated || libData.is_deprecated;

                    return (
                      <tr key={idx} className="hover:bg-slate-50">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <Package className="h-4 w-4 text-slate-400" />
                            <span className="font-medium text-slate-900">{libData.name as string}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-slate-600">{libData.category as string}</td>
                        <td className="px-4 py-3">
                          <span className="font-mono text-sm text-slate-500">
                            {(libData.version as string) || "—"}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          {quantumRisk === "critical" || quantumRisk === "high" ? (
                            <Badge className="bg-red-100 text-red-700 hover:bg-red-100">High</Badge>
                          ) : quantumRisk === "low" ? (
                            <Badge className="bg-amber-100 text-amber-700 hover:bg-amber-100">Low</Badge>
                          ) : (
                            <Badge className="bg-emerald-100 text-emerald-700 hover:bg-emerald-100">Safe</Badge>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          {isDeprecated ? (
                            <Badge variant="outline" className="text-orange-600 border-orange-300">Deprecated</Badge>
                          ) : (
                            <Badge variant="outline" className="text-slate-500">Active</Badge>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* All Algorithms */}
        {report.algorithms.length > 0 && (
          <div className="mb-4">
            <button
              onClick={() => toggleSection("algorithms")}
              className="w-full flex items-center justify-between p-4 bg-slate-50 border border-slate-200 rounded-lg hover:bg-slate-100 transition-colors"
            >
              <div className="flex items-center gap-3">
                <Lock className="h-5 w-5 text-slate-600" />
                <span className="font-medium text-slate-900">
                  Detected Algorithms ({report.algorithms.length})
                </span>
              </div>
              {expandedSections.algorithms ? (
                <ChevronUp className="h-5 w-5 text-slate-500" />
              ) : (
                <ChevronDown className="h-5 w-5 text-slate-500" />
              )}
            </button>
            {expandedSections.algorithms && (
              <div className="mt-2 bg-white border border-slate-200 rounded-lg p-4">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {report.algorithms.map((algo, idx) => (
                    <div key={idx} className="flex items-center gap-3 p-3 bg-slate-50 rounded-lg">
                      <Lock className="h-4 w-4 text-slate-500" />
                      <div>
                        <p className="font-medium text-slate-900">{algo.name}</p>
                        <p className="text-xs text-slate-500">
                          {algo.category}
                          {algo.library && ` • ${algo.library}`}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Additional Metrics */}
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          <h3 className="font-medium text-slate-900 mb-4 flex items-center gap-2">
            <Info className="h-4 w-4 text-slate-400" />
            Additional Details
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-3 bg-slate-50 rounded-lg">
              <p className="text-2xl font-bold text-slate-900">{report.metrics.deprecatedCount}</p>
              <p className="text-sm text-slate-600">Deprecated</p>
            </div>
            <div className="text-center p-3 bg-slate-50 rounded-lg">
              <p className="text-2xl font-bold text-emerald-600">{report.metrics.quantumSafeCount}</p>
              <p className="text-sm text-slate-600">Quantum Safe</p>
            </div>
            <div className="text-center p-3 bg-slate-50 rounded-lg">
              <p className="text-2xl font-bold text-red-600">{report.metrics.quantumVulnerableCount}</p>
              <p className="text-sm text-slate-600">Vulnerable</p>
            </div>
            <div className="text-center p-3 bg-slate-50 rounded-lg">
              <div className="flex items-center justify-center">
                {report.metrics.hasPqc ? (
                  <CheckCircle className="h-6 w-6 text-emerald-500" />
                ) : (
                  <Unlock className="h-6 w-6 text-slate-400" />
                )}
              </div>
              <p className="text-sm text-slate-600 mt-1">
                {report.metrics.hasPqc ? "PQC Enabled" : "No PQC"}
              </p>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
