"use client";

import { useState } from "react";
import { Code, Play, AlertTriangle, CheckCircle, Shield, Atom, Download, FileJson, FileText, Lightbulb } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard-layout";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { api, CodeScanResponse, CodeScanQuickResponse, PQCRecommendationResponse, SupportedLanguage } from "@/lib/api";

const EXAMPLE_CODE = `from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib

# Generate key
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt data
encrypted = cipher.encrypt(b"sensitive data")

# Using MD5 (weak!)
md5_hash = hashlib.md5(b"data").hexdigest()

# Using SHA256 (good)
sha256_hash = hashlib.sha256(b"data").hexdigest()
`;

export default function ScannerPage() {
  const [code, setCode] = useState(EXAMPLE_CODE);
  const [language, setLanguage] = useState<string>("python");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<CodeScanResponse | null>(null);
  const [quickResult, setQuickResult] = useState<CodeScanQuickResponse | null>(null);
  const [recommendations, setRecommendations] = useState<PQCRecommendationResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<"full" | "quick">("full");
  const [exporting, setExporting] = useState<string | null>(null);
  const [loadingRecs, setLoadingRecs] = useState(false);
  const [dataProfile, setDataProfile] = useState<string>("general");

  const handleScan = async () => {
    setScanning(true);
    setError(null);
    setResult(null);
    setQuickResult(null);
    setRecommendations(null);

    try {
      if (mode === "quick") {
        const res = await api.scanCodeQuick({ code, language });
        setQuickResult(res);
      } else {
        const res = await api.scanCode({ code, language });
        setResult(res);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  const handleExportCBOM = async (format: "json" | "cyclonedx" | "spdx") => {
    setExporting(format);
    try {
      const data = await api.exportCBOM({ code, language, format });
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cbom-${format}-${new Date().toISOString().slice(0, 10)}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(null);
    }
  };

  const handleGetRecommendations = async () => {
    setLoadingRecs(true);
    try {
      const recs = await api.getPQCRecommendations({
        code,
        language,
        data_profile: dataProfile as "healthcare" | "national_security" | "financial" | "general" | "short_lived",
      });
      setRecommendations(recs);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to get recommendations");
    } finally {
      setLoadingRecs(false);
    }
  };

  const getUrgencyColor = (urgency: string) => {
    switch (urgency.toLowerCase()) {
      case "critical": return "text-red-600 bg-red-50 border-red-200";
      case "high": return "text-orange-600 bg-orange-50 border-orange-200";
      case "medium": return "text-yellow-600 bg-yellow-50 border-yellow-200";
      case "low": return "text-green-600 bg-green-50 border-green-200";
      default: return "text-blue-600 bg-blue-50 border-blue-200";
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk.toLowerCase()) {
      case "critical": return "text-red-600 bg-red-50";
      case "high": return "text-orange-600 bg-orange-50";
      case "medium": return "text-yellow-600 bg-yellow-50";
      case "low": return "text-blue-600 bg-blue-50";
      default: return "text-green-600 bg-green-50";
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical": return "destructive";
      case "high": return "destructive";
      case "medium": return "warning";
      default: return "secondary";
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-8">
        <div>
          <h1 className="text-2xl font-bold">Code Scanner</h1>
          <p className="text-slate-600">
            Analyze source code for cryptographic usage, weak algorithms, and quantum vulnerabilities
          </p>
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          {/* Input Panel */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Code className="h-5 w-5" />
                Source Code
              </CardTitle>
              <CardDescription>
                Paste code to analyze for crypto usage
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-4">
                <div className="flex-1">
                  <label className="block text-sm font-medium mb-1">Language</label>
                  <select
                    className="w-full px-3 py-2 border rounded-lg"
                    value={language}
                    onChange={(e) => setLanguage(e.target.value)}
                  >
                    <option value="python">Python</option>
                    <option value="javascript">JavaScript</option>
                    <option value="go">Go</option>
                    <option value="java">Java</option>
                    <option value="rust">Rust</option>
                  </select>
                </div>
                <div className="flex-1">
                  <label className="block text-sm font-medium mb-1">Scan Mode</label>
                  <select
                    className="w-full px-3 py-2 border rounded-lg"
                    value={mode}
                    onChange={(e) => setMode(e.target.value as "full" | "quick")}
                  >
                    <option value="full">Full Analysis</option>
                    <option value="quick">Quick Check (CI/CD)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1">Code</label>
                <textarea
                  className="w-full h-64 px-3 py-2 border rounded-lg font-mono text-sm"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  placeholder="Paste your code here..."
                />
              </div>

              <Button onClick={handleScan} disabled={scanning || !code.trim()}>
                <Play className="h-4 w-4 mr-2" />
                {scanning ? "Scanning..." : "Scan Code"}
              </Button>
            </CardContent>
          </Card>

          {/* Results Panel */}
          <div className="space-y-4">
            {error && (
              <Card className="border-red-200 bg-red-50">
                <CardContent className="py-4">
                  <p className="text-red-700">{error}</p>
                </CardContent>
              </Card>
            )}

            {/* Quick Result */}
            {quickResult && (
              <Card>
                <CardHeader>
                  <CardTitle>Quick Scan Results</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className={`p-4 rounded-lg ${getRiskColor(quickResult.risk_level)}`}>
                      <p className="text-sm font-medium">Risk Level</p>
                      <p className="text-2xl font-bold capitalize">{quickResult.risk_level}</p>
                    </div>
                    <div className="p-4 rounded-lg bg-slate-50">
                      <p className="text-sm font-medium text-slate-600">Crypto Detected</p>
                      <p className="text-2xl font-bold">{quickResult.has_crypto ? "Yes" : "No"}</p>
                    </div>
                  </div>

                  {quickResult.algorithms.length > 0 && (
                    <div>
                      <p className="text-sm font-medium mb-2">Algorithms Found</p>
                      <div className="flex flex-wrap gap-2">
                        {quickResult.algorithms.map((alg) => (
                          <Badge key={alg} variant="outline">{alg}</Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {quickResult.weak_algorithms.length > 0 && (
                    <div>
                      <p className="text-sm font-medium mb-2 text-red-600">Weak Algorithms</p>
                      <div className="flex flex-wrap gap-2">
                        {quickResult.weak_algorithms.map((alg) => (
                          <Badge key={alg} variant="destructive">{alg}</Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {quickResult.quantum_vulnerable.length > 0 && (
                    <div>
                      <p className="text-sm font-medium mb-2 text-orange-600">
                        <Atom className="inline h-4 w-4 mr-1" />
                        Quantum Vulnerable
                      </p>
                      <div className="flex flex-wrap gap-2">
                        {quickResult.quantum_vulnerable.map((alg) => (
                          <Badge key={alg} variant="warning">{alg}</Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="p-4 bg-blue-50 rounded-lg">
                    <p className="text-sm text-blue-800">{quickResult.recommendation}</p>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Full Result */}
            {result && (
              <>
                {/* Summary */}
                <Card>
                  <CardHeader>
                    <CardTitle>Scan Summary</CardTitle>
                    <CardDescription>
                      {result.lines_scanned} lines scanned
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-3 gap-4 text-center">
                      <div className="p-4 bg-slate-50 rounded-lg">
                        <p className="text-3xl font-bold">{result.usages.length}</p>
                        <p className="text-sm text-slate-600">Crypto Usages</p>
                      </div>
                      <div className="p-4 bg-slate-50 rounded-lg">
                        <p className="text-3xl font-bold text-red-600">
                          {result.findings.filter(f => f.severity === "high" || f.severity === "critical").length}
                        </p>
                        <p className="text-sm text-slate-600">Issues Found</p>
                      </div>
                      <div className="p-4 bg-slate-50 rounded-lg">
                        <p className="text-3xl font-bold text-orange-600">
                          {result.cbom.quantum_summary.vulnerable || 0}
                        </p>
                        <p className="text-sm text-slate-600">Quantum Vulnerable</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Findings */}
                {result.findings.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <AlertTriangle className="h-5 w-5 text-orange-500" />
                        Security Findings
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      {result.findings.map((finding, i) => (
                        <div key={i} className="p-3 border rounded-lg">
                          <div className="flex items-start justify-between">
                            <div className="flex items-center gap-2">
                              <Badge variant={getSeverityBadge(finding.severity) as "destructive" | "secondary" | "outline"}>
                                {finding.severity}
                              </Badge>
                              <span className="font-medium">{finding.category}</span>
                            </div>
                            {finding.line_number && (
                              <span className="text-sm text-slate-500">Line {finding.line_number}</span>
                            )}
                          </div>
                          <p className="mt-2 text-sm">{finding.message}</p>
                          <p className="mt-1 text-sm text-blue-600">{finding.recommendation}</p>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                )}

                {/* Usages */}
                {result.usages.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Shield className="h-5 w-5" />
                        Crypto Usages
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      {result.usages.map((usage, i) => (
                        <div key={i} className="p-3 border rounded-lg">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <Badge variant="outline">{usage.algorithm}</Badge>
                              <span className="text-sm text-slate-600">{usage.category}</span>
                              {usage.is_weak && (
                                <Badge variant="destructive">Weak</Badge>
                              )}
                            </div>
                            <span className="text-sm text-slate-500">Line {usage.line_number}</span>
                          </div>
                          <p className="mt-1 text-sm text-slate-600">
                            Library: {usage.library}
                          </p>
                          {usage.quantum_risk !== "none" && (
                            <p className="text-sm text-orange-600">
                              Quantum Risk: {usage.quantum_risk}
                            </p>
                          )}
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                )}

                {/* CBOM Preview */}
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle>Cryptographic Bill of Materials</CardTitle>
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleExportCBOM("json")}
                          disabled={exporting !== null}
                        >
                          <FileJson className="h-4 w-4 mr-1" />
                          {exporting === "json" ? "..." : "JSON"}
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleExportCBOM("cyclonedx")}
                          disabled={exporting !== null}
                        >
                          <Download className="h-4 w-4 mr-1" />
                          {exporting === "cyclonedx" ? "..." : "CycloneDX"}
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handleExportCBOM("spdx")}
                          disabled={exporting !== null}
                        >
                          <FileText className="h-4 w-4 mr-1" />
                          {exporting === "spdx" ? "..." : "SPDX"}
                        </Button>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div>
                        <p className="text-sm font-medium mb-2">Algorithms</p>
                        <div className="flex flex-wrap gap-2">
                          {result.cbom.algorithms.map((alg) => (
                            <Badge key={alg.name} variant="outline">
                              {alg.name} ({alg.count}x)
                            </Badge>
                          ))}
                        </div>
                      </div>
                      <div>
                        <p className="text-sm font-medium mb-2">Libraries</p>
                        <div className="flex flex-wrap gap-2">
                          {result.cbom.libraries.map((lib) => (
                            <Badge key={lib} variant="secondary">{lib}</Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* PQC Recommendations */}
                <Card>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="flex items-center gap-2">
                        <Lightbulb className="h-5 w-5 text-yellow-500" />
                        PQC Migration Recommendations
                      </CardTitle>
                      <div className="flex items-center gap-2">
                        <select
                          className="px-2 py-1 text-sm border rounded"
                          value={dataProfile}
                          onChange={(e) => setDataProfile(e.target.value)}
                        >
                          <option value="short_lived">Short-lived (1yr)</option>
                          <option value="general">General (10yr)</option>
                          <option value="financial">Financial (25yr)</option>
                          <option value="national_security">Gov/Defense (75yr)</option>
                          <option value="healthcare">Healthcare (100yr)</option>
                        </select>
                        <Button
                          size="sm"
                          onClick={handleGetRecommendations}
                          disabled={loadingRecs}
                        >
                          {loadingRecs ? "Analyzing..." : "Get Recommendations"}
                        </Button>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    {!recommendations ? (
                      <p className="text-sm text-slate-500">
                        Click &quot;Get Recommendations&quot; to analyze quantum readiness and get PQC migration guidance.
                      </p>
                    ) : (
                      <div className="space-y-4">
                        {/* Quantum Readiness Score */}
                        <div className="grid grid-cols-2 gap-4">
                          <div className={`p-4 rounded-lg border ${getUrgencyColor(recommendations.overall_urgency)}`}>
                            <p className="text-sm font-medium">Migration Urgency</p>
                            <p className="text-2xl font-bold capitalize">{recommendations.overall_urgency}</p>
                          </div>
                          <div className="p-4 rounded-lg bg-slate-50">
                            <p className="text-sm font-medium text-slate-600">Quantum Readiness</p>
                            <p className="text-2xl font-bold">{recommendations.quantum_readiness_score.toFixed(0)}%</p>
                          </div>
                        </div>

                        {/* SNDL Assessment */}
                        {recommendations.sndl_assessment.vulnerable && (
                          <div className="p-3 bg-orange-50 border border-orange-200 rounded-lg">
                            <p className="font-medium text-orange-800">SNDL Risk Detected</p>
                            <p className="text-sm text-orange-700 mt-1">{recommendations.sndl_assessment.explanation}</p>
                            <div className="mt-2 grid grid-cols-3 gap-2 text-sm">
                              <div>
                                <span className="text-orange-600">Protection needed:</span>{" "}
                                {recommendations.sndl_assessment.protection_years_required} years
                              </div>
                              <div>
                                <span className="text-orange-600">Quantum threat:</span>{" "}
                                ~{recommendations.sndl_assessment.estimated_quantum_years} years
                              </div>
                              <div>
                                <span className="text-orange-600">Risk window:</span>{" "}
                                {recommendations.sndl_assessment.risk_window_years} years
                              </div>
                            </div>
                          </div>
                        )}

                        {/* Key Findings */}
                        {recommendations.key_findings.length > 0 && (
                          <div>
                            <p className="text-sm font-medium mb-2">Key Findings</p>
                            <ul className="list-disc list-inside text-sm space-y-1">
                              {recommendations.key_findings.map((finding, i) => (
                                <li key={i} className="text-slate-700">{finding}</li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {/* Algorithm Recommendations */}
                        {(recommendations.kem_recommendations.length > 0 || recommendations.signature_recommendations.length > 0) && (
                          <div>
                            <p className="text-sm font-medium mb-2">Algorithm Recommendations</p>
                            <div className="space-y-2">
                              {recommendations.kem_recommendations.map((rec, i) => (
                                <div key={`kem-${i}`} className="p-2 bg-blue-50 rounded text-sm">
                                  <span className="font-medium">{rec.current_algorithm}</span>
                                  <span className="text-slate-500"> → </span>
                                  <span className="text-blue-700 font-medium">{rec.recommended_algorithm}</span>
                                  <span className="text-slate-500 ml-2">({rec.fips_standard})</span>
                                </div>
                              ))}
                              {recommendations.signature_recommendations.map((rec, i) => (
                                <div key={`sig-${i}`} className="p-2 bg-purple-50 rounded text-sm">
                                  <span className="font-medium">{rec.current_algorithm}</span>
                                  <span className="text-slate-500"> → </span>
                                  <span className="text-purple-700 font-medium">{rec.recommended_algorithm}</span>
                                  <span className="text-slate-500 ml-2">({rec.fips_standard})</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Next Steps */}
                        {recommendations.next_steps.length > 0 && (
                          <div className="p-3 bg-green-50 border border-green-200 rounded-lg">
                            <p className="font-medium text-green-800 mb-2">Next Steps</p>
                            <ol className="list-decimal list-inside text-sm space-y-1">
                              {recommendations.next_steps.slice(0, 3).map((step, i) => (
                                <li key={i} className="text-green-700">{step}</li>
                              ))}
                            </ol>
                          </div>
                        )}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </>
            )}

            {!result && !quickResult && !error && (
              <Card>
                <CardContent className="py-12 text-center text-slate-500">
                  <Code className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Paste code and click Scan to analyze</p>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
