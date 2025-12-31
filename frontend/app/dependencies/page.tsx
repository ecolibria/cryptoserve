"use client";

import { useState } from "react";
import { Package, Play, AlertTriangle, Atom, FileJson } from "lucide-react";
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
import { api, DependencyScanResponse, DependencyScanQuickResponse } from "@/lib/api";

const EXAMPLE_PACKAGE_JSON = `{
  "name": "my-app",
  "dependencies": {
    "crypto-js": "^4.1.1",
    "bcrypt": "^5.1.0",
    "jsonwebtoken": "^9.0.0",
    "node-rsa": "^1.1.1",
    "tweetnacl": "^1.0.3",
    "express": "^4.18.2",
    "lodash": "^4.17.21"
  }
}`;

const EXAMPLE_REQUIREMENTS = `cryptography>=41.0.0
bcrypt>=4.0.0
PyJWT>=2.8.0
rsa>=4.9
pycryptodome>=3.19.0
flask>=3.0.0
requests>=2.31.0
`;

export default function DependenciesPage() {
  const [content, setContent] = useState(EXAMPLE_PACKAGE_JSON);
  const [filename, setFilename] = useState("package.json");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<DependencyScanResponse | null>(null);
  const [quickResult, setQuickResult] = useState<DependencyScanQuickResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<"full" | "quick">("full");

  const handleScan = async () => {
    setScanning(true);
    setError(null);
    setResult(null);
    setQuickResult(null);

    try {
      if (mode === "quick") {
        const res = await api.scanDependenciesQuick({ content, filename });
        setQuickResult(res);
      } else {
        const res = await api.scanDependencies({ content, filename });
        setResult(res);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  const handleFileSelect = (type: string) => {
    setFilename(type);
    if (type === "package.json") {
      setContent(EXAMPLE_PACKAGE_JSON);
    } else if (type === "requirements.txt") {
      setContent(EXAMPLE_REQUIREMENTS);
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk.toLowerCase()) {
      case "high": return "text-red-600 bg-red-50";
      case "medium": return "text-yellow-600 bg-yellow-50";
      case "low": return "text-blue-600 bg-blue-50";
      default: return "text-green-600 bg-green-50";
    }
  };

  const getQuantumBadge = (risk: string) => {
    switch (risk.toLowerCase()) {
      case "critical": return "destructive";
      case "high": return "destructive";
      case "low": return "warning";
      default: return "secondary";
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-8">
        <div>
          <h1 className="text-2xl font-bold">Dependency Scanner</h1>
          <p className="text-slate-600">
            Scan package files for cryptographic dependencies and quantum vulnerabilities
          </p>
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          {/* Input Panel */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Package className="h-5 w-5" />
                Package File
              </CardTitle>
              <CardDescription>
                Paste your package file content to analyze
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-4">
                <div className="flex-1">
                  <label className="block text-sm font-medium mb-1">File Type</label>
                  <select
                    className="w-full px-3 py-2 border rounded-lg"
                    value={filename}
                    onChange={(e) => handleFileSelect(e.target.value)}
                  >
                    <option value="package.json">package.json (npm)</option>
                    <option value="requirements.txt">requirements.txt (Python)</option>
                    <option value="go.mod">go.mod (Go)</option>
                    <option value="Cargo.toml">Cargo.toml (Rust)</option>
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
                <label className="block text-sm font-medium mb-1">Content</label>
                <textarea
                  className="w-full h-64 px-3 py-2 border rounded-lg font-mono text-sm"
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                  placeholder="Paste your package file content..."
                />
              </div>

              <Button onClick={handleScan} disabled={scanning || !content.trim()}>
                <Play className="h-4 w-4 mr-2" />
                {scanning ? "Scanning..." : "Scan Dependencies"}
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
                      <p className="text-sm font-medium text-slate-600">Crypto Packages</p>
                      <p className="text-2xl font-bold">{quickResult.crypto_count}</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className={`p-4 rounded-lg ${quickResult.quantum_vulnerable ? "bg-orange-50" : "bg-green-50"}`}>
                      <div className="flex items-center gap-2">
                        <Atom className={`h-5 w-5 ${quickResult.quantum_vulnerable ? "text-orange-600" : "text-green-600"}`} />
                        <span className={`font-medium ${quickResult.quantum_vulnerable ? "text-orange-600" : "text-green-600"}`}>
                          {quickResult.quantum_vulnerable ? "Quantum Vulnerable" : "Quantum Safe"}
                        </span>
                      </div>
                    </div>
                    <div className={`p-4 rounded-lg ${quickResult.deprecated_present ? "bg-red-50" : "bg-green-50"}`}>
                      <div className="flex items-center gap-2">
                        <AlertTriangle className={`h-5 w-5 ${quickResult.deprecated_present ? "text-red-600" : "text-green-600"}`} />
                        <span className={`font-medium ${quickResult.deprecated_present ? "text-red-600" : "text-green-600"}`}>
                          {quickResult.deprecated_present ? "Deprecated Found" : "No Deprecated"}
                        </span>
                      </div>
                    </div>
                  </div>

                  {quickResult.top_algorithms.length > 0 && (
                    <div>
                      <p className="text-sm font-medium mb-2">Top Algorithms</p>
                      <div className="flex flex-wrap gap-2">
                        {quickResult.top_algorithms.map((alg) => (
                          <Badge key={alg} variant="outline">{alg}</Badge>
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
                      Detected {result.package_type} package file
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-4 gap-4 text-center">
                      <div className="p-4 bg-slate-50 rounded-lg">
                        <p className="text-2xl font-bold">{result.total_packages}</p>
                        <p className="text-xs text-slate-600">Total Packages</p>
                      </div>
                      <div className="p-4 bg-blue-50 rounded-lg">
                        <p className="text-2xl font-bold text-blue-600">{result.crypto_packages}</p>
                        <p className="text-xs text-slate-600">Crypto Packages</p>
                      </div>
                      <div className="p-4 bg-orange-50 rounded-lg">
                        <p className="text-2xl font-bold text-orange-600">{result.quantum_vulnerable_count}</p>
                        <p className="text-xs text-slate-600">Quantum Risk</p>
                      </div>
                      <div className="p-4 bg-red-50 rounded-lg">
                        <p className="text-2xl font-bold text-red-600">{result.deprecated_count}</p>
                        <p className="text-xs text-slate-600">Deprecated</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Recommendations */}
                {result.recommendations.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle>Recommendations</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <ul className="space-y-2">
                        {result.recommendations.map((rec, i) => (
                          <li key={i} className="flex items-start gap-2 text-sm">
                            <span className="text-blue-500 mt-1">•</span>
                            {rec}
                          </li>
                        ))}
                      </ul>
                    </CardContent>
                  </Card>
                )}

                {/* Dependencies */}
                {result.dependencies.length > 0 && (
                  <Card>
                    <CardHeader>
                      <CardTitle>Crypto Dependencies</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      {result.dependencies.map((dep, i) => (
                        <div key={i} className="p-3 border rounded-lg">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span className="font-medium">{dep.name}</span>
                              {dep.version && (
                                <Badge variant="outline">{dep.version}</Badge>
                              )}
                              {dep.is_deprecated && (
                                <Badge variant="destructive">Deprecated</Badge>
                              )}
                            </div>
                            <Badge variant={getQuantumBadge(dep.quantum_risk) as "destructive" | "secondary" | "outline" | "warning"}>
                              {dep.quantum_risk}
                            </Badge>
                          </div>

                          <p className="text-sm text-slate-600 mt-1">
                            {dep.category} • {dep.package_type}
                          </p>

                          {dep.algorithms.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-2">
                              {dep.algorithms.map((alg) => (
                                <Badge key={alg} variant="secondary" className="text-xs">
                                  {alg}
                                </Badge>
                              ))}
                            </div>
                          )}

                          {dep.is_deprecated && dep.deprecation_reason && (
                            <p className="text-sm text-red-600 mt-2">
                              {dep.deprecation_reason}
                            </p>
                          )}

                          {dep.recommended_replacement && (
                            <p className="text-sm text-green-600 mt-1">
                              Recommended: {dep.recommended_replacement}
                            </p>
                          )}
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                )}
              </>
            )}

            {!result && !quickResult && !error && (
              <Card>
                <CardContent className="py-12 text-center text-slate-500">
                  <Package className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Paste package file and click Scan to analyze</p>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
