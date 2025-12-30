"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Shield,
  Lock,
  Zap,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  Search,
  Filter,
  ChevronDown,
  X,
  Award,
  Clock,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { DashboardLayout } from "@/components/dashboard-layout";
import { api, AlgorithmInfo, AlgorithmDetail, AlgorithmTypeInfo } from "@/lib/api";
import { cn } from "@/lib/utils";

const statusColors: Record<string, { bg: string; text: string; icon: typeof CheckCircle2 }> = {
  recommended: { bg: "bg-green-100", text: "text-green-700", icon: CheckCircle2 },
  acceptable: { bg: "bg-blue-100", text: "text-blue-700", icon: Shield },
  legacy: { bg: "bg-yellow-100", text: "text-yellow-700", icon: Clock },
  deprecated: { bg: "bg-orange-100", text: "text-orange-700", icon: AlertTriangle },
  broken: { bg: "bg-red-100", text: "text-red-700", icon: AlertTriangle },
};

const typeIcons: Record<string, typeof Lock> = {
  symmetric_encryption: Lock,
  asymmetric_encryption: Shield,
  hash: Zap,
  signature: Award,
  key_exchange: Shield,
  key_derivation: Lock,
  mac: Shield,
  aead: Lock,
};

export default function AlgorithmsPage() {
  const [algorithms, setAlgorithms] = useState<AlgorithmInfo[]>([]);
  const [algorithmTypes, setAlgorithmTypes] = useState<AlgorithmTypeInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [showQuantumOnly, setShowQuantumOnly] = useState(false);
  const [showRecommendedOnly, setShowRecommendedOnly] = useState(false);
  const [selectedAlgorithm, setSelectedAlgorithm] = useState<AlgorithmDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const [algos, types] = await Promise.all([
        api.listAlgorithms(),
        api.getAlgorithmTypes(),
      ]);
      setAlgorithms(algos);
      setAlgorithmTypes(types);
    } catch (error) {
      console.error("Failed to load algorithms:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const loadAlgorithmDetail = async (name: string) => {
    setLoadingDetail(true);
    try {
      const detail = await api.getAlgorithm(name);
      setSelectedAlgorithm(detail);
    } catch (error) {
      console.error("Failed to load algorithm detail:", error);
    } finally {
      setLoadingDetail(false);
    }
  };

  // Filter algorithms
  const filteredAlgorithms = algorithms.filter((algo) => {
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matches =
        algo.name.toLowerCase().includes(term) ||
        algo.family.toLowerCase().includes(term) ||
        algo.aliases.some((a) => a.toLowerCase().includes(term));
      if (!matches) return false;
    }
    if (selectedType && algo.type !== selectedType) return false;
    if (showQuantumOnly && !algo.quantum_resistant) return false;
    if (showRecommendedOnly && algo.status !== "recommended") return false;
    return true;
  });

  // Group by type
  const groupedAlgorithms = filteredAlgorithms.reduce((acc, algo) => {
    const type = algo.type;
    if (!acc[type]) acc[type] = [];
    acc[type].push(algo);
    return acc;
  }, {} as Record<string, AlgorithmInfo[]>);

  const getTypeLabel = (type: string) => {
    const typeInfo = algorithmTypes.find((t) => t.value === type);
    return typeInfo?.label || type;
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold">Cryptographic Algorithms</h1>
          <p className="text-slate-600">
            Browse available encryption algorithms and their security properties
          </p>
        </div>

        {/* Filters */}
        <Card>
          <CardContent className="pt-6">
            <div className="flex flex-wrap gap-4">
              {/* Search */}
              <div className="flex-1 min-w-[200px]">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                  <Input
                    placeholder="Search algorithms..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10"
                  />
                </div>
              </div>

              {/* Type Filter */}
              <select
                value={selectedType || ""}
                onChange={(e) => setSelectedType(e.target.value || null)}
                className="px-3 py-2 border rounded-md text-sm min-w-[180px]"
              >
                <option value="">All Types</option>
                {algorithmTypes.map((type) => (
                  <option key={type.value} value={type.value}>
                    {type.label} ({type.count})
                  </option>
                ))}
              </select>

              {/* Quick Filters */}
              <div className="flex gap-2">
                <button
                  onClick={() => setShowQuantumOnly(!showQuantumOnly)}
                  className={cn(
                    "px-3 py-2 rounded-md text-sm border transition-all flex items-center gap-2",
                    showQuantumOnly
                      ? "bg-purple-100 text-purple-700 border-purple-200"
                      : "bg-white hover:bg-slate-50 border-slate-200"
                  )}
                >
                  <Shield className="h-4 w-4" />
                  Quantum Safe
                </button>
                <button
                  onClick={() => setShowRecommendedOnly(!showRecommendedOnly)}
                  className={cn(
                    "px-3 py-2 rounded-md text-sm border transition-all flex items-center gap-2",
                    showRecommendedOnly
                      ? "bg-green-100 text-green-700 border-green-200"
                      : "bg-white hover:bg-slate-50 border-slate-200"
                  )}
                >
                  <CheckCircle2 className="h-4 w-4" />
                  Recommended
                </button>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold">{algorithms.length}</div>
              <div className="text-sm text-slate-500">Total Algorithms</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-green-600">
                {algorithms.filter((a) => a.status === "recommended").length}
              </div>
              <div className="text-sm text-slate-500">Recommended</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-purple-600">
                {algorithms.filter((a) => a.quantum_resistant).length}
              </div>
              <div className="text-sm text-slate-500">Quantum Resistant</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <div className="text-2xl font-bold text-orange-600">
                {algorithms.filter((a) => a.status === "deprecated" || a.status === "broken").length}
              </div>
              <div className="text-sm text-slate-500">Deprecated</div>
            </CardContent>
          </Card>
        </div>

        {/* Algorithm Grid */}
        {Object.entries(groupedAlgorithms).map(([type, typeAlgorithms]) => {
          const TypeIcon = typeIcons[type] || Lock;
          return (
            <div key={type} className="space-y-4">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <TypeIcon className="h-5 w-5 text-slate-400" />
                {getTypeLabel(type)}
                <span className="text-sm font-normal text-slate-500">
                  ({typeAlgorithms.length})
                </span>
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {typeAlgorithms.map((algo) => {
                  const StatusInfo = statusColors[algo.status] || statusColors.acceptable;
                  const StatusIcon = StatusInfo.icon;

                  return (
                    <Card
                      key={algo.name}
                      className="cursor-pointer hover:border-blue-300 transition-colors"
                      onClick={() => loadAlgorithmDetail(algo.name)}
                    >
                      <CardHeader className="pb-2">
                        <div className="flex items-start justify-between">
                          <div>
                            <CardTitle className="text-base font-mono">
                              {algo.name}
                            </CardTitle>
                            <p className="text-xs text-slate-500">{algo.family}</p>
                          </div>
                          <div className="flex items-center gap-1">
                            {algo.quantum_resistant && (
                              <span className="px-2 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-700">
                                PQC
                              </span>
                            )}
                            {algo.hardware_acceleration && (
                              <span title="Hardware accelerated">
                                <Cpu className="h-4 w-4 text-blue-500" />
                              </span>
                            )}
                          </div>
                        </div>
                      </CardHeader>
                      <CardContent className="space-y-3">
                        {/* Status Badge */}
                        <div className="flex items-center gap-2">
                          <span
                            className={cn(
                              "px-2 py-0.5 rounded text-xs font-medium flex items-center gap-1",
                              StatusInfo.bg,
                              StatusInfo.text
                            )}
                          >
                            <StatusIcon className="h-3 w-3" />
                            {algo.status}
                          </span>
                          <span className="text-xs text-slate-500">
                            {algo.security_bits}-bit security
                          </span>
                        </div>

                        {/* Use Cases */}
                        {algo.use_cases.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {algo.use_cases.slice(0, 3).map((use) => (
                              <span
                                key={use}
                                className="px-2 py-0.5 rounded text-xs bg-slate-100 text-slate-600"
                              >
                                {use}
                              </span>
                            ))}
                          </div>
                        )}

                        {/* Standards */}
                        {algo.standards.length > 0 && (
                          <p className="text-xs text-slate-500">
                            {algo.standards.slice(0, 2).join(", ")}
                          </p>
                        )}

                        {/* Replacement Warning */}
                        {algo.replacement && (
                          <div className="flex items-center gap-1 text-xs text-orange-600">
                            <AlertTriangle className="h-3 w-3" />
                            Use {algo.replacement} instead
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </div>
          );
        })}

        {filteredAlgorithms.length === 0 && (
          <div className="text-center py-12">
            <Lock className="h-12 w-12 text-slate-300 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-slate-900 mb-2">No algorithms found</h3>
            <p className="text-slate-500">Try adjusting your filters</p>
          </div>
        )}
      </div>

      {/* Algorithm Detail Modal */}
      {selectedAlgorithm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-auto">
            <div className="sticky top-0 bg-white border-b px-6 py-4 flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold font-mono">{selectedAlgorithm.name}</h2>
                <p className="text-sm text-slate-500">{selectedAlgorithm.family}</p>
              </div>
              <button
                onClick={() => setSelectedAlgorithm(null)}
                className="text-slate-400 hover:text-slate-600"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="px-6 py-6 space-y-6">
              {/* Status and Properties */}
              <div className="flex flex-wrap gap-2">
                <span
                  className={cn(
                    "px-3 py-1 rounded-md text-sm font-medium flex items-center gap-1",
                    statusColors[selectedAlgorithm.status]?.bg || "bg-blue-100",
                    statusColors[selectedAlgorithm.status]?.text || "text-blue-700"
                  )}
                >
                  {selectedAlgorithm.status}
                </span>
                {selectedAlgorithm.quantum_resistant && (
                  <span className="px-3 py-1 rounded-md text-sm font-medium bg-purple-100 text-purple-700">
                    Quantum Resistant
                  </span>
                )}
                {selectedAlgorithm.hardware_acceleration && (
                  <span className="px-3 py-1 rounded-md text-sm font-medium bg-blue-100 text-blue-700 flex items-center gap-1">
                    <Cpu className="h-4 w-4" />
                    Hardware Accelerated
                  </span>
                )}
              </div>

              {/* Key Stats */}
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center p-3 bg-slate-50 rounded-lg">
                  <div className="text-2xl font-bold">{selectedAlgorithm.security_bits}</div>
                  <div className="text-xs text-slate-500">Security Bits</div>
                </div>
                <div className="text-center p-3 bg-slate-50 rounded-lg">
                  <div className="text-2xl font-bold capitalize">{selectedAlgorithm.relative_speed}</div>
                  <div className="text-xs text-slate-500">Speed</div>
                </div>
                <div className="text-center p-3 bg-slate-50 rounded-lg">
                  <div className="text-2xl font-bold capitalize">{selectedAlgorithm.memory_usage}</div>
                  <div className="text-xs text-slate-500">Memory</div>
                </div>
              </div>

              {/* Use Cases */}
              {selectedAlgorithm.use_cases.length > 0 && (
                <div>
                  <h3 className="font-medium mb-2">Use Cases</h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedAlgorithm.use_cases.map((use) => (
                      <span key={use} className="px-2 py-1 bg-slate-100 rounded text-sm">
                        {use}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Standards */}
              {selectedAlgorithm.standards.length > 0 && (
                <div>
                  <h3 className="font-medium mb-2">Standards</h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedAlgorithm.standards.map((std) => (
                      <span key={std} className="px-2 py-1 bg-blue-50 text-blue-700 rounded text-sm">
                        {std}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Compliance Frameworks */}
              {selectedAlgorithm.compliance_frameworks.length > 0 && (
                <div>
                  <h3 className="font-medium mb-2">Compliance</h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedAlgorithm.compliance_frameworks.map((fw) => (
                      <span key={fw} className="px-2 py-1 bg-emerald-50 text-emerald-700 rounded text-sm">
                        {fw}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Key Sizes */}
              {selectedAlgorithm.key_sizes.length > 0 && (
                <div>
                  <h3 className="font-medium mb-2">Key Sizes</h3>
                  <p className="text-sm text-slate-600">
                    {selectedAlgorithm.key_sizes.join(", ")} bits
                  </p>
                </div>
              )}

              {/* Vulnerabilities */}
              {selectedAlgorithm.vulnerabilities.length > 0 && (
                <div className="bg-red-50 rounded-lg p-4">
                  <h3 className="font-medium text-red-800 mb-2 flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4" />
                    Known Vulnerabilities
                  </h3>
                  <ul className="list-disc list-inside text-sm text-red-700 space-y-1">
                    {selectedAlgorithm.vulnerabilities.map((v, i) => (
                      <li key={i}>{v}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Replacement */}
              {selectedAlgorithm.replacement && (
                <div className="bg-orange-50 rounded-lg p-4">
                  <h3 className="font-medium text-orange-800 mb-1">Recommended Replacement</h3>
                  <p className="text-sm text-orange-700 font-mono">
                    {selectedAlgorithm.replacement}
                  </p>
                </div>
              )}

              {/* Implementation Notes */}
              {selectedAlgorithm.implementation_notes.length > 0 && (
                <div>
                  <h3 className="font-medium mb-2">Implementation Notes</h3>
                  <ul className="list-disc list-inside text-sm text-slate-600 space-y-1">
                    {selectedAlgorithm.implementation_notes.map((note, i) => (
                      <li key={i}>{note}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Common Mistakes */}
              {selectedAlgorithm.common_mistakes.length > 0 && (
                <div className="bg-yellow-50 rounded-lg p-4">
                  <h3 className="font-medium text-yellow-800 mb-2">Common Mistakes to Avoid</h3>
                  <ul className="list-disc list-inside text-sm text-yellow-700 space-y-1">
                    {selectedAlgorithm.common_mistakes.map((mistake, i) => (
                      <li key={i}>{mistake}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Aliases */}
              {selectedAlgorithm.aliases.length > 0 && (
                <div>
                  <h3 className="font-medium mb-2">Also Known As</h3>
                  <p className="text-sm text-slate-600">
                    {selectedAlgorithm.aliases.join(", ")}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </DashboardLayout>
  );
}
