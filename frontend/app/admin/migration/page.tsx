"use client";

import { useEffect, useState } from "react";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ChevronRight,
  ChevronLeft,
  Check,
  ArrowRight,
  Play,
  RefreshCw,
  Clock,
  Zap,
  Info,
  CheckCircle2,
  XCircle,
  Loader2,
  Sparkles,
  Target,
  TrendingUp,
  History,
  AlertCircle,
} from "lucide-react";
import { AdminLayout } from "@/components/admin-layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  api,
  MigrationAssessment,
  MigrationRecommendation,
  MigrationPreview,
  MigrationResult,
  MigrationHistoryEntry,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { StatCard } from "@/components/ui/stat-card";

type WizardStep = 1 | 2 | 3 | 4 | 5;

export default function MigrationWizardPage() {
  const [step, setStep] = useState<WizardStep>(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Data from API
  const [assessment, setAssessment] = useState<MigrationAssessment | null>(null);
  const [history, setHistory] = useState<MigrationHistoryEntry[]>([]);

  // Selected migrations
  const [selectedMigrations, setSelectedMigrations] = useState<Set<string>>(new Set());

  // Preview/simulation results
  const [previews, setPreviews] = useState<Map<string, MigrationPreview>>(new Map());
  const [simulating, setSimulating] = useState(false);

  // Execution state
  const [executing, setExecuting] = useState(false);
  const [executionResults, setExecutionResults] = useState<MigrationResult[]>([]);
  const [currentlyExecuting, setCurrentlyExecuting] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [assessmentData, historyData] = await Promise.all([
        api.getMigrationAssessment(),
        api.getMigrationHistory(),
      ]);
      setAssessment(assessmentData);
      setHistory(historyData);
    } catch (err) {
      console.error("Failed to load migration data:", err);
      setError("Failed to load migration assessment. Make sure the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Risk gauge color based on score
  const getRiskColor = (score: number) => {
    if (score <= 30) return { stroke: "#10b981", text: "text-emerald-600", bg: "bg-emerald-100" };
    if (score <= 60) return { stroke: "#f59e0b", text: "text-amber-600", bg: "bg-amber-100" };
    if (score <= 80) return { stroke: "#f97316", text: "text-orange-600", bg: "bg-orange-100" };
    return { stroke: "#ef4444", text: "text-red-600", bg: "bg-red-100" };
  };

  const getUrgencyBadge = (urgency: string) => {
    switch (urgency) {
      case "immediate":
        return <Badge className="bg-red-100 text-red-700 border-red-200">Immediate</Badge>;
      case "soon":
        return <Badge className="bg-amber-100 text-amber-700 border-amber-200">Soon</Badge>;
      default:
        return <Badge className="bg-blue-100 text-blue-700 border-blue-200">Planned</Badge>;
    }
  };

  const getRiskScoreBadge = (score: number) => {
    const colors = getRiskColor(score);
    return (
      <span className={cn("px-2 py-1 rounded-full text-xs font-medium", colors.bg, colors.text)}>
        Risk: {score}
      </span>
    );
  };

  // Toggle selection for a recommendation
  const toggleSelection = (contextName: string) => {
    const newSelected = new Set(selectedMigrations);
    if (newSelected.has(contextName)) {
      newSelected.delete(contextName);
    } else {
      newSelected.add(contextName);
    }
    setSelectedMigrations(newSelected);
  };

  // Select all
  const selectAll = () => {
    if (assessment) {
      setSelectedMigrations(new Set(assessment.recommendations.map((r) => r.contextName)));
    }
  };

  // Clear all
  const clearAll = () => {
    setSelectedMigrations(new Set());
  };

  // Simulate selected migrations
  const simulateMigrations = async () => {
    if (!assessment) return;
    setSimulating(true);
    const newPreviews = new Map<string, MigrationPreview>();

    for (const contextName of Array.from(selectedMigrations)) {
      const rec = assessment.recommendations.find((r) => r.contextName === contextName);
      if (rec) {
        try {
          const preview = await api.simulateMigration(contextName, rec.recommendedAlgorithm);
          newPreviews.set(contextName, preview);
        } catch (err) {
          console.error(`Failed to simulate ${contextName}:`, err);
        }
      }
    }

    setPreviews(newPreviews);
    setSimulating(false);
    setStep(3);
  };

  // Execute migrations
  const executeMigrations = async () => {
    if (!assessment) return;
    setExecuting(true);
    setExecutionResults([]);

    for (const contextName of Array.from(selectedMigrations)) {
      const rec = assessment.recommendations.find((r) => r.contextName === contextName);
      if (rec) {
        setCurrentlyExecuting(contextName);
        try {
          const result = await api.executeMigration(contextName, rec.recommendedAlgorithm);
          setExecutionResults((prev) => [...prev, result]);
        } catch (err) {
          console.error(`Failed to migrate ${contextName}:`, err);
          setExecutionResults((prev) => [
            ...prev,
            {
              success: false,
              contextName,
              previousAlgorithm: rec.currentAlgorithm,
              newAlgorithm: rec.recommendedAlgorithm,
              message: err instanceof Error ? err.message : "Unknown error",
            },
          ]);
        }
      }
    }

    setCurrentlyExecuting(null);
    setExecuting(false);
    setStep(5);
  };

  // Check if we can proceed to next step
  const canProceed = () => {
    switch (step) {
      case 1:
        return assessment && assessment.recommendations.length > 0;
      case 2:
        return selectedMigrations.size > 0;
      case 3:
        return previews.size > 0 && Array.from(previews.values()).some((p) => p.canProceed);
      default:
        return false;
    }
  };

  // Reset wizard
  const resetWizard = () => {
    setStep(1);
    setSelectedMigrations(new Set());
    setPreviews(new Map());
    setExecutionResults([]);
    loadData();
  };

  if (loading) {
    return (
      <AdminLayout title="Algorithm Migration" subtitle="Guided migration from deprecated algorithms">
        <div className="flex items-center justify-center py-20">
          <Loader2 className="h-8 w-8 animate-spin text-indigo-600" />
        </div>
      </AdminLayout>
    );
  }

  if (error) {
    return (
      <AdminLayout title="Algorithm Migration" subtitle="Guided migration from deprecated algorithms">
        <div className="p-6 bg-red-50 border border-red-200 rounded-xl">
          <div className="flex items-start gap-3">
            <AlertCircle className="h-5 w-5 text-red-500 mt-0.5" />
            <div>
              <h3 className="font-medium text-red-900">Error Loading Migration Data</h3>
              <p className="text-sm text-red-700 mt-1">{error}</p>
              <Button variant="outline" size="sm" className="mt-3" onClick={loadData}>
                <RefreshCw className="h-4 w-4 mr-2" />
                Retry
              </Button>
            </div>
          </div>
        </div>
      </AdminLayout>
    );
  }

  return (
    <AdminLayout
      title="Algorithm Migration"
      subtitle="Guided wizard to safely migrate from deprecated algorithms"
      onRefresh={loadData}
    >
      <div className="space-y-8">
        {/* Progress Bar */}
        {step < 5 && (
          <div className="mb-8">
            <div className="flex items-center justify-between text-sm text-slate-500 mb-2">
              <span>Step {step} of 4</span>
              <span>{Math.round((step / 4) * 100)}% complete</span>
            </div>
            <div className="h-2 bg-slate-200 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-indigo-500 to-purple-500 transition-all duration-300"
                style={{ width: `${(step / 4) * 100}%` }}
              />
            </div>
            <div className="flex justify-between mt-2 text-xs text-slate-400">
              <span className={step >= 1 ? "text-indigo-600 font-medium" : ""}>Assessment</span>
              <span className={step >= 2 ? "text-indigo-600 font-medium" : ""}>Select</span>
              <span className={step >= 3 ? "text-indigo-600 font-medium" : ""}>Review</span>
              <span className={step >= 4 ? "text-indigo-600 font-medium" : ""}>Execute</span>
            </div>
          </div>
        )}

        {/* Step 1: Assessment Overview */}
        {step === 1 && assessment && (
          <div className="space-y-8">
            <div className="text-center">
              <h2 className="text-2xl font-bold text-slate-900">Migration Assessment</h2>
              <p className="text-slate-600 mt-2">{assessment.summary}</p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Risk Gauge */}
              <Card className="lg:col-span-4">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium text-slate-600">
                    Overall Risk Score
                  </CardTitle>
                </CardHeader>
                <CardContent className="flex flex-col items-center justify-center py-6">
                  <div className="relative w-40 h-40">
                    <svg className="w-40 h-40 transform -rotate-90">
                      <circle
                        cx="80"
                        cy="80"
                        r="70"
                        stroke="#e5e7eb"
                        strokeWidth="14"
                        fill="none"
                      />
                      <circle
                        cx="80"
                        cy="80"
                        r="70"
                        stroke={getRiskColor(assessment.overallRiskScore).stroke}
                        strokeWidth="14"
                        fill="none"
                        strokeLinecap="round"
                        strokeDasharray={`${(assessment.overallRiskScore / 100) * 439.82} 439.82`}
                        className="transition-all duration-1000 ease-out"
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className={cn("text-4xl font-bold", getRiskColor(assessment.overallRiskScore).text)}>
                        {assessment.overallRiskScore}
                      </span>
                      <span className="text-sm text-slate-500 capitalize">{assessment.overallLevel}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Stats Grid */}
              <div className="lg:col-span-8 grid grid-cols-2 md:grid-cols-4 gap-4">
                <StatCard
                  title="Critical"
                  value={assessment.categories.critical.count}
                  subtitle="Needs immediate action"
                  icon={<ShieldAlert className="h-5 w-5" />}
                  color="rose"
                />
                <StatCard
                  title="High Priority"
                  value={assessment.categories.high.count}
                  subtitle="Address soon"
                  icon={<AlertTriangle className="h-5 w-5" />}
                  color="amber"
                />
                <StatCard
                  title="Medium"
                  value={assessment.categories.medium.count}
                  subtitle="Plan for migration"
                  icon={<Shield className="h-5 w-5" />}
                  color="blue"
                />
                <StatCard
                  title="Low Priority"
                  value={assessment.categories.low.count}
                  subtitle="Monitor"
                  icon={<ShieldCheck className="h-5 w-5" />}
                  color="green"
                />
              </div>
            </div>

            {/* Quantum Readiness */}
            <Card className="border-purple-200">
              <CardContent className="py-5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="h-12 w-12 rounded-xl bg-purple-100 flex items-center justify-center">
                      <Sparkles className="h-6 w-6 text-purple-600" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-slate-900">Quantum Readiness</h3>
                      <p className="text-sm text-slate-500">
                        {assessment.quantumReadiness.percentage}% of contexts are quantum-ready
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-2xl font-bold text-purple-600">
                      {assessment.quantumReadiness.percentage}%
                    </div>
                    <p className="text-xs text-slate-500">
                      {assessment.quantumReadiness.contextsNeedingPQC} contexts need PQC
                    </p>
                  </div>
                </div>
                {assessment.quantumReadiness.recommendation && (
                  <p className="mt-3 text-sm text-purple-700 bg-purple-50 px-3 py-2 rounded-lg">
                    {assessment.quantumReadiness.recommendation}
                  </p>
                )}
              </CardContent>
            </Card>

            {/* No Issues Message */}
            {assessment.recommendations.length === 0 && (
              <Card className="border-green-200 bg-green-50">
                <CardContent className="py-8 text-center">
                  <CheckCircle2 className="h-12 w-12 text-green-500 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-green-900">
                    All algorithms are up to date!
                  </h3>
                  <p className="text-green-700 mt-2">
                    No deprecated algorithms found. Your cryptographic configuration is secure.
                  </p>
                </CardContent>
              </Card>
            )}

            {/* Recent Migration History */}
            {history.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-base">
                    <History className="h-5 w-5 text-slate-400" />
                    Recent Migrations
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {history.slice(0, 5).map((entry, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between py-2 px-3 bg-slate-50 rounded-lg"
                      >
                        <div className="flex items-center gap-3">
                          {entry.success ? (
                            <CheckCircle2 className="h-4 w-4 text-green-500" />
                          ) : (
                            <XCircle className="h-4 w-4 text-red-500" />
                          )}
                          <span className="font-medium">{entry.contextName}</span>
                          <ArrowRight className="h-4 w-4 text-slate-400" />
                          <Badge variant="outline">{entry.newAlgorithm}</Badge>
                        </div>
                        <span className="text-xs text-slate-500">
                          {new Date(entry.migratedAt).toLocaleDateString()}
                        </span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        )}

        {/* Step 2: Select Migrations */}
        {step === 2 && assessment && (
          <div className="space-y-6">
            <div className="text-center">
              <h2 className="text-2xl font-bold text-slate-900">Select Contexts to Migrate</h2>
              <p className="text-slate-600 mt-2">
                Choose which contexts to migrate. Recommendations are sorted by risk priority.
              </p>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Button variant="outline" size="sm" onClick={selectAll}>
                  Select All
                </Button>
                <Button variant="outline" size="sm" onClick={clearAll}>
                  Clear All
                </Button>
              </div>
              <span className="text-sm text-slate-500">
                {selectedMigrations.size} of {assessment.recommendations.length} selected
              </span>
            </div>

            <div className="space-y-4">
              {assessment.recommendations.map((rec) => {
                const isSelected = selectedMigrations.has(rec.contextName);
                const riskColors = getRiskColor(rec.riskScore.score);

                return (
                  <Card
                    key={rec.contextName}
                    className={cn(
                      "cursor-pointer transition-all border-l-4",
                      isSelected
                        ? "ring-2 ring-indigo-500 bg-indigo-50/50 border-l-indigo-500"
                        : "hover:border-slate-300",
                      rec.urgency === "immediate" && !isSelected && "border-l-red-400",
                      rec.urgency === "soon" && !isSelected && "border-l-amber-400",
                      rec.urgency === "planned" && !isSelected && "border-l-blue-400"
                    )}
                    onClick={() => toggleSelection(rec.contextName)}
                  >
                    <CardContent className="p-4">
                      <div className="flex items-start justify-between">
                        <div className="flex items-start gap-4">
                          <div
                            className={cn(
                              "w-6 h-6 rounded-full border-2 flex items-center justify-center mt-0.5",
                              isSelected
                                ? "bg-indigo-600 border-indigo-600"
                                : "border-slate-300"
                            )}
                          >
                            {isSelected && <Check className="h-4 w-4 text-white" />}
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <h3 className="font-semibold text-slate-900">
                                {rec.contextName}
                              </h3>
                              {getUrgencyBadge(rec.urgency)}
                              {getRiskScoreBadge(rec.riskScore.score)}
                            </div>

                            <div className="flex items-center gap-3 mt-2">
                              <Badge variant="destructive" className="font-mono text-xs">
                                {rec.currentAlgorithm}
                              </Badge>
                              <ArrowRight className="h-4 w-4 text-slate-400" />
                              <Badge className="bg-green-100 text-green-700 font-mono text-xs">
                                {rec.recommendedAlgorithm}
                              </Badge>
                            </div>

                            <p className="text-sm text-slate-600 mt-2">{rec.reason}</p>

                            {/* Migration Steps Preview */}
                            <div className="mt-3 text-xs text-slate-500">
                              <span className="font-medium">Steps:</span>{" "}
                              {rec.steps.slice(0, 2).join(" > ")}
                              {rec.steps.length > 2 && ` (+${rec.steps.length - 2} more)`}
                            </div>
                          </div>
                        </div>
                        <div className="text-right shrink-0 ml-4">
                          <div className={cn("text-2xl font-bold", riskColors.text)}>
                            #{rec.priority}
                          </div>
                          <span className="text-xs text-slate-500">Priority</span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </div>
        )}

        {/* Step 3: Review Plan */}
        {step === 3 && assessment && (
          <div className="space-y-6">
            <div className="text-center">
              <h2 className="text-2xl font-bold text-slate-900">Review Migration Plan</h2>
              <p className="text-slate-600 mt-2">
                Verify the migration plan before executing. Migrations will be performed in order.
              </p>
            </div>

            {simulating ? (
              <div className="flex flex-col items-center justify-center py-12">
                <Loader2 className="h-8 w-8 animate-spin text-indigo-600 mb-4" />
                <p className="text-slate-600">Simulating migrations...</p>
              </div>
            ) : (
              <div className="space-y-4">
                {Array.from(selectedMigrations).map((contextName) => {
                  const rec = assessment.recommendations.find((r) => r.contextName === contextName);
                  const preview = previews.get(contextName);

                  if (!rec) return null;

                  return (
                    <Card
                      key={contextName}
                      className={cn(
                        "border-l-4",
                        preview?.canProceed
                          ? "border-l-green-500"
                          : "border-l-red-500"
                      )}
                    >
                      <CardContent className="p-4">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-2">
                              {preview?.canProceed ? (
                                <CheckCircle2 className="h-5 w-5 text-green-500" />
                              ) : (
                                <XCircle className="h-5 w-5 text-red-500" />
                              )}
                              <h3 className="font-semibold text-slate-900">{contextName}</h3>
                              <Badge variant="outline" className="font-mono text-xs">
                                {rec.currentAlgorithm} → {rec.recommendedAlgorithm}
                              </Badge>
                            </div>

                            {preview && (
                              <div className="mt-3 space-y-3">
                                {/* Impact Summary */}
                                <div className="grid grid-cols-3 gap-4 text-sm">
                                  <div className="px-3 py-2 bg-slate-50 rounded-lg">
                                    <span className="text-slate-500">Compatibility:</span>
                                    <span className="ml-2 font-medium capitalize">
                                      {preview.impactSummary.compatibility.replace(/-/g, " ")}
                                    </span>
                                  </div>
                                  <div className="px-3 py-2 bg-slate-50 rounded-lg">
                                    <span className="text-slate-500">Key Rederivation:</span>
                                    <span className="ml-2 font-medium">
                                      {preview.impactSummary.requiresKeyRederivation ? "Yes" : "No"}
                                    </span>
                                  </div>
                                  <div className="px-3 py-2 bg-slate-50 rounded-lg">
                                    <span className="text-slate-500">Downtime:</span>
                                    <span className="ml-2 font-medium capitalize">
                                      {preview.impactSummary.estimatedDowntime}
                                    </span>
                                  </div>
                                </div>

                                {/* Warnings */}
                                {preview.warnings.length > 0 && (
                                  <div className="p-3 bg-amber-50 rounded-lg border border-amber-200">
                                    <h4 className="text-sm font-medium text-amber-800 flex items-center gap-2">
                                      <AlertTriangle className="h-4 w-4" />
                                      Warnings
                                    </h4>
                                    <ul className="mt-2 text-sm text-amber-700 space-y-1">
                                      {preview.warnings.map((w, i) => (
                                        <li key={i}>• {w}</li>
                                      ))}
                                    </ul>
                                  </div>
                                )}

                                {/* Rollback Info */}
                                {preview.impactSummary.compatibility !== "direct" && (
                                  <div className="p-3 bg-blue-50 rounded-lg border border-blue-200">
                                    <h4 className="text-sm font-medium text-blue-800 flex items-center gap-2">
                                      <RefreshCw className="h-4 w-4" />
                                      Rollback Available
                                    </h4>
                                    <p className="mt-1 text-sm text-blue-700">
                                      Configuration can be reverted if issues occur
                                    </p>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}

                {/* Summary */}
                <Card className="bg-slate-50">
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="font-medium text-slate-900">Migration Summary</h4>
                        <p className="text-sm text-slate-600">
                          {Array.from(previews.values()).filter((p) => p.canProceed).length} of{" "}
                          {previews.size} migrations ready to execute
                        </p>
                      </div>
                      {Array.from(previews.values()).some((p) => !p.canProceed) && (
                        <div className="text-amber-600 text-sm flex items-center gap-2">
                          <AlertTriangle className="h-4 w-4" />
                          Some migrations have issues
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}
          </div>
        )}

        {/* Step 4: Execute */}
        {step === 4 && (
          <div className="space-y-6">
            <div className="text-center">
              <h2 className="text-2xl font-bold text-slate-900">Executing Migrations</h2>
              <p className="text-slate-600 mt-2">
                Migration is in progress. Please wait...
              </p>
            </div>

            <div className="space-y-3">
              {Array.from(selectedMigrations).map((contextName) => {
                const result = executionResults.find((r) => r.contextName === contextName);
                const isExecuting = currentlyExecuting === contextName;
                const isPending = !result && !isExecuting;

                return (
                  <div
                    key={contextName}
                    className={cn(
                      "flex items-center justify-between p-4 rounded-lg border",
                      result?.success && "bg-green-50 border-green-200",
                      result && !result.success && "bg-red-50 border-red-200",
                      isExecuting && "bg-indigo-50 border-indigo-200",
                      isPending && "bg-slate-50 border-slate-200"
                    )}
                  >
                    <div className="flex items-center gap-3">
                      {result?.success && <CheckCircle2 className="h-5 w-5 text-green-500" />}
                      {result && !result.success && <XCircle className="h-5 w-5 text-red-500" />}
                      {isExecuting && <Loader2 className="h-5 w-5 text-indigo-500 animate-spin" />}
                      {isPending && <Clock className="h-5 w-5 text-slate-400" />}
                      <span className="font-medium">{contextName}</span>
                    </div>
                    {result && (
                      <span className={cn("text-sm", result.success ? "text-green-700" : "text-red-700")}>
                        {result.message}
                      </span>
                    )}
                    {isExecuting && (
                      <span className="text-sm text-indigo-600">Migrating...</span>
                    )}
                    {isPending && (
                      <span className="text-sm text-slate-500">Pending</span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Step 5: Confirmation */}
        {step === 5 && (
          <div className="space-y-8">
            <div className="text-center">
              <div className="inline-flex items-center justify-center w-16 h-16 bg-green-100 rounded-full mb-4">
                <CheckCircle2 className="h-8 w-8 text-green-500" />
              </div>
              <h2 className="text-2xl font-bold text-slate-900">Migration Complete</h2>
              <p className="text-slate-600 mt-2">
                All selected migrations have been processed.
              </p>
            </div>

            {/* Results Summary */}
            <div className="grid grid-cols-2 gap-4 max-w-md mx-auto">
              <Card className="bg-green-50 border-green-200">
                <CardContent className="py-4 text-center">
                  <div className="text-3xl font-bold text-green-600">
                    {executionResults.filter((r) => r.success).length}
                  </div>
                  <div className="text-sm text-green-700">Successful</div>
                </CardContent>
              </Card>
              <Card className="bg-red-50 border-red-200">
                <CardContent className="py-4 text-center">
                  <div className="text-3xl font-bold text-red-600">
                    {executionResults.filter((r) => !r.success).length}
                  </div>
                  <div className="text-sm text-red-700">Failed</div>
                </CardContent>
              </Card>
            </div>

            {/* Detailed Results */}
            <Card>
              <CardHeader>
                <CardTitle>Migration Results</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {executionResults.map((result, i) => (
                    <div
                      key={i}
                      className={cn(
                        "flex items-center justify-between p-3 rounded-lg",
                        result.success ? "bg-green-50" : "bg-red-50"
                      )}
                    >
                      <div className="flex items-center gap-3">
                        {result.success ? (
                          <CheckCircle2 className="h-5 w-5 text-green-500" />
                        ) : (
                          <XCircle className="h-5 w-5 text-red-500" />
                        )}
                        <div>
                          <span className="font-medium">{result.contextName}</span>
                          <div className="flex items-center gap-2 text-sm text-slate-600">
                            <span>{result.previousAlgorithm}</span>
                            <ArrowRight className="h-3 w-3" />
                            <span>{result.newAlgorithm}</span>
                          </div>
                        </div>
                      </div>
                      <span className={cn("text-sm", result.success ? "text-green-700" : "text-red-700")}>
                        {result.message}
                      </span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Next Steps */}
            <Card className="bg-blue-50 border-blue-200">
              <CardContent className="py-5">
                <h4 className="font-semibold text-blue-900 flex items-center gap-2 mb-3">
                  <Zap className="h-5 w-5" />
                  Next Steps
                </h4>
                <ul className="space-y-2 text-sm text-blue-800">
                  <li className="flex items-start gap-2">
                    <Check className="h-4 w-4 mt-0.5 text-blue-600" />
                    Verify applications are working correctly with new algorithms
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="h-4 w-4 mt-0.5 text-blue-600" />
                    Monitor logs for any encryption/decryption errors
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="h-4 w-4 mt-0.5 text-blue-600" />
                    Schedule key rotation for migrated contexts
                  </li>
                  <li className="flex items-start gap-2">
                    <Check className="h-4 w-4 mt-0.5 text-blue-600" />
                    Update documentation and runbooks
                  </li>
                </ul>
              </CardContent>
            </Card>

            <div className="flex justify-center gap-4">
              <Button variant="outline" onClick={resetWizard}>
                <RefreshCw className="h-4 w-4 mr-2" />
                Start New Migration
              </Button>
              <Button onClick={() => window.location.href = "/admin/contexts"}>
                View Contexts
              </Button>
            </div>
          </div>
        )}

        {/* Navigation */}
        {step < 5 && (
          <div className="flex items-center justify-between pt-6 border-t">
            <Button
              variant="ghost"
              onClick={() => setStep((step - 1) as WizardStep)}
              disabled={step === 1}
            >
              <ChevronLeft className="h-5 w-5 mr-2" />
              Back
            </Button>

            {step === 1 && (
              <Button
                onClick={() => setStep(2)}
                disabled={!canProceed()}
              >
                Start Migration Wizard
                <ChevronRight className="h-5 w-5 ml-2" />
              </Button>
            )}

            {step === 2 && (
              <Button
                onClick={simulateMigrations}
                disabled={!canProceed() || simulating}
              >
                {simulating ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Simulating...
                  </>
                ) : (
                  <>
                    Preview Migrations
                    <ChevronRight className="h-5 w-5 ml-2" />
                  </>
                )}
              </Button>
            )}

            {step === 3 && (
              <Button
                onClick={() => {
                  setStep(4);
                  executeMigrations();
                }}
                disabled={!canProceed() || executing}
                className="bg-green-600 hover:bg-green-700"
              >
                <Play className="h-4 w-4 mr-2" />
                Execute Migrations
              </Button>
            )}
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
