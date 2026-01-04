"use client";

import { useEffect, useState, useMemo } from "react";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Info,
  AlertTriangle,
  Ban,
  CheckCircle2,
  XCircle,
  Play,
  Plus,
  Pencil,
  Trash2,
  Save,
  X,
  FileCheck,
  FileWarning,
  Settings,
  TrendingUp,
  Activity,
  Lock,
  ChevronDown,
  ChevronUp,
  Lightbulb,
  GitBranch,
  Server,
  Code2,
  Workflow,
  HelpCircle,
  Zap,
  Eye,
  BookOpen,
  RotateCw,
  Atom,
  Edit,
  Layers,
} from "lucide-react";
import { AdminLayout } from "@/components/admin-layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  api,
  Policy,
  PolicyEvaluationRequest,
  PolicyEvaluationResponse,
  Context,
  ClassificationAlgorithmPolicy,
  DataClassification,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { StatCard } from "@/components/ui/stat-card";

type SeverityFilter = "all" | "block" | "warn" | "info";
type PolicyTab = "rules" | "classification";

// Classification config for algorithm policy tab
const classificationConfig: Record<DataClassification, {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  description: string;
  color: string;
  bgColor: string;
  borderColor: string;
}> = {
  PUBLIC: {
    icon: Shield,
    label: "Public",
    description: "Non-sensitive, can be exposed",
    color: "text-slate-600",
    bgColor: "bg-slate-100",
    borderColor: "border-slate-300",
  },
  INTERNAL: {
    icon: ShieldCheck,
    label: "Internal",
    description: "Internal use, basic protection",
    color: "text-blue-600",
    bgColor: "bg-blue-100",
    borderColor: "border-blue-300",
  },
  SENSITIVE: {
    icon: ShieldAlert,
    label: "Sensitive",
    description: "PII, requires strong encryption",
    color: "text-amber-600",
    bgColor: "bg-amber-100",
    borderColor: "border-amber-300",
  },
  CRITICAL: {
    icon: ShieldX,
    label: "Critical",
    description: "Financial, health, maximum protection",
    color: "text-red-600",
    bgColor: "bg-red-100",
    borderColor: "border-red-300",
  },
};

const encryptionOptions = ["AES-128-GCM", "AES-256-GCM", "AES-256-GCM + HKDF", "ChaCha20-Poly1305"];
const macOptions = ["HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"];
const signingOptions = ["Ed25519", "Ed448", "ECDSA-P256", "ECDSA-P384"];

interface PolicyFormData {
  name: string;
  description: string;
  rule: string;
  severity: "block" | "warn" | "info";
  contexts: string[];
  enabled: boolean;
}

const emptyPolicy: PolicyFormData = {
  name: "",
  description: "",
  rule: "",
  severity: "warn",
  contexts: [],
  enabled: true,
};

export default function AdminPoliciesPage() {
  // Tab state
  const [activeTab, setActiveTab] = useState<PolicyTab>("rules");

  // Rules tab state
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [defaultPolicies, setDefaultPolicies] = useState<Policy[]>([]);
  const [contexts, setContexts] = useState<Context[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [showEvaluator, setShowEvaluator] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<string | null>(null);
  const [formData, setFormData] = useState<PolicyFormData>(emptyPolicy);
  const [saving, setSaving] = useState(false);

  // Evaluation state
  const [evalAlgorithm, setEvalAlgorithm] = useState("AES-256-GCM");
  const [evalContext, setEvalContext] = useState("");
  const [evalSensitivity, setEvalSensitivity] = useState<"low" | "medium" | "high" | "critical">("medium");
  const [evalPii, setEvalPii] = useState(false);
  const [evalPhi, setEvalPhi] = useState(false);
  const [evalPci, setEvalPci] = useState(false);
  const [evalResult, setEvalResult] = useState<PolicyEvaluationResponse | null>(null);
  const [evaluating, setEvaluating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showHowItWorks, setShowHowItWorks] = useState(false);

  // Classification tab state
  const [algorithmPolicies, setAlgorithmPolicies] = useState<ClassificationAlgorithmPolicy[]>([]);
  const [quantumReady, setQuantumReady] = useState(false);
  const [showClassificationEditModal, setShowClassificationEditModal] = useState(false);
  const [editingClassification, setEditingClassification] = useState<ClassificationAlgorithmPolicy | null>(null);
  const [classFormEncryption, setClassFormEncryption] = useState("");
  const [classFormMac, setClassFormMac] = useState("");
  const [classFormSigning, setClassFormSigning] = useState("");
  const [classFormRotation, setClassFormRotation] = useState(90);

  const loadData = async () => {
    setError(null);

    // Load each resource independently so partial failures don't break everything
    const results = await Promise.allSettled([
      api.listPolicies(),
      api.getDefaultPolicies(),
      api.listContexts(),
      api.getAlgorithmPolicies(),
    ]);

    const [policiesResult, defaultPoliciesResult, contextsResult, algorithmPoliciesResult] = results;

    // Handle custom policies
    if (policiesResult.status === "fulfilled") {
      setPolicies(policiesResult.value);
    } else {
      console.error("Failed to load custom policies:", policiesResult.reason);
    }

    // Handle default policies
    if (defaultPoliciesResult.status === "fulfilled") {
      setDefaultPolicies(defaultPoliciesResult.value);
    } else {
      console.error("Failed to load default policies:", defaultPoliciesResult.reason);
      // If default policies fail, it's likely an auth or backend issue
      setError(`Failed to load policies: ${defaultPoliciesResult.reason?.message || "Backend unavailable"}`);
    }

    // Handle contexts
    if (contextsResult.status === "fulfilled") {
      setContexts(contextsResult.value);
      if (contextsResult.value.length > 0 && !evalContext) {
        setEvalContext(contextsResult.value[0].name);
      }
    } else {
      console.error("Failed to load contexts:", contextsResult.reason);
    }

    // Handle algorithm policies
    if (algorithmPoliciesResult.status === "fulfilled") {
      setAlgorithmPolicies(algorithmPoliciesResult.value);
      setQuantumReady(algorithmPoliciesResult.value.some((p: ClassificationAlgorithmPolicy) => p.requireQuantumSafe));
    } else {
      console.error("Failed to load algorithm policies:", algorithmPoliciesResult.reason);
    }

    setLoading(false);
  };

  useEffect(() => {
    loadData();
  }, []);

  const allPolicies = [...defaultPolicies, ...policies];
  const filteredPolicies =
    severityFilter === "all"
      ? allPolicies
      : allPolicies.filter((p) => p.severity === severityFilter);

  const handleEvaluate = async () => {
    if (!evalContext) return;
    setEvaluating(true);
    try {
      const result = await api.evaluatePolicies({
        algorithm: evalAlgorithm,
        context_name: evalContext,
        sensitivity: evalSensitivity,
        pii: evalPii,
        phi: evalPhi,
        pci: evalPci,
        operation: "encrypt",
      });
      setEvalResult(result);
    } catch (error) {
      console.error("Evaluation failed:", error);
    } finally {
      setEvaluating(false);
    }
  };

  const handleCreatePolicy = async () => {
    if (!formData.name || !formData.rule) return;
    setSaving(true);
    try {
      await api.createPolicy(formData);
      await loadData();
      setShowCreateForm(false);
      setFormData(emptyPolicy);
    } catch (error) {
      console.error("Failed to create policy:", error);
      alert("Failed to create policy. Check the console for details.");
    } finally {
      setSaving(false);
    }
  };

  const handleUpdatePolicy = async () => {
    if (!editingPolicy || !formData.name || !formData.rule) return;
    setSaving(true);
    try {
      await api.updatePolicy(editingPolicy, formData);
      await loadData();
      setEditingPolicy(null);
      setFormData(emptyPolicy);
    } catch (error) {
      console.error("Failed to update policy:", error);
      alert("Failed to update policy. Check the console for details.");
    } finally {
      setSaving(false);
    }
  };

  const handleDeletePolicy = async (policyName: string) => {
    if (!confirm(`Delete policy "${policyName}"? This cannot be undone.`)) return;
    try {
      await api.deletePolicy(policyName);
      await loadData();
    } catch (error) {
      console.error("Failed to delete policy:", error);
      alert("Failed to delete policy. Default policies cannot be deleted.");
    }
  };

  const handleTogglePolicy = async (policy: Policy) => {
    try {
      await api.updatePolicy(policy.name, { enabled: !policy.enabled });
      await loadData();
    } catch (error) {
      console.error("Failed to toggle policy:", error);
    }
  };

  const startEditing = (policy: Policy) => {
    setFormData({
      name: policy.name,
      description: policy.description,
      rule: policy.rule,
      severity: policy.severity as "block" | "warn" | "info",
      contexts: policy.contexts,
      enabled: policy.enabled,
    });
    setEditingPolicy(policy.name);
    setShowCreateForm(false);
  };

  const cancelForm = () => {
    setShowCreateForm(false);
    setEditingPolicy(null);
    setFormData(emptyPolicy);
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "block":
        return <Ban className="h-4 w-4 text-red-500" />;
      case "warn":
        return <AlertTriangle className="h-4 w-4 text-amber-500" />;
      default:
        return <Info className="h-4 w-4 text-blue-500" />;
    }
  };

  const getSeverityBadge = (severity: string) => {
    const styles: Record<string, string> = {
      block: "bg-red-100 text-red-700",
      warn: "bg-amber-100 text-amber-700",
      info: "bg-blue-100 text-blue-700",
    };
    return (
      <span className={cn("px-2 py-0.5 rounded text-xs font-medium", styles[severity] || styles.info)}>
        {severity}
      </span>
    );
  };

  const blockCount = allPolicies.filter((p) => p.severity === "block" && p.enabled).length;
  const warnCount = allPolicies.filter((p) => p.severity === "warn" && p.enabled).length;
  const infoCount = allPolicies.filter((p) => p.severity === "info" && p.enabled).length;

  const isDefault = (policyName: string) => defaultPolicies.some((p) => p.name === policyName);

  // Computed metrics for policy health overview
  const policyMetrics = useMemo(() => {
    const total = allPolicies.length;
    const enabled = allPolicies.filter((p) => p.enabled).length;
    const disabled = total - enabled;
    const custom = policies.length;
    const defaults = defaultPolicies.length;

    // Calculate enforcement score: weighted by severity and enabled status
    const severityWeights = { block: 3, warn: 2, info: 1 };
    const maxScore = allPolicies.reduce((sum, p) => sum + severityWeights[p.severity as keyof typeof severityWeights], 0);
    const actualScore = allPolicies
      .filter((p) => p.enabled)
      .reduce((sum, p) => sum + severityWeights[p.severity as keyof typeof severityWeights], 0);
    const enforcementScore = maxScore > 0 ? Math.round((actualScore / maxScore) * 100) : 0;

    // Context coverage - how many contexts have specific policies
    const contextsWithPolicies = new Set<string>();
    allPolicies.forEach((p) => p.contexts.forEach((c) => contextsWithPolicies.add(c)));
    const contextCoverage = contexts.length > 0
      ? Math.round((contextsWithPolicies.size / contexts.length) * 100)
      : 100; // If no specific context targeting, assume all covered

    // Security posture - based on blocking policies being enabled
    const blockingEnabled = allPolicies.filter((p) => p.severity === "block" && p.enabled).length;
    const totalBlocking = allPolicies.filter((p) => p.severity === "block").length;
    const securityPosture = totalBlocking > 0 ? Math.round((blockingEnabled / totalBlocking) * 100) : 100;

    return {
      total,
      enabled,
      disabled,
      custom,
      defaults,
      enforcementScore,
      contextCoverage,
      securityPosture,
      blockingEnabled,
      totalBlocking,
    };
  }, [allPolicies, policies, defaultPolicies, contexts]);

  // Score color based on enforcement level
  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-emerald-600";
    if (score >= 60) return "text-amber-600";
    return "text-red-600";
  };

  const getScoreStroke = (score: number) => {
    if (score >= 80) return "#10b981";
    if (score >= 60) return "#f59e0b";
    return "#ef4444";
  };

  // Classification tab handlers
  const openClassificationEdit = (policy: ClassificationAlgorithmPolicy) => {
    setEditingClassification(policy);
    setClassFormEncryption(policy.defaultEncryptionAlgorithm);
    setClassFormMac(policy.defaultMacAlgorithm);
    setClassFormSigning(policy.defaultSigningAlgorithm || "");
    setClassFormRotation(policy.keyRotationDays);
    setShowClassificationEditModal(true);
  };

  const closeClassificationEdit = () => {
    setShowClassificationEditModal(false);
    setEditingClassification(null);
  };

  const handleSaveClassification = async () => {
    if (!editingClassification) return;
    setSaving(true);
    try {
      await api.updateAlgorithmPolicyByClassification(editingClassification.classification, {
        defaultEncryptionAlgorithm: classFormEncryption,
        defaultMacAlgorithm: classFormMac,
        defaultSigningAlgorithm: classFormSigning || null,
        keyRotationDays: classFormRotation,
      });
      await loadData();
      closeClassificationEdit();
    } catch (error) {
      console.error("Failed to save policy:", error);
      alert("Failed to save policy. Please try again.");
    } finally {
      setSaving(false);
    }
  };

  const handleToggleQuantumReady = async () => {
    setQuantumReady(!quantumReady);
    // In a real implementation, this would call an API
    console.log("Quantum ready toggled:", !quantumReady);
  };

  return (
    <AdminLayout
      title="Policy Management"
      subtitle="Configure cryptographic policies that govern algorithm usage"
      onRefresh={loadData}
    >
      <div className="space-y-8">
        {/* Error Banner */}
        {error && (
          <div className="p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-red-500 mt-0.5 flex-shrink-0" />
            <div>
              <h3 className="font-medium text-red-900">Connection Error</h3>
              <p className="text-sm text-red-700 mt-1">{error}</p>
              <p className="text-xs text-red-600 mt-2">
                Make sure the backend is running on port 8003. Run: <code className="bg-red-100 px-1 rounded">docker compose up -d</code>
              </p>
            </div>
          </div>
        )}

        {/* Tab Navigation */}
        <div className="border-b border-slate-200">
          <nav className="flex gap-4" aria-label="Tabs">
            <button
              onClick={() => setActiveTab("rules")}
              className={cn(
                "flex items-center gap-2 px-1 py-3 text-sm font-medium border-b-2 transition-colors",
                activeTab === "rules"
                  ? "border-indigo-600 text-indigo-600"
                  : "border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300"
              )}
            >
              <ShieldCheck className="h-4 w-4" />
              Policy Rules
            </button>
            <button
              onClick={() => setActiveTab("classification")}
              className={cn(
                "flex items-center gap-2 px-1 py-3 text-sm font-medium border-b-2 transition-colors",
                activeTab === "classification"
                  ? "border-indigo-600 text-indigo-600"
                  : "border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300"
              )}
            >
              <Layers className="h-4 w-4" />
              By Classification
            </button>
          </nav>
        </div>

        {/* Rules Tab Content */}
        {activeTab === "rules" && (
          <>
        {/* How Policies Work - Expandable Explainer */}
        <div className="bg-gradient-to-r from-indigo-50 to-blue-50 border border-indigo-100 rounded-xl overflow-hidden">
          <button
            onClick={() => setShowHowItWorks(!showHowItWorks)}
            className="w-full p-4 flex items-center justify-between text-left hover:bg-indigo-50/50 transition-colors"
          >
            <div className="flex items-center gap-3">
              <div className="p-2 bg-indigo-100 rounded-lg">
                <Lightbulb className="h-5 w-5 text-indigo-600" />
              </div>
              <div>
                <h3 className="font-semibold text-slate-900">How Policies Work</h3>
                <p className="text-sm text-slate-600">
                  Policies automatically enforce cryptographic standards across your organization
                </p>
              </div>
            </div>
            {showHowItWorks ? (
              <ChevronUp className="h-5 w-5 text-slate-400" />
            ) : (
              <ChevronDown className="h-5 w-5 text-slate-400" />
            )}
          </button>

          {showHowItWorks && (
            <div className="px-4 pb-4 space-y-6">
              {/* Quick Summary */}
              <div className="p-4 bg-white/60 rounded-lg">
                <p className="text-sm text-slate-700">
                  Policies define rules that are evaluated whenever cryptographic operations occur.
                  They check the algorithm being used, the data sensitivity, and compliance requirements
                  to determine if the operation should be <span className="font-medium text-green-600">allowed</span>,
                  <span className="font-medium text-amber-600"> warned</span>, or
                  <span className="font-medium text-red-600"> blocked</span>.
                </p>
              </div>

              {/* When Policies Are Evaluated */}
              <div>
                <h4 className="text-sm font-semibold text-slate-900 mb-3 flex items-center gap-2">
                  <Zap className="h-4 w-4 text-amber-500" />
                  When Policies Are Evaluated
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <div className="p-3 bg-white rounded-lg border border-slate-200">
                    <div className="flex items-center gap-2 mb-2">
                      <Code2 className="h-4 w-4 text-blue-500" />
                      <span className="font-medium text-sm">SDK Initialization</span>
                    </div>
                    <p className="text-xs text-slate-600">
                      When apps start, the SDK scans for crypto libraries and reports inventory.
                      Policies evaluate detected algorithms against your rules.
                    </p>
                  </div>
                  <div className="p-3 bg-white rounded-lg border border-slate-200">
                    <div className="flex items-center gap-2 mb-2">
                      <GitBranch className="h-4 w-4 text-purple-500" />
                      <span className="font-medium text-sm">CI/CD Pipeline Gates</span>
                    </div>
                    <p className="text-xs text-slate-600">
                      Before deployment, CI/CD gates check code for crypto usage.
                      Blocking policies can fail the build if violations are found.
                    </p>
                  </div>
                  <div className="p-3 bg-white rounded-lg border border-slate-200">
                    <div className="flex items-center gap-2 mb-2">
                      <Server className="h-4 w-4 text-green-500" />
                      <span className="font-medium text-sm">Runtime Operations</span>
                    </div>
                    <p className="text-xs text-slate-600">
                      Every encrypt/decrypt call is evaluated in real-time.
                      Blocking policies prevent unauthorized algorithms from being used.
                    </p>
                  </div>
                </div>
              </div>

              {/* Severity Levels Explained */}
              <div>
                <h4 className="text-sm font-semibold text-slate-900 mb-3 flex items-center gap-2">
                  <Shield className="h-4 w-4 text-blue-500" />
                  What Each Severity Level Does
                </h4>
                <div className="space-y-2">
                  <div className="flex items-start gap-3 p-3 bg-red-50 rounded-lg border border-red-100">
                    <Ban className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-red-900">Block</span>
                        <span className="text-xs px-1.5 py-0.5 bg-red-100 text-red-700 rounded">Strictest</span>
                      </div>
                      <p className="text-sm text-red-800 mt-1">
                        <strong>Prevents the operation entirely.</strong> Use for deprecated algorithms (DES, MD5),
                        compliance violations, or critical security requirements. The SDK will throw an error
                        and CI/CD gates will fail the build.
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 p-3 bg-amber-50 rounded-lg border border-amber-100">
                    <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5 shrink-0" />
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-amber-900">Warn</span>
                        <span className="text-xs px-1.5 py-0.5 bg-amber-100 text-amber-700 rounded">Balanced</span>
                      </div>
                      <p className="text-sm text-amber-800 mt-1">
                        <strong>Allows the operation but logs a warning.</strong> Ideal for quantum-vulnerable
                        algorithms that need migration. Operations succeed, but violations appear in audit logs
                        and dashboards for remediation planning.
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3 p-3 bg-blue-50 rounded-lg border border-blue-100">
                    <Eye className="h-5 w-5 text-blue-500 mt-0.5 shrink-0" />
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-blue-900">Info</span>
                        <span className="text-xs px-1.5 py-0.5 bg-blue-100 text-blue-700 rounded">Monitoring</span>
                      </div>
                      <p className="text-sm text-blue-800 mt-1">
                        <strong>Silent observation only.</strong> Use for tracking adoption of new algorithms
                        or gathering usage metrics. No user-visible warnings, data collected for analytics
                        and reporting.
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Rule Syntax Quick Reference */}
              <div>
                <h4 className="text-sm font-semibold text-slate-900 mb-3 flex items-center gap-2">
                  <BookOpen className="h-4 w-4 text-indigo-500" />
                  Rule Syntax Quick Reference
                </h4>
                <div className="p-3 bg-white rounded-lg border border-slate-200">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div>
                      <p className="font-medium text-slate-700 mb-2">Algorithm Properties:</p>
                      <ul className="space-y-1 text-xs text-slate-600 font-mono">
                        <li><code className="bg-slate-100 px-1 rounded">algorithm.name</code> - Algorithm name (AES-256-GCM)</li>
                        <li><code className="bg-slate-100 px-1 rounded">algorithm.key_bits</code> - Key size (256, 128)</li>
                        <li><code className="bg-slate-100 px-1 rounded">algorithm.quantum_resistant</code> - PQC status (true/false)</li>
                      </ul>
                    </div>
                    <div>
                      <p className="font-medium text-slate-700 mb-2">Context Properties:</p>
                      <ul className="space-y-1 text-xs text-slate-600 font-mono">
                        <li><code className="bg-slate-100 px-1 rounded">context.sensitivity</code> - Data sensitivity level</li>
                        <li><code className="bg-slate-100 px-1 rounded">context.pii</code> / <code className="bg-slate-100 px-1 rounded">phi</code> / <code className="bg-slate-100 px-1 rounded">pci</code> - Compliance flags</li>
                        <li><code className="bg-slate-100 px-1 rounded">context.frameworks</code> - Compliance frameworks</li>
                      </ul>
                    </div>
                  </div>
                  <div className="mt-3 pt-3 border-t border-slate-100">
                    <p className="text-xs text-slate-500">
                      <strong>Example:</strong> <code className="bg-slate-100 px-1 rounded">algorithm.key_bits &gt;= 256 and context.pci == true</code>
                      - Requires 256-bit keys for PCI data
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-3">
          <Button
            onClick={() => {
              setShowCreateForm(true);
              setEditingPolicy(null);
              setFormData(emptyPolicy);
            }}
          >
            <Plus className="h-4 w-4 mr-2" />
            Create Policy
          </Button>
          <Button
            variant={showEvaluator ? "default" : "outline"}
            onClick={() => setShowEvaluator(!showEvaluator)}
          >
            <Play className="h-4 w-4 mr-2" />
            Test Policies
          </Button>
        </div>

        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : (
          <>
            {/* Create/Edit Form */}
            {(showCreateForm || editingPolicy) && (
              <Card className="border-2 border-indigo-200">
                <CardHeader>
                  <CardTitle className="flex items-center justify-between">
                    <span className="flex items-center gap-2">
                      {editingPolicy ? <Pencil className="h-5 w-5" /> : <Plus className="h-5 w-5" />}
                      {editingPolicy ? "Edit Policy" : "Create New Policy"}
                    </span>
                    <Button variant="ghost" size="sm" onClick={cancelForm}>
                      <X className="h-4 w-4" />
                    </Button>
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium text-slate-700 block mb-1">
                        Policy Name *
                      </label>
                      <input
                        type="text"
                        value={formData.name}
                        onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                        placeholder="e.g., require-aes-256"
                        className="w-full px-3 py-2 border rounded-md text-sm"
                        disabled={!!editingPolicy}
                      />
                    </div>
                    <div>
                      <label className="text-sm font-medium text-slate-700 block mb-1">
                        Severity *
                      </label>
                      <select
                        value={formData.severity}
                        onChange={(e) => setFormData({ ...formData, severity: e.target.value as any })}
                        className="w-full px-3 py-2 border rounded-md text-sm"
                      >
                        <option value="block">Block - Prevent operation</option>
                        <option value="warn">Warn - Log but allow</option>
                        <option value="info">Info - Monitor only</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="text-sm font-medium text-slate-700 block mb-1">
                      Description *
                    </label>
                    <input
                      type="text"
                      value={formData.description}
                      onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                      placeholder="What this policy enforces..."
                      className="w-full px-3 py-2 border rounded-md text-sm"
                    />
                  </div>

                  <div>
                    <label className="text-sm font-medium text-slate-700 block mb-1">
                      Rule Expression *
                    </label>
                    <textarea
                      value={formData.rule}
                      onChange={(e) => setFormData({ ...formData, rule: e.target.value })}
                      placeholder="e.g., algorithm.key_bits >= 256"
                      className="w-full px-3 py-2 border rounded-md text-sm font-mono"
                      rows={2}
                    />
                    <p className="text-xs text-slate-500 mt-1">
                      Available variables: algorithm.name, algorithm.key_bits, algorithm.quantum_resistant,
                      context.sensitivity, context.pii, context.phi, context.pci, context.frameworks
                    </p>
                  </div>

                  <div>
                    <label className="text-sm font-medium text-slate-700 block mb-1">
                      Apply to Contexts (leave empty for all)
                    </label>
                    <div className="flex flex-wrap gap-2">
                      {contexts.map((ctx) => (
                        <label key={ctx.name} className="flex items-center gap-1 text-sm">
                          <input
                            type="checkbox"
                            checked={formData.contexts.includes(ctx.name)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setFormData({ ...formData, contexts: [...formData.contexts, ctx.name] });
                              } else {
                                setFormData({ ...formData, contexts: formData.contexts.filter((c) => c !== ctx.name) });
                              }
                            }}
                            className="rounded"
                          />
                          {ctx.display_name}
                        </label>
                      ))}
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id="enabled"
                      checked={formData.enabled}
                      onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
                      className="rounded"
                    />
                    <label htmlFor="enabled" className="text-sm font-medium text-slate-700">
                      Enabled
                    </label>
                  </div>

                  <div className="flex justify-end gap-2">
                    <Button variant="outline" onClick={cancelForm}>
                      Cancel
                    </Button>
                    <Button
                      onClick={editingPolicy ? handleUpdatePolicy : handleCreatePolicy}
                      disabled={saving || !formData.name || !formData.rule}
                    >
                      {saving ? (
                        <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full mr-2" />
                      ) : (
                        <Save className="h-4 w-4 mr-2" />
                      )}
                      {editingPolicy ? "Save Changes" : "Create Policy"}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Policy Evaluator */}
            {showEvaluator && (
              <Card className="border-2 border-primary/20">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    Policy Evaluator
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p className="text-sm text-slate-600">
                    Test how policies will evaluate for a given algorithm and context configuration.
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div>
                      <label className="text-sm font-medium text-slate-700 block mb-1">
                        Algorithm
                      </label>
                      <select
                        value={evalAlgorithm}
                        onChange={(e) => setEvalAlgorithm(e.target.value)}
                        className="w-full px-3 py-2 border rounded-md text-sm"
                      >
                        <option value="AES-256-GCM">AES-256-GCM</option>
                        <option value="AES-128-GCM">AES-128-GCM</option>
                        <option value="ChaCha20-Poly1305">ChaCha20-Poly1305</option>
                        <option value="DES">DES (legacy)</option>
                        <option value="3DES">3DES (legacy)</option>
                        <option value="CRYSTALS-Kyber">CRYSTALS-Kyber (PQC)</option>
                      </select>
                    </div>

                    <div>
                      <label className="text-sm font-medium text-slate-700 block mb-1">
                        Context
                      </label>
                      <select
                        value={evalContext}
                        onChange={(e) => setEvalContext(e.target.value)}
                        className="w-full px-3 py-2 border rounded-md text-sm"
                      >
                        {contexts.map((ctx) => (
                          <option key={ctx.name} value={ctx.name}>
                            {ctx.display_name}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div>
                      <label className="text-sm font-medium text-slate-700 block mb-1">
                        Sensitivity
                      </label>
                      <select
                        value={evalSensitivity}
                        onChange={(e) => setEvalSensitivity(e.target.value as any)}
                        className="w-full px-3 py-2 border rounded-md text-sm"
                      >
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                        <option value="critical">Critical</option>
                      </select>
                    </div>

                    <div>
                      <label className="text-sm font-medium text-slate-700 block mb-1">
                        Data Types
                      </label>
                      <div className="flex gap-4">
                        <label className="flex items-center gap-1 text-sm">
                          <input
                            type="checkbox"
                            checked={evalPii}
                            onChange={(e) => setEvalPii(e.target.checked)}
                            className="rounded"
                          />
                          PII
                        </label>
                        <label className="flex items-center gap-1 text-sm">
                          <input
                            type="checkbox"
                            checked={evalPhi}
                            onChange={(e) => setEvalPhi(e.target.checked)}
                            className="rounded"
                          />
                          PHI
                        </label>
                        <label className="flex items-center gap-1 text-sm">
                          <input
                            type="checkbox"
                            checked={evalPci}
                            onChange={(e) => setEvalPci(e.target.checked)}
                            className="rounded"
                          />
                          PCI
                        </label>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <Button onClick={handleEvaluate} disabled={evaluating || !evalContext}>
                      {evaluating ? (
                        <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full mr-2" />
                      ) : (
                        <Play className="h-4 w-4 mr-2" />
                      )}
                      Evaluate
                    </Button>

                    {evalResult && (
                      <div className="flex items-center gap-3">
                        {evalResult.allowed ? (
                          <div className="flex items-center gap-2 text-green-600">
                            <CheckCircle2 className="h-5 w-5" />
                            <span className="font-medium">Allowed</span>
                          </div>
                        ) : (
                          <div className="flex items-center gap-2 text-red-600">
                            <XCircle className="h-5 w-5" />
                            <span className="font-medium">Blocked</span>
                          </div>
                        )}
                        <span className="text-sm text-slate-500">
                          {evalResult.blocking_violations} blocking, {evalResult.warning_violations} warnings
                        </span>
                      </div>
                    )}
                  </div>

                  {evalResult && evalResult.results.length > 0 && (
                    <div className="mt-4 border rounded-lg overflow-hidden">
                      <table className="w-full text-sm">
                        <thead className="bg-slate-50">
                          <tr>
                            <th className="px-4 py-2 text-left font-medium text-slate-600">Policy</th>
                            <th className="px-4 py-2 text-left font-medium text-slate-600">Result</th>
                            <th className="px-4 py-2 text-left font-medium text-slate-600">Severity</th>
                            <th className="px-4 py-2 text-left font-medium text-slate-600">Message</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y">
                          {evalResult.results.map((r, i) => (
                            <tr key={i} className={cn(!r.passed && "bg-red-50/50")}>
                              <td className="px-4 py-2 font-mono text-xs">{r.policy_name}</td>
                              <td className="px-4 py-2">
                                {r.passed ? (
                                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                                ) : (
                                  <XCircle className="h-4 w-4 text-red-500" />
                                )}
                              </td>
                              <td className="px-4 py-2">{getSeverityBadge(r.severity)}</td>
                              <td className="px-4 py-2 text-slate-600">{r.message || "-"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* Policy Health Overview */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Enforcement Score Circle */}
              <Card className="lg:col-span-3">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium text-slate-600">
                    Policy Enforcement
                  </CardTitle>
                </CardHeader>
                <CardContent className="flex flex-col items-center justify-center">
                  <div className="relative w-32 h-32">
                    <svg className="w-32 h-32 transform -rotate-90">
                      <circle
                        cx="64"
                        cy="64"
                        r="56"
                        stroke="#e5e7eb"
                        strokeWidth="12"
                        fill="none"
                      />
                      <circle
                        cx="64"
                        cy="64"
                        r="56"
                        stroke={getScoreStroke(policyMetrics.enforcementScore)}
                        strokeWidth="12"
                        fill="none"
                        strokeLinecap="round"
                        strokeDasharray={`${(policyMetrics.enforcementScore / 100) * 351.86} 351.86`}
                        className="transition-all duration-1000 ease-out"
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className={cn("text-3xl font-bold", getScoreColor(policyMetrics.enforcementScore))}>
                        {policyMetrics.enforcementScore}%
                      </span>
                      <span className="text-xs text-slate-500">Active</span>
                    </div>
                  </div>
                  <div className="mt-4 text-center">
                    <p className="text-sm text-slate-600">
                      {policyMetrics.enabled} of {policyMetrics.total} policies enabled
                    </p>
                    <p className="text-xs text-slate-500 mt-1">
                      Weighted by severity level
                    </p>
                  </div>
                </CardContent>
              </Card>

              {/* Stats Grid */}
              <div className="lg:col-span-9 grid grid-cols-2 md:grid-cols-3 gap-4">
                <StatCard
                  title="Total Policies"
                  value={policyMetrics.total}
                  subtitle={`${policyMetrics.defaults} default, ${policyMetrics.custom} custom`}
                  icon={<Shield className="h-5 w-5" />}
                  color="blue"
                />
                <StatCard
                  title="Active Policies"
                  value={policyMetrics.enabled}
                  subtitle={`${policyMetrics.disabled} currently disabled`}
                  icon={<CheckCircle2 className="h-5 w-5" />}
                  color="green"
                />
                <StatCard
                  title="Custom Policies"
                  value={policyMetrics.custom}
                  subtitle="Organization-specific rules"
                  icon={<Settings className="h-5 w-5" />}
                  color="purple"
                />
                <StatCard
                  title="Security Posture"
                  value={`${policyMetrics.securityPosture}%`}
                  subtitle={`${policyMetrics.blockingEnabled}/${policyMetrics.totalBlocking} blocking active`}
                  icon={<Lock className="h-5 w-5" />}
                  color={policyMetrics.securityPosture >= 80 ? "green" : policyMetrics.securityPosture >= 60 ? "amber" : "rose"}
                />
                <StatCard
                  title="Context Coverage"
                  value={policyMetrics.contextCoverage > 0 ? `${policyMetrics.contextCoverage}%` : "All"}
                  subtitle="Contexts with policies"
                  icon={<TrendingUp className="h-5 w-5" />}
                  color="blue"
                />
                <StatCard
                  title="Compliance Rules"
                  value={blockCount + warnCount}
                  subtitle={`${blockCount} blocking, ${warnCount} warnings`}
                  icon={<FileCheck className="h-5 w-5" />}
                  color="default"
                />
              </div>
            </div>

            {/* Severity Filter Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Card
                className={cn(
                  "cursor-pointer transition-all hover:shadow-md",
                  severityFilter === "block" ? "ring-2 ring-red-500 bg-red-50" : "hover:border-red-300"
                )}
                onClick={() => setSeverityFilter(severityFilter === "block" ? "all" : "block")}
              >
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-red-100">
                        <Ban className="h-5 w-5 text-red-600" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-slate-600">Blocking Policies</p>
                        <p className="text-2xl font-bold text-red-600">{blockCount}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-slate-500">Click to filter</p>
                      <p className="text-xs text-red-600 font-medium">Prevents operations</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card
                className={cn(
                  "cursor-pointer transition-all hover:shadow-md",
                  severityFilter === "warn" ? "ring-2 ring-amber-500 bg-amber-50" : "hover:border-amber-300"
                )}
                onClick={() => setSeverityFilter(severityFilter === "warn" ? "all" : "warn")}
              >
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-amber-100">
                        <AlertTriangle className="h-5 w-5 text-amber-600" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-slate-600">Warning Policies</p>
                        <p className="text-2xl font-bold text-amber-600">{warnCount}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-slate-500">Click to filter</p>
                      <p className="text-xs text-amber-600 font-medium">Logs but allows</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card
                className={cn(
                  "cursor-pointer transition-all hover:shadow-md",
                  severityFilter === "info" ? "ring-2 ring-blue-500 bg-blue-50" : "hover:border-blue-300"
                )}
                onClick={() => setSeverityFilter(severityFilter === "info" ? "all" : "info")}
              >
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-blue-100">
                        <Info className="h-5 w-5 text-blue-600" />
                      </div>
                      <div>
                        <p className="text-sm font-medium text-slate-600">Info Policies</p>
                        <p className="text-2xl font-bold text-blue-600">{infoCount}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-slate-500">Click to filter</p>
                      <p className="text-xs text-blue-600 font-medium">Monitoring only</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Policy List */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <div>
                    <span>
                      {severityFilter === "all" ? "All Policies" : `${severityFilter.charAt(0).toUpperCase() + severityFilter.slice(1)} Policies`}
                    </span>
                    <p className="text-sm font-normal text-slate-500 mt-1">
                      Click on a policy to see details. Toggle the switch to enable/disable.
                    </p>
                  </div>
                  {severityFilter !== "all" && (
                    <Button variant="ghost" size="sm" onClick={() => setSeverityFilter("all")}>
                      Clear filter
                    </Button>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {filteredPolicies.map((policy) => {
                    // Generate contextual "What happens" text based on severity
                    const getWhatHappens = () => {
                      switch (policy.severity) {
                        case "block":
                          return "Operations matching this rule will be blocked. SDK throws error, CI/CD fails build.";
                        case "warn":
                          return "Operations are allowed but logged as warnings. Visible in audit logs and dashboards.";
                        case "info":
                          return "Silently tracked for analytics. No warnings shown to users.";
                        default:
                          return "";
                      }
                    };

                    // Generate "When applies" text
                    const getWhenApplies = () => {
                      if (policy.contexts.length === 0) {
                        return "Applies to all contexts";
                      }
                      return `Only applies to: ${policy.contexts.join(", ")}`;
                    };

                    return (
                      <div
                        key={policy.name}
                        className={cn(
                          "border rounded-lg overflow-hidden transition-all",
                          !policy.enabled && "opacity-60",
                          policy.severity === "block" && policy.enabled && "border-l-4 border-l-red-400",
                          policy.severity === "warn" && policy.enabled && "border-l-4 border-l-amber-400",
                          policy.severity === "info" && policy.enabled && "border-l-4 border-l-blue-400",
                        )}
                      >
                        {/* Policy Header */}
                        <div className="p-4">
                          <div className="flex items-start justify-between">
                            <div className="flex items-start gap-3">
                              <div className={cn(
                                "p-2 rounded-lg shrink-0",
                                policy.severity === "block" && "bg-red-50",
                                policy.severity === "warn" && "bg-amber-50",
                                policy.severity === "info" && "bg-blue-50",
                              )}>
                                {getSeverityIcon(policy.severity)}
                              </div>
                              <div className="min-w-0">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <h3 className="font-medium text-slate-900">{policy.name}</h3>
                                  {getSeverityBadge(policy.severity)}
                                  {isDefault(policy.name) && (
                                    <span className="px-2 py-0.5 rounded text-xs font-medium bg-indigo-100 text-indigo-700">
                                      default
                                    </span>
                                  )}
                                  {!policy.enabled && (
                                    <span className="px-2 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-600">
                                      disabled
                                    </span>
                                  )}
                                </div>
                                <p className="text-sm text-slate-600 mt-1">
                                  {policy.description}
                                </p>
                              </div>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              {!isDefault(policy.name) && (
                                <>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => startEditing(policy)}
                                    title="Edit policy"
                                  >
                                    <Pencil className="h-4 w-4" />
                                  </Button>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => handleDeletePolicy(policy.name)}
                                    title="Delete policy"
                                    className="text-red-500 hover:text-red-700"
                                  >
                                    <Trash2 className="h-4 w-4" />
                                  </Button>
                                </>
                              )}
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleTogglePolicy(policy)}
                                title={policy.enabled ? "Disable policy" : "Enable policy"}
                              >
                                {policy.enabled ? (
                                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                                ) : (
                                  <XCircle className="h-4 w-4 text-slate-400" />
                                )}
                              </Button>
                            </div>
                          </div>
                        </div>

                        {/* Policy Details Footer */}
                        <div className="px-4 py-3 bg-slate-50 border-t border-slate-100">
                          <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-xs">
                            {/* Rule Expression */}
                            <div className="flex items-center gap-1.5">
                              <Code2 className="h-3.5 w-3.5 text-slate-400" />
                              <span className="text-slate-500">Rule:</span>
                              <code className="font-mono text-slate-700 bg-white px-1.5 py-0.5 rounded border border-slate-200">
                                {policy.rule}
                              </code>
                            </div>

                            {/* What Happens */}
                            <div className="flex items-center gap-1.5">
                              <Zap className="h-3.5 w-3.5 text-slate-400" />
                              <span className="text-slate-500">Effect:</span>
                              <span className={cn(
                                "font-medium",
                                policy.severity === "block" && "text-red-600",
                                policy.severity === "warn" && "text-amber-600",
                                policy.severity === "info" && "text-blue-600",
                              )}>
                                {policy.severity === "block" && "Blocks operation"}
                                {policy.severity === "warn" && "Warns but allows"}
                                {policy.severity === "info" && "Silent tracking"}
                              </span>
                            </div>

                            {/* Context Scope */}
                            <div className="flex items-center gap-1.5">
                              <Workflow className="h-3.5 w-3.5 text-slate-400" />
                              <span className="text-slate-500">Scope:</span>
                              {policy.contexts.length === 0 ? (
                                <span className="text-slate-700">All contexts</span>
                              ) : (
                                <div className="flex gap-1">
                                  {policy.contexts.map((ctx) => (
                                    <span
                                      key={ctx}
                                      className="px-1.5 py-0.5 rounded bg-white border border-slate-200 text-slate-700"
                                    >
                                      {ctx}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}

                  {filteredPolicies.length === 0 && (
                    <div className="text-center py-8 text-slate-500">
                      No policies found with this filter
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </>
        )}
          </>
        )}

        {/* Classification Tab Content */}
        {activeTab === "classification" && (
          <>
            {/* Info Banner */}
            <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
              <div className="flex items-start gap-3">
                <Info className="h-5 w-5 text-blue-500 mt-0.5 flex-shrink-0" />
                <div className="text-sm">
                  <p className="font-medium text-blue-800 mb-1">About Algorithm Policies</p>
                  <p className="text-blue-700">
                    These policies determine which algorithms are automatically assigned when creating new contexts.
                    Individual contexts can override these defaults if needed.
                  </p>
                </div>
              </div>
            </div>

            {/* Policy Cards Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {algorithmPolicies.map((policy) => {
                const config = classificationConfig[policy.classification];
                const Icon = config.icon;

                return (
                  <Card key={policy.classification} className={cn("relative overflow-hidden", config.borderColor, "border-l-4")}>
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className={cn("h-10 w-10 rounded-lg flex items-center justify-center", config.bgColor)}>
                            <Icon className={cn("h-5 w-5", config.color)} />
                          </div>
                          <div>
                            <CardTitle className="text-base font-semibold">{config.label}</CardTitle>
                            <p className="text-xs text-slate-500">{config.description}</p>
                          </div>
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => openClassificationEdit(policy)}
                        >
                          <Edit className="h-4 w-4 mr-1.5" />
                          Edit
                        </Button>
                      </div>
                    </CardHeader>

                    <CardContent className="space-y-4">
                      {/* Algorithm Details */}
                      <div className="grid grid-cols-1 gap-3">
                        <div className="flex items-center justify-between py-2 px-3 bg-slate-50 rounded-lg">
                          <span className="text-sm text-slate-600">Encryption</span>
                          <Badge variant="secondary" className="font-mono text-xs">
                            {policy.defaultEncryptionAlgorithm}
                          </Badge>
                        </div>
                        <div className="flex items-center justify-between py-2 px-3 bg-slate-50 rounded-lg">
                          <span className="text-sm text-slate-600">MAC</span>
                          <Badge variant="secondary" className="font-mono text-xs">
                            {policy.defaultMacAlgorithm}
                          </Badge>
                        </div>
                        <div className="flex items-center justify-between py-2 px-3 bg-slate-50 rounded-lg">
                          <span className="text-sm text-slate-600">Signing</span>
                          <Badge variant="secondary" className="font-mono text-xs">
                            {policy.defaultSigningAlgorithm || "None"}
                          </Badge>
                        </div>
                      </div>

                      {/* Rotation Schedule */}
                      <div className="pt-3 border-t border-slate-100">
                        <div className="flex items-center gap-2 mb-2">
                          <RotateCw className="h-4 w-4 text-slate-400" />
                          <span className="text-xs font-medium text-slate-500 uppercase tracking-wide">
                            Rotation Schedule
                          </span>
                        </div>
                        <div className="flex flex-wrap gap-2 text-xs">
                          <span className="px-2 py-1 bg-slate-100 rounded text-slate-600">
                            Key Rotation {policy.keyRotationDays}d
                          </span>
                          <span className="px-2 py-1 bg-slate-100 rounded text-slate-600">
                            Min Key Bits {policy.minKeyBits}
                          </span>
                          {policy.requireQuantumSafe && (
                            <span className="px-2 py-1 bg-purple-100 rounded text-purple-600">
                              Quantum Safe
                            </span>
                          )}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>

            {/* Quantum-Ready Section */}
            <Card className="border-purple-200 border-l-4">
              <CardContent className="py-5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="h-12 w-12 rounded-xl bg-purple-100 flex items-center justify-center">
                      <Atom className="h-6 w-6 text-purple-600" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-slate-900">Quantum-Ready Algorithms</h3>
                      <p className="text-sm text-slate-500">
                        Enable post-quantum algorithms for new CRITICAL contexts
                      </p>
                      <p className="text-xs text-slate-400 mt-1">
                        Uses ML-KEM-768 for key encapsulation (hybrid mode)
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={handleToggleQuantumReady}
                    className={cn(
                      "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
                      quantumReady ? "bg-purple-600" : "bg-slate-300"
                    )}
                  >
                    <span
                      className={cn(
                        "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                        quantumReady ? "translate-x-6" : "translate-x-1"
                      )}
                    />
                  </button>
                </div>

                {quantumReady && (
                  <div className="mt-4 p-3 bg-purple-50 rounded-lg">
                    <p className="text-sm text-purple-800">
                      <strong>Enabled:</strong> New CRITICAL contexts will use hybrid ML-KEM-768 + AES-256-GCM
                      for maximum quantum resistance. This provides protection against future quantum computer attacks
                      while maintaining compatibility with current systems.
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </>
        )}

        {/* Classification Edit Modal */}
        {showClassificationEditModal && editingClassification && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-white rounded-xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden">
              {/* Header */}
              <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200">
                <div className="flex items-center gap-3">
                  {(() => {
                    const config = classificationConfig[editingClassification.classification];
                    const Icon = config.icon;
                    return (
                      <>
                        <div className={cn("h-10 w-10 rounded-lg flex items-center justify-center", config.bgColor)}>
                          <Icon className={cn("h-5 w-5", config.color)} />
                        </div>
                        <div>
                          <h2 className="text-lg font-semibold">Edit Policy: {config.label}</h2>
                          <p className="text-sm text-slate-500">{config.description}</p>
                        </div>
                      </>
                    );
                  })()}
                </div>
                <button
                  onClick={closeClassificationEdit}
                  className="p-2 hover:bg-slate-100 rounded-lg transition-colors"
                >
                  <X className="h-5 w-5 text-slate-400" />
                </button>
              </div>

              {/* Content */}
              <div className="px-6 py-5 space-y-5 max-h-[60vh] overflow-y-auto">
                <div>
                  <Label className="text-sm font-medium text-slate-700 mb-2 block">
                    Encryption Algorithm
                  </Label>
                  <select
                    value={classFormEncryption}
                    onChange={(e) => setClassFormEncryption(e.target.value)}
                    className="w-full px-3 py-2.5 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    {encryptionOptions.map((opt) => (
                      <option key={opt} value={opt}>{opt}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <Label className="text-sm font-medium text-slate-700 mb-2 block">
                    MAC Algorithm
                  </Label>
                  <select
                    value={classFormMac}
                    onChange={(e) => setClassFormMac(e.target.value)}
                    className="w-full px-3 py-2.5 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    {macOptions.map((opt) => (
                      <option key={opt} value={opt}>{opt}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <Label className="text-sm font-medium text-slate-700 mb-2 block">
                    Signing Algorithm
                  </Label>
                  <select
                    value={classFormSigning}
                    onChange={(e) => setClassFormSigning(e.target.value)}
                    className="w-full px-3 py-2.5 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    {signingOptions.map((opt) => (
                      <option key={opt} value={opt}>{opt}</option>
                    ))}
                  </select>
                </div>

                <div className="pt-4 border-t border-slate-200">
                  <h4 className="text-sm font-medium text-slate-700 mb-3">Key Rotation Schedule</h4>
                  <div>
                    <Label className="text-xs text-slate-500 mb-1.5 block">Rotation Period (days)</Label>
                    <Input
                      type="number"
                      min={7}
                      max={365}
                      value={classFormRotation}
                      onChange={(e) => setClassFormRotation(parseInt(e.target.value) || 90)}
                    />
                    <p className="text-xs text-slate-400 mt-1">Recommended: 30 (Critical), 60 (Sensitive), 90 (Internal), 180 (Public)</p>
                  </div>
                </div>
              </div>

              {/* Footer */}
              <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-slate-200 bg-slate-50">
                <Button variant="outline" onClick={closeClassificationEdit} disabled={saving}>
                  Cancel
                </Button>
                <Button onClick={handleSaveClassification} disabled={saving}>
                  {saving ? (
                    <>
                      <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full mr-2" />
                      Saving...
                    </>
                  ) : (
                    "Save Policy"
                  )}
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
