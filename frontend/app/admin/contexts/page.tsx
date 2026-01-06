"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  Shield,
  ShieldAlert,
  Key,
  Users,
  Activity,
  RotateCw,
  Lock,
  AlertTriangle,
  CheckCircle2,
  Plus,
  Edit,
  ChevronRight,
  ChevronDown,
  X,
  Zap,
  Clock,
  Globe,
  FileWarning,
  TrendingUp,
  BarChart3,
  Database,
  HardDrive,
  ArrowRightLeft,
  Cpu,
  Radio,
  KeyRound,
  Hash,
  PenTool,
  Fingerprint,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AdminLayout } from "@/components/admin-layout";
import { StatCard } from "@/components/ui/stat-card";
import {
  api,
  AdminContextStats,
  ContextConfig,
  ContextFullResponse,
  DataIdentity,
  RegulatoryMapping,
  ThreatModel,
  AccessPatterns,
  Sensitivity,
  DataCategory,
  Adversary,
  AccessFrequency,
  AlgorithmPolicy,
  PolicyEnforcement,
  AlgorithmSuite,
  DerivedRequirements,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie,
} from "recharts";

// Default values for new context
const defaultDataIdentity: DataIdentity = {
  category: "general",
  subcategory: null,
  sensitivity: "medium",
  usage_context: "at_rest",
  pii: false,
  phi: false,
  pci: false,
  notification_required: false,
  examples: [],
};

const defaultRegulatory: RegulatoryMapping = {
  frameworks: [],
  data_residency: null,
  retention: null,
  cross_border_allowed: true,
};

const defaultThreatModel: ThreatModel = {
  adversaries: ["opportunistic_attacker"],
  attack_vectors: [],
  protection_lifetime_years: 5,
};

const defaultAccessPatterns: AccessPatterns = {
  frequency: "medium",
  operations_per_second: null,
  latency_requirement_ms: null,
  batch_operations: false,
  search_required: false,
};

const defaultConfig: ContextConfig = {
  data_identity: defaultDataIdentity,
  regulatory: defaultRegulatory,
  threat_model: defaultThreatModel,
  access_patterns: defaultAccessPatterns,
};

// Default algorithm policy
const defaultAlgorithmPolicy: AlgorithmPolicy = {
  allowed_ciphers: ["AES", "ChaCha20"],
  allowed_modes: ["gcm", "gcm-siv", "ccm"],
  min_key_bits: 128,
  require_quantum_safe: false,
};

// Display mappings
const sensitivityLabels: Record<Sensitivity, { label: string; color: string }> = {
  critical: { label: "Critical", color: "bg-red-100 text-red-700" },
  high: { label: "High", color: "bg-orange-100 text-orange-700" },
  medium: { label: "Medium", color: "bg-yellow-100 text-yellow-700" },
  low: { label: "Low", color: "bg-green-100 text-green-700" },
};

const categoryLabels: Record<DataCategory, string> = {
  personal_identifier: "Personal Identifier",
  financial: "Financial",
  health: "Health",
  authentication: "Authentication",
  business_confidential: "Business Confidential",
  general: "General",
};

const adversaryLabels: Record<Adversary, string> = {
  opportunistic_attacker: "Opportunistic Attacker",
  organized_crime: "Organized Crime",
  nation_state: "Nation State",
  insider_threat: "Insider Threat",
  quantum_computer: "Quantum Computer",
};

const frequencyLabels: Record<AccessFrequency, string> = {
  high: "High (>1000 ops/sec)",
  medium: "Medium (100-1000 ops/sec)",
  low: "Low (10-100 ops/sec)",
  rare: "Rare (<10 ops/sec)",
};

const usageContextLabels: Record<string, { label: string; description: string; icon: React.ComponentType<{ className?: string }> }> = {
  at_rest: { label: "At Rest", description: "Data stored on disk, databases, backups", icon: HardDrive },
  in_transit: { label: "In Transit", description: "Data moving over network, APIs, TLS", icon: ArrowRightLeft },
  in_use: { label: "In Use", description: "Data being processed in memory", icon: Cpu },
  streaming: { label: "Streaming", description: "Real-time data streams, logs", icon: Radio },
};

const algorithmOptions = [
  { value: "auto", label: "Auto (Recommended)", description: "System chooses based on context" },
  { value: "AES-128-GCM", label: "AES-128-GCM", description: "128-bit, fast, hardware accelerated" },
  { value: "AES-256-GCM", label: "AES-256-GCM", description: "256-bit, standard for sensitive data" },
  { value: "ChaCha20-Poly1305", label: "ChaCha20-Poly1305", description: "256-bit, no hardware needed" },
  { value: "AES-256-GCM+ML-KEM-768", label: "AES-256 + ML-KEM-768", description: "Post-quantum hybrid" },
  { value: "AES-256-GCM+ML-KEM-1024", label: "AES-256 + ML-KEM-1024", description: "Maximum quantum resistance" },
];

const cipherModeOptions = [
  { value: "gcm", label: "GCM", description: "Galois/Counter Mode - authenticated, parallelizable" },
  { value: "gcm-siv", label: "GCM-SIV", description: "Nonce-misuse resistant, slightly slower" },
  { value: "ctr", label: "CTR", description: "Counter mode - no authentication, needs separate MAC" },
  { value: "cbc", label: "CBC", description: "Legacy mode - avoid for new applications" },
  { value: "ccm", label: "CCM", description: "Counter with CBC-MAC - constrained devices" },
];

const frameworkOptions = ["GDPR", "CCPA", "PCI-DSS", "HIPAA", "SOX", "SOC2"];

// Policy enforcement options
const enforcementOptions: { value: PolicyEnforcement; label: string; description: string; color: string }[] = [
  { value: "none", label: "None", description: "Developer overrides allowed", color: "bg-slate-100 text-slate-700" },
  { value: "warn", label: "Warn", description: "Allow override but log warning", color: "bg-amber-100 text-amber-700" },
  { value: "enforce", label: "Enforce", description: "Reject policy violations", color: "bg-red-100 text-red-700" },
];

// Cipher options for policy
const cipherOptions = ["AES", "ChaCha20"];

// Mode options for policy
const modeOptions = ["gcm", "gcm-siv", "cbc", "ctr", "ccm"];

// Key size options for policy
const keySizeOptions = [128, 192, 256];

// Chart colors
const CHART_COLORS = ["#3b82f6", "#22c55e", "#f59e0b", "#ef4444", "#8b5cf6", "#06b6d4", "#ec4899"];

export default function AdminContextsPage() {
  const router = useRouter();
  const [contexts, setContexts] = useState<AdminContextStats[]>([]);
  const [loading, setLoading] = useState(true);
  const [rotating, setRotating] = useState<string | null>(null);

  // Expanded context state for algorithm suite display
  const [expandedContexts, setExpandedContexts] = useState<Set<string>>(new Set());
  const [contextSuites, setContextSuites] = useState<Record<string, DerivedRequirements | null>>({});
  const [loadingSuites, setLoadingSuites] = useState<Set<string>>(new Set());

  // Modal state
  const [showModal, setShowModal] = useState(false);
  const [editingContext, setEditingContext] = useState<string | null>(null);
  const [currentStep, setCurrentStep] = useState(0);
  const [saving, setSaving] = useState(false);

  // Form state
  const [formName, setFormName] = useState("");
  const [formDisplayName, setFormDisplayName] = useState("");
  const [formDescription, setFormDescription] = useState("");
  const [formConfig, setFormConfig] = useState<ContextConfig>(defaultConfig);

  // Policy form state
  const [formAlgorithmPolicy, setFormAlgorithmPolicy] = useState<AlgorithmPolicy | null>(null);
  const [formPolicyEnforcement, setFormPolicyEnforcement] = useState<PolicyEnforcement>("none");
  const [policyEnabled, setPolicyEnabled] = useState(false);

  const steps = [
    { name: "Basic Info", icon: Shield },
    { name: "Data Identity", icon: FileWarning },
    { name: "Regulatory", icon: Globe },
    { name: "Threat Model", icon: AlertTriangle },
    { name: "Access Patterns", icon: Zap },
    { name: "Algorithm Policy", icon: ShieldAlert },
  ];

  const loadContexts = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.getContextsWithStats();
      setContexts(data);
    } catch (error) {
      console.error("Failed to load contexts:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadContexts();
  }, [loadContexts]);

  // Toggle expanded state and load algorithm suite if needed
  const toggleContextExpansion = async (contextName: string) => {
    const newExpanded = new Set(expandedContexts);
    if (newExpanded.has(contextName)) {
      newExpanded.delete(contextName);
    } else {
      newExpanded.add(contextName);
      // Load algorithm suite if not already loaded
      if (!contextSuites[contextName] && !loadingSuites.has(contextName)) {
        setLoadingSuites(prev => new Set([...prev, contextName]));
        try {
          const derived = await api.resolveContextAlgorithm(contextName);
          setContextSuites(prev => ({ ...prev, [contextName]: derived }));
        } catch (error) {
          console.error(`Failed to load algorithm suite for ${contextName}:`, error);
          setContextSuites(prev => ({ ...prev, [contextName]: null }));
        } finally {
          setLoadingSuites(prev => {
            const next = new Set(prev);
            next.delete(contextName);
            return next;
          });
        }
      }
    }
    setExpandedContexts(newExpanded);
  };

  const handleRotateKey = async (contextName: string) => {
    if (!confirm(`Are you sure you want to rotate the encryption key for "${contextName}"? This action will create a new key version. Existing encrypted data will continue to be decryptable.`)) {
      return;
    }
    setRotating(contextName);
    try {
      await api.rotateContextKey(contextName);
      await loadContexts();
    } catch (error) {
      console.error("Failed to rotate key:", error);
      alert("Failed to rotate key. Please try again.");
    } finally {
      setRotating(null);
    }
  };

  const getDaysSinceRotation = (lastRotation: string | null) => {
    if (!lastRotation) return null;
    const days = Math.floor(
      (Date.now() - new Date(lastRotation).getTime()) / (1000 * 60 * 60 * 24)
    );
    return days;
  };

  const getRotationStatus = (lastRotation: string | null) => {
    const days = getDaysSinceRotation(lastRotation);
    if (days === null) return { status: "unknown", color: "slate" };
    if (days > 90) return { status: "overdue", color: "red" };
    if (days > 60) return { status: "due-soon", color: "amber" };
    return { status: "healthy", color: "green" };
  };

  const resetForm = () => {
    setFormName("");
    setFormDisplayName("");
    setFormDescription("");
    setFormConfig(defaultConfig);
    setFormAlgorithmPolicy(null);
    setFormPolicyEnforcement("none");
    setPolicyEnabled(false);
    setCurrentStep(0);
    setEditingContext(null);
  };

  const openCreateModal = () => {
    resetForm();
    setShowModal(true);
  };

  const openEditModal = async (contextName: string) => {
    try {
      const detail = await api.getContextDetail(contextName);
      setFormName(detail.name);
      setFormDisplayName(detail.display_name);
      setFormDescription(detail.description);
      setFormConfig(detail.config || defaultConfig);
      // Load policy fields
      if (detail.algorithm_policy) {
        setFormAlgorithmPolicy(detail.algorithm_policy);
        setPolicyEnabled(true);
      } else {
        setFormAlgorithmPolicy(null);
        setPolicyEnabled(false);
      }
      setFormPolicyEnforcement(detail.policy_enforcement || "none");
      setEditingContext(contextName);
      setCurrentStep(0);
      setShowModal(true);
    } catch (error) {
      console.error("Failed to load context:", error);
      alert("Failed to load context details");
    }
  };

  const closeModal = () => {
    setShowModal(false);
    resetForm();
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      if (editingContext) {
        await api.updateContext(editingContext, {
          name: formName,
          display_name: formDisplayName,
          description: formDescription,
          config: formConfig,
          algorithm_policy: policyEnabled ? formAlgorithmPolicy : null,
          policy_enforcement: formPolicyEnforcement,
        });
      } else {
        await api.createContext({
          name: formName,
          display_name: formDisplayName,
          description: formDescription,
          config: formConfig,
        });
      }
      await loadContexts();
      closeModal();
    } catch (error) {
      console.error("Failed to save context:", error);
      alert(`Failed to save context: ${error instanceof Error ? error.message : "Unknown error"}`);
    } finally {
      setSaving(false);
    }
  };

  const updateDataIdentity = (updates: Partial<DataIdentity>) => {
    setFormConfig((prev) => ({
      ...prev,
      data_identity: { ...prev.data_identity, ...updates },
    }));
  };

  const updateRegulatory = (updates: Partial<RegulatoryMapping>) => {
    setFormConfig((prev) => ({
      ...prev,
      regulatory: { ...prev.regulatory, ...updates },
    }));
  };

  const updateThreatModel = (updates: Partial<ThreatModel>) => {
    setFormConfig((prev) => ({
      ...prev,
      threat_model: { ...prev.threat_model, ...updates },
    }));
  };

  const updateAccessPatterns = (updates: Partial<AccessPatterns>) => {
    setFormConfig((prev) => ({
      ...prev,
      access_patterns: { ...prev.access_patterns, ...updates },
    }));
  };

  const toggleFramework = (framework: string) => {
    const current = formConfig.regulatory.frameworks;
    const updated = current.includes(framework)
      ? current.filter((f) => f !== framework)
      : [...current, framework];
    updateRegulatory({ frameworks: updated });
  };

  const toggleAdversary = (adversary: Adversary) => {
    const current = formConfig.threat_model.adversaries;
    const updated = current.includes(adversary)
      ? current.filter((a) => a !== adversary)
      : [...current, adversary];
    updateThreatModel({ adversaries: updated });
  };

  const updateAlgorithmPolicy = (updates: Partial<AlgorithmPolicy>) => {
    setFormAlgorithmPolicy((prev) => ({
      ...(prev || defaultAlgorithmPolicy),
      ...updates,
    }));
  };

  const togglePolicyCipher = (cipher: string) => {
    const current = formAlgorithmPolicy?.allowed_ciphers || defaultAlgorithmPolicy.allowed_ciphers;
    const updated = current.includes(cipher)
      ? current.filter((c) => c !== cipher)
      : [...current, cipher];
    updateAlgorithmPolicy({ allowed_ciphers: updated });
  };

  const togglePolicyMode = (mode: string) => {
    const current = formAlgorithmPolicy?.allowed_modes || defaultAlgorithmPolicy.allowed_modes;
    const updated = current.includes(mode)
      ? current.filter((m) => m !== mode)
      : [...current, mode];
    updateAlgorithmPolicy({ allowed_modes: updated });
  };

  // Calculate metrics
  const totalOperations = contexts.reduce((sum, c) => sum + c.operation_count, 0);
  const totalIdentities = contexts.reduce((sum, c) => sum + c.identity_count, 0);
  const overdueKeys = contexts.filter((c) => getRotationStatus(c.last_key_rotation).status === "overdue").length;
  const dueSoonKeys = contexts.filter((c) => getRotationStatus(c.last_key_rotation).status === "due-soon").length;
  const healthyKeys = contexts.filter((c) => getRotationStatus(c.last_key_rotation).status === "healthy").length;

  // Chart data - Operations by context
  const operationsChartData = contexts
    .map((c) => ({
      name: c.display_name.length > 12 ? c.display_name.substring(0, 12) + "..." : c.display_name,
      fullName: c.display_name,
      operations: c.operation_count,
    }))
    .sort((a, b) => b.operations - a.operations)
    .slice(0, 6);

  // Key rotation status data for pie chart
  const rotationStatusData = [
    { name: "Healthy", value: healthyKeys, color: "#22c55e" },
    { name: "Due Soon", value: dueSoonKeys, color: "#f59e0b" },
    { name: "Overdue", value: overdueKeys, color: "#ef4444" },
  ].filter((d) => d.value > 0);

  // Render step content
  const renderStepContent = () => {
    switch (currentStep) {
      case 0:
        return (
          <div className="space-y-6">
            <div>
              <Label htmlFor="name" className="text-sm font-medium text-slate-700 mb-1.5 block">Context ID</Label>
              <Input
                id="name"
                value={formName}
                onChange={(e) => setFormName(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "-"))}
                placeholder="e.g., user-pii, payment-data"
                disabled={!!editingContext}
                className="font-mono"
              />
              <p className="text-xs text-slate-500 mt-2">Lowercase with hyphens only. Used as the API identifier.</p>
            </div>
            <div>
              <Label htmlFor="displayName" className="text-sm font-medium text-slate-700 mb-1.5 block">Display Name</Label>
              <Input
                id="displayName"
                value={formDisplayName}
                onChange={(e) => setFormDisplayName(e.target.value)}
                placeholder="e.g., User Personal Data"
              />
            </div>
            <div>
              <Label htmlFor="description" className="text-sm font-medium text-slate-700 mb-1.5 block">Description</Label>
              <textarea
                id="description"
                value={formDescription}
                onChange={(e) => setFormDescription(e.target.value)}
                placeholder="Describe what data this context protects..."
                className="w-full h-28 px-3 py-2.5 border border-slate-200 rounded-lg text-sm resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
              <p className="text-xs text-slate-500 mt-2">This description helps other team members understand when to use this context.</p>
            </div>
          </div>
        );

      case 1:
        return (
          <div className="space-y-6">
            <div>
              <Label>Data Category</Label>
              <select
                value={formConfig.data_identity.category}
                onChange={(e) => updateDataIdentity({ category: e.target.value as DataCategory })}
                className="w-full px-3 py-2 border rounded-md text-sm"
              >
                {(Object.entries(categoryLabels) as [DataCategory, string][]).map(([value, label]) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </select>
            </div>

            <div>
              <Label>Sensitivity Level</Label>
              <div className="grid grid-cols-4 gap-2 mt-2">
                {(Object.entries(sensitivityLabels) as [Sensitivity, { label: string; color: string }][]).map(([value, { label, color }]) => (
                  <button
                    key={value}
                    onClick={() => updateDataIdentity({ sensitivity: value })}
                    className={cn(
                      "px-3 py-2 rounded-md text-sm font-medium border transition-all",
                      formConfig.data_identity.sensitivity === value
                        ? `${color} border-transparent`
                        : "bg-white hover:bg-slate-50 border-slate-200"
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <Label>Data Flags</Label>
              <div className="flex flex-wrap gap-2 mt-2">
                {[
                  { key: "pii", label: "PII (Personal Info)" },
                  { key: "phi", label: "PHI (Health Info)" },
                  { key: "pci", label: "PCI (Payment Data)" },
                  { key: "notification_required", label: "Breach Notification" },
                ].map(({ key, label }) => (
                  <button
                    key={key}
                    onClick={() => updateDataIdentity({ [key]: !formConfig.data_identity[key as keyof DataIdentity] })}
                    className={cn(
                      "px-3 py-1.5 rounded-md text-sm border transition-all",
                      formConfig.data_identity[key as keyof DataIdentity]
                        ? "bg-blue-100 text-blue-700 border-blue-200"
                        : "bg-white hover:bg-slate-50 border-slate-200"
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <Label>Usage Context</Label>
              <p className="text-xs text-slate-500 mb-2">How will this data be used? Affects algorithm selection.</p>
              <div className="grid grid-cols-2 gap-2 mt-2">
                {Object.entries(usageContextLabels).map(([value, { label, description, icon: Icon }]) => (
                  <button
                    key={value}
                    onClick={() => updateDataIdentity({ usage_context: value as any })}
                    className={cn(
                      "flex items-start gap-2 p-3 rounded-lg border text-left transition-all",
                      formConfig.data_identity.usage_context === value
                        ? "bg-blue-50 border-blue-300 ring-1 ring-blue-300"
                        : "bg-white hover:bg-slate-50 border-slate-200"
                    )}
                  >
                    <Icon className={cn(
                      "h-5 w-5 mt-0.5",
                      formConfig.data_identity.usage_context === value ? "text-blue-600" : "text-slate-400"
                    )} />
                    <div>
                      <div className="font-medium text-sm">{label}</div>
                      <div className="text-xs text-slate-500">{description}</div>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </div>
        );

      case 2:
        return (
          <div className="space-y-6">
            <div>
              <Label>Compliance Frameworks</Label>
              <div className="flex flex-wrap gap-2 mt-2">
                {frameworkOptions.map((framework) => (
                  <button
                    key={framework}
                    onClick={() => toggleFramework(framework)}
                    className={cn(
                      "px-3 py-1.5 rounded-md text-sm border transition-all",
                      formConfig.regulatory.frameworks.includes(framework)
                        ? "bg-emerald-100 text-emerald-700 border-emerald-200"
                        : "bg-white hover:bg-slate-50 border-slate-200"
                    )}
                  >
                    {framework}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-3">
              <input
                type="checkbox"
                id="crossBorder"
                checked={formConfig.regulatory.cross_border_allowed}
                onChange={(e) => updateRegulatory({ cross_border_allowed: e.target.checked })}
                className="h-4 w-4 rounded border-slate-300"
              />
              <Label htmlFor="crossBorder" className="font-normal">
                Allow cross-border data transfer
              </Label>
            </div>
          </div>
        );

      case 3:
        return (
          <div className="space-y-6">
            <div>
              <Label>Threat Actors</Label>
              <div className="flex flex-wrap gap-2 mt-2">
                {(Object.entries(adversaryLabels) as [Adversary, string][]).map(([value, label]) => (
                  <button
                    key={value}
                    onClick={() => toggleAdversary(value)}
                    className={cn(
                      "px-3 py-1.5 rounded-md text-sm border transition-all",
                      formConfig.threat_model.adversaries.includes(value)
                        ? value === "quantum_computer"
                          ? "bg-purple-100 text-purple-700 border-purple-200"
                          : value === "nation_state"
                          ? "bg-red-100 text-red-700 border-red-200"
                          : "bg-orange-100 text-orange-700 border-orange-200"
                        : "bg-white hover:bg-slate-50 border-slate-200"
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <Label htmlFor="protectionYears">Protection Lifetime (years)</Label>
              <Input
                id="protectionYears"
                type="number"
                min={1}
                max={100}
                value={formConfig.threat_model.protection_lifetime_years}
                onChange={(e) => updateThreatModel({ protection_lifetime_years: parseFloat(e.target.value) || 5 })}
              />
              <p className="text-xs text-slate-500 mt-1">
                {formConfig.threat_model.protection_lifetime_years > 10
                  ? "Quantum-resistant algorithms will be required"
                  : "Standard algorithms are sufficient"}
              </p>
            </div>
          </div>
        );

      case 4:
        return (
          <div className="space-y-6">
            <div>
              <Label>Access Frequency</Label>
              <select
                value={formConfig.access_patterns.frequency}
                onChange={(e) => updateAccessPatterns({ frequency: e.target.value as AccessFrequency })}
                className="w-full px-3 py-2 border rounded-md text-sm"
              >
                {(Object.entries(frequencyLabels) as [AccessFrequency, string][]).map(([value, label]) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </select>
            </div>

            <div>
              <Label htmlFor="latency">Maximum Latency (ms)</Label>
              <Input
                id="latency"
                type="number"
                min={1}
                placeholder="Optional - leave empty for default"
                value={formConfig.access_patterns.latency_requirement_ms || ""}
                onChange={(e) => updateAccessPatterns({ latency_requirement_ms: e.target.value ? parseInt(e.target.value) : null })}
              />
              <p className="text-xs text-slate-500 mt-1">
                Lower latency requirements may enable hardware acceleration
              </p>
            </div>

            <div className="space-y-2">
              <div className="flex items-center gap-3">
                <input
                  type="checkbox"
                  id="batchOps"
                  checked={formConfig.access_patterns.batch_operations}
                  onChange={(e) => updateAccessPatterns({ batch_operations: e.target.checked })}
                  className="h-4 w-4 rounded border-slate-300"
                />
                <Label htmlFor="batchOps" className="font-normal">
                  Enable batch operations (bulk encrypt/decrypt)
                </Label>
              </div>
              <div className="flex items-center gap-3">
                <input
                  type="checkbox"
                  id="searchRequired"
                  checked={formConfig.access_patterns.search_required}
                  onChange={(e) => updateAccessPatterns({ search_required: e.target.checked })}
                  className="h-4 w-4 rounded border-slate-300"
                />
                <Label htmlFor="searchRequired" className="font-normal">
                  Enable encrypted search (searchable encryption)
                </Label>
              </div>
            </div>

            {/* Algorithm Preferences - Expert Options */}
            <div className="pt-4 border-t border-slate-200">
              <div className="flex items-center gap-2 mb-3">
                <Key className="h-4 w-4 text-slate-500" />
                <Label className="text-slate-700">Algorithm Preferences (Optional)</Label>
              </div>
              <p className="text-xs text-slate-500 mb-3">
                Override the auto-selected algorithm. Leave as Auto for system to choose based on your context settings.
              </p>

              <div className="space-y-3">
                <div>
                  <Label className="text-xs text-slate-600">Algorithm</Label>
                  <select
                    value={(formConfig as any).algorithm_override || "auto"}
                    onChange={(e) => setFormConfig(prev => ({ ...prev, algorithm_override: e.target.value === "auto" ? undefined : e.target.value }))}
                    className="w-full px-3 py-2 border rounded-md text-sm mt-1"
                  >
                    {algorithmOptions.map(({ value, label, description }) => (
                      <option key={value} value={value} title={description}>
                        {label} - {description}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <Label className="text-xs text-slate-600">Cipher Mode</Label>
                  <select
                    value={(formConfig as any).cipher_mode || "gcm"}
                    onChange={(e) => setFormConfig(prev => ({ ...prev, cipher_mode: e.target.value }))}
                    className="w-full px-3 py-2 border rounded-md text-sm mt-1"
                  >
                    {cipherModeOptions.map(({ value, label, description }) => (
                      <option key={value} value={value}>
                        {label} - {description}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="bg-slate-50 p-3 rounded-lg text-xs">
                  <div className="font-medium text-slate-700 mb-1">Key Size Information</div>
                  <ul className="text-slate-600 space-y-1">
                    <li>• AES-128: 128-bit key, fast, NIST approved</li>
                    <li>• AES-256: 256-bit key, higher security margin</li>
                    <li>• ChaCha20: 256-bit, great for mobile/IoT</li>
                    <li>• ML-KEM hybrids: Post-quantum resistant</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        );

      case 5:
        return (
          <div className="space-y-6">
            {/* Policy Enable Toggle */}
            <div className="flex items-center justify-between p-4 border rounded-lg bg-slate-50">
              <div>
                <div className="font-medium text-slate-900">Algorithm Policy</div>
                <p className="text-sm text-slate-500">
                  {editingContext
                    ? "Enforce algorithm constraints for this context"
                    : "Policy can only be configured when editing an existing context"}
                </p>
              </div>
              <button
                onClick={() => {
                  if (!policyEnabled) {
                    setFormAlgorithmPolicy(defaultAlgorithmPolicy);
                  }
                  setPolicyEnabled(!policyEnabled);
                }}
                disabled={!editingContext}
                className={cn(
                  "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
                  policyEnabled ? "bg-blue-600" : "bg-slate-300",
                  !editingContext && "opacity-50 cursor-not-allowed"
                )}
              >
                <span
                  className={cn(
                    "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                    policyEnabled ? "translate-x-6" : "translate-x-1"
                  )}
                />
              </button>
            </div>

            {policyEnabled && (
              <>
                {/* Enforcement Level */}
                <div>
                  <Label>Enforcement Level</Label>
                  <p className="text-xs text-slate-500 mb-2">How strictly should the policy be enforced?</p>
                  <div className="grid grid-cols-3 gap-2 mt-2">
                    {enforcementOptions.map(({ value, label, description, color }) => (
                      <button
                        key={value}
                        onClick={() => setFormPolicyEnforcement(value)}
                        className={cn(
                          "p-3 rounded-lg border text-left transition-all",
                          formPolicyEnforcement === value
                            ? `${color} border-transparent ring-2 ring-offset-1 ${value === "enforce" ? "ring-red-400" : value === "warn" ? "ring-amber-400" : "ring-slate-400"}`
                            : "bg-white hover:bg-slate-50 border-slate-200"
                        )}
                      >
                        <div className="font-medium text-sm">{label}</div>
                        <div className="text-xs text-slate-500 mt-0.5">{description}</div>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Allowed Ciphers */}
                <div>
                  <Label>Allowed Ciphers</Label>
                  <p className="text-xs text-slate-500 mb-2">Which cipher families can developers use?</p>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {cipherOptions.map((cipher) => (
                      <button
                        key={cipher}
                        onClick={() => togglePolicyCipher(cipher)}
                        className={cn(
                          "px-4 py-2 rounded-md text-sm font-medium border transition-all",
                          (formAlgorithmPolicy?.allowed_ciphers || []).includes(cipher)
                            ? "bg-blue-100 text-blue-700 border-blue-200"
                            : "bg-white hover:bg-slate-50 border-slate-200"
                        )}
                      >
                        {cipher}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Allowed Modes */}
                <div>
                  <Label>Allowed Modes</Label>
                  <p className="text-xs text-slate-500 mb-2">Which cipher modes are permitted?</p>
                  <div className="flex flex-wrap gap-2 mt-2">
                    {modeOptions.map((mode) => (
                      <button
                        key={mode}
                        onClick={() => togglePolicyMode(mode)}
                        className={cn(
                          "px-3 py-1.5 rounded-md text-sm border transition-all uppercase",
                          (formAlgorithmPolicy?.allowed_modes || []).includes(mode)
                            ? "bg-emerald-100 text-emerald-700 border-emerald-200"
                            : "bg-white hover:bg-slate-50 border-slate-200"
                        )}
                      >
                        {mode}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Minimum Key Size */}
                <div>
                  <Label>Minimum Key Size</Label>
                  <p className="text-xs text-slate-500 mb-2">Minimum required key size in bits</p>
                  <div className="flex gap-2 mt-2">
                    {keySizeOptions.map((size) => (
                      <button
                        key={size}
                        onClick={() => updateAlgorithmPolicy({ min_key_bits: size })}
                        className={cn(
                          "px-4 py-2 rounded-md text-sm font-medium border transition-all",
                          (formAlgorithmPolicy?.min_key_bits || 128) === size
                            ? "bg-purple-100 text-purple-700 border-purple-200"
                            : "bg-white hover:bg-slate-50 border-slate-200"
                        )}
                      >
                        {size}-bit
                      </button>
                    ))}
                  </div>
                </div>

                {/* Require Quantum Safe */}
                <div className="flex items-center justify-between p-4 border rounded-lg">
                  <div>
                    <div className="font-medium text-slate-900">Require Quantum-Safe Algorithms</div>
                    <p className="text-sm text-slate-500">
                      Only allow post-quantum or hybrid algorithms (ML-KEM)
                    </p>
                  </div>
                  <button
                    onClick={() => updateAlgorithmPolicy({ require_quantum_safe: !formAlgorithmPolicy?.require_quantum_safe })}
                    className={cn(
                      "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
                      formAlgorithmPolicy?.require_quantum_safe ? "bg-purple-600" : "bg-slate-300"
                    )}
                  >
                    <span
                      className={cn(
                        "inline-block h-4 w-4 transform rounded-full bg-white transition-transform",
                        formAlgorithmPolicy?.require_quantum_safe ? "translate-x-6" : "translate-x-1"
                      )}
                    />
                  </button>
                </div>

                {/* Policy Summary */}
                <div className="bg-slate-50 p-4 rounded-lg">
                  <div className="font-medium text-slate-700 mb-2">Policy Summary</div>
                  <ul className="text-sm text-slate-600 space-y-1">
                    <li>
                      <span className="text-slate-500">Enforcement:</span>{" "}
                      <span className={cn(
                        "font-medium",
                        formPolicyEnforcement === "enforce" && "text-red-600",
                        formPolicyEnforcement === "warn" && "text-amber-600"
                      )}>
                        {formPolicyEnforcement === "none" ? "Disabled" : formPolicyEnforcement === "warn" ? "Warn on violations" : "Block violations"}
                      </span>
                    </li>
                    <li>
                      <span className="text-slate-500">Ciphers:</span>{" "}
                      {(formAlgorithmPolicy?.allowed_ciphers || []).join(", ") || "None selected"}
                    </li>
                    <li>
                      <span className="text-slate-500">Modes:</span>{" "}
                      {(formAlgorithmPolicy?.allowed_modes || []).map(m => m.toUpperCase()).join(", ") || "None selected"}
                    </li>
                    <li>
                      <span className="text-slate-500">Min key size:</span>{" "}
                      {formAlgorithmPolicy?.min_key_bits || 128} bits
                    </li>
                    <li>
                      <span className="text-slate-500">Quantum-safe required:</span>{" "}
                      {formAlgorithmPolicy?.require_quantum_safe ? "Yes" : "No"}
                    </li>
                  </ul>
                </div>
              </>
            )}
          </div>
        );

      default:
        return null;
    }
  };

  if (loading) {
    return (
      <AdminLayout title="Context Management" subtitle="Loading...">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </AdminLayout>
    );
  }

  return (
    <AdminLayout
      title="Context Management"
      subtitle="Encryption contexts define data protection policies"
      onRefresh={loadContexts}
      actions={
        <Button onClick={openCreateModal}>
          <Plus className="h-4 w-4 mr-2" />
          Create Context
        </Button>
      }
    >
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatCard
          title="Total Contexts"
          value={contexts.length.toString()}
          subtitle="Encryption contexts"
          icon={<Lock className="h-5 w-5 text-blue-500" />}
        />
        <StatCard
          title="Total Operations"
          value={totalOperations.toLocaleString()}
          subtitle="All-time operations"
          icon={<Activity className="h-5 w-5 text-green-500" />}
          trend={{ value: 12, label: "this week" }}
        />
        <StatCard
          title="Identities"
          value={totalIdentities.toString()}
          subtitle="Active identities"
          icon={<Users className="h-5 w-5 text-purple-500" />}
        />
        <StatCard
          title="Key Health"
          value={`${healthyKeys}/${contexts.length}`}
          subtitle={overdueKeys > 0 ? `${overdueKeys} overdue` : "All healthy"}
          icon={<Key className="h-5 w-5 text-amber-500" />}
          trend={overdueKeys > 0 ? { value: overdueKeys, label: "overdue" } : undefined}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* Operations by Context */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-blue-500" />
              Operations by Context
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-56">
              {operationsChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={operationsChartData} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" horizontal={true} vertical={false} />
                    <XAxis
                      type="number"
                      tick={{ fontSize: 11 }}
                      stroke="#94a3b8"
                      tickLine={false}
                      tickFormatter={(v) => v.toLocaleString()}
                    />
                    <YAxis
                      type="category"
                      dataKey="name"
                      tick={{ fontSize: 11 }}
                      stroke="#94a3b8"
                      tickLine={false}
                      axisLine={false}
                      width={100}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#1e293b",
                        border: "none",
                        borderRadius: "8px",
                        color: "#f8fafc",
                      }}
                      formatter={(value, name, props) => [
                        (value ?? 0).toLocaleString(),
                        props?.payload?.fullName ?? name,
                      ]}
                    />
                    <Bar dataKey="operations" radius={[0, 4, 4, 0]}>
                      {operationsChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-slate-500">
                  No operation data available
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Key Rotation Status */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Key className="h-5 w-5 text-amber-500" />
              Key Rotation Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-40">
              {rotationStatusData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={rotationStatusData}
                      cx="50%"
                      cy="50%"
                      innerRadius={35}
                      outerRadius={55}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {rotationStatusData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#1e293b",
                        border: "none",
                        borderRadius: "8px",
                        color: "#f8fafc",
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-slate-500">
                  No contexts configured
                </div>
              )}
            </div>
            <div className="flex justify-center gap-4 mt-2">
              {rotationStatusData.map((item) => (
                <div key={item.name} className="flex items-center gap-1.5 text-xs">
                  <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-slate-600">{item.name} ({item.value})</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Contexts Grid */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Database className="h-5 w-5 text-blue-500" />
            All Contexts
          </CardTitle>
        </CardHeader>
        <CardContent>
          {contexts.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {contexts.map((context) => {
                const rotationStatus = getRotationStatus(context.last_key_rotation);
                const daysSince = getDaysSinceRotation(context.last_key_rotation);

                return (
                  <div
                    key={context.name}
                    className="p-4 border rounded-lg hover:shadow-md transition-shadow bg-white"
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center gap-2">
                        <div className="h-9 w-9 rounded-lg bg-blue-100 flex items-center justify-center">
                          <Lock className="h-4 w-4 text-blue-600" />
                        </div>
                        <div>
                          <div className="font-medium text-slate-900">{context.display_name}</div>
                          <div className="text-xs text-slate-500 font-mono">{context.name}</div>
                        </div>
                      </div>
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => toggleContextExpansion(context.name)}
                          className="h-8 w-8 p-0"
                          title={expandedContexts.has(context.name) ? "Hide Algorithm Suite" : "Show Algorithm Suite"}
                        >
                          <ChevronDown className={cn(
                            "h-4 w-4 transition-transform",
                            expandedContexts.has(context.name) && "rotate-180"
                          )} />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => router.push(`/admin/contexts/${context.name}/keys`)}
                          className="h-8 w-8 p-0"
                          title="Manage Keys"
                        >
                          <KeyRound className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => openEditModal(context.name)}
                          className="h-8 w-8 p-0"
                          title="Edit Context"
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>

                    {/* Compliance Tags */}
                    {context.compliance_tags && context.compliance_tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mb-3">
                        {context.compliance_tags.map((tag) => (
                          <span
                            key={tag}
                            className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-emerald-100 text-emerald-700"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Stats Row */}
                    <div className="flex items-center gap-4 text-xs text-slate-600 mb-3">
                      <div className="flex items-center gap-1">
                        <Activity className="h-3.5 w-3.5" />
                        {context.operation_count.toLocaleString()} ops
                      </div>
                      <div className="flex items-center gap-1">
                        <Users className="h-3.5 w-3.5" />
                        {context.identity_count} identities
                      </div>
                    </div>

                    {/* Key Rotation Status */}
                    <div className="flex items-center justify-between pt-3 border-t">
                      <div className="flex items-center gap-2 text-xs">
                        {rotationStatus.status === "overdue" && (
                          <AlertTriangle className="h-4 w-4 text-red-500" />
                        )}
                        {rotationStatus.status === "due-soon" && (
                          <AlertTriangle className="h-4 w-4 text-amber-500" />
                        )}
                        {rotationStatus.status === "healthy" && (
                          <CheckCircle2 className="h-4 w-4 text-green-500" />
                        )}
                        <span className={cn(
                          rotationStatus.status === "overdue" && "text-red-600",
                          rotationStatus.status === "due-soon" && "text-amber-600",
                          rotationStatus.status === "healthy" && "text-green-600"
                        )}>
                          {daysSince !== null ? `${daysSince}d ago` : "Never rotated"}
                        </span>
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleRotateKey(context.name)}
                        disabled={rotating === context.name}
                        className="h-7 text-xs"
                      >
                        {rotating === context.name ? (
                          <span className="animate-spin h-3 w-3 border-2 border-slate-600 border-t-transparent rounded-full" />
                        ) : (
                          <RotateCw className="h-3 w-3 mr-1" />
                        )}
                        {rotating === context.name ? "..." : "Rotate"}
                      </Button>
                    </div>

                    {/* Expandable Algorithm Suite */}
                    {expandedContexts.has(context.name) && (
                      <div className="mt-3 pt-3 border-t bg-slate-50 -mx-4 -mb-4 px-4 pb-4 rounded-b-lg">
                        <div className="text-xs font-medium text-slate-700 mb-2">Algorithm Suite</div>
                        {loadingSuites.has(context.name) ? (
                          <div className="flex items-center gap-2 text-xs text-slate-500">
                            <span className="animate-spin h-3 w-3 border-2 border-slate-400 border-t-transparent rounded-full" />
                            Loading...
                          </div>
                        ) : contextSuites[context.name]?.algorithm_suite ? (
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            <div className="flex items-center gap-1.5 p-2 bg-white rounded border">
                              <Lock className="h-3.5 w-3.5 text-blue-500" />
                              <div>
                                <div className="text-slate-500">Symmetric</div>
                                <div className="font-medium">{contextSuites[context.name]?.algorithm_suite?.symmetric}</div>
                              </div>
                            </div>
                            <div className="flex items-center gap-1.5 p-2 bg-white rounded border">
                              <PenTool className="h-3.5 w-3.5 text-purple-500" />
                              <div>
                                <div className="text-slate-500">Signing</div>
                                <div className="font-medium">{contextSuites[context.name]?.algorithm_suite?.signing}</div>
                              </div>
                            </div>
                            <div className="flex items-center gap-1.5 p-2 bg-white rounded border">
                              <Hash className="h-3.5 w-3.5 text-green-500" />
                              <div>
                                <div className="text-slate-500">Hash</div>
                                <div className="font-medium">{contextSuites[context.name]?.algorithm_suite?.hash}</div>
                              </div>
                            </div>
                            <div className="flex items-center gap-1.5 p-2 bg-white rounded border">
                              <Fingerprint className="h-3.5 w-3.5 text-amber-500" />
                              <div>
                                <div className="text-slate-500">KDF</div>
                                <div className="font-medium">{contextSuites[context.name]?.algorithm_suite?.kdf}</div>
                              </div>
                            </div>
                          </div>
                        ) : (
                          <div className="text-xs text-slate-500">
                            Algorithm suite not available
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-center py-12">
              <Shield className="h-12 w-12 text-slate-300 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-slate-900 mb-2">No contexts configured</h3>
              <p className="text-slate-500 mb-4">Encryption contexts define data types and their security policies.</p>
              <Button onClick={openCreateModal}>
                <Plus className="h-4 w-4 mr-2" />
                Create Your First Context
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create/Edit Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b">
              <h2 className="text-lg font-semibold">
                {editingContext ? `Edit Context: ${editingContext}` : "Create New Context"}
              </h2>
              <button onClick={closeModal} className="text-slate-400 hover:text-slate-600">
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Steps Indicator */}
            <div className="px-6 py-4 border-b bg-slate-50">
              <div className="flex items-center justify-between">
                {steps.map((step, index) => {
                  const Icon = step.icon;
                  return (
                    <button
                      key={step.name}
                      onClick={() => setCurrentStep(index)}
                      className={cn(
                        "flex items-center gap-2 px-3 py-1.5 rounded-md text-sm transition-all",
                        currentStep === index
                          ? "bg-blue-100 text-blue-700"
                          : "text-slate-500 hover:text-slate-700"
                      )}
                    >
                      <Icon className="h-4 w-4" />
                      <span className="hidden sm:inline">{step.name}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Content */}
            <div className="px-6 py-8 min-h-[340px] overflow-y-auto max-h-[calc(90vh-220px)]">
              {renderStepContent()}
            </div>

            {/* Footer */}
            <div className="flex items-center justify-between px-6 py-4 border-t bg-slate-50">
              <Button
                variant="outline"
                onClick={() => setCurrentStep(Math.max(0, currentStep - 1))}
                disabled={currentStep === 0}
              >
                Previous
              </Button>
              <div className="flex gap-2">
                <Button variant="outline" onClick={closeModal}>
                  Cancel
                </Button>
                {currentStep === steps.length - 1 ? (
                  <Button onClick={handleSave} disabled={saving || !formName || !formDisplayName}>
                    {saving ? "Saving..." : editingContext ? "Update Context" : "Create Context"}
                  </Button>
                ) : (
                  <Button onClick={() => setCurrentStep(currentStep + 1)}>
                    Next
                    <ChevronRight className="h-4 w-4 ml-1" />
                  </Button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </AdminLayout>
  );
}
