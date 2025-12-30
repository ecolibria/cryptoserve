"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Shield,
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
  X,
  Zap,
  Clock,
  Globe,
  FileWarning,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AdminLayout } from "@/components/admin-layout";
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
} from "@/lib/api";
import { cn } from "@/lib/utils";

// Default values for new context
const defaultDataIdentity: DataIdentity = {
  category: "general",
  subcategory: null,
  sensitivity: "medium",
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

const frameworkOptions = ["GDPR", "CCPA", "PCI-DSS", "HIPAA", "SOX", "SOC2"];

export default function AdminContextsPage() {
  const [contexts, setContexts] = useState<AdminContextStats[]>([]);
  const [loading, setLoading] = useState(true);
  const [rotating, setRotating] = useState<string | null>(null);

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

  const steps = [
    { name: "Basic Info", icon: Shield },
    { name: "Data Identity", icon: FileWarning },
    { name: "Regulatory", icon: Globe },
    { name: "Threat Model", icon: AlertTriangle },
    { name: "Access Patterns", icon: Zap },
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

  // Render step content
  const renderStepContent = () => {
    switch (currentStep) {
      case 0:
        return (
          <div className="space-y-4">
            <div>
              <Label htmlFor="name">Context ID</Label>
              <Input
                id="name"
                value={formName}
                onChange={(e) => setFormName(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "-"))}
                placeholder="e.g., user-pii, payment-data"
                disabled={!!editingContext}
                className="font-mono"
              />
              <p className="text-xs text-slate-500 mt-1">Lowercase with hyphens only</p>
            </div>
            <div>
              <Label htmlFor="displayName">Display Name</Label>
              <Input
                id="displayName"
                value={formDisplayName}
                onChange={(e) => setFormDisplayName(e.target.value)}
                placeholder="e.g., User Personal Data"
              />
            </div>
            <div>
              <Label htmlFor="description">Description</Label>
              <textarea
                id="description"
                value={formDescription}
                onChange={(e) => setFormDescription(e.target.value)}
                placeholder="Describe what data this context protects..."
                className="w-full h-24 px-3 py-2 border rounded-md text-sm resize-none"
              />
            </div>
          </div>
        );

      case 1:
        return (
          <div className="space-y-4">
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
          </div>
        );

      case 2:
        return (
          <div className="space-y-4">
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
          <div className="space-y-4">
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
          <div className="space-y-4">
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
      subtitle={`${contexts.length} encryption contexts configured`}
      onRefresh={loadContexts}
    >
      {/* Create Context Button */}
      <div className="mb-6">
        <Button onClick={openCreateModal}>
          <Plus className="h-4 w-4 mr-2" />
          Create Context
        </Button>
      </div>

      {/* Contexts Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {contexts.map((context) => {
          const rotationStatus = getRotationStatus(context.last_key_rotation);
          const daysSince = getDaysSinceRotation(context.last_key_rotation);

          return (
            <Card key={context.name} className="overflow-hidden">
              <CardHeader className="pb-2">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <div className="h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center">
                      <Lock className="h-5 w-5 text-blue-600" />
                    </div>
                    <div>
                      <CardTitle className="text-base">{context.display_name}</CardTitle>
                      <p className="text-xs text-slate-500 font-mono">{context.name}</p>
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => openEditModal(context.name)}
                  >
                    <Edit className="h-4 w-4" />
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Description */}
                <p className="text-sm text-slate-600">{context.description}</p>

                {/* Compliance Tags */}
                {context.compliance_tags && context.compliance_tags.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {context.compliance_tags.map((tag) => (
                      <span
                        key={tag}
                        className="px-2 py-0.5 rounded text-xs font-medium bg-emerald-100 text-emerald-700"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                )}

                {/* Algorithm */}
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-500">Algorithm</span>
                  <span className="font-mono text-xs bg-slate-100 px-2 py-1 rounded">
                    {context.algorithm}
                  </span>
                </div>

                {/* Stats */}
                <div className="grid grid-cols-2 gap-4 pt-2 border-t">
                  <div className="flex items-center gap-2">
                    <Activity className="h-4 w-4 text-slate-400" />
                    <div>
                      <p className="text-lg font-semibold">{context.operation_count.toLocaleString()}</p>
                      <p className="text-xs text-slate-500">Operations</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Users className="h-4 w-4 text-slate-400" />
                    <div>
                      <p className="text-lg font-semibold">{context.identity_count}</p>
                      <p className="text-xs text-slate-500">Identities</p>
                    </div>
                  </div>
                </div>

                {/* Key Info */}
                <div className="pt-3 border-t space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-500">Key Version</span>
                    <span className="text-sm font-medium">v{context.key_version}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-500">Last Rotation</span>
                    <div className="flex items-center gap-2">
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
                        "text-sm font-medium",
                        rotationStatus.status === "overdue" && "text-red-600",
                        rotationStatus.status === "due-soon" && "text-amber-600",
                        rotationStatus.status === "healthy" && "text-green-600"
                      )}>
                        {daysSince !== null ? `${daysSince} days ago` : "Never"}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Actions */}
                <div className="pt-3 border-t">
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full"
                    onClick={() => handleRotateKey(context.name)}
                    disabled={rotating === context.name}
                  >
                    {rotating === context.name ? (
                      <>
                        <span className="animate-spin h-4 w-4 border-2 border-slate-600 border-t-transparent rounded-full mr-2" />
                        Rotating...
                      </>
                    ) : (
                      <>
                        <RotateCw className="h-4 w-4 mr-2" />
                        Rotate Key
                      </>
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {contexts.length === 0 && (
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
            <div className="px-6 py-6 min-h-[300px]">
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
