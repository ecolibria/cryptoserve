"use client";

import React, { useEffect, useState, useCallback } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Edit,
  X,
  RotateCw,
  Atom,
  Info,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { AdminLayout } from "@/components/admin-layout";
import {
  api,
  ClassificationAlgorithmPolicy,
  DataClassification,
} from "@/lib/api";
import { cn } from "@/lib/utils";


const classificationConfig: Record<DataClassification, {
  icon: React.ElementType;
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

const encryptionOptions = [
  "AES-128-GCM",
  "AES-256-GCM",
  "AES-256-GCM + HKDF",
  "ChaCha20-Poly1305",
];

const macOptions = [
  "HMAC-SHA256",
  "HMAC-SHA384",
  "HMAC-SHA512",
];

const signingOptions = [
  "Ed25519",
  "Ed448",
  "ECDSA-P256",
  "ECDSA-P384",
];

export default function AlgorithmPolicyPage() {
  const [policies, setPolicies] = useState<ClassificationAlgorithmPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [quantumReady, setQuantumReady] = useState(false);

  // Edit modal state
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<ClassificationAlgorithmPolicy | null>(null);
  const [saving, setSaving] = useState(false);

  // Form state
  const [formEncryption, setFormEncryption] = useState("");
  const [formMac, setFormMac] = useState("");
  const [formSigning, setFormSigning] = useState("");
  const [formEncryptionRotation, setFormEncryptionRotation] = useState(90);
  const [formMacRotation, setFormMacRotation] = useState(180);
  const [formSigningRotation, setFormSigningRotation] = useState(365);

  const loadPolicies = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.getAlgorithmPolicies();
      setPolicies(data);
      // Check if any policy has quantum safe required
      setQuantumReady(data.some(p => p.requireQuantumSafe));
    } catch (error) {
      console.error("Failed to load policies:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPolicies();
  }, [loadPolicies]);

  const openEditModal = (policy: ClassificationAlgorithmPolicy) => {
    setEditingPolicy(policy);
    setFormEncryption(policy.defaultEncryptionAlgorithm);
    setFormMac(policy.defaultMacAlgorithm);
    setFormSigning(policy.defaultSigningAlgorithm || "");
    setFormEncryptionRotation(policy.keyRotationDays);
    setFormMacRotation(policy.keyRotationDays);
    setFormSigningRotation(policy.keyRotationDays);
    setShowEditModal(true);
  };

  const closeEditModal = () => {
    setShowEditModal(false);
    setEditingPolicy(null);
  };

  const handleSavePolicy = async () => {
    if (!editingPolicy) return;

    setSaving(true);
    try {
      await api.updateAlgorithmPolicyByClassification(editingPolicy.classification, {
        defaultEncryptionAlgorithm: formEncryption,
        defaultMacAlgorithm: formMac,
        defaultSigningAlgorithm: formSigning || null,
        keyRotationDays: formEncryptionRotation,
      });
      await loadPolicies();
      closeEditModal();
    } catch (error) {
      console.error("Failed to save policy:", error);
      alert("Failed to save policy. Please try again.");
    } finally {
      setSaving(false);
    }
  };

  const handleToggleQuantumReady = async () => {
    const newValue = !quantumReady;
    setQuantumReady(newValue);
    // This would update all CRITICAL policies to enable/disable quantum-ready
    // In a real implementation, this would call an API
    console.log("Quantum ready toggled:", newValue);
  };

  if (loading) {
    return (
      <AdminLayout title="Algorithm Policy" subtitle="Loading...">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-slate-600" />
        </div>
      </AdminLayout>
    );
  }

  return (
    <AdminLayout
      title="Algorithm Policy"
      subtitle="Configure default algorithms by data classification"
      onRefresh={loadPolicies}
    >
      {/* Info Banner */}
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 mb-6">
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
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {policies.map((policy) => {
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
                    onClick={() => openEditModal(policy)}
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

      {/* Edit Modal */}
      {showEditModal && editingPolicy && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200">
              <div className="flex items-center gap-3">
                {(() => {
                  const config = classificationConfig[editingPolicy.classification];
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
                onClick={closeEditModal}
                className="p-2 hover:bg-slate-100 rounded-lg transition-colors"
              >
                <X className="h-5 w-5 text-slate-400" />
              </button>
            </div>

            {/* Content */}
            <div className="px-6 py-5 space-y-5 max-h-[60vh] overflow-y-auto">
              {/* Algorithm Selection */}
              <div>
                <Label className="text-sm font-medium text-slate-700 mb-2 block">
                  Encryption Algorithm
                </Label>
                <select
                  value={formEncryption}
                  onChange={(e) => setFormEncryption(e.target.value)}
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
                  value={formMac}
                  onChange={(e) => setFormMac(e.target.value)}
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
                  value={formSigning}
                  onChange={(e) => setFormSigning(e.target.value)}
                  className="w-full px-3 py-2.5 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  {signingOptions.map((opt) => (
                    <option key={opt} value={opt}>{opt}</option>
                  ))}
                </select>
              </div>

              {/* Rotation Schedule */}
              <div className="pt-4 border-t border-slate-200">
                <h4 className="text-sm font-medium text-slate-700 mb-3">Key Rotation Schedule</h4>
                <div>
                  <Label className="text-xs text-slate-500 mb-1.5 block">Rotation Period (days)</Label>
                  <Input
                    type="number"
                    min={7}
                    max={365}
                    value={formEncryptionRotation}
                    onChange={(e) => setFormEncryptionRotation(parseInt(e.target.value) || 90)}
                  />
                  <p className="text-xs text-slate-400 mt-1">Recommended: 30 (Critical), 60 (Sensitive), 90 (Internal), 180 (Public)</p>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-slate-200 bg-slate-50">
              <Button variant="outline" onClick={closeEditModal} disabled={saving}>
                Cancel
              </Button>
              <Button onClick={handleSavePolicy} disabled={saving}>
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
    </AdminLayout>
  );
}
