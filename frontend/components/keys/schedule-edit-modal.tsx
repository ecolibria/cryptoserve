"use client";

import React, { useState, useEffect } from "react";
import { Calendar, Key, Shield, FileSignature, X, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { KeyType, KeyInfo } from "@/lib/api";
import { cn } from "@/lib/utils";

interface ScheduleEditModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (rotationScheduleDays: number) => Promise<void>;
  keyType: KeyType;
  keyInfo: KeyInfo;
  contextName: string;
}

const keyTypeConfig: Record<KeyType, { icon: React.ElementType; label: string; color: string }> = {
  ENCRYPTION: { icon: Key, label: "Encryption Key", color: "text-blue-600" },
  MAC: { icon: Shield, label: "MAC Key", color: "text-emerald-600" },
  SIGNING: { icon: FileSignature, label: "Signing Key", color: "text-purple-600" },
};

const presetSchedules = [
  { days: 30, label: "30 days", description: "High security" },
  { days: 90, label: "90 days", description: "Recommended" },
  { days: 180, label: "180 days", description: "Standard" },
  { days: 365, label: "1 year", description: "Low frequency" },
];

export function ScheduleEditModal({
  isOpen,
  onClose,
  onConfirm,
  keyType,
  keyInfo,
  contextName,
}: ScheduleEditModalProps) {
  const [rotationDays, setRotationDays] = useState(keyInfo.rotationScheduleDays);
  const [customDays, setCustomDays] = useState("");
  const [useCustom, setUseCustom] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const config = keyTypeConfig[keyType];
  const Icon = config.icon;

  // Reset state when modal opens
  useEffect(() => {
    if (isOpen) {
      const currentDays = keyInfo.rotationScheduleDays;
      setRotationDays(currentDays);
      // Check if current value matches a preset
      const isPreset = presetSchedules.some(p => p.days === currentDays);
      setUseCustom(!isPreset);
      setCustomDays(isPreset ? "" : String(currentDays));
      setError(null);
    }
  }, [isOpen, keyInfo.rotationScheduleDays]);

  const handlePresetSelect = (days: number) => {
    setUseCustom(false);
    setRotationDays(days);
    setError(null);
  };

  const handleCustomChange = (value: string) => {
    setCustomDays(value);
    setUseCustom(true);
    const parsed = parseInt(value, 10);
    if (!isNaN(parsed) && parsed > 0) {
      setRotationDays(parsed);
      setError(null);
    } else if (value) {
      setError("Please enter a valid number of days");
    }
  };

  const handleConfirm = async () => {
    if (rotationDays < 1) {
      setError("Rotation schedule must be at least 1 day");
      return;
    }
    if (rotationDays > 3650) {
      setError("Rotation schedule cannot exceed 10 years (3650 days)");
      return;
    }

    setIsSaving(true);
    setError(null);
    try {
      await onConfirm(rotationDays);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update schedule");
    } finally {
      setIsSaving(false);
    }
  };

  const formatNextRotation = (days: number) => {
    const nextDate = new Date();
    nextDate.setDate(nextDate.getDate() + days);
    return nextDate.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200">
          <div className="flex items-center gap-3">
            <div className={cn("h-10 w-10 rounded-lg bg-blue-100 flex items-center justify-center")}>
              <Calendar className="h-5 w-5 text-blue-600" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-900">Edit Rotation Schedule</h2>
              <p className="text-sm text-slate-500">{config.label} - {contextName}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-100 rounded-lg transition-colors"
          >
            <X className="h-5 w-5 text-slate-400" />
          </button>
        </div>

        {/* Content */}
        <div className="px-6 py-5 space-y-5">
          {/* Current Schedule Info */}
          <div className="bg-slate-50 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <Icon className={cn("h-5 w-5", config.color)} />
              <div className="text-sm">
                <p className="font-medium text-slate-700">
                  Current schedule: Every {keyInfo.rotationScheduleDays} days
                </p>
                <p className="text-slate-500">
                  Last rotated: {new Date(keyInfo.lastRotatedAt).toLocaleDateString()}
                </p>
              </div>
            </div>
          </div>

          {/* Preset Options */}
          <div>
            <Label className="text-sm font-medium text-slate-700 mb-3 block">
              Rotation Frequency
            </Label>
            <div className="grid grid-cols-2 gap-3">
              {presetSchedules.map((preset) => (
                <button
                  key={preset.days}
                  onClick={() => handlePresetSelect(preset.days)}
                  className={cn(
                    "p-3 rounded-lg border text-left transition-all",
                    !useCustom && rotationDays === preset.days
                      ? "border-blue-500 bg-blue-50 ring-2 ring-blue-200"
                      : "border-slate-200 hover:border-slate-300 hover:bg-slate-50"
                  )}
                >
                  <div className="font-medium text-slate-900">{preset.label}</div>
                  <div className="text-xs text-slate-500">{preset.description}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Custom Input */}
          <div>
            <Label className="text-sm font-medium text-slate-700 mb-2 block">
              Or enter custom days
            </Label>
            <div className="flex items-center gap-3">
              <input
                type="number"
                min="1"
                max="3650"
                value={customDays}
                onChange={(e) => handleCustomChange(e.target.value)}
                placeholder="Enter days..."
                className={cn(
                  "flex-1 px-3 py-2.5 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent",
                  useCustom && customDays ? "border-blue-500 bg-blue-50" : "border-slate-200"
                )}
              />
              <span className="text-sm text-slate-500">days</span>
            </div>
          </div>

          {/* Preview */}
          {rotationDays > 0 && (
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <Calendar className="h-5 w-5 text-blue-500 mt-0.5 flex-shrink-0" />
                <div className="text-sm">
                  <p className="font-medium text-blue-800">New Schedule Preview</p>
                  <p className="text-blue-700 mt-1">
                    Keys will rotate every <strong>{rotationDays}</strong> days.
                    Next rotation: <strong>{formatNextRotation(rotationDays)}</strong>
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <div className="flex items-center gap-2 text-red-700 text-sm">
                <AlertCircle className="h-4 w-4" />
                {error}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-slate-200 bg-slate-50">
          <Button variant="outline" onClick={onClose} disabled={isSaving}>
            Cancel
          </Button>
          <Button
            onClick={handleConfirm}
            disabled={isSaving || rotationDays < 1 || rotationDays === keyInfo.rotationScheduleDays}
          >
            {isSaving ? (
              <>
                <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full mr-2" />
                Saving...
              </>
            ) : (
              "Save Schedule"
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}
