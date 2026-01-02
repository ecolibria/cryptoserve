"use client";

import React, { useState } from "react";
import { AlertTriangle, Key, Shield, FileSignature, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { KeyType } from "@/lib/api";
import { cn } from "@/lib/utils";

interface RotationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (reason: string, reencrypt: boolean) => Promise<void>;
  keyType: KeyType;
  contextName: string;
  currentVersion: number;
}

const keyTypeConfig: Record<KeyType, { icon: React.ElementType; label: string; color: string }> = {
  ENCRYPTION: { icon: Key, label: "Encryption Key", color: "text-blue-600" },
  MAC: { icon: Shield, label: "MAC Key", color: "text-emerald-600" },
  SIGNING: { icon: FileSignature, label: "Signing Key", color: "text-purple-600" },
};

const defaultReasons = [
  "Scheduled rotation",
  "Security policy compliance",
  "Key compromise suspected",
  "Personnel change",
  "Compliance audit",
];

export function RotationModal({
  isOpen,
  onClose,
  onConfirm,
  keyType,
  contextName,
  currentVersion,
}: RotationModalProps) {
  const [reason, setReason] = useState(defaultReasons[0]);
  const [customReason, setCustomReason] = useState("");
  const [reencrypt, setReencrypt] = useState(false);
  const [isConfirming, setIsConfirming] = useState(false);

  const config = keyTypeConfig[keyType];
  const Icon = config.icon;

  const handleConfirm = async () => {
    setIsConfirming(true);
    try {
      const finalReason = reason === "custom" ? customReason : reason;
      await onConfirm(finalReason, reencrypt);
      onClose();
    } catch (error) {
      console.error("Rotation failed:", error);
    } finally {
      setIsConfirming(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200">
          <div className="flex items-center gap-3">
            <div className={cn("h-10 w-10 rounded-lg bg-amber-100 flex items-center justify-center")}>
              <AlertTriangle className="h-5 w-5 text-amber-600" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-900">Rotate {config.label}</h2>
              <p className="text-sm text-slate-500">This action cannot be undone</p>
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
          {/* Warning Banner */}
          <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5 flex-shrink-0" />
              <div className="text-sm">
                <p className="font-medium text-amber-800 mb-1">You are about to rotate:</p>
                <ul className="text-amber-700 space-y-1">
                  <li><strong>Context:</strong> {contextName}</li>
                  <li><strong>Current Version:</strong> {currentVersion}</li>
                  <li><strong>New Version:</strong> {currentVersion + 1}</li>
                </ul>
              </div>
            </div>
          </div>

          {/* What Will Happen */}
          <div className="bg-slate-50 rounded-lg p-4">
            <p className="text-sm font-medium text-slate-700 mb-2">This will:</p>
            <ul className="text-sm text-slate-600 space-y-1.5">
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 bg-slate-400 rounded-full" />
                Generate a new {config.label.toLowerCase()}
              </li>
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 bg-slate-400 rounded-full" />
                Mark the current key for retirement
              </li>
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 bg-slate-400 rounded-full" />
                New operations will use the new key
              </li>
              <li className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 bg-slate-400 rounded-full" />
                Old data remains decryptable during transition
              </li>
            </ul>
          </div>

          {/* Reason Selection */}
          <div>
            <Label className="text-sm font-medium text-slate-700 mb-2 block">
              Reason for rotation
            </Label>
            <select
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="w-full px-3 py-2.5 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              {defaultReasons.map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
              <option value="custom">Custom reason...</option>
            </select>
            {reason === "custom" && (
              <textarea
                value={customReason}
                onChange={(e) => setCustomReason(e.target.value)}
                placeholder="Enter your reason..."
                className="w-full mt-2 px-3 py-2.5 border border-slate-200 rounded-lg text-sm resize-none h-20 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            )}
          </div>

          {/* Re-encrypt Option (only for encryption keys) */}
          {keyType === "ENCRYPTION" && (
            <div className="flex items-start gap-3 p-4 border border-slate-200 rounded-lg">
              <input
                type="checkbox"
                id="reencrypt"
                checked={reencrypt}
                onChange={(e) => setReencrypt(e.target.checked)}
                className="h-4 w-4 mt-0.5 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
              />
              <div>
                <Label htmlFor="reencrypt" className="font-medium text-slate-900 cursor-pointer">
                  Re-encrypt existing data with new key
                </Label>
                <p className="text-xs text-slate-500 mt-0.5">
                  This may take significant time depending on data volume.
                  Data remains accessible during the process.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-slate-200 bg-slate-50">
          <Button variant="outline" onClick={onClose} disabled={isConfirming}>
            Cancel
          </Button>
          <Button
            onClick={handleConfirm}
            disabled={isConfirming || (reason === "custom" && !customReason.trim())}
            className="bg-amber-600 hover:bg-amber-700"
          >
            {isConfirming ? (
              <>
                <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full mr-2" />
                Rotating...
              </>
            ) : (
              "Confirm Rotation"
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}
