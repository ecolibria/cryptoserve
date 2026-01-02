"use client";

import React from "react";
import { Key, Shield, FileSignature, CheckCircle2, Clock, Archive } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { KeyHistoryEntry, KeyType, KeyStatus } from "@/lib/api";
import { cn } from "@/lib/utils";

interface KeyHistoryTableProps {
  history: KeyHistoryEntry[];
  isLoading?: boolean;
}

const keyTypeConfig: Record<KeyType, { icon: React.ElementType; label: string; color: string; bgColor: string }> = {
  ENCRYPTION: { icon: Key, label: "Encryption", color: "text-blue-600", bgColor: "bg-blue-100" },
  MAC: { icon: Shield, label: "MAC", color: "text-emerald-600", bgColor: "bg-emerald-100" },
  SIGNING: { icon: FileSignature, label: "Signing", color: "text-purple-600", bgColor: "bg-purple-100" },
};

const statusConfig: Record<KeyStatus, { icon: React.ElementType; label: string; color: string }> = {
  ACTIVE: { icon: CheckCircle2, label: "Active", color: "text-green-600" },
  RETIRING: { icon: Clock, label: "Retiring", color: "text-amber-600" },
  RETIRED: { icon: Archive, label: "Retired", color: "text-slate-500" },
};

export function KeyHistoryTable({ history, isLoading }: KeyHistoryTableProps) {
  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-48">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-slate-600" />
      </div>
    );
  }

  if (history.length === 0) {
    return (
      <div className="text-center py-12 text-slate-500">
        <Archive className="h-12 w-12 mx-auto mb-3 text-slate-300" />
        <p className="text-sm">No key rotation history available</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-slate-200">
            <th className="text-left text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
              Version
            </th>
            <th className="text-left text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
              Type
            </th>
            <th className="text-left text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
              Algorithm
            </th>
            <th className="text-left text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
              Created
            </th>
            <th className="text-left text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
              Retired
            </th>
            <th className="text-left text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
              Status
            </th>
            <th className="text-left text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
              Reason
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {history.map((entry) => {
            const typeConfig = keyTypeConfig[entry.keyType];
            const status = statusConfig[entry.status];
            const TypeIcon = typeConfig.icon;
            const StatusIcon = status.icon;

            return (
              <tr
                key={entry.id}
                className={cn(
                  "hover:bg-slate-50 transition-colors",
                  entry.status === "RETIRED" && "opacity-60"
                )}
              >
                <td className="py-3 px-4">
                  <span className="font-mono text-sm font-medium text-slate-900">
                    v{entry.version}
                  </span>
                </td>
                <td className="py-3 px-4">
                  <div className="flex items-center gap-2">
                    <div className={cn("h-6 w-6 rounded flex items-center justify-center", typeConfig.bgColor)}>
                      <TypeIcon className={cn("h-3.5 w-3.5", typeConfig.color)} />
                    </div>
                    <span className="text-sm text-slate-700">{typeConfig.label}</span>
                  </div>
                </td>
                <td className="py-3 px-4">
                  <span className="text-sm font-mono text-slate-600">{entry.algorithm}</span>
                </td>
                <td className="py-3 px-4">
                  <span className="text-sm text-slate-600">{formatDate(entry.createdAt)}</span>
                </td>
                <td className="py-3 px-4">
                  <span className="text-sm text-slate-600">
                    {entry.retiredAt ? formatDate(entry.retiredAt) : "—"}
                  </span>
                </td>
                <td className="py-3 px-4">
                  <div className="flex items-center gap-1.5">
                    <StatusIcon className={cn("h-4 w-4", status.color)} />
                    <span className={cn("text-sm font-medium", status.color)}>
                      {status.label}
                    </span>
                  </div>
                </td>
                <td className="py-3 px-4">
                  <span className="text-sm text-slate-600 truncate max-w-[200px] block">
                    {entry.rotationReason || "—"}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
