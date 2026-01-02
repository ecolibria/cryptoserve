"use client";

import React from "react";
import { Key, Shield, FileSignature, Clock, Calendar, RotateCw, Settings } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { KeyInfo, KeyType, KeyStatus } from "@/lib/api";
import { cn } from "@/lib/utils";

interface KeyInfoCardProps {
  keyInfo: KeyInfo;
  keyType: KeyType;
  onRotate: () => void;
  onEditSchedule: () => void;
  isRotating?: boolean;
}

const keyTypeConfig: Record<KeyType, { icon: React.ElementType; label: string; color: string; bgColor: string }> = {
  ENCRYPTION: { icon: Key, label: "Encryption Key", color: "text-blue-600", bgColor: "bg-blue-100" },
  MAC: { icon: Shield, label: "MAC Key", color: "text-emerald-600", bgColor: "bg-emerald-100" },
  SIGNING: { icon: FileSignature, label: "Signing Key", color: "text-purple-600", bgColor: "bg-purple-100" },
};

const statusConfig: Record<KeyStatus, { label: string; variant: "default" | "secondary" | "destructive" | "outline" | "success" | "warning" }> = {
  ACTIVE: { label: "Active", variant: "success" },
  RETIRING: { label: "Retiring", variant: "warning" },
  RETIRED: { label: "Retired", variant: "secondary" },
};

export function KeyInfoCard({ keyInfo, keyType, onRotate, onEditSchedule, isRotating }: KeyInfoCardProps) {
  const config = keyTypeConfig[keyType];
  const Icon = config.icon;
  const status = statusConfig[keyInfo.status];

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  const getDaysUntilExpiry = (expiresAt: string) => {
    const now = new Date();
    const expiry = new Date(expiresAt);
    const diffTime = expiry.getTime() - now.getTime();
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
  };

  const daysUntilExpiry = getDaysUntilExpiry(keyInfo.expiresAt);
  const isExpiringSoon = daysUntilExpiry <= 30;
  const isExpired = daysUntilExpiry <= 0;

  return (
    <Card className="relative overflow-hidden">
      {/* Top accent bar */}
      <div className={cn("absolute top-0 left-0 right-0 h-1", config.bgColor.replace("100", "500"))} />

      <CardHeader className="pb-3 pt-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={cn("h-10 w-10 rounded-lg flex items-center justify-center", config.bgColor)}>
              <Icon className={cn("h-5 w-5", config.color)} />
            </div>
            <div>
              <CardTitle className="text-base font-semibold">{config.label}</CardTitle>
              <p className="text-xs text-slate-500 font-mono mt-0.5">v{keyInfo.version}</p>
            </div>
          </div>
          <Badge variant={status.variant}>{status.label}</Badge>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Key Details Grid */}
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-slate-500 text-xs mb-1">Algorithm</p>
            <p className="font-medium text-slate-900">{keyInfo.algorithm}</p>
          </div>
          <div>
            <p className="text-slate-500 text-xs mb-1">Version</p>
            <p className="font-medium text-slate-900">{keyInfo.version}</p>
          </div>
          <div>
            <p className="text-slate-500 text-xs mb-1">Created</p>
            <p className="font-medium text-slate-900">{formatDate(keyInfo.createdAt)}</p>
          </div>
          <div>
            <p className="text-slate-500 text-xs mb-1">Expires</p>
            <p className={cn(
              "font-medium",
              isExpired ? "text-red-600" : isExpiringSoon ? "text-amber-600" : "text-slate-900"
            )}>
              {formatDate(keyInfo.expiresAt)}
              <span className="text-xs ml-1">
                ({isExpired ? "Expired" : `${daysUntilExpiry} days`})
              </span>
            </p>
          </div>
        </div>

        {/* Rotation Schedule */}
        <div className="pt-3 border-t border-slate-100">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2 text-sm">
              <Clock className="h-4 w-4 text-slate-400" />
              <span className="text-slate-600">Rotation Schedule</span>
            </div>
            <span className="text-sm font-medium text-slate-900">
              Every {keyInfo.rotationScheduleDays} days
            </span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2">
              <Calendar className="h-4 w-4 text-slate-400" />
              <span className="text-slate-600">Last Rotated</span>
            </div>
            <span className="font-medium text-slate-900">{formatDate(keyInfo.lastRotatedAt)}</span>
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-2 pt-3 border-t border-slate-100">
          <Button
            variant="default"
            size="sm"
            onClick={onRotate}
            disabled={isRotating}
            className="flex-1"
          >
            {isRotating ? (
              <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
            ) : (
              <RotateCw className="h-4 w-4 mr-1.5" />
            )}
            Rotate Now
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={onEditSchedule}
            className="flex-1"
          >
            <Settings className="h-4 w-4 mr-1.5" />
            Edit Schedule
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
