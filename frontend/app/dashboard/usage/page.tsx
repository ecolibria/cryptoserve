"use client";

import React, { useEffect, useState, useCallback } from "react";
import {
  Activity,
  BarChart3,
  AlertTriangle,
  TrendingUp,
  Lock,
  Unlock,
  FileSignature,
  CheckCircle2,
  Clock,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DashboardLayout } from "@/components/dashboard-layout";
import { StatCard } from "@/components/ui/stat-card";
import {
  api,
  UsageStatsResponse,
  ContextUsageStats,
  ErrorSummary,
  DailyUsageStats,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const periodOptions = [
  { value: "7", label: "Last 7 days" },
  { value: "14", label: "Last 14 days" },
  { value: "30", label: "Last 30 days" },
  { value: "90", label: "Last 90 days" },
];

export default function UsageStatsPage() {
  const [stats, setStats] = useState<UsageStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedPeriod, setSelectedPeriod] = useState("30");

  const loadStats = useCallback(async () => {
    try {
      setLoading(true);
      const days = parseInt(selectedPeriod);
      const endDate = new Date();
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - days);

      const data = await api.getUsageStats({
        startDate: startDate.toISOString(),
        endDate: endDate.toISOString(),
      });
      setStats(data);
    } catch (error) {
      console.error("Failed to load stats:", error);
    } finally {
      setLoading(false);
    }
  }, [selectedPeriod]);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  const formatNumber = (num: number) => {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + "M";
    if (num >= 1000) return (num / 1000).toFixed(1) + "K";
    return num.toString();
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
    });
  };

  const getRelativeTime = (dateString: string) => {
    const now = new Date();
    const then = new Date(dateString);
    const diffMs = now.getTime() - then.getTime();
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return "Today";
    if (diffDays === 1) return "Yesterday";
    if (diffDays < 7) return `${diffDays}d ago`;
    if (diffDays < 30) return `${Math.floor(diffDays / 7)}w ago`;
    return `${Math.floor(diffDays / 30)}mo ago`;
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-slate-600" />
        </div>
      </DashboardLayout>
    );
  }

  if (!stats) {
    return (
      <DashboardLayout>
        <div className="px-4 sm:px-6 lg:px-8 py-8 max-w-7xl mx-auto">
          <div className="text-center py-12">
            <AlertTriangle className="h-12 w-12 text-amber-500 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-slate-900 mb-2">Unable to load statistics</h3>
            <p className="text-slate-500">Please try again later.</p>
          </div>
        </div>
      </DashboardLayout>
    );
  }

  // Calculate totals
  const totalEncrypt = stats.byContext.reduce((sum, c) => sum + c.encryptCalls, 0);
  const totalDecrypt = stats.byContext.reduce((sum, c) => sum + c.decryptCalls, 0);
  const totalSign = stats.byContext.reduce((sum, c) => sum + c.signCalls, 0);
  const totalVerify = stats.byContext.reduce((sum, c) => sum + c.verifyCalls, 0);
  const totalErrors = stats.errors.reduce((sum, e) => sum + e.count, 0);

  return (
    <DashboardLayout>
      <div className="px-4 sm:px-6 lg:px-8 py-8 max-w-7xl mx-auto">
        {/* Page Header */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-8 gap-4">
          <div>
            <h1 className="text-2xl font-bold text-slate-900">Usage Statistics</h1>
            <p className="text-slate-500 mt-1">
              API call statistics and error tracking
            </p>
          </div>
          <select
            value={selectedPeriod}
            onChange={(e) => setSelectedPeriod(e.target.value)}
            className="px-3 py-2 border border-slate-200 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            {periodOptions.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

        {/* Summary Stats */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
          <StatCard
            title="Total Calls"
            value={formatNumber(stats.totalCalls)}
            subtitle={`Last ${selectedPeriod} days`}
            icon={<Activity className="h-5 w-5 text-blue-500" />}
          />
          <StatCard
            title="Encrypt"
            value={formatNumber(totalEncrypt)}
            subtitle="Operations"
            icon={<Lock className="h-5 w-5 text-green-500" />}
            color="green"
          />
          <StatCard
            title="Decrypt"
            value={formatNumber(totalDecrypt)}
            subtitle="Operations"
            icon={<Unlock className="h-5 w-5 text-emerald-500" />}
            color="green"
          />
          <StatCard
            title="Sign/Verify"
            value={formatNumber(totalSign + totalVerify)}
            subtitle="Operations"
            icon={<FileSignature className="h-5 w-5 text-purple-500" />}
            color="purple"
          />
          <StatCard
            title="Errors"
            value={totalErrors.toString()}
            subtitle={`Last ${selectedPeriod} days`}
            icon={<AlertTriangle className="h-5 w-5 text-red-500" />}
            color={totalErrors > 0 ? "rose" : "default"}
          />
        </div>

        {/* Usage Chart */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="h-5 w-5 text-blue-500" />
              API Calls Over Time
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={stats.dailyBreakdown}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis
                    dataKey="date"
                    tick={{ fontSize: 11 }}
                    stroke="#94a3b8"
                    tickLine={false}
                    tickFormatter={formatDate}
                  />
                  <YAxis
                    tick={{ fontSize: 11 }}
                    stroke="#94a3b8"
                    tickLine={false}
                    tickFormatter={formatNumber}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#1e293b",
                      border: "none",
                      borderRadius: "8px",
                      color: "#f8fafc",
                    }}
                    formatter={(value) => [formatNumber(value as number), "Calls"]}
                    labelFormatter={(label) => formatDate(label as string)}
                  />
                  <Line
                    type="monotone"
                    dataKey="totalCalls"
                    stroke="#3b82f6"
                    strokeWidth={2}
                    dot={false}
                    activeDot={{ r: 4 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Context Usage Table */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-blue-500" />
              By Context
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-200">
                    <th className="text-left text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
                      Context
                    </th>
                    <th className="text-right text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
                      Encrypt
                    </th>
                    <th className="text-right text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
                      Decrypt
                    </th>
                    <th className="text-right text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
                      Sign
                    </th>
                    <th className="text-right text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
                      Verify
                    </th>
                    <th className="text-right text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
                      Total
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {stats.byContext.map((ctx) => {
                    const total = ctx.encryptCalls + ctx.decryptCalls + ctx.signCalls + ctx.verifyCalls;
                    return (
                      <tr key={ctx.contextId} className="hover:bg-slate-50 transition-colors">
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <div className="h-8 w-8 rounded-lg bg-blue-100 flex items-center justify-center">
                              <Lock className="h-4 w-4 text-blue-600" />
                            </div>
                            <span className="font-medium text-slate-900">{ctx.contextName}</span>
                          </div>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <span className="font-mono text-sm text-slate-600">
                            {formatNumber(ctx.encryptCalls)}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <span className="font-mono text-sm text-slate-600">
                            {formatNumber(ctx.decryptCalls)}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <span className="font-mono text-sm text-slate-600">
                            {ctx.signCalls > 0 ? formatNumber(ctx.signCalls) : "—"}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <span className="font-mono text-sm text-slate-600">
                            {ctx.verifyCalls > 0 ? formatNumber(ctx.verifyCalls) : "—"}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <span className="font-mono text-sm font-medium text-slate-900">
                            {formatNumber(total)}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        {/* Error Summary */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              Errors (Last {selectedPeriod} days)
            </CardTitle>
          </CardHeader>
          <CardContent>
            {stats.errors.length === 0 ? (
              <div className="text-center py-8">
                <CheckCircle2 className="h-12 w-12 text-green-500 mx-auto mb-3" />
                <p className="text-slate-600 font-medium">No errors reported</p>
                <p className="text-sm text-slate-500">All operations completed successfully</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-slate-200">
                      <th className="text-left text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
                        Context
                      </th>
                      <th className="text-left text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
                        Error Type
                      </th>
                      <th className="text-right text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
                        Count
                      </th>
                      <th className="text-right text-xs font-medium text-slate-500 uppercase tracking-wider py-3 px-4">
                        Last Occurred
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {stats.errors.map((error, idx) => (
                      <tr key={idx} className="hover:bg-slate-50 transition-colors">
                        <td className="py-3 px-4">
                          <span className="font-medium text-slate-900">{error.contextName}</span>
                        </td>
                        <td className="py-3 px-4">
                          <Badge variant="destructive" className="font-mono text-xs">
                            {error.errorType}
                          </Badge>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <span className="font-mono text-sm font-medium text-red-600">
                            {error.count}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end gap-1.5 text-sm text-slate-500">
                            <Clock className="h-3.5 w-3.5" />
                            {getRelativeTime(error.lastOccurred)}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
