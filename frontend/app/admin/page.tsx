"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Users,
  Key,
  Activity,
  CheckCircle2,
  Clock,
  Database,
  AlertTriangle,
  XCircle,
  Zap,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AdminLayout } from "@/components/admin-layout";
import { StatCard } from "@/components/ui/stat-card";
import { LineChart } from "@/components/charts/line-chart";
import { BarChart } from "@/components/charts/bar-chart";
import {
  api,
  AdminDashboardStats,
  TrendDataPoint,
  TeamUsage,
  HealthStatus,
  AuditLog,
  RiskScoreResponse,
  QuantumReadinessResponse,
  ComplianceStatusResponse,
  AlgorithmMetrics,
} from "@/lib/api";
import { RiskScoreGauge } from "@/components/premium/risk-score-gauge";
import { QuantumReadinessMeter } from "@/components/premium/quantum-readiness-meter";
import { ComplianceBadges } from "@/components/premium/compliance-badges";
import { cn } from "@/lib/utils";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function formatNumber(num: number): string {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + "M";
  if (num >= 1000) return (num / 1000).toFixed(1) + "K";
  return num.toString();
}

export default function AdminDashboard() {
  const [stats, setStats] = useState<AdminDashboardStats | null>(null);
  const [trends, setTrends] = useState<TrendDataPoint[]>([]);
  const [teamUsage, setTeamUsage] = useState<TeamUsage[]>([]);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [recentLogs, setRecentLogs] = useState<AuditLog[]>([]);
  const [riskScore, setRiskScore] = useState<RiskScoreResponse | null>(null);
  const [quantumReadiness, setQuantumReadiness] = useState<QuantumReadinessResponse | null>(null);
  const [complianceStatus, setComplianceStatus] = useState<ComplianceStatusResponse | null>(null);
  const [algorithmMetrics, setAlgorithmMetrics] = useState<AlgorithmMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = useCallback(async () => {
    try {
      const [
        statsData,
        trendsData,
        teamsData,
        healthData,
        logsData,
        riskData,
        quantumData,
        complianceData,
        algoMetrics,
      ] = await Promise.all([
        api.getAdminDashboard(),
        api.getOperationTrends(30),
        api.getTeamUsage(5),
        api.getSystemHealth(),
        api.getGlobalAuditLogs({ limit: 10 }),
        api.getRiskScore(),
        api.getQuantumReadiness(),
        api.getComplianceStatus(),
        api.getAlgorithmMetrics(30),
      ]);
      setStats(statsData);
      setTrends(trendsData);
      setTeamUsage(teamsData);
      setHealth(healthData);
      setRecentLogs(logsData);
      setRiskScore(riskData);
      setQuantumReadiness(quantumData);
      setComplianceStatus(complianceData);
      setAlgorithmMetrics(algoMetrics);
    } catch (error) {
      console.error("Failed to load admin data:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const calculateGrowth = (today: number, yesterday: number): number => {
    if (yesterday === 0) return today > 0 ? 100 : 0;
    return Math.round(((today - yesterday) / yesterday) * 100);
  };

  const getHealthStatusColor = (status: string) => {
    switch (status) {
      case "healthy":
        return "text-green-500";
      case "degraded":
        return "text-yellow-500";
      case "unhealthy":
        return "text-red-500";
      default:
        return "text-slate-500";
    }
  };

  const getHealthStatusIcon = (status: string) => {
    switch (status) {
      case "healthy":
        return <CheckCircle2 className="h-4 w-4 text-green-500" />;
      case "degraded":
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      case "unhealthy":
        return <XCircle className="h-4 w-4 text-red-500" />;
      default:
        return <Clock className="h-4 w-4 text-slate-500" />;
    }
  };

  if (loading) {
    return (
      <AdminLayout title="Admin Dashboard" subtitle="Loading...">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </AdminLayout>
    );
  }

  const operationsGrowth = stats
    ? calculateGrowth(stats.operations_today, stats.operations_yesterday)
    : 0;
  const successRate = stats && stats.total_operations > 0
    ? Math.round((stats.successful_operations / stats.total_operations) * 100)
    : 100;

  // Transform trend data for chart
  const chartData = trends.map((t) => ({
    date: new Date(t.date).toLocaleDateString("en-US", { month: "short", day: "numeric" }),
    encrypt: t.encrypt_count,
    decrypt: t.decrypt_count,
    success: t.success_count,
    failed: t.failed_count,
  }));

  // Transform team data for chart
  const teamChartData = teamUsage.map((t) => ({
    team: t.team,
    operations: t.operation_count,
  }));

  return (
    <AdminLayout
      title="Admin Dashboard"
      subtitle="Organization-wide overview"
      onRefresh={loadData}
      refreshInterval={30}
    >
      {/* Alert Banner */}
      {stats && stats.expiring_soon > 0 && (
        <div className="mb-6 bg-amber-50 border border-amber-200 rounded-lg p-4 flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-amber-500 shrink-0" />
          <div>
            <p className="text-sm font-medium text-amber-800">
              {stats.expiring_soon} application{stats.expiring_soon === 1 ? "" : "s"} expiring in the next 7 days
            </p>
            <p className="text-xs text-amber-600 mt-0.5">
              Review and extend or revoke expiring credentials to maintain security.
            </p>
          </div>
        </div>
      )}

      {/* KPI Cards - Enterprise: monochromatic with status-based color only */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4 mb-8">
        <StatCard
          title="Total Users"
          value={stats?.total_users ?? 0}
          subtitle={`+${stats?.new_users_today ?? 0} today`}
          icon={<Users className="h-5 w-5" />}
        />
        <StatCard
          title="Active Applications"
          value={stats?.active_identities ?? 0}
          subtitle={`${stats?.total_identities ?? 0} total`}
          icon={<Key className="h-5 w-5" />}
        />
        <StatCard
          title="Operations Today"
          value={formatNumber(stats?.operations_today ?? 0)}
          trend={
            operationsGrowth !== 0
              ? { value: operationsGrowth, label: "vs yesterday" }
              : undefined
          }
          icon={<Activity className="h-5 w-5" />}
        />
        <StatCard
          title="Success Rate"
          value={`${successRate}%`}
          subtitle={`${formatNumber(stats?.failed_operations ?? 0)} failed`}
          icon={<CheckCircle2 className="h-5 w-5" />}
          color={successRate >= 95 ? "green" : successRate >= 80 ? "amber" : "rose"}
        />
        <StatCard
          title="Avg Latency"
          value={`${Math.round(stats?.avg_latency_ms ?? 0)}ms`}
          subtitle="p50 response time"
          icon={<Zap className="h-5 w-5" />}
          color={(stats?.avg_latency_ms ?? 0) > 100 ? "amber" : "default"}
        />
        <StatCard
          title="Data Processed"
          value={formatBytes(stats?.total_data_bytes ?? 0)}
          subtitle={`${stats?.contexts_count ?? 0} contexts`}
          icon={<Database className="h-5 w-5" />}
        />
      </div>

      {/* Premium Insights Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {riskScore && <RiskScoreGauge data={riskScore} />}
        {quantumReadiness && <QuantumReadinessMeter data={quantumReadiness} />}
        {complianceStatus && <ComplianceBadges data={complianceStatus} />}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Operations Trend */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Operations Trend (30 Days)</CardTitle>
          </CardHeader>
          <CardContent>
            {chartData.length > 0 ? (
              <LineChart
                data={chartData}
                xAxisKey="date"
                lines={[
                  { dataKey: "encrypt", name: "Encrypt", color: "#3b82f6" },
                  { dataKey: "decrypt", name: "Decrypt", color: "#10b981" },
                ]}
                height={280}
              />
            ) : (
              <div className="h-[280px] flex items-center justify-center text-slate-500 text-sm">
                No operation data yet
              </div>
            )}
          </CardContent>
        </Card>

        {/* Team Usage */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Top Teams by Usage</CardTitle>
          </CardHeader>
          <CardContent>
            {teamChartData.length > 0 ? (
              <BarChart
                data={teamChartData}
                dataKey="operations"
                nameKey="team"
                height={280}
                layout="vertical"
              />
            ) : (
              <div className="h-[280px] flex items-center justify-center text-slate-500 text-sm">
                No team data yet
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Algorithm Usage */}
      {algorithmMetrics && (
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="text-base">Algorithm Usage (Last 30 Days)</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {/* By Cipher */}
              <div>
                <h4 className="text-sm font-medium text-slate-600 mb-3">By Cipher</h4>
                <div className="space-y-2">
                  {Object.entries(algorithmMetrics.by_cipher).length > 0 ? (
                    Object.entries(algorithmMetrics.by_cipher)
                      .sort(([, a], [, b]) => b - a)
                      .slice(0, 5)
                      .map(([cipher, count]) => {
                        const total = Object.values(algorithmMetrics.by_cipher).reduce((a, b) => a + b, 0);
                        const percent = total > 0 ? Math.round((count / total) * 100) : 0;
                        return (
                          <div key={cipher} className="flex items-center gap-2">
                            <div className="flex-1">
                              <div className="flex justify-between text-sm mb-1">
                                <span className="font-medium">{cipher}</span>
                                <span className="text-slate-500">{percent}%</span>
                              </div>
                              <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-blue-500 rounded-full"
                                  style={{ width: `${percent}%` }}
                                />
                              </div>
                            </div>
                          </div>
                        );
                      })
                  ) : (
                    <p className="text-sm text-slate-400">No data yet</p>
                  )}
                </div>
              </div>

              {/* By Mode */}
              <div>
                <h4 className="text-sm font-medium text-slate-600 mb-3">By Mode</h4>
                <div className="space-y-2">
                  {Object.entries(algorithmMetrics.by_mode).length > 0 ? (
                    Object.entries(algorithmMetrics.by_mode)
                      .sort(([, a], [, b]) => b - a)
                      .slice(0, 5)
                      .map(([mode, count]) => {
                        const total = Object.values(algorithmMetrics.by_mode).reduce((a, b) => a + b, 0);
                        const percent = total > 0 ? Math.round((count / total) * 100) : 0;
                        return (
                          <div key={mode} className="flex items-center gap-2">
                            <div className="flex-1">
                              <div className="flex justify-between text-sm mb-1">
                                <span className="font-medium">{mode.toUpperCase()}</span>
                                <span className="text-slate-500">{percent}%</span>
                              </div>
                              <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-emerald-500 rounded-full"
                                  style={{ width: `${percent}%` }}
                                />
                              </div>
                            </div>
                          </div>
                        );
                      })
                  ) : (
                    <p className="text-sm text-slate-400">No data yet</p>
                  )}
                </div>
              </div>

              {/* By Key Size */}
              <div>
                <h4 className="text-sm font-medium text-slate-600 mb-3">By Key Size</h4>
                <div className="space-y-2">
                  {Object.entries(algorithmMetrics.by_key_bits).length > 0 ? (
                    Object.entries(algorithmMetrics.by_key_bits)
                      .sort(([a], [b]) => parseInt(b) - parseInt(a))
                      .map(([bits, count]) => {
                        const total = Object.values(algorithmMetrics.by_key_bits).reduce((a, b) => a + b, 0);
                        const percent = total > 0 ? Math.round((count / total) * 100) : 0;
                        return (
                          <div key={bits} className="flex items-center gap-2">
                            <div className="flex-1">
                              <div className="flex justify-between text-sm mb-1">
                                <span className="font-medium">{bits}-bit</span>
                                <span className="text-slate-500">{percent}%</span>
                              </div>
                              <div className="h-1.5 bg-slate-100 rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-purple-500 rounded-full"
                                  style={{ width: `${percent}%` }}
                                />
                              </div>
                            </div>
                          </div>
                        );
                      })
                  ) : (
                    <p className="text-sm text-slate-400">No data yet</p>
                  )}
                </div>
              </div>

              {/* Summary Stats */}
              <div>
                <h4 className="text-sm font-medium text-slate-600 mb-3">Summary</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-600">Total Operations</span>
                    <span className="font-medium">{formatNumber(algorithmMetrics.total_operations)}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-600">Quantum-Safe</span>
                    <span className={cn(
                      "font-medium",
                      algorithmMetrics.quantum_safe_operations > 0 ? "text-emerald-600" : "text-slate-500"
                    )}>
                      {formatNumber(algorithmMetrics.quantum_safe_operations)}
                    </span>
                  </div>
                  {algorithmMetrics.policy_violations > 0 && (
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-slate-600">Policy Violations</span>
                      <span className="font-medium text-amber-600">
                        {algorithmMetrics.policy_violations}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Activity */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Recent Activity</CardTitle>
          </CardHeader>
          <CardContent>
            {recentLogs.length > 0 ? (
              <div className="space-y-3">
                {recentLogs.slice(0, 8).map((log) => (
                  <div
                    key={log.id}
                    className="flex items-center gap-3 text-sm"
                  >
                    <div
                      className={cn(
                        "h-2 w-2 rounded-full shrink-0",
                        log.success ? "bg-green-500" : "bg-red-500"
                      )}
                    />
                    <div className="flex-1 min-w-0">
                      <p className="truncate">
                        <span className="font-medium">{log.identity_name || "Unknown"}</span>
                        {" "}
                        <span className="text-slate-500">{log.operation}</span>
                        {" "}
                        <span className="text-slate-600">{log.context}</span>
                      </p>
                    </div>
                    <span className="text-xs text-slate-400 shrink-0">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="h-48 flex items-center justify-center text-slate-500 text-sm">
                No recent activity
              </div>
            )}
          </CardContent>
        </Card>

        {/* System Health */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">System Health</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {/* Database Status */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Database className="h-4 w-4 text-slate-500" />
                  <span className="text-sm">Database</span>
                </div>
                <div className="flex items-center gap-2">
                  {getHealthStatusIcon(health?.database ?? "unknown")}
                  <span className={cn("text-sm capitalize", getHealthStatusColor(health?.database ?? "unknown"))}>
                    {health?.database ?? "Unknown"}
                  </span>
                </div>
              </div>

              {/* Encryption Service */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Key className="h-4 w-4 text-slate-500" />
                  <span className="text-sm">Encryption Service</span>
                </div>
                <div className="flex items-center gap-2">
                  {getHealthStatusIcon(health?.encryption_service ?? "unknown")}
                  <span className={cn("text-sm capitalize", getHealthStatusColor(health?.encryption_service ?? "unknown"))}>
                    {health?.encryption_service ?? "Unknown"}
                  </span>
                </div>
              </div>

              <div className="border-t pt-4 mt-4 space-y-3">
                {/* Failed Operations */}
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-600">Failed ops (last hour)</span>
                  <span className={cn(
                    "font-medium",
                    (health?.failed_operations_last_hour ?? 0) > 10
                      ? "text-red-600"
                      : "text-slate-900"
                  )}>
                    {health?.failed_operations_last_hour ?? 0}
                  </span>
                </div>

                {/* Avg Latency */}
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-600">Avg latency (last hour)</span>
                  <span className={cn(
                    "font-medium",
                    (health?.avg_latency_last_hour ?? 0) > 100
                      ? "text-amber-600"
                      : "text-slate-900"
                  )}>
                    {Math.round(health?.avg_latency_last_hour ?? 0)}ms
                  </span>
                </div>

                {/* Expiring Applications */}
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-600">Expiring applications</span>
                  <span className={cn(
                    "font-medium",
                    (health?.expiring_identities ?? 0) > 0
                      ? "text-amber-600"
                      : "text-slate-900"
                  )}>
                    {health?.expiring_identities ?? 0}
                  </span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </AdminLayout>
  );
}
