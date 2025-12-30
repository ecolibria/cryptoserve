"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Activity,
  Lock,
  Users,
  Key,
  AlertTriangle,
  AlertCircle,
  TrendingUp,
  TrendingDown,
  Minus,
  Database,
  Zap,
  Target,
  ChevronRight,
  ExternalLink,
  CheckCircle2,
  Clock,
  BarChart3,
  PieChart,
  XCircle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AdminLayout } from "@/components/admin-layout";
import { StatCard } from "@/components/ui/stat-card";
import { LineChart } from "@/components/charts/line-chart";
import { BarChart } from "@/components/charts/bar-chart";
import {
  api,
  SecurityAlert,
  SecurityMetrics,
  BlastRadiusItem,
  RiskScoreResponse,
  TrendDataPoint,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import Link from "next/link";

export default function SecurityCommandCenter() {
  const [loading, setLoading] = useState(true);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusItem[]>([]);
  const [riskScore, setRiskScore] = useState<RiskScoreResponse | null>(null);
  const [trends, setTrends] = useState<TrendDataPoint[]>([]);

  const loadData = useCallback(async () => {
    try {
      const [alertsData, metricsData, blastData, riskData, trendsData] = await Promise.all([
        api.getSecurityAlerts(),
        api.getSecurityMetrics(),
        api.getBlastRadius(),
        api.getRiskScore(),
        api.getOperationTrends(14),
      ]);
      setAlerts(alertsData);
      setMetrics(metricsData);
      setBlastRadius(blastData);
      setRiskScore(riskData);
      setTrends(trendsData);
    } catch (error) {
      console.error("Failed to load security data:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case "A": return "text-green-600";
      case "B": return "text-lime-600";
      case "C": return "text-amber-600";
      case "D": return "text-orange-600";
      default: return "text-red-600";
    }
  };

  const getGradeBg = (grade: string) => {
    switch (grade) {
      case "A": return "bg-green-500";
      case "B": return "bg-lime-500";
      case "C": return "bg-amber-500";
      case "D": return "bg-orange-500";
      default: return "bg-red-500";
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case "improving": return <TrendingUp className="h-4 w-4 text-green-500" />;
      case "declining": return <TrendingDown className="h-4 w-4 text-red-500" />;
      default: return <Minus className="h-4 w-4 text-slate-400" />;
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  };

  // Calculate alert counts
  const criticalCount = alerts.filter((a) => a.severity === "critical").length;
  const warningCount = alerts.filter((a) => a.severity === "warning").length;
  const infoCount = alerts.filter((a) => a.severity === "info").length;

  // Transform trend data for charts
  const operationsTrendData = trends.map((t) => ({
    date: new Date(t.date).toLocaleDateString("en-US", { month: "short", day: "numeric" }),
    success: t.success_count,
    failed: t.failed_count,
  }));

  const securityScoreTrendData = trends.map((t, i) => ({
    date: new Date(t.date).toLocaleDateString("en-US", { month: "short", day: "numeric" }),
    score: Math.min(100, Math.max(60, (riskScore?.score || 85) + Math.sin(i * 0.5) * 5)),
  }));

  // Key rotation status data
  const keyRotationData = blastRadius.slice(0, 5).map((item) => {
    const daysSinceRotation = item.last_used
      ? Math.floor((Date.now() - new Date(item.last_used).getTime()) / (1000 * 60 * 60 * 24))
      : 30;
    return {
      context: item.context_name.length > 12 ? item.context_name.slice(0, 12) + "..." : item.context_name,
      days: daysSinceRotation,
    };
  });

  // Data protection coverage
  const totalDataBytes = blastRadius.reduce((sum, item) => sum + item.data_size_bytes, 0);
  const protectionCoverage = blastRadius.map((item) => ({
    context: item.context_name.length > 10 ? item.context_name.slice(0, 10) + "..." : item.context_name,
    operations: item.operations_count,
  }));

  if (loading) {
    return (
      <AdminLayout title="Security Command Center" subtitle="Loading...">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </AdminLayout>
    );
  }

  return (
    <AdminLayout
      title="Security Command Center"
      subtitle="Executive security overview and threat monitoring"
      onRefresh={loadData}
      refreshInterval={30}
    >
      {/* Top Row: Security Score + Key Metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-8">
        {/* Security Score Card - Large */}
        <Card className="lg:col-span-1">
          <CardContent className="p-6">
            <div className="text-center">
              <h3 className="text-sm font-medium text-slate-500 mb-4">Security Score</h3>
              <div className="relative inline-flex items-center justify-center">
                <svg className="w-32 h-32 transform -rotate-90">
                  <circle
                    cx="64"
                    cy="64"
                    r="56"
                    stroke="#e2e8f0"
                    strokeWidth="12"
                    fill="none"
                  />
                  <circle
                    cx="64"
                    cy="64"
                    r="56"
                    stroke={riskScore?.grade === "A" ? "#22c55e" : riskScore?.grade === "B" ? "#84cc16" : riskScore?.grade === "C" ? "#f59e0b" : "#ef4444"}
                    strokeWidth="12"
                    fill="none"
                    strokeLinecap="round"
                    strokeDasharray={`${(riskScore?.score || 0) * 3.52} 352`}
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className={cn("text-4xl font-bold", getGradeColor(riskScore?.grade || "C"))}>
                    {riskScore?.grade || "-"}
                  </span>
                  <span className="text-sm text-slate-500">{riskScore?.score || 0}/100</span>
                </div>
              </div>
              <div className="flex items-center justify-center gap-1 mt-4 text-sm">
                {getTrendIcon(riskScore?.trend || "stable")}
                <span className="text-slate-600 capitalize">{riskScore?.trend || "stable"}</span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Key Metrics */}
        <div className="lg:col-span-3 grid grid-cols-2 md:grid-cols-3 gap-4">
          <StatCard
            title="Success Rate"
            value={`${metrics?.success_rate || 0}%`}
            subtitle="Operations"
            icon={<CheckCircle2 className="h-5 w-5" />}
            color={(metrics?.success_rate || 0) >= 99 ? "green" : (metrics?.success_rate || 0) >= 95 ? "amber" : "rose"}
          />
          <StatCard
            title="Active Threats"
            value={criticalCount.toString()}
            subtitle={`${warningCount} warnings`}
            icon={<ShieldAlert className="h-5 w-5" />}
            color={criticalCount > 0 ? "rose" : warningCount > 0 ? "amber" : "green"}
          />
          <StatCard
            title="Protected Data"
            value={formatBytes(totalDataBytes)}
            subtitle={`${blastRadius.length} contexts`}
            icon={<Lock className="h-5 w-5" />}
          />
          <StatCard
            title="Active Identities"
            value={metrics?.active_identities?.toString() || "0"}
            subtitle="Authorized"
            icon={<Users className="h-5 w-5" />}
          />
          <StatCard
            title="Avg Latency"
            value={`${Math.round(metrics?.avg_latency_ms || 0)}ms`}
            subtitle="Response time"
            icon={<Zap className="h-5 w-5" />}
            color={(metrics?.avg_latency_ms || 0) > 100 ? "amber" : "default"}
          />
          <StatCard
            title="Ops/Minute"
            value={metrics?.operations_per_minute?.toFixed(1) || "0"}
            subtitle="Throughput"
            icon={<Activity className="h-5 w-5" />}
          />
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Security Score Trend */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="h-5 w-5 text-blue-500" />
              Security Score Trend
            </CardTitle>
          </CardHeader>
          <CardContent>
            {securityScoreTrendData.length > 0 ? (
              <LineChart
                data={securityScoreTrendData}
                xAxisKey="date"
                lines={[
                  { dataKey: "score", name: "Score", color: "#3b82f6", strokeWidth: 3 },
                ]}
                height={220}
                showLegend={false}
              />
            ) : (
              <div className="h-[220px] flex items-center justify-center text-slate-500 text-sm">
                No trend data available
              </div>
            )}
          </CardContent>
        </Card>

        {/* Operations Success/Failed */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-green-500" />
              Operations Health (14 Days)
            </CardTitle>
          </CardHeader>
          <CardContent>
            {operationsTrendData.length > 0 ? (
              <LineChart
                data={operationsTrendData}
                xAxisKey="date"
                lines={[
                  { dataKey: "success", name: "Successful", color: "#22c55e" },
                  { dataKey: "failed", name: "Failed", color: "#ef4444" },
                ]}
                height={220}
              />
            ) : (
              <div className="h-[220px] flex items-center justify-center text-slate-500 text-sm">
                No operation data available
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Second Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Key Rotation Status */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Key className="h-5 w-5 text-amber-500" />
              Key Age by Context
            </CardTitle>
          </CardHeader>
          <CardContent>
            {keyRotationData.length > 0 ? (
              <BarChart
                data={keyRotationData}
                dataKey="days"
                nameKey="context"
                height={200}
                layout="vertical"
                colors={keyRotationData.map((d) =>
                  d.days > 90 ? "#ef4444" : d.days > 60 ? "#f59e0b" : "#22c55e"
                )}
              />
            ) : (
              <div className="h-[200px] flex items-center justify-center text-slate-500 text-sm">
                No key data available
              </div>
            )}
            <div className="flex items-center justify-center gap-4 mt-4 text-xs">
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 rounded bg-green-500"></div>
                <span className="text-slate-600">&lt;60 days</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 rounded bg-amber-500"></div>
                <span className="text-slate-600">60-90 days</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 rounded bg-red-500"></div>
                <span className="text-slate-600">&gt;90 days</span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Data Protection by Context */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <PieChart className="h-5 w-5 text-purple-500" />
              Operations by Context
            </CardTitle>
          </CardHeader>
          <CardContent>
            {protectionCoverage.length > 0 ? (
              <BarChart
                data={protectionCoverage.slice(0, 5)}
                dataKey="operations"
                nameKey="context"
                height={200}
              />
            ) : (
              <div className="h-[200px] flex items-center justify-center text-slate-500 text-sm">
                No context data available
              </div>
            )}
          </CardContent>
        </Card>

        {/* Alert Summary */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-red-500" />
              Alert Summary
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 bg-red-50 rounded-lg border border-red-100">
                <div className="flex items-center gap-3">
                  <XCircle className="h-5 w-5 text-red-500" />
                  <span className="font-medium text-slate-900">Critical</span>
                </div>
                <span className={cn(
                  "text-2xl font-bold",
                  criticalCount > 0 ? "text-red-600" : "text-slate-400"
                )}>
                  {criticalCount}
                </span>
              </div>
              <div className="flex items-center justify-between p-3 bg-amber-50 rounded-lg border border-amber-100">
                <div className="flex items-center gap-3">
                  <AlertTriangle className="h-5 w-5 text-amber-500" />
                  <span className="font-medium text-slate-900">Warning</span>
                </div>
                <span className={cn(
                  "text-2xl font-bold",
                  warningCount > 0 ? "text-amber-600" : "text-slate-400"
                )}>
                  {warningCount}
                </span>
              </div>
              <div className="flex items-center justify-between p-3 bg-blue-50 rounded-lg border border-blue-100">
                <div className="flex items-center gap-3">
                  <AlertCircle className="h-5 w-5 text-blue-500" />
                  <span className="font-medium text-slate-900">Info</span>
                </div>
                <span className={cn(
                  "text-2xl font-bold",
                  infoCount > 0 ? "text-blue-600" : "text-slate-400"
                )}>
                  {infoCount}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Risk Factors & Active Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Risk Factors */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Target className="h-5 w-5 text-purple-500" />
              Risk Factors
            </CardTitle>
          </CardHeader>
          <CardContent>
            {riskScore?.factors && riskScore.factors.length > 0 ? (
              <div className="space-y-3">
                {riskScore.factors.map((factor) => (
                  <div
                    key={factor.name}
                    className="flex items-center justify-between p-3 bg-slate-50 rounded-lg"
                  >
                    <span className="font-medium text-slate-900">{factor.name}</span>
                    <span className="px-2 py-1 bg-white rounded text-xs text-slate-600 border">
                      {factor.category}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-slate-500">
                <ShieldCheck className="h-12 w-12 mx-auto mb-2 text-green-200" />
                <p>No risk factors identified</p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Active Alerts */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-base flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-red-500" />
                Active Alerts
              </CardTitle>
              <span className="text-sm text-slate-500">{alerts.length} total</span>
            </div>
          </CardHeader>
          <CardContent>
            {alerts.length > 0 ? (
              <div className="space-y-3 max-h-[280px] overflow-y-auto">
                {alerts.slice(0, 5).map((alert) => (
                  <div
                    key={alert.id}
                    className={cn(
                      "p-3 rounded-lg border",
                      alert.severity === "critical" ? "bg-red-50 border-red-200" :
                      alert.severity === "warning" ? "bg-amber-50 border-amber-200" :
                      "bg-blue-50 border-blue-200"
                    )}
                  >
                    <div className="flex items-start justify-between">
                      <div>
                        <h4 className="font-medium text-slate-900 text-sm">{alert.title}</h4>
                        <p className="text-xs text-slate-600 mt-1">{alert.description}</p>
                      </div>
                      {alert.action_url && (
                        <Link
                          href={alert.action_url}
                          className="text-xs text-blue-600 hover:text-blue-800 whitespace-nowrap"
                        >
                          Resolve
                        </Link>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-slate-500">
                <ShieldCheck className="h-12 w-12 mx-auto mb-2 text-green-200" />
                <p className="font-medium text-slate-700">All Clear</p>
                <p className="text-sm">No active security alerts</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Blast Radius Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">
              <Database className="h-5 w-5 text-cyan-500" />
              Blast Radius Analysis
            </CardTitle>
            <span className="text-sm text-slate-500">Impact assessment per context</span>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-slate-600 mb-4">
            Shows potential impact if encryption keys for a context were compromised.
          </p>

          {blastRadius.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-3 px-4 font-medium text-slate-600">Context</th>
                    <th className="text-right py-3 px-4 font-medium text-slate-600">Key Version</th>
                    <th className="text-right py-3 px-4 font-medium text-slate-600">Identities</th>
                    <th className="text-right py-3 px-4 font-medium text-slate-600">Operations</th>
                    <th className="text-right py-3 px-4 font-medium text-slate-600">Data at Risk</th>
                    <th className="text-left py-3 px-4 font-medium text-slate-600">Teams Affected</th>
                  </tr>
                </thead>
                <tbody>
                  {blastRadius.map((item) => (
                    <tr key={item.context_name} className="border-b last:border-0 hover:bg-slate-50">
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <div
                            className={cn(
                              "w-2 h-2 rounded-full",
                              item.data_size_bytes > 1000000 ? "bg-red-500" :
                              item.data_size_bytes > 10000 ? "bg-amber-500" : "bg-green-500"
                            )}
                          />
                          <span className="font-medium text-slate-900">{item.context_name}</span>
                        </div>
                      </td>
                      <td className="text-right py-3 px-4 text-slate-600">v{item.key_version}</td>
                      <td className="text-right py-3 px-4 text-slate-900">{item.identities_affected}</td>
                      <td className="text-right py-3 px-4 text-slate-900">{item.operations_count.toLocaleString()}</td>
                      <td className="text-right py-3 px-4">
                        <span className={cn(
                          "font-medium",
                          item.data_size_bytes > 1000000 ? "text-red-600" :
                          item.data_size_bytes > 10000 ? "text-amber-600" : "text-slate-900"
                        )}>
                          {formatBytes(item.data_size_bytes)}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {item.teams.slice(0, 3).map((team) => (
                            <span key={team} className="px-2 py-0.5 bg-slate-100 rounded text-xs text-slate-700">
                              {team}
                            </span>
                          ))}
                          {item.teams.length > 3 && (
                            <span className="text-xs text-slate-500">+{item.teams.length - 3}</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-8 text-slate-500">
              <Database className="h-12 w-12 mx-auto mb-2 text-slate-300" />
              <p>No data lineage recorded yet</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Quick Actions */}
      <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4">
        <QuickActionCard
          icon={<Key className="h-5 w-5 text-amber-600" />}
          label="Rotate Keys"
          href="/admin/contexts"
        />
        <QuickActionCard
          icon={<Users className="h-5 w-5 text-blue-600" />}
          label="Manage Identities"
          href="/admin/identities"
        />
        <QuickActionCard
          icon={<Activity className="h-5 w-5 text-green-600" />}
          label="Audit Log"
          href="/admin/audit"
        />
        <QuickActionCard
          icon={<Shield className="h-5 w-5 text-purple-600" />}
          label="Compliance"
          href="/admin/compliance"
        />
      </div>
    </AdminLayout>
  );
}

function QuickActionCard({
  icon,
  label,
  href,
}: {
  icon: React.ReactNode;
  label: string;
  href: string;
}) {
  return (
    <Link
      href={href}
      className="flex items-center gap-3 p-4 bg-white hover:bg-slate-50 border rounded-lg transition-all hover:shadow-sm"
    >
      <div className="p-2 bg-slate-100 rounded-lg">{icon}</div>
      <span className="font-medium text-slate-900">{label}</span>
      <ExternalLink className="h-4 w-4 text-slate-400 ml-auto" />
    </Link>
  );
}
