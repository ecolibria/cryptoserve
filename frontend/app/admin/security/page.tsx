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
  Clock,
  Database,
  Zap,
  Target,
  ChevronRight,
  ExternalLink,
  CheckCircle2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AdminLayout } from "@/components/admin-layout";
import { StatCard } from "@/components/ui/stat-card";
import {
  api,
  SecurityAlert,
  SecurityMetrics,
  BlastRadiusItem,
  RiskScoreResponse,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import Link from "next/link";

export default function SecurityCommandCenter() {
  const [loading, setLoading] = useState(true);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusItem[]>([]);
  const [riskScore, setRiskScore] = useState<RiskScoreResponse | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [alertsData, metricsData, blastData, riskData] = await Promise.all([
        api.getSecurityAlerts(),
        api.getSecurityMetrics(),
        api.getBlastRadius(),
        api.getRiskScore(),
      ]);
      setAlerts(alertsData);
      setMetrics(metricsData);
      setBlastRadius(blastData);
      setRiskScore(riskData);
    } catch (error) {
      console.error("Failed to load security data:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const getAlertIcon = (severity: string) => {
    switch (severity) {
      case "critical":
        return <ShieldAlert className="h-5 w-5 text-red-500" />;
      case "warning":
        return <AlertTriangle className="h-5 w-5 text-amber-500" />;
      default:
        return <AlertCircle className="h-5 w-5 text-blue-500" />;
    }
  };

  const getAlertStyles = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-50 border-red-200";
      case "warning":
        return "bg-amber-50 border-amber-200";
      default:
        return "bg-blue-50 border-blue-200";
    }
  };

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case "A":
        return "text-green-600";
      case "B":
        return "text-lime-600";
      case "C":
        return "text-amber-600";
      case "D":
        return "text-orange-600";
      default:
        return "text-red-600";
    }
  };

  const getGradeBg = (grade: string) => {
    switch (grade) {
      case "A":
        return "bg-green-100";
      case "B":
        return "bg-lime-100";
      case "C":
        return "bg-amber-100";
      case "D":
        return "bg-orange-100";
      default:
        return "bg-red-100";
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case "improving":
        return <TrendingUp className="h-4 w-4 text-green-500" />;
      case "declining":
        return <TrendingDown className="h-4 w-4 text-red-500" />;
      default:
        return <Minus className="h-4 w-4 text-slate-400" />;
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const criticalCount = alerts.filter((a) => a.severity === "critical").length;
  const warningCount = alerts.filter((a) => a.severity === "warning").length;

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
      subtitle="Real-time threat monitoring and risk assessment"
      onRefresh={loadData}
      refreshInterval={30}
    >
      {/* Status Banner */}
      <div
        className={cn(
          "mb-6 p-4 rounded-lg border flex items-center justify-between",
          criticalCount > 0
            ? "bg-red-50 border-red-200"
            : warningCount > 0
            ? "bg-amber-50 border-amber-200"
            : "bg-green-50 border-green-200"
        )}
      >
        <div className="flex items-center gap-4">
          {criticalCount > 0 ? (
            <ShieldAlert className="h-10 w-10 text-red-500" />
          ) : warningCount > 0 ? (
            <AlertTriangle className="h-10 w-10 text-amber-500" />
          ) : (
            <ShieldCheck className="h-10 w-10 text-green-500" />
          )}
          <div>
            <h2 className="text-lg font-semibold text-slate-900">
              {criticalCount > 0
                ? `${criticalCount} Critical Alert${criticalCount > 1 ? "s" : ""} Require Attention`
                : warningCount > 0
                ? `${warningCount} Warning${warningCount > 1 ? "s" : ""} to Review`
                : "All Systems Operational"}
            </h2>
            <p className="text-sm text-slate-600">
              {criticalCount > 0
                ? "Immediate action required to maintain security posture"
                : warningCount > 0
                ? "Review recommended items to prevent future issues"
                : "Your cryptographic infrastructure is secure and healthy"}
            </p>
          </div>
        </div>
        {riskScore && (
          <div className={cn("text-center px-6 py-3 rounded-lg", getGradeBg(riskScore.grade))}>
            <div className={cn("text-4xl font-bold", getGradeColor(riskScore.grade))}>
              {riskScore.grade}
            </div>
            <div className="flex items-center gap-1 text-sm text-slate-600 mt-1">
              Score: {riskScore.score}
              {getTrendIcon(riskScore.trend)}
            </div>
          </div>
        )}
      </div>

      {/* Metrics Row */}
      {metrics && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4 mb-8">
          <StatCard
            title="Ops/min"
            value={metrics.operations_per_minute.toFixed(1)}
            subtitle="Last hour avg"
            icon={<Activity className="h-5 w-5" />}
          />
          <StatCard
            title="Encrypt Rate"
            value={`${metrics.encryption_rate}%`}
            subtitle="of operations"
            icon={<Lock className="h-5 w-5" />}
          />
          <StatCard
            title="Success Rate"
            value={`${metrics.success_rate}%`}
            subtitle={metrics.success_rate >= 99 ? "Excellent" : "Review errors"}
            icon={<CheckCircle2 className="h-5 w-5" />}
            color={metrics.success_rate >= 95 ? "green" : "amber"}
          />
          <StatCard
            title="Latency"
            value={`${metrics.avg_latency_ms}ms`}
            subtitle="Avg response"
            icon={<Zap className="h-5 w-5" />}
          />
          <StatCard
            title="Active IDs"
            value={metrics.active_identities.toString()}
            subtitle="Currently valid"
            icon={<Users className="h-5 w-5" />}
          />
          <StatCard
            title="Contexts"
            value={metrics.contexts_in_use.toString()}
            subtitle="Last 24h"
            icon={<Target className="h-5 w-5" />}
          />
          <StatCard
            title="Data"
            value={`${metrics.data_processed_mb.toFixed(1)} MB`}
            subtitle="Encrypted"
            icon={<Database className="h-5 w-5" />}
          />
        </div>
      )}

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Alerts Panel */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-blue-500" />
              Security Alerts
              <span className="ml-auto text-sm font-normal text-slate-500">
                {alerts.length} active
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {alerts.length === 0 ? (
              <div className="text-center py-12 text-slate-500">
                <ShieldCheck className="h-16 w-16 mx-auto mb-4 text-green-200" />
                <p className="text-lg font-medium text-slate-700">No active alerts</p>
                <p className="text-sm text-slate-500">Your security posture is excellent</p>
              </div>
            ) : (
              <div className="space-y-3 max-h-[400px] overflow-y-auto">
                {alerts.map((alert) => (
                  <div
                    key={alert.id}
                    className={cn(
                      "p-4 rounded-lg border transition-all hover:shadow-sm",
                      getAlertStyles(alert.severity)
                    )}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-3">
                        {getAlertIcon(alert.severity)}
                        <div>
                          <h4 className="font-medium text-slate-900">{alert.title}</h4>
                          <p className="text-sm text-slate-600 mt-1">{alert.description}</p>
                          <div className="flex items-center gap-4 mt-2 text-xs text-slate-500">
                            <span className="px-2 py-0.5 bg-white/50 rounded">
                              {alert.category}
                            </span>
                            <span>{alert.affected_count} affected</span>
                            {alert.auto_resolvable && (
                              <span className="text-green-600">Auto-resolvable</span>
                            )}
                          </div>
                        </div>
                      </div>
                      {alert.action_url && (
                        <Link
                          href={alert.action_url}
                          className="flex items-center gap-1 text-sm text-blue-600 hover:text-blue-800"
                        >
                          Resolve
                          <ChevronRight className="h-4 w-4" />
                        </Link>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Risk Factors */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Target className="h-5 w-5 text-purple-500" />
              Risk Factors
            </CardTitle>
          </CardHeader>
          <CardContent>
            {riskScore?.factors.map((factor) => (
              <div
                key={factor.name}
                className="flex items-center justify-between py-3 border-b last:border-0"
              >
                <span className="text-slate-700">{factor.name}</span>
                <span className="px-2 py-0.5 bg-slate-100 rounded text-xs text-slate-600">
                  {factor.category}
                </span>
              </div>
            ))}
            <div className="mt-4 p-3 bg-purple-50 border border-purple-200 rounded-lg">
              <p className="text-sm text-purple-700">
                Detailed factor scores available in Premium
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Blast Radius Table */}
      <Card className="mb-8">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">
              <Key className="h-5 w-5 text-amber-500" />
              Blast Radius Analysis
            </CardTitle>
            <span className="text-sm text-slate-500">Impact assessment per context</span>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-slate-600 mb-4">
            If a key is compromised, this shows the data and teams affected.
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
                    <th className="text-right py-3 px-4 font-medium text-slate-600">Data Size</th>
                    <th className="text-left py-3 px-4 font-medium text-slate-600">Teams</th>
                  </tr>
                </thead>
                <tbody>
                  {blastRadius.slice(0, 10).map((item) => (
                    <tr key={item.context_name} className="border-b last:border-0 hover:bg-slate-50">
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <div
                            className={cn(
                              "w-2 h-2 rounded-full",
                              item.data_size_bytes > 1000000
                                ? "bg-red-500"
                                : item.data_size_bytes > 10000
                                ? "bg-amber-500"
                                : "bg-green-500"
                            )}
                          />
                          <span className="font-medium text-slate-900">{item.context_name}</span>
                        </div>
                      </td>
                      <td className="text-right py-3 px-4 text-slate-600">v{item.key_version}</td>
                      <td className="text-right py-3 px-4 text-slate-900">{item.identities_affected}</td>
                      <td className="text-right py-3 px-4 text-slate-900">
                        {item.operations_count.toLocaleString()}
                      </td>
                      <td className="text-right py-3 px-4 text-slate-900">
                        {formatBytes(item.data_size_bytes)}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {item.teams.slice(0, 3).map((team) => (
                            <span
                              key={team}
                              className="px-2 py-0.5 bg-slate-100 rounded text-xs text-slate-700"
                            >
                              {team}
                            </span>
                          ))}
                          {item.teams.length > 3 && (
                            <span className="text-xs text-slate-500">+{item.teams.length - 3} more</span>
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
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <QuickActionCard
          icon={<Key className="h-5 w-5 text-amber-600" />}
          label="Rotate All Keys"
          href="/admin/contexts"
        />
        <QuickActionCard
          icon={<Users className="h-5 w-5 text-blue-600" />}
          label="Review Identities"
          href="/admin/identities"
        />
        <QuickActionCard
          icon={<Activity className="h-5 w-5 text-green-600" />}
          label="View Audit Log"
          href="/admin/audit"
        />
        <QuickActionCard
          icon={<Shield className="h-5 w-5 text-purple-600" />}
          label="Compliance Report"
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
