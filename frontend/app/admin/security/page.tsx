"use client";

import { useState, useEffect } from "react";
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
  Info,
  TrendingUp,
  TrendingDown,
  Minus,
  Clock,
  Database,
  Zap,
  Target,
  RefreshCw,
  ChevronRight,
  ExternalLink,
} from "lucide-react";
import {
  api,
  SecurityAlert,
  SecurityMetrics,
  BlastRadiusItem,
  RiskScoreResponse,
} from "@/lib/api";
import Link from "next/link";

export default function SecurityCommandCenter() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [metrics, setMetrics] = useState<SecurityMetrics | null>(null);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusItem[]>([]);
  const [riskScore, setRiskScore] = useState<RiskScoreResponse | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  const loadData = async (showRefresh = false) => {
    if (showRefresh) setRefreshing(true);
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
      setLastUpdated(new Date());
    } catch (error) {
      console.error("Failed to load security data:", error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
    // Auto-refresh every 30 seconds
    const interval = setInterval(() => loadData(), 30000);
    return () => clearInterval(interval);
  }, []);

  const getAlertIcon = (severity: string) => {
    switch (severity) {
      case "critical":
        return <ShieldAlert className="h-5 w-5 text-red-500" />;
      case "warning":
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      default:
        return <Info className="h-5 w-5 text-blue-500" />;
    }
  };

  const getAlertBg = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-50 border-red-200 dark:bg-red-950/30 dark:border-red-900";
      case "warning":
        return "bg-yellow-50 border-yellow-200 dark:bg-yellow-950/30 dark:border-yellow-900";
      default:
        return "bg-blue-50 border-blue-200 dark:bg-blue-950/30 dark:border-blue-900";
    }
  };

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case "A":
        return "text-green-500";
      case "B":
        return "text-lime-500";
      case "C":
        return "text-yellow-500";
      case "D":
        return "text-orange-500";
      default:
        return "text-red-500";
    }
  };

  const getTrendIcon = (trend: string) => {
    switch (trend) {
      case "improving":
        return <TrendingUp className="h-4 w-4 text-green-500" />;
      case "declining":
        return <TrendingDown className="h-4 w-4 text-red-500" />;
      default:
        return <Minus className="h-4 w-4 text-gray-500" />;
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
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl shadow-lg shadow-blue-500/20">
            <Shield className="h-8 w-8" />
          </div>
          <div>
            <h1 className="text-3xl font-bold bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
              Security Command Center
            </h1>
            <p className="text-slate-400 flex items-center gap-2">
              <Clock className="h-4 w-4" />
              Last updated: {lastUpdated.toLocaleTimeString()}
            </p>
          </div>
        </div>
        <button
          onClick={() => loadData(true)}
          disabled={refreshing}
          className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
        >
          <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Status Banner */}
      <div
        className={`mb-8 p-4 rounded-xl border flex items-center justify-between ${
          criticalCount > 0
            ? "bg-red-500/10 border-red-500/30"
            : warningCount > 0
            ? "bg-yellow-500/10 border-yellow-500/30"
            : "bg-green-500/10 border-green-500/30"
        }`}
      >
        <div className="flex items-center gap-4">
          {criticalCount > 0 ? (
            <ShieldAlert className="h-10 w-10 text-red-500" />
          ) : warningCount > 0 ? (
            <AlertTriangle className="h-10 w-10 text-yellow-500" />
          ) : (
            <ShieldCheck className="h-10 w-10 text-green-500" />
          )}
          <div>
            <h2 className="text-xl font-semibold">
              {criticalCount > 0
                ? `${criticalCount} Critical Alert${criticalCount > 1 ? "s" : ""} Require Attention`
                : warningCount > 0
                ? `${warningCount} Warning${warningCount > 1 ? "s" : ""} to Review`
                : "All Systems Operational"}
            </h2>
            <p className="text-slate-400">
              {criticalCount > 0
                ? "Immediate action required to maintain security posture"
                : warningCount > 0
                ? "Review recommended items to prevent future issues"
                : "Your cryptographic infrastructure is secure and healthy"}
            </p>
          </div>
        </div>
        {riskScore && (
          <div className="text-center">
            <div
              className={`text-5xl font-bold ${getGradeColor(riskScore.grade)}`}
            >
              {riskScore.grade}
            </div>
            <div className="flex items-center gap-1 text-slate-400 text-sm">
              Risk Score: {riskScore.score}
              {getTrendIcon(riskScore.trend)}
            </div>
          </div>
        )}
      </div>

      {/* Real-time Metrics Grid */}
      {metrics && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4 mb-8">
          <MetricCard
            icon={<Activity className="h-5 w-5 text-blue-400" />}
            label="Ops/min"
            value={metrics.operations_per_minute.toFixed(1)}
            sublabel="Last hour avg"
          />
          <MetricCard
            icon={<Lock className="h-5 w-5 text-green-400" />}
            label="Encrypt Rate"
            value={`${metrics.encryption_rate}%`}
            sublabel="of operations"
          />
          <MetricCard
            icon={<ShieldCheck className="h-5 w-5 text-emerald-400" />}
            label="Success Rate"
            value={`${metrics.success_rate}%`}
            sublabel={metrics.success_rate >= 99 ? "Excellent" : "Review errors"}
            highlight={metrics.success_rate < 95}
          />
          <MetricCard
            icon={<Zap className="h-5 w-5 text-yellow-400" />}
            label="Latency"
            value={`${metrics.avg_latency_ms}ms`}
            sublabel="Avg response"
          />
          <MetricCard
            icon={<Users className="h-5 w-5 text-purple-400" />}
            label="Active Identities"
            value={metrics.active_identities.toString()}
            sublabel="Currently valid"
          />
          <MetricCard
            icon={<Target className="h-5 w-5 text-pink-400" />}
            label="Contexts Active"
            value={metrics.contexts_in_use.toString()}
            sublabel="Last 24h"
          />
          <MetricCard
            icon={<Database className="h-5 w-5 text-cyan-400" />}
            label="Data Processed"
            value={`${metrics.data_processed_mb.toFixed(1)} MB`}
            sublabel="Total encrypted"
          />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Alerts Panel */}
        <div className="lg:col-span-2 bg-slate-800/50 rounded-xl border border-slate-700 p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-blue-400" />
              Security Alerts
            </h3>
            <span className="text-sm text-slate-400">
              {alerts.length} active alert{alerts.length !== 1 ? "s" : ""}
            </span>
          </div>

          {alerts.length === 0 ? (
            <div className="text-center py-12 text-slate-500">
              <ShieldCheck className="h-16 w-16 mx-auto mb-4 text-green-500/50" />
              <p className="text-lg">No active alerts</p>
              <p className="text-sm">Your security posture is excellent</p>
            </div>
          ) : (
            <div className="space-y-3 max-h-[400px] overflow-y-auto pr-2">
              {alerts.map((alert) => (
                <div
                  key={alert.id}
                  className={`p-4 rounded-lg border ${getAlertBg(
                    alert.severity
                  )} transition-all hover:scale-[1.01]`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3">
                      {getAlertIcon(alert.severity)}
                      <div>
                        <h4 className="font-medium text-slate-100">
                          {alert.title}
                        </h4>
                        <p className="text-sm text-slate-400 mt-1">
                          {alert.description}
                        </p>
                        <div className="flex items-center gap-4 mt-2 text-xs text-slate-500">
                          <span className="px-2 py-0.5 bg-slate-700/50 rounded">
                            {alert.category}
                          </span>
                          <span>{alert.affected_count} affected</span>
                          {alert.auto_resolvable && (
                            <span className="text-green-400">Auto-resolvable</span>
                          )}
                        </div>
                      </div>
                    </div>
                    {alert.action_url && (
                      <Link
                        href={alert.action_url}
                        className="flex items-center gap-1 text-sm text-blue-400 hover:text-blue-300"
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
        </div>

        {/* Risk Factors */}
        <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
          <h3 className="text-lg font-semibold flex items-center gap-2 mb-4">
            <Target className="h-5 w-5 text-purple-400" />
            Risk Factors
          </h3>
          {riskScore?.factors.map((factor) => (
            <div
              key={factor.name}
              className="flex items-center justify-between py-3 border-b border-slate-700 last:border-0"
            >
              <span className="text-slate-300">{factor.name}</span>
              <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-slate-400">
                {factor.category}
              </span>
            </div>
          ))}
          <div className="mt-4 p-3 bg-purple-500/10 border border-purple-500/30 rounded-lg">
            <p className="text-sm text-purple-300">
              Detailed factor scores available in Premium
            </p>
          </div>
        </div>
      </div>

      {/* Blast Radius / Data Lineage */}
      <div className="mt-6 bg-slate-800/50 rounded-xl border border-slate-700 p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <Key className="h-5 w-5 text-amber-400" />
            Blast Radius Analysis
          </h3>
          <span className="text-sm text-slate-400">
            Impact assessment per context
          </span>
        </div>
        <p className="text-slate-400 text-sm mb-4">
          If a key is compromised, this shows the data and teams affected.
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="text-left py-3 px-4 font-medium text-slate-400">
                  Context
                </th>
                <th className="text-right py-3 px-4 font-medium text-slate-400">
                  Key Version
                </th>
                <th className="text-right py-3 px-4 font-medium text-slate-400">
                  Identities
                </th>
                <th className="text-right py-3 px-4 font-medium text-slate-400">
                  Operations
                </th>
                <th className="text-right py-3 px-4 font-medium text-slate-400">
                  Data Size
                </th>
                <th className="text-left py-3 px-4 font-medium text-slate-400">
                  Teams
                </th>
              </tr>
            </thead>
            <tbody>
              {blastRadius.slice(0, 10).map((item) => (
                <tr
                  key={item.context_name}
                  className="border-b border-slate-700/50 hover:bg-slate-700/30"
                >
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <div
                        className={`w-2 h-2 rounded-full ${
                          item.data_size_bytes > 1000000
                            ? "bg-red-500"
                            : item.data_size_bytes > 10000
                            ? "bg-yellow-500"
                            : "bg-green-500"
                        }`}
                      />
                      <span className="font-medium text-slate-200">
                        {item.context_name}
                      </span>
                    </div>
                  </td>
                  <td className="text-right py-3 px-4 text-slate-400">
                    v{item.key_version}
                  </td>
                  <td className="text-right py-3 px-4 text-slate-300">
                    {item.identities_affected}
                  </td>
                  <td className="text-right py-3 px-4 text-slate-300">
                    {item.operations_count.toLocaleString()}
                  </td>
                  <td className="text-right py-3 px-4 text-slate-300">
                    {formatBytes(item.data_size_bytes)}
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex flex-wrap gap-1">
                      {item.teams.slice(0, 3).map((team) => (
                        <span
                          key={team}
                          className="px-2 py-0.5 bg-slate-700 rounded text-xs"
                        >
                          {team}
                        </span>
                      ))}
                      {item.teams.length > 3 && (
                        <span className="text-xs text-slate-500">
                          +{item.teams.length - 3} more
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {blastRadius.length === 0 && (
          <div className="text-center py-8 text-slate-500">
            <Database className="h-12 w-12 mx-auto mb-2 opacity-50" />
            <p>No data lineage recorded yet</p>
          </div>
        )}
      </div>

      {/* Quick Actions */}
      <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4">
        <QuickAction
          icon={<Key className="h-5 w-5" />}
          label="Rotate All Keys"
          href="/admin/contexts"
        />
        <QuickAction
          icon={<Users className="h-5 w-5" />}
          label="Review Identities"
          href="/admin/identities"
        />
        <QuickAction
          icon={<Activity className="h-5 w-5" />}
          label="View Audit Log"
          href="/admin/audit"
        />
        <QuickAction
          icon={<Shield className="h-5 w-5" />}
          label="Compliance Report"
          href="/admin/compliance"
        />
      </div>
    </div>
  );
}

function MetricCard({
  icon,
  label,
  value,
  sublabel,
  highlight = false,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  sublabel: string;
  highlight?: boolean;
}) {
  return (
    <div
      className={`bg-slate-800/50 rounded-xl border p-4 ${
        highlight ? "border-yellow-500/50" : "border-slate-700"
      }`}
    >
      <div className="flex items-center gap-2 mb-2">
        {icon}
        <span className="text-xs text-slate-400">{label}</span>
      </div>
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-xs text-slate-500 mt-1">{sublabel}</div>
    </div>
  );
}

function QuickAction({
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
      className="flex items-center gap-3 p-4 bg-slate-800/50 hover:bg-slate-700/50 border border-slate-700 rounded-xl transition-all hover:scale-[1.02] hover:border-slate-600"
    >
      <div className="p-2 bg-slate-700 rounded-lg">{icon}</div>
      <span className="font-medium">{label}</span>
      <ExternalLink className="h-4 w-4 text-slate-500 ml-auto" />
    </Link>
  );
}
