"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import Link from "next/link";
import {
  Key,
  Activity,
  CheckCircle,
  XCircle,
  Plus,
  Shield,
  AlertTriangle,
  Atom,
  Clock,
  ChevronRight,
  Lock,
  FileText,
  RefreshCw,
  Scan,
  Terminal,
  ArrowRight,
  Sparkles,
  Eye,
  Play,
  BookOpen,
  Zap,
  TrendingUp,
} from "lucide-react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { api, Application, AuditStats, DashboardMetrics } from "@/lib/api";
import { cn } from "@/lib/utils";

export default function DashboardPage() {
  const [applications, setApplications] = useState<Application[]>([]);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const [apps, s, m] = await Promise.all([
        api.listApplications(),
        api.getAuditStats(),
        api.getDashboardMetrics().catch(() => null),
      ]);
      setApplications(apps);
      setStats(s);
      setMetrics(m);
    } catch (error) {
      console.error("Failed to load dashboard data:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const activeApplications = useMemo(
    () => applications.filter((a) => a.status === "active"),
    [applications]
  );

  // Apps needing attention
  const attentionApps = useMemo(() => {
    const now = new Date();
    const sevenDaysFromNow = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    return applications.filter((a) => {
      if (a.status === "expired" || a.status === "revoked") return true;
      const exp = new Date(a.expires_at);
      if (a.status === "active" && exp > now && exp < sevenDaysFromNow) return true;
      if (a.status === "active" && (!a.last_used_at || new Date(a.last_used_at) < thirtyDaysAgo)) return true;
      return false;
    });
  }, [applications]);

  const getLastUsedText = (lastUsed: string | null) => {
    if (!lastUsed) return "Never used";
    const date = new Date(lastUsed);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      </DashboardLayout>
    );
  }

  const overallScore = metrics?.security_posture.overall_score || 0;
  const quantumReadiness = metrics?.security_posture.quantum_readiness || 0;
  const recentOps = metrics?.recent_activity.total_operations_24h || 0;

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Welcome Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-slate-800">Welcome back</h1>
            <p className="text-slate-500 mt-1">Here's what's happening with your crypto operations</p>
          </div>
          <Button variant="outline" size="sm" onClick={loadData}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>

        {/* Quick Actions */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Link
            href="/applications/new"
            className="flex items-center gap-3 p-4 bg-white border border-slate-200 rounded-xl hover:border-blue-300 hover:shadow-sm transition-all group"
          >
            <div className="p-2 bg-blue-50 rounded-lg group-hover:bg-blue-100 transition-colors">
              <Plus className="h-5 w-5 text-blue-500" />
            </div>
            <div>
              <div className="font-medium text-slate-800">New App</div>
              <div className="text-xs text-slate-400">Register application</div>
            </div>
          </Link>
          <Link
            href="/cbom"
            className="flex items-center gap-3 p-4 bg-white border border-slate-200 rounded-xl hover:border-purple-300 hover:shadow-sm transition-all group"
          >
            <div className="p-2 bg-purple-50 rounded-lg group-hover:bg-purple-100 transition-colors">
              <Scan className="h-5 w-5 text-purple-500" />
            </div>
            <div>
              <div className="font-medium text-slate-800">Scan Code</div>
              <div className="text-xs text-slate-400">Generate CBOM</div>
            </div>
          </Link>
          <Link
            href="/audit"
            className="flex items-center gap-3 p-4 bg-white border border-slate-200 rounded-xl hover:border-green-300 hover:shadow-sm transition-all group"
          >
            <div className="p-2 bg-green-50 rounded-lg group-hover:bg-green-100 transition-colors">
              <Activity className="h-5 w-5 text-green-500" />
            </div>
            <div>
              <div className="font-medium text-slate-800">View Logs</div>
              <div className="text-xs text-slate-400">Audit activity</div>
            </div>
          </Link>
          <Link
            href="/certificates"
            className="flex items-center gap-3 p-4 bg-white border border-slate-200 rounded-xl hover:border-amber-300 hover:shadow-sm transition-all group"
          >
            <div className="p-2 bg-amber-50 rounded-lg group-hover:bg-amber-100 transition-colors">
              <Shield className="h-5 w-5 text-amber-500" />
            </div>
            <div>
              <div className="font-medium text-slate-800">Certificates</div>
              <div className="text-xs text-slate-400">Manage certs</div>
            </div>
          </Link>
        </div>

        {/* Status Overview */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Security Score */}
          <div className="bg-white border border-slate-200 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <span className="text-sm font-medium text-slate-500">Security Score</span>
              <Link href="/admin/security" className="text-xs text-blue-500 hover:text-blue-600">
                View details
              </Link>
            </div>
            <div className="flex items-end gap-3">
              <span className={cn(
                "text-4xl font-bold",
                overallScore >= 80 ? "text-green-600" :
                overallScore >= 60 ? "text-amber-600" : "text-rose-600"
              )}>
                {overallScore}
              </span>
              <span className="text-slate-400 mb-1">/ 100</span>
            </div>
            <div className="mt-3 h-2 bg-slate-100 rounded-full overflow-hidden">
              <div
                className={cn(
                  "h-full rounded-full transition-all duration-500",
                  overallScore >= 80 ? "bg-green-500" :
                  overallScore >= 60 ? "bg-amber-500" : "bg-rose-500"
                )}
                style={{ width: `${overallScore}%` }}
              />
            </div>
          </div>

          {/* Quantum Readiness */}
          <div className="bg-white border border-slate-200 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <span className="text-sm font-medium text-slate-500">Quantum Readiness</span>
              <Atom className="h-4 w-4 text-purple-400" />
            </div>
            <div className="flex items-end gap-3">
              <span className={cn(
                "text-4xl font-bold",
                quantumReadiness >= 50 ? "text-purple-600" : "text-slate-600"
              )}>
                {quantumReadiness}%
              </span>
            </div>
            <div className="mt-3 h-2 bg-slate-100 rounded-full overflow-hidden">
              <div
                className="h-full bg-purple-500 rounded-full transition-all duration-500"
                style={{ width: `${quantumReadiness}%` }}
              />
            </div>
          </div>

          {/* Operations */}
          <div className="bg-white border border-slate-200 rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <span className="text-sm font-medium text-slate-500">Operations (24h)</span>
              <Activity className="h-4 w-4 text-green-400" />
            </div>
            <div className="flex items-end gap-3">
              <span className="text-4xl font-bold text-slate-800">{recentOps}</span>
              <span className="text-slate-400 mb-1">ops</span>
            </div>
            <div className="mt-3 flex items-center gap-2 text-sm">
              <span className="text-green-600">{metrics?.recent_activity.successful_24h || 0} successful</span>
              <span className="text-slate-300">•</span>
              <span className="text-rose-600">{metrics?.recent_activity.failed_24h || 0} failed</span>
            </div>
          </div>
        </div>

        {/* Attention Banner */}
        {attentionApps.length > 0 && (
          <div className="bg-orange-50 border border-orange-200 rounded-xl p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-orange-100 rounded-lg">
                  <AlertTriangle className="h-5 w-5 text-orange-500" />
                </div>
                <div>
                  <p className="font-medium text-orange-800">
                    {attentionApps.length} application{attentionApps.length !== 1 ? "s" : ""} need attention
                  </p>
                  <p className="text-sm text-orange-600">
                    Expired, expiring soon, or unused for 30+ days
                  </p>
                </div>
              </div>
              <Link href="/applications?filter=attention">
                <Button variant="outline" size="sm" className="border-orange-300 text-orange-700 hover:bg-orange-100">
                  Review
                  <ArrowRight className="h-4 w-4 ml-1" />
                </Button>
              </Link>
            </div>
          </div>
        )}

        {/* Warnings */}
        {metrics && metrics.warnings.length > 0 && (
          <div className="bg-amber-50 border border-amber-200 rounded-xl p-4">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5" />
              <div>
                <p className="font-medium text-amber-800">Recommendations</p>
                <ul className="mt-1 text-sm text-amber-700 space-y-1">
                  {metrics.warnings.slice(0, 3).map((w, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <ChevronRight className="h-4 w-4 mt-0.5 shrink-0" />
                      {w}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        )}

        {/* Two Column Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* My Applications */}
          <div className="bg-white border border-slate-200 rounded-xl">
            <div className="flex items-center justify-between p-4 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <Key className="h-5 w-5 text-slate-400" />
                <span className="font-medium text-slate-800">My Applications</span>
                <span className="text-xs bg-slate-100 text-slate-500 px-2 py-0.5 rounded-full">
                  {applications.length}
                </span>
              </div>
              <Link href="/applications" className="text-sm text-blue-500 hover:text-blue-600">
                View all
              </Link>
            </div>
            <div className="p-2">
              {applications.length === 0 ? (
                <div className="text-center py-8">
                  <Key className="h-10 w-10 mx-auto text-slate-200 mb-3" />
                  <p className="text-slate-500 mb-4">No applications yet</p>
                  <Link href="/applications/new">
                    <Button size="sm">
                      <Plus className="h-4 w-4 mr-2" />
                      Create First App
                    </Button>
                  </Link>
                </div>
              ) : (
                <div className="space-y-1">
                  {applications.slice(0, 5).map((app) => (
                    <Link
                      key={app.id}
                      href={`/applications/${app.id}/tokens`}
                      className="flex items-center justify-between p-3 rounded-lg hover:bg-slate-50 transition-colors group"
                    >
                      <div className="flex items-center gap-3">
                        <div className={cn(
                          "h-8 w-8 rounded-lg flex items-center justify-center",
                          app.status === "active" ? "bg-green-50" :
                          app.status === "expired" ? "bg-amber-50" : "bg-rose-50"
                        )}>
                          {app.status === "active" ? (
                            <CheckCircle className="h-4 w-4 text-green-500" />
                          ) : app.status === "expired" ? (
                            <Clock className="h-4 w-4 text-amber-500" />
                          ) : (
                            <XCircle className="h-4 w-4 text-rose-500" />
                          )}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-slate-800">{app.name}</span>
                            <Badge variant="outline" className={cn(
                              "text-xs",
                              app.environment === "production"
                                ? "bg-rose-50 text-rose-600 border-rose-200"
                                : app.environment === "staging"
                                ? "bg-amber-50 text-amber-600 border-amber-200"
                                : "bg-green-50 text-green-600 border-green-200"
                            )}>
                              {app.environment}
                            </Badge>
                          </div>
                          <span className="text-xs text-slate-400">{app.team}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-slate-400">{getLastUsedText(app.last_used_at)}</span>
                        <ChevronRight className="h-4 w-4 text-slate-300 group-hover:text-slate-500 transition-colors" />
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Recent Activity */}
          <div className="bg-white border border-slate-200 rounded-xl">
            <div className="flex items-center justify-between p-4 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <Activity className="h-5 w-5 text-slate-400" />
                <span className="font-medium text-slate-800">Recent Activity</span>
              </div>
              <Link href="/audit" className="text-sm text-blue-500 hover:text-blue-600">
                View logs
              </Link>
            </div>
            <div className="p-4">
              {stats && stats.total_operations > 0 ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-3 gap-4 text-center">
                    <div className="p-3 bg-slate-50 rounded-lg">
                      <div className="text-2xl font-bold text-slate-800">{stats.total_operations}</div>
                      <div className="text-xs text-slate-500">Total Ops</div>
                    </div>
                    <div className="p-3 bg-green-50 rounded-lg">
                      <div className="text-2xl font-bold text-green-600">{stats.successful_operations}</div>
                      <div className="text-xs text-green-600">Successful</div>
                    </div>
                    <div className="p-3 bg-rose-50 rounded-lg">
                      <div className="text-2xl font-bold text-rose-600">{stats.failed_operations}</div>
                      <div className="text-xs text-rose-600">Failed</div>
                    </div>
                  </div>

                  {/* Top Contexts */}
                  {stats.operations_by_context && Object.keys(stats.operations_by_context).length > 0 && (
                    <div className="pt-4 border-t border-slate-100">
                      <p className="text-xs font-medium text-slate-500 uppercase mb-2">Top Contexts</p>
                      <div className="space-y-2">
                        {Object.entries(stats.operations_by_context)
                          .sort(([, a], [, b]) => b - a)
                          .slice(0, 4)
                          .map(([op, count]) => (
                            <div key={op} className="flex items-center justify-between">
                              <span className="text-sm text-slate-600">{op}</span>
                              <span className="text-sm font-medium text-slate-800">{count}</span>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-center py-8">
                  <Activity className="h-10 w-10 mx-auto text-slate-200 mb-3" />
                  <p className="text-slate-500">No activity yet</p>
                  <p className="text-xs text-slate-400 mt-1">Operations will appear here</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Getting Started / Resources */}
        {applications.length < 3 && (
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-6">
            <div className="flex items-start gap-4">
              <div className="p-3 bg-blue-100 rounded-xl">
                <Sparkles className="h-6 w-6 text-blue-500" />
              </div>
              <div className="flex-1">
                <h3 className="font-semibold text-slate-800 mb-1">Getting Started</h3>
                <p className="text-sm text-slate-500 mb-4">
                  New to CryptoServe? Here are some quick actions to get you up and running.
                </p>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <Link
                    href="/applications/new"
                    className="flex items-center gap-2 p-3 bg-white border border-slate-200 rounded-lg hover:border-blue-300 transition-colors"
                  >
                    <Play className="h-4 w-4 text-blue-500" />
                    <span className="text-sm text-slate-700">Register an app</span>
                  </Link>
                  <Link
                    href="/cbom"
                    className="flex items-center gap-2 p-3 bg-white border border-slate-200 rounded-lg hover:border-purple-300 transition-colors"
                  >
                    <Scan className="h-4 w-4 text-purple-500" />
                    <span className="text-sm text-slate-700">Run a CBOM scan</span>
                  </Link>
                  <a
                    href="https://docs.cryptoserve.io"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 p-3 bg-white border border-slate-200 rounded-lg hover:border-green-300 transition-colors"
                  >
                    <BookOpen className="h-4 w-4 text-green-500" />
                    <span className="text-sm text-slate-700">Read the docs</span>
                  </a>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* CLI Quick Start */}
        <div className="bg-white border border-slate-200 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-4">
            <Terminal className="h-5 w-5 text-slate-400" />
            <span className="font-medium text-slate-800">CLI Quick Start</span>
          </div>
          <div className="bg-slate-900 rounded-lg p-4 font-mono text-sm overflow-x-auto">
            <div className="text-slate-400"># Install the CLI</div>
            <div className="text-green-400">pip install cryptoserve</div>
            <div className="text-slate-400 mt-3"># Scan your code for crypto usage</div>
            <div className="text-green-400">cryptoserve scan ./my-project</div>
            <div className="text-slate-400 mt-3"># Generate a CBOM report</div>
            <div className="text-green-400">cryptoserve cbom ./my-project --upload</div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
