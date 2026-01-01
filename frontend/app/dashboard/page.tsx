"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Key, Activity, CheckCircle, XCircle, Plus, Shield, AlertTriangle, Atom, TrendingUp, Clock, Settings, Rocket, Server, Code, ArrowUpRight, Timer, Lock } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { api, Application, AuditStats, DashboardMetrics } from "@/lib/api";

export default function DashboardPage() {
  const [applications, setApplications] = useState<Application[]>([]);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api.listApplications(),
      api.getAuditStats(),
      api.getDashboardMetrics().catch(() => null),
    ])
      .then(([apps, s, m]) => {
        setApplications(apps);
        setStats(s);
        setMetrics(m);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const activeApplications = applications.filter((a) => a.status === "active");

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-600";
    if (score >= 60) return "text-yellow-600";
    return "text-red-600";
  };

  const getScoreBg = (score: number) => {
    if (score >= 80) return "bg-green-50";
    if (score >= 60) return "bg-yellow-50";
    return "bg-red-50";
  };

  const getLastUsedText = (lastUsed: string | null) => {
    if (!lastUsed) return "Never used";
    const date = new Date(lastUsed);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins} min ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  const getAppStatusIcon = (app: Application) => {
    if (app.status !== "active") {
      return <XCircle className="h-4 w-4 text-red-500" />;
    }
    if (app.refresh_token_expires_at) {
      const expiresAt = new Date(app.refresh_token_expires_at);
      const daysUntilExpiry = (expiresAt.getTime() - Date.now()) / (1000 * 60 * 60 * 24);
      if (daysUntilExpiry < 7) {
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      }
    }
    return <CheckCircle className="h-4 w-4 text-green-500" />;
  };

  const getEnvironmentBadge = (env: string) => {
    switch (env.toLowerCase()) {
      case "production":
        return <Badge className="bg-green-100 text-green-800 hover:bg-green-100">Production</Badge>;
      case "staging":
        return <Badge className="bg-blue-100 text-blue-800 hover:bg-blue-100">Staging</Badge>;
      case "development":
      default:
        return <Badge className="bg-gray-100 text-gray-800 hover:bg-gray-100">Development</Badge>;
    }
  };

  const getEnvironmentIcon = (env: string) => {
    switch (env.toLowerCase()) {
      case "production":
        return <Server className="h-4 w-4 text-green-600" />;
      case "staging":
        return <Rocket className="h-4 w-4 text-blue-600" />;
      default:
        return <Code className="h-4 w-4 text-gray-600" />;
    }
  };

  // Group applications by environment
  const productionApps = activeApplications.filter(a => a.environment.toLowerCase() === "production");
  const devApps = activeApplications.filter(a => a.environment.toLowerCase() !== "production");

  return (
    <DashboardLayout>
      <div className="space-y-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Dashboard</h1>
            <p className="text-slate-600">
              Security overview and cryptographic operations
            </p>
          </div>
          <Link href="/applications/new">
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              New Application
            </Button>
          </Link>
        </div>

        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : (
          <>
            {/* Security Posture Card */}
            {metrics && (
              <Card className={getScoreBg(metrics.security_posture.overall_score)}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        <Shield className="h-5 w-5" />
                        Security Posture
                      </CardTitle>
                      <CardDescription>
                        Overall crypto health assessment
                      </CardDescription>
                    </div>
                    <div className="text-right">
                      <div className={`text-4xl font-bold ${getScoreColor(metrics.security_posture.overall_score)}`}>
                        {metrics.security_posture.overall_score}
                      </div>
                      <p className="text-sm text-muted-foreground">out of 100</p>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="p-3 bg-white/50 rounded-lg">
                      <Atom className="h-4 w-4 text-purple-500 mb-1" />
                      <p className="text-sm font-medium">Quantum Readiness</p>
                      <p className={`text-xl font-bold ${getScoreColor(metrics.security_posture.quantum_readiness)}`}>
                        {metrics.security_posture.quantum_readiness}%
                      </p>
                    </div>
                    <div className="p-3 bg-white/50 rounded-lg">
                      <AlertTriangle className="h-4 w-4 text-yellow-500 mb-1" />
                      <p className="text-sm font-medium">Deprecated Usage</p>
                      <p className={`text-xl font-bold ${metrics.security_posture.deprecated_usage > 0 ? "text-red-600" : "text-green-600"}`}>
                        {metrics.security_posture.deprecated_usage}
                      </p>
                    </div>
                    <div className="p-3 bg-white/50 rounded-lg">
                      <TrendingUp className="h-4 w-4 text-blue-500 mb-1" />
                      <p className="text-sm font-medium">PQC Operations</p>
                      <p className="text-xl font-bold text-blue-600">
                        {metrics.pqc_ready_count}
                      </p>
                    </div>
                    <div className="p-3 bg-white/50 rounded-lg">
                      <Activity className="h-4 w-4 text-slate-500 mb-1" />
                      <p className="text-sm font-medium">24h Operations</p>
                      <p className="text-xl font-bold">
                        {metrics.recent_activity.total_operations_24h}
                      </p>
                    </div>
                  </div>

                  {metrics.warnings.length > 0 && (
                    <div className="mt-4 p-3 bg-yellow-100 rounded-lg">
                      <p className="text-sm font-medium text-yellow-800 mb-1">Warnings</p>
                      <ul className="text-sm text-yellow-700 space-y-1">
                        {metrics.warnings.map((w, i) => (
                          <li key={i} className="flex items-center gap-2">
                            <AlertTriangle className="h-3 w-3" />
                            {w}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {metrics.security_posture.recommendations.length > 0 && (
                    <div className="mt-4">
                      <p className="text-sm font-medium mb-2">Recommendations</p>
                      <ul className="text-sm text-muted-foreground space-y-1">
                        {metrics.security_posture.recommendations.map((r, i) => (
                          <li key={i}>• {r}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* My Applications Section */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Key className="h-5 w-5" />
                      My Applications
                    </CardTitle>
                    <CardDescription>
                      Your SDK applications and their activity
                    </CardDescription>
                  </div>
                  <div className="flex gap-2">
                    <Link href="/applications">
                      <Button variant="outline" size="sm">View All</Button>
                    </Link>
                    <Link href="/applications/new">
                      <Button size="sm">
                        <Plus className="h-4 w-4 mr-1" />
                        New
                      </Button>
                    </Link>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                {activeApplications.length === 0 ? (
                  <div className="text-center py-8">
                    <Key className="h-10 w-10 mx-auto text-slate-400 mb-3" />
                    <p className="text-slate-600 mb-4">No applications yet</p>
                    <Link href="/applications/new">
                      <Button>
                        <Plus className="h-4 w-4 mr-2" />
                        Create Your First Application
                      </Button>
                    </Link>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {/* Production Apps */}
                    {productionApps.length > 0 && (
                      <div className="space-y-2">
                        <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">Production</p>
                        {productionApps.slice(0, 3).map((app) => (
                          <Link key={app.id} href={`/applications/${app.id}/tokens`}>
                            <div className="flex items-center justify-between p-3 border rounded-lg hover:bg-slate-50 transition-colors cursor-pointer border-green-200 bg-green-50/30">
                              <div className="flex items-start gap-3">
                                <div className="mt-0.5">{getAppStatusIcon(app)}</div>
                                <div>
                                  <div className="flex items-center gap-2">
                                    <p className="font-medium">{app.name}</p>
                                    {getEnvironmentBadge(app.environment)}
                                  </div>
                                  <div className="flex gap-1 flex-wrap mt-1">
                                    {app.allowed_contexts.slice(0, 3).map((ctx) => (
                                      <Badge key={ctx} variant="secondary" className="text-xs">
                                        {ctx}
                                      </Badge>
                                    ))}
                                    {app.allowed_contexts.length > 3 && (
                                      <Badge variant="outline" className="text-xs">
                                        +{app.allowed_contexts.length - 3}
                                      </Badge>
                                    )}
                                  </div>
                                </div>
                              </div>
                              <div className="text-right text-sm text-slate-500">
                                <div className="flex items-center gap-1 justify-end">
                                  <Clock className="h-3 w-3" />
                                  <span>{getLastUsedText(app.last_used_at)}</span>
                                </div>
                              </div>
                            </div>
                          </Link>
                        ))}
                      </div>
                    )}

                    {/* Development Apps */}
                    {devApps.length > 0 && (
                      <div className="space-y-2">
                        <p className="text-xs font-medium text-slate-500 uppercase tracking-wider mt-4">Development</p>
                        {devApps.slice(0, 3).map((app) => (
                          <Link key={app.id} href={`/applications/${app.id}/tokens`}>
                            <div className="flex items-center justify-between p-3 border rounded-lg hover:bg-slate-50 transition-colors cursor-pointer">
                              <div className="flex items-start gap-3">
                                <div className="mt-0.5">{getAppStatusIcon(app)}</div>
                                <div>
                                  <div className="flex items-center gap-2">
                                    <p className="font-medium">{app.name}</p>
                                    {getEnvironmentBadge(app.environment)}
                                  </div>
                                  <div className="flex gap-1 flex-wrap mt-1">
                                    {app.allowed_contexts.slice(0, 3).map((ctx) => (
                                      <Badge key={ctx} variant="secondary" className="text-xs">
                                        {ctx}
                                      </Badge>
                                    ))}
                                    {app.allowed_contexts.length > 3 && (
                                      <Badge variant="outline" className="text-xs">
                                        +{app.allowed_contexts.length - 3}
                                      </Badge>
                                    )}
                                  </div>
                                </div>
                              </div>
                              <div className="text-right text-sm text-slate-500">
                                <div className="flex items-center gap-1 justify-end">
                                  <Clock className="h-3 w-3" />
                                  <span>{getLastUsedText(app.last_used_at)}</span>
                                </div>
                              </div>
                            </div>
                          </Link>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Promotion Readiness Section */}
            {metrics?.promotion_metrics && metrics.promotion_metrics.total_dev_apps > 0 && (
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="flex items-center gap-2">
                        <Rocket className="h-5 w-5" />
                        Promotion Readiness
                      </CardTitle>
                      <CardDescription>
                        Progress toward production deployment
                      </CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={metrics.promotion_metrics.apps_ready_for_promotion > 0 ? "default" : "secondary"}>
                        {metrics.promotion_metrics.apps_ready_for_promotion} ready
                      </Badge>
                      {metrics.promotion_metrics.apps_blocking > 0 && (
                        <Badge variant="outline" className="text-yellow-600">
                          {metrics.promotion_metrics.apps_blocking} pending
                        </Badge>
                      )}
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {/* Tier Distribution Summary */}
                    <div className="grid grid-cols-3 gap-3">
                      <div className="p-3 bg-green-50 rounded-lg text-center">
                        <p className="text-xs text-green-600 font-medium">Tier 1 (Low)</p>
                        <p className="text-xl font-bold text-green-700">
                          {metrics.promotion_metrics.tier_distribution?.tier_1 || 0}
                        </p>
                      </div>
                      <div className="p-3 bg-yellow-50 rounded-lg text-center">
                        <p className="text-xs text-yellow-600 font-medium">Tier 2 (Medium)</p>
                        <p className="text-xl font-bold text-yellow-700">
                          {metrics.promotion_metrics.tier_distribution?.tier_2 || 0}
                        </p>
                      </div>
                      <div className="p-3 bg-red-50 rounded-lg text-center">
                        <p className="text-xs text-red-600 font-medium">Tier 3 (High)</p>
                        <p className="text-xl font-bold text-red-700">
                          {metrics.promotion_metrics.tier_distribution?.tier_3 || 0}
                        </p>
                      </div>
                    </div>

                    {/* Per-App Promotion Status */}
                    <div className="space-y-2">
                      <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">Application Status</p>
                      {metrics.promotion_metrics.app_statuses.map((app) => (
                        <Link key={app.app_id} href={`/applications/${app.app_id}/promotion`}>
                          <div className={`flex items-center justify-between p-3 border rounded-lg hover:bg-slate-50 transition-colors cursor-pointer ${
                            app.is_ready ? "border-green-200 bg-green-50/30" : "border-yellow-200 bg-yellow-50/30"
                          }`}>
                            <div className="flex items-start gap-3">
                              <div className="mt-0.5">
                                {app.is_ready ? (
                                  <CheckCircle className="h-4 w-4 text-green-500" />
                                ) : (
                                  <Timer className="h-4 w-4 text-yellow-500" />
                                )}
                              </div>
                              <div>
                                <div className="flex items-center gap-2">
                                  <p className="font-medium">{app.app_name}</p>
                                  <Badge variant="outline" className="text-xs">
                                    {app.environment}
                                  </Badge>
                                  {app.requires_approval && (
                                    <span title="Requires approval">
                                      <Lock className="h-3 w-3 text-purple-500" />
                                    </span>
                                  )}
                                </div>
                                <div className="flex items-center gap-2 mt-1 text-xs text-slate-500">
                                  <span>{app.ready_count}/{app.total_count} contexts ready</span>
                                  {app.blocking_contexts.length > 0 && (
                                    <span className="text-yellow-600">
                                      Blocking: {app.blocking_contexts.slice(0, 2).join(", ")}
                                      {app.blocking_contexts.length > 2 && ` +${app.blocking_contexts.length - 2}`}
                                    </span>
                                  )}
                                </div>
                              </div>
                            </div>
                            <div className="text-right">
                              {app.is_ready ? (
                                <Badge className="bg-green-100 text-green-800">Ready</Badge>
                              ) : app.estimated_ready_at ? (
                                <span className="text-xs text-slate-500">
                                  Est: {new Date(app.estimated_ready_at).toLocaleDateString()}
                                </span>
                              ) : (
                                <Badge variant="outline">In Progress</Badge>
                              )}
                              <ArrowUpRight className="h-4 w-4 text-slate-400 mt-1 ml-auto" />
                            </div>
                          </div>
                        </Link>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Stats cards */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">
                    Active Applications
                  </CardTitle>
                  <Key className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">
                    {activeApplications.length}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {applications.length} total
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">
                    Total Operations
                  </CardTitle>
                  <Activity className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">
                    {stats?.total_operations || 0}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    encrypt & decrypt calls
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">
                    Successful
                  </CardTitle>
                  <CheckCircle className="h-4 w-4 text-green-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">
                    {stats?.successful_operations || 0}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {stats && stats.total_operations > 0
                      ? `${Math.round(
                          (stats.successful_operations / stats.total_operations) *
                            100
                        )}% success rate`
                      : "No operations yet"}
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Failed</CardTitle>
                  <XCircle className="h-4 w-4 text-red-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">
                    {stats?.failed_operations || 0}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Check audit log for details
                  </p>
                </CardContent>
              </Card>
            </div>

            {/* Algorithm Distribution */}
            {metrics && metrics.algorithm_distribution.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Algorithm Usage (24h)</CardTitle>
                  <CardDescription>
                    Distribution of cryptographic algorithms used
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {metrics.algorithm_distribution.map((algo) => (
                      <div key={algo.algorithm} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-sm">{algo.algorithm.toUpperCase()}</span>
                          <Badge variant={algo.quantum_safe ? "default" : "secondary"}>
                            {algo.quantum_safe ? "Quantum-Safe" : "Classical"}
                          </Badge>
                          <Badge variant="outline">{algo.category}</Badge>
                        </div>
                        <span className="text-slate-600">{algo.count} ops</span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Operations by context */}
            {stats && Object.keys(stats.operations_by_context).length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Operations by Context</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {Object.entries(stats.operations_by_context).map(
                      ([context, count]) => (
                        <div
                          key={context}
                          className="flex items-center justify-between"
                        >
                          <span className="font-mono text-sm">{context}</span>
                          <span className="text-slate-600">{count}</span>
                        </div>
                      )
                    )}
                  </div>
                </CardContent>
              </Card>
            )}
          </>
        )}
      </div>
    </DashboardLayout>
  );
}
