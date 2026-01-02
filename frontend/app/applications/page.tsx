"use client";

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { Settings, Key, Clock, Trash2, CheckCircle, AlertTriangle, XCircle, Server, Rocket, Code, ArrowUpCircle, Activity, TrendingUp, Shield, Zap } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { api, Application } from "@/lib/api";

export default function ApplicationsPage() {
  const [applications, setApplications] = useState<Application[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listApplications()
      .then(setApplications)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to revoke this application? All tokens will be invalidated immediately.")) return;

    try {
      await api.deleteApplication(id);
      setApplications(apps => apps.map(a =>
        a.id === id ? { ...a, status: "revoked" as const } : a
      ));
    } catch (error) {
      alert(error instanceof Error ? error.message : "Failed to revoke application");
    }
  };

  const getStatusIcon = (app: Application) => {
    if (app.status !== "active") {
      return <XCircle className="h-4 w-4 text-red-500" />;
    }

    // Check if token is expiring soon (within 7 days)
    if (app.refresh_token_expires_at) {
      const expiresAt = new Date(app.refresh_token_expires_at);
      const daysUntilExpiry = (expiresAt.getTime() - Date.now()) / (1000 * 60 * 60 * 24);
      if (daysUntilExpiry < 7) {
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
      }
    }

    return <CheckCircle className="h-4 w-4 text-green-500" />;
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
  const activeApps = applications.filter(a => a.status === "active");
  const revokedApps = applications.filter(a => a.status !== "active");
  const productionApps = activeApps.filter(a => a.environment.toLowerCase() === "production");
  const stagingApps = activeApps.filter(a => a.environment.toLowerCase() === "staging");
  const devApps = activeApps.filter(a => a.environment.toLowerCase() === "development" || !["production", "staging"].includes(a.environment.toLowerCase()));

  // Calculate stats
  const stats = useMemo(() => {
    const now = new Date();
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    const recentlyUsed = activeApps.filter(app => {
      if (!app.last_used_at) return false;
      return new Date(app.last_used_at) > weekAgo;
    });

    const expiringSoon = activeApps.filter(app => {
      const expiresAt = new Date(app.expires_at);
      const daysUntil = (expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
      return daysUntil <= 30 && daysUntil > 0;
    });

    const uniqueContexts = new Set<string>();
    activeApps.forEach(app => app.allowed_contexts.forEach(ctx => uniqueContexts.add(ctx)));

    return {
      total: applications.length,
      active: activeApps.length,
      production: productionApps.length,
      staging: stagingApps.length,
      development: devApps.length,
      revoked: revokedApps.length,
      recentlyUsed: recentlyUsed.length,
      expiringSoon: expiringSoon.length,
      uniqueContexts: uniqueContexts.size,
    };
  }, [applications, activeApps, productionApps, stagingApps, devApps, revokedApps]);

  return (
    <DashboardLayout>
      <div className="space-y-8">
        <div>
          <h1 className="text-2xl font-bold">My Applications</h1>
          <p className="text-slate-600">
            Applications are automatically registered when you use the SDK
          </p>
        </div>

        {/* Stats Dashboard */}
        {!loading && applications.length > 0 && (
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            {/* Environment Distribution Card */}
            <div className="lg:col-span-2 bg-white rounded-xl border border-slate-200 p-5">
              <h3 className="text-sm font-medium text-slate-600 mb-4">Environment Distribution</h3>
              <div className="flex items-center gap-6">
                {/* Visual Bar Chart */}
                <div className="flex-1 space-y-3">
                  <div className="flex items-center gap-3">
                    <div className="w-24 text-sm text-slate-600 flex items-center gap-2">
                      <Server className="h-4 w-4 text-green-500" />
                      Production
                    </div>
                    <div className="flex-1 bg-slate-100 rounded-full h-3 overflow-hidden">
                      <div
                        className="h-full bg-green-500 rounded-full transition-all"
                        style={{ width: stats.active > 0 ? `${(stats.production / stats.active) * 100}%` : "0%" }}
                      />
                    </div>
                    <span className="w-8 text-sm font-semibold text-slate-900 text-right">{stats.production}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="w-24 text-sm text-slate-600 flex items-center gap-2">
                      <Rocket className="h-4 w-4 text-blue-500" />
                      Staging
                    </div>
                    <div className="flex-1 bg-slate-100 rounded-full h-3 overflow-hidden">
                      <div
                        className="h-full bg-blue-500 rounded-full transition-all"
                        style={{ width: stats.active > 0 ? `${(stats.staging / stats.active) * 100}%` : "0%" }}
                      />
                    </div>
                    <span className="w-8 text-sm font-semibold text-slate-900 text-right">{stats.staging}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="w-24 text-sm text-slate-600 flex items-center gap-2">
                      <Code className="h-4 w-4 text-slate-500" />
                      Dev
                    </div>
                    <div className="flex-1 bg-slate-100 rounded-full h-3 overflow-hidden">
                      <div
                        className="h-full bg-slate-400 rounded-full transition-all"
                        style={{ width: stats.active > 0 ? `${(stats.development / stats.active) * 100}%` : "0%" }}
                      />
                    </div>
                    <span className="w-8 text-sm font-semibold text-slate-900 text-right">{stats.development}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Quick Stats Cards */}
            <div className="bg-white rounded-xl border border-slate-200 p-5">
              <div className="flex items-center gap-3 mb-3">
                <div className="p-2 bg-green-50 rounded-lg">
                  <Activity className="h-5 w-5 text-green-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900">{stats.recentlyUsed}</p>
                  <p className="text-sm text-slate-500">Active this week</p>
                </div>
              </div>
              <div className="text-xs text-slate-400 mt-2">
                {stats.active > 0 ? Math.round((stats.recentlyUsed / stats.active) * 100) : 0}% of apps used recently
              </div>
            </div>

            <div className="bg-white rounded-xl border border-slate-200 p-5">
              <div className="flex items-center gap-3 mb-3">
                <div className={`p-2 rounded-lg ${stats.expiringSoon > 0 ? "bg-amber-50" : "bg-green-50"}`}>
                  <Clock className={`h-5 w-5 ${stats.expiringSoon > 0 ? "text-amber-600" : "text-green-600"}`} />
                </div>
                <div>
                  <p className="text-2xl font-bold text-slate-900">{stats.expiringSoon}</p>
                  <p className="text-sm text-slate-500">Expiring soon</p>
                </div>
              </div>
              <div className="text-xs text-slate-400 mt-2">
                {stats.expiringSoon > 0 ? "Within next 30 days" : "No upcoming expirations"}
              </div>
            </div>
          </div>
        )}

        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : applications.length === 0 ? (
          <Card>
            <CardContent className="py-12 text-center">
              <Key className="h-12 w-12 mx-auto text-slate-400 mb-4" />
              <h3 className="text-lg font-medium mb-2">No applications yet</h3>
              <p className="text-slate-600 mb-4">
                Applications are automatically created when you use the SDK
              </p>
              <div className="bg-slate-50 rounded-lg p-4 max-w-lg mx-auto text-left">
                <p className="text-sm font-mono text-slate-700 mb-2">
                  # Install the SDK
                </p>
                <p className="text-sm font-mono text-slate-600 mb-4">
                  pip install cryptoserve
                </p>
                <p className="text-sm font-mono text-slate-700 mb-2">
                  # Use in your code
                </p>
                <p className="text-sm font-mono text-slate-600">
                  from cryptoserve import CryptoServe<br/>
                  crypto = CryptoServe(app_name=&quot;my-app&quot;)
                </p>
              </div>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-6">
            {/* Production Applications */}
            {productionApps.length > 0 && (
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <div className="p-1.5 bg-green-100 rounded-lg">
                    <Server className="h-4 w-4 text-green-600" />
                  </div>
                  <h2 className="text-sm font-semibold text-slate-700">Production</h2>
                  <span className="text-xs font-medium text-green-700 bg-green-100 px-2 py-0.5 rounded-full">{productionApps.length}</span>
                </div>
                <div className="grid gap-4">
                  {productionApps.map((app) => (
                    <div key={app.id} className="bg-white rounded-xl border-2 border-green-200 hover:shadow-md transition-shadow">
                      <div className="p-5">
                        {/* Top Row: Name + Status */}
                        <div className="flex items-start justify-between mb-4">
                          <div className="flex items-center gap-3">
                            {getStatusIcon(app)}
                            <div>
                              <h3 className="font-semibold text-slate-900">{app.name}</h3>
                              {app.description && (
                                <p className="text-sm text-slate-500 mt-0.5">{app.description}</p>
                              )}
                            </div>
                          </div>
                          {getEnvironmentBadge(app.environment)}
                        </div>

                        {/* Info Grid */}
                        <div className="grid grid-cols-3 gap-4 py-4 border-y border-slate-100">
                          <div>
                            <p className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">Team</p>
                            <p className="text-sm font-medium text-slate-700">{app.team}</p>
                          </div>
                          <div>
                            <p className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">Last Activity</p>
                            <div className="flex items-center gap-1.5 text-sm text-slate-700">
                              <Clock className="h-3.5 w-3.5 text-slate-400" />
                              <span>{getLastUsedText(app.last_used_at)}</span>
                            </div>
                          </div>
                          <div>
                            <p className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">Expires</p>
                            <p className="text-sm text-slate-700">{new Date(app.expires_at).toLocaleDateString()}</p>
                          </div>
                        </div>

                        {/* Bottom Row: Contexts + Actions */}
                        <div className="flex items-center justify-between mt-4">
                          <div>
                            <p className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-2">Encryption Contexts</p>
                            <div className="flex gap-1.5 flex-wrap">
                              {app.allowed_contexts.map((ctx) => (
                                <span key={ctx} className="inline-flex items-center gap-1 px-2 py-1 bg-blue-50 border border-blue-100 rounded-md text-xs font-medium text-blue-700">
                                  <Shield className="h-3 w-3" />
                                  {ctx}
                                </span>
                              ))}
                            </div>
                          </div>
                          <div className="flex gap-2">
                            <Link href={`/applications/${app.id}/tokens`}>
                              <Button variant="outline" size="sm">
                                <Settings className="h-4 w-4 mr-1.5" />
                                Manage
                              </Button>
                            </Link>
                            <Button variant="outline" size="sm" onClick={() => handleDelete(app.id)} className="text-red-600 hover:text-red-700 hover:bg-red-50">
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Staging Applications */}
            {stagingApps.length > 0 && (
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <div className="p-1.5 bg-blue-100 rounded-lg">
                    <Rocket className="h-4 w-4 text-blue-600" />
                  </div>
                  <h2 className="text-sm font-semibold text-slate-700">Staging</h2>
                  <span className="text-xs font-medium text-blue-700 bg-blue-100 px-2 py-0.5 rounded-full">{stagingApps.length}</span>
                </div>
                <div className="grid gap-4">
                  {stagingApps.map((app) => (
                    <div key={app.id} className="bg-white rounded-xl border-2 border-blue-200 hover:shadow-md transition-shadow">
                      <div className="p-5">
                        {/* Top Row: Name + Status */}
                        <div className="flex items-start justify-between mb-4">
                          <div className="flex items-center gap-3">
                            {getStatusIcon(app)}
                            <div>
                              <h3 className="font-semibold text-slate-900">{app.name}</h3>
                              {app.description && (
                                <p className="text-sm text-slate-500 mt-0.5">{app.description}</p>
                              )}
                            </div>
                          </div>
                          {getEnvironmentBadge(app.environment)}
                        </div>

                        {/* Info Grid */}
                        <div className="grid grid-cols-3 gap-4 py-4 border-y border-slate-100">
                          <div>
                            <p className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">Team</p>
                            <p className="text-sm font-medium text-slate-700">{app.team}</p>
                          </div>
                          <div>
                            <p className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">Last Activity</p>
                            <div className="flex items-center gap-1.5 text-sm text-slate-700">
                              <Clock className="h-3.5 w-3.5 text-slate-400" />
                              <span>{getLastUsedText(app.last_used_at)}</span>
                            </div>
                          </div>
                          <div>
                            <p className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">Expires</p>
                            <p className="text-sm text-slate-700">{new Date(app.expires_at).toLocaleDateString()}</p>
                          </div>
                        </div>

                        {/* Bottom Row: Contexts + Actions */}
                        <div className="flex items-center justify-between mt-4">
                          <div>
                            <p className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-2">Encryption Contexts</p>
                            <div className="flex gap-1.5 flex-wrap">
                              {app.allowed_contexts.map((ctx) => (
                                <span key={ctx} className="inline-flex items-center gap-1 px-2 py-1 bg-blue-50 border border-blue-100 rounded-md text-xs font-medium text-blue-700">
                                  <Shield className="h-3 w-3" />
                                  {ctx}
                                </span>
                              ))}
                            </div>
                          </div>
                          <div className="flex gap-2">
                            <Link href={`/applications/${app.id}/tokens`}>
                              <Button variant="outline" size="sm">
                                <Settings className="h-4 w-4 mr-1.5" />
                                Manage
                              </Button>
                            </Link>
                            <Button variant="outline" size="sm" onClick={() => handleDelete(app.id)} className="text-red-600 hover:text-red-700 hover:bg-red-50">
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Development Applications */}
            {devApps.length > 0 && (
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <div className="p-1.5 bg-slate-100 rounded-lg">
                    <Code className="h-4 w-4 text-slate-600" />
                  </div>
                  <h2 className="text-sm font-semibold text-slate-700">Development</h2>
                  <span className="text-xs font-medium text-slate-500 bg-slate-100 px-2 py-0.5 rounded-full">{devApps.length}</span>
                </div>
                <div className="grid gap-4">
                  {devApps.map((app) => (
                    <div key={app.id} className="bg-white rounded-xl border border-slate-200 hover:shadow-md transition-shadow">
                      <div className="p-5">
                        {/* Top Row: Name + Status */}
                        <div className="flex items-start justify-between mb-4">
                          <div className="flex items-center gap-3">
                            {getStatusIcon(app)}
                            <div>
                              <h3 className="font-semibold text-slate-900">{app.name}</h3>
                              {app.description && (
                                <p className="text-sm text-slate-500 mt-0.5">{app.description}</p>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            {getEnvironmentBadge(app.environment)}
                            <Badge variant="outline" className="text-xs bg-purple-50 text-purple-700 border-purple-200">
                              <ArrowUpCircle className="h-3 w-3 mr-1" />
                              Ready to promote
                            </Badge>
                          </div>
                        </div>

                        {/* Info Grid */}
                        <div className="grid grid-cols-3 gap-4 py-4 border-y border-slate-100">
                          <div>
                            <p className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">Team</p>
                            <p className="text-sm font-medium text-slate-700">{app.team}</p>
                          </div>
                          <div>
                            <p className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">Last Activity</p>
                            <div className="flex items-center gap-1.5 text-sm text-slate-700">
                              <Clock className="h-3.5 w-3.5 text-slate-400" />
                              <span>{getLastUsedText(app.last_used_at)}</span>
                            </div>
                          </div>
                          <div>
                            <p className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">Expires</p>
                            <p className="text-sm text-slate-700">{new Date(app.expires_at).toLocaleDateString()}</p>
                          </div>
                        </div>

                        {/* Bottom Row: Contexts + Actions */}
                        <div className="flex items-center justify-between mt-4">
                          <div>
                            <p className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-2">Encryption Contexts</p>
                            <div className="flex gap-1.5 flex-wrap">
                              {app.allowed_contexts.map((ctx) => (
                                <span key={ctx} className="inline-flex items-center gap-1 px-2 py-1 bg-blue-50 border border-blue-100 rounded-md text-xs font-medium text-blue-700">
                                  <Shield className="h-3 w-3" />
                                  {ctx}
                                </span>
                              ))}
                            </div>
                          </div>
                          <div className="flex gap-2">
                            <Link href={`/applications/${app.id}/tokens`}>
                              <Button variant="outline" size="sm">
                                <Settings className="h-4 w-4 mr-1.5" />
                                Manage
                              </Button>
                            </Link>
                            <Button variant="outline" size="sm" onClick={() => handleDelete(app.id)} className="text-red-600 hover:text-red-700 hover:bg-red-50">
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Revoked Applications */}
            {revokedApps.length > 0 && (
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <div className="p-1.5 bg-red-100 rounded-lg">
                    <XCircle className="h-4 w-4 text-red-500" />
                  </div>
                  <h2 className="text-sm font-semibold text-slate-700">Revoked</h2>
                  <span className="text-xs font-medium text-red-700 bg-red-100 px-2 py-0.5 rounded-full">{revokedApps.length}</span>
                </div>
                <div className="grid gap-4">
                  {revokedApps.map((app) => (
                    <div key={app.id} className="bg-slate-50 rounded-xl border border-slate-200 opacity-70">
                      <div className="p-5">
                        {/* Top Row: Name + Status */}
                        <div className="flex items-start justify-between mb-4">
                          <div className="flex items-center gap-3">
                            {getStatusIcon(app)}
                            <div>
                              <h3 className="font-semibold text-slate-600">{app.name}</h3>
                              {app.description && (
                                <p className="text-sm text-slate-400 mt-0.5">{app.description}</p>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant="destructive">{app.status}</Badge>
                            {getEnvironmentBadge(app.environment)}
                          </div>
                        </div>

                        {/* Info Grid */}
                        <div className="grid grid-cols-2 gap-4 py-4 border-y border-slate-200">
                          <div>
                            <p className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">Team</p>
                            <p className="text-sm text-slate-500">{app.team}</p>
                          </div>
                          <div>
                            <p className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-1">Last Activity</p>
                            <div className="flex items-center gap-1.5 text-sm text-slate-500">
                              <Clock className="h-3.5 w-3.5 text-slate-400" />
                              <span>{getLastUsedText(app.last_used_at)}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
