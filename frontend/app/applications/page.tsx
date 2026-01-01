"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Plus, Settings, Key, Clock, Trash2, CheckCircle, AlertTriangle, XCircle, Server, Rocket, Code, ArrowUpCircle } from "lucide-react";
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

  return (
    <DashboardLayout>
      <div className="space-y-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">My Applications</h1>
            <p className="text-slate-600">
              Manage your SDK applications and tokens
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
        ) : applications.length === 0 ? (
          <Card>
            <CardContent className="py-12 text-center">
              <Key className="h-12 w-12 mx-auto text-slate-400 mb-4" />
              <h3 className="text-lg font-medium mb-2">No applications yet</h3>
              <p className="text-slate-600 mb-6">
                Create your first application to get started with the SDK
              </p>
              <Link href="/applications/new">
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  Create Application
                </Button>
              </Link>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-6">
            {/* Production Applications */}
            {productionApps.length > 0 && (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <Server className="h-4 w-4 text-green-600" />
                  <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wider">Production</h2>
                  <Badge className="bg-green-100 text-green-800">{productionApps.length}</Badge>
                </div>
                <div className="grid gap-3">
                  {productionApps.map((app) => (
                    <Card key={app.id} className="border-green-200 bg-green-50/30">
                      <CardContent className="py-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-start gap-4">
                            <div className="mt-1">{getStatusIcon(app)}</div>
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <h3 className="font-semibold">{app.name}</h3>
                                {getEnvironmentBadge(app.environment)}
                              </div>
                              <p className="text-sm text-slate-500">
                                {app.team} {app.description && `- ${app.description}`}
                              </p>
                              <div className="flex gap-1 flex-wrap mt-2">
                                {app.allowed_contexts.map((ctx) => (
                                  <Badge key={ctx} variant="secondary" className="text-xs">{ctx}</Badge>
                                ))}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-4">
                            <div className="text-right text-sm text-slate-500">
                              <div className="flex items-center gap-1 justify-end">
                                <Clock className="h-3 w-3" />
                                <span>{getLastUsedText(app.last_used_at)}</span>
                              </div>
                              <p className="text-xs mt-1">Expires: {new Date(app.expires_at).toLocaleDateString()}</p>
                            </div>
                            <div className="flex gap-2">
                              <Link href={`/applications/${app.id}/tokens`}>
                                <Button variant="outline" size="sm"><Settings className="h-4 w-4" /></Button>
                              </Link>
                              <Button variant="outline" size="sm" onClick={() => handleDelete(app.id)}>
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </div>
            )}

            {/* Staging Applications */}
            {stagingApps.length > 0 && (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <Rocket className="h-4 w-4 text-blue-600" />
                  <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wider">Staging</h2>
                  <Badge className="bg-blue-100 text-blue-800">{stagingApps.length}</Badge>
                </div>
                <div className="grid gap-3">
                  {stagingApps.map((app) => (
                    <Card key={app.id} className="border-blue-200 bg-blue-50/30">
                      <CardContent className="py-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-start gap-4">
                            <div className="mt-1">{getStatusIcon(app)}</div>
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <h3 className="font-semibold">{app.name}</h3>
                                {getEnvironmentBadge(app.environment)}
                              </div>
                              <p className="text-sm text-slate-500">
                                {app.team} {app.description && `- ${app.description}`}
                              </p>
                              <div className="flex gap-1 flex-wrap mt-2">
                                {app.allowed_contexts.map((ctx) => (
                                  <Badge key={ctx} variant="secondary" className="text-xs">{ctx}</Badge>
                                ))}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-4">
                            <div className="text-right text-sm text-slate-500">
                              <div className="flex items-center gap-1 justify-end">
                                <Clock className="h-3 w-3" />
                                <span>{getLastUsedText(app.last_used_at)}</span>
                              </div>
                              <p className="text-xs mt-1">Expires: {new Date(app.expires_at).toLocaleDateString()}</p>
                            </div>
                            <div className="flex gap-2">
                              <Link href={`/applications/${app.id}/tokens`}>
                                <Button variant="outline" size="sm"><Settings className="h-4 w-4" /></Button>
                              </Link>
                              <Button variant="outline" size="sm" onClick={() => handleDelete(app.id)}>
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </div>
            )}

            {/* Development Applications */}
            {devApps.length > 0 && (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <Code className="h-4 w-4 text-gray-600" />
                  <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wider">Development</h2>
                  <Badge className="bg-gray-100 text-gray-800">{devApps.length}</Badge>
                </div>
                <div className="grid gap-3">
                  {devApps.map((app) => (
                    <Card key={app.id}>
                      <CardContent className="py-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-start gap-4">
                            <div className="mt-1">{getStatusIcon(app)}</div>
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <h3 className="font-semibold">{app.name}</h3>
                                {getEnvironmentBadge(app.environment)}
                                <Badge variant="outline" className="text-xs bg-purple-50 text-purple-700 border-purple-200">
                                  <ArrowUpCircle className="h-3 w-3 mr-1" />
                                  Ready to promote
                                </Badge>
                              </div>
                              <p className="text-sm text-slate-500">
                                {app.team} {app.description && `- ${app.description}`}
                              </p>
                              <div className="flex gap-1 flex-wrap mt-2">
                                {app.allowed_contexts.map((ctx) => (
                                  <Badge key={ctx} variant="secondary" className="text-xs">{ctx}</Badge>
                                ))}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-4">
                            <div className="text-right text-sm text-slate-500">
                              <div className="flex items-center gap-1 justify-end">
                                <Clock className="h-3 w-3" />
                                <span>{getLastUsedText(app.last_used_at)}</span>
                              </div>
                              <p className="text-xs mt-1">Expires: {new Date(app.expires_at).toLocaleDateString()}</p>
                            </div>
                            <div className="flex gap-2">
                              <Link href={`/applications/${app.id}/tokens`}>
                                <Button variant="outline" size="sm"><Settings className="h-4 w-4" /></Button>
                              </Link>
                              <Button variant="outline" size="sm" onClick={() => handleDelete(app.id)}>
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </div>
            )}

            {/* Revoked Applications */}
            {revokedApps.length > 0 && (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <XCircle className="h-4 w-4 text-red-500" />
                  <h2 className="text-sm font-semibold text-slate-700 uppercase tracking-wider">Revoked</h2>
                  <Badge className="bg-red-100 text-red-800">{revokedApps.length}</Badge>
                </div>
                <div className="grid gap-3">
                  {revokedApps.map((app) => (
                    <Card key={app.id} className="opacity-60">
                      <CardContent className="py-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-start gap-4">
                            <div className="mt-1">{getStatusIcon(app)}</div>
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <h3 className="font-semibold">{app.name}</h3>
                                <Badge variant="destructive">{app.status}</Badge>
                                {getEnvironmentBadge(app.environment)}
                              </div>
                              <p className="text-sm text-slate-500">
                                {app.team} {app.description && `- ${app.description}`}
                              </p>
                              <div className="flex gap-1 flex-wrap mt-2">
                                {app.allowed_contexts.map((ctx) => (
                                  <Badge key={ctx} variant="secondary" className="text-xs">{ctx}</Badge>
                                ))}
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
                      </CardContent>
                    </Card>
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
