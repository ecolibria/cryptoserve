"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { AdminLayout } from "@/components/admin-layout";
import { Button } from "@/components/ui/button";
import { api, Application } from "@/lib/api";
import { cn } from "@/lib/utils";
import Link from "next/link";
import {
  Key,
  Clock,
  AlertCircle,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Download,
  ChevronRight,
  Search,
  LayoutGrid,
  List,
  Calendar,
  Activity,
} from "lucide-react";

type ViewMode = "grid" | "list";
type FilterStatus = "all" | "active" | "expired" | "revoked" | "attention";

export default function ApplicationsPage() {
  const [applications, setApplications] = useState<Application[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [viewMode, setViewMode] = useState<ViewMode>("grid");
  const [filterStatus, setFilterStatus] = useState<FilterStatus>("all");

  const fetchApplications = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.listApplications();
      setApplications(data);
      setError(null);
    } catch (err) {
      setError("Failed to load applications");
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchApplications();
  }, [fetchApplications]);

  // Identify apps needing attention
  const needsAttention = useMemo(() => {
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

  // Filter applications
  const filteredApps = useMemo(() => {
    let filtered = applications;

    if (filterStatus === "active") {
      filtered = filtered.filter((a) => a.status === "active");
    } else if (filterStatus === "expired") {
      filtered = filtered.filter((a) => a.status === "expired");
    } else if (filterStatus === "revoked") {
      filtered = filtered.filter((a) => a.status === "revoked");
    } else if (filterStatus === "attention") {
      filtered = needsAttention;
    }

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (a) =>
          a.name.toLowerCase().includes(q) ||
          a.team.toLowerCase().includes(q) ||
          a.id.toLowerCase().includes(q)
      );
    }

    return filtered;
  }, [applications, filterStatus, searchQuery, needsAttention]);

  const getRelativeTime = (dateString: string | null | undefined) => {
    if (!dateString) return "Never";
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return "Today";
    if (diffDays === 1) return "Yesterday";
    if (diffDays < 7) return `${diffDays}d ago`;
    if (diffDays < 30) return `${Math.floor(diffDays / 7)}w ago`;
    return `${Math.floor(diffDays / 30)}mo ago`;
  };

  const getExpiresIn = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = date.getTime() - now.getTime();
    const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

    if (diffDays < 0) return { text: "Expired", urgent: true };
    if (diffDays === 0) return { text: "Today", urgent: true };
    if (diffDays === 1) return { text: "Tomorrow", urgent: true };
    if (diffDays < 7) return { text: `${diffDays} days`, urgent: true };
    if (diffDays < 30) return { text: `${Math.floor(diffDays / 7)} weeks`, urgent: false };
    return { text: `${Math.floor(diffDays / 30)} months`, urgent: false };
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "active":
        return { label: "Active", class: "bg-green-50 text-green-600 border border-green-200" };
      case "expired":
        return { label: "Expired", class: "bg-amber-50 text-amber-600 border border-amber-200" };
      case "revoked":
        return { label: "Revoked", class: "bg-rose-50 text-rose-600 border border-rose-200" };
      default:
        return { label: status, class: "bg-slate-50 text-slate-600 border border-slate-200" };
    }
  };

  const getEnvBadge = (env: string) => {
    switch (env.toLowerCase()) {
      case "production":
        return "bg-rose-50 text-rose-600 border-rose-200";
      case "staging":
        return "bg-amber-50 text-amber-600 border-amber-200";
      case "development":
        return "bg-green-50 text-green-600 border-green-200";
      default:
        return "bg-blue-50 text-blue-600 border-blue-200";
    }
  };

  // Stats
  const stats = {
    total: applications.length,
    active: applications.filter((a) => a.status === "active").length,
    expired: applications.filter((a) => a.status === "expired").length,
    revoked: applications.filter((a) => a.status === "revoked").length,
  };

  if (loading) {
    return (
      <AdminLayout title="Applications" subtitle="Loading...">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      </AdminLayout>
    );
  }

  return (
    <AdminLayout
      title="Applications"
      subtitle="Manage registered applications and SDK credentials"
      onRefresh={fetchApplications}
      actions={
        <Button variant="outline" size="sm">
          <Download className="h-4 w-4 mr-2" />
          Export
        </Button>
      }
    >
      {error && (
        <div className="mb-6 bg-rose-50 border border-rose-200 rounded-lg p-4 flex items-center gap-3">
          <AlertCircle className="h-5 w-5 text-rose-500" />
          <p className="text-rose-700">{error}</p>
        </div>
      )}

      {/* Filter Tabs */}
      <div className="flex flex-wrap items-center gap-2 mb-6">
        <button
          onClick={() => setFilterStatus("all")}
          className={cn(
            "px-4 py-2 rounded-lg text-sm font-medium transition-colors",
            filterStatus === "all"
              ? "bg-slate-100 text-slate-900"
              : "bg-white border border-slate-200 text-slate-500 hover:bg-slate-50"
          )}
        >
          All ({stats.total})
        </button>
        <button
          onClick={() => setFilterStatus("active")}
          className={cn(
            "px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2",
            filterStatus === "active"
              ? "bg-green-50 text-green-700 border border-green-200"
              : "bg-white border border-slate-200 text-slate-500 hover:bg-slate-50"
          )}
        >
          <CheckCircle2 className="h-4 w-4" />
          Active ({stats.active})
        </button>
        <button
          onClick={() => setFilterStatus("expired")}
          className={cn(
            "px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2",
            filterStatus === "expired"
              ? "bg-amber-50 text-amber-700 border border-amber-200"
              : "bg-white border border-slate-200 text-slate-500 hover:bg-slate-50"
          )}
        >
          <Clock className="h-4 w-4" />
          Expired ({stats.expired})
        </button>
        <button
          onClick={() => setFilterStatus("revoked")}
          className={cn(
            "px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2",
            filterStatus === "revoked"
              ? "bg-rose-50 text-rose-700 border border-rose-200"
              : "bg-white border border-slate-200 text-slate-500 hover:bg-slate-50"
          )}
        >
          <XCircle className="h-4 w-4" />
          Revoked ({stats.revoked})
        </button>
        {needsAttention.length > 0 && (
          <button
            onClick={() => setFilterStatus("attention")}
            className={cn(
              "px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2",
              filterStatus === "attention"
                ? "bg-orange-50 text-orange-700 border border-orange-200"
                : "bg-white border border-slate-200 text-slate-500 hover:bg-slate-50"
            )}
          >
            <AlertTriangle className="h-4 w-4" />
            Needs Attention ({needsAttention.length})
          </button>
        )}

        <div className="flex-1" />

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 pr-4 py-2 text-sm border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300 w-48"
          />
        </div>

        {/* View Toggle */}
        <div className="flex items-center border border-slate-200 rounded-lg overflow-hidden">
          <button
            onClick={() => setViewMode("grid")}
            className={cn(
              "p-2 transition-colors",
              viewMode === "grid" ? "bg-slate-100 text-slate-700" : "bg-white text-slate-400 hover:bg-slate-50"
            )}
          >
            <LayoutGrid className="h-4 w-4" />
          </button>
          <button
            onClick={() => setViewMode("list")}
            className={cn(
              "p-2 transition-colors",
              viewMode === "list" ? "bg-slate-100 text-slate-700" : "bg-white text-slate-400 hover:bg-slate-50"
            )}
          >
            <List className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Content */}
      {filteredApps.length > 0 ? (
        viewMode === "grid" ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {filteredApps.map((app) => {
              const statusBadge = getStatusBadge(app.status);
              const expires = getExpiresIn(app.expires_at);
              const isAttention = needsAttention.includes(app);

              return (
                <Link
                  key={app.id}
                  href={`/applications/${app.id}/tokens`}
                  className={cn(
                    "block bg-white border border-slate-200 rounded-xl p-4 hover:shadow-md hover:border-slate-300 transition-all group",
                    isAttention && "border-orange-200 bg-orange-50/30"
                  )}
                >
                  {/* Header */}
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className={cn(
                        "h-10 w-10 rounded-lg flex items-center justify-center",
                        app.status === "active" ? "bg-green-50" :
                        app.status === "expired" ? "bg-amber-50" : "bg-rose-50"
                      )}>
                        <Key className={cn(
                          "h-5 w-5",
                          app.status === "active" ? "text-green-500" :
                          app.status === "expired" ? "text-amber-500" : "text-rose-500"
                        )} />
                      </div>
                      <div>
                        <h3 className="font-medium text-slate-800 group-hover:text-blue-600 transition-colors line-clamp-1">
                          {app.name}
                        </h3>
                        <p className="text-xs text-slate-400">{app.team}</p>
                      </div>
                    </div>
                    <ChevronRight className="h-4 w-4 text-slate-300 group-hover:text-blue-400 transition-colors" />
                  </div>

                  {/* Badges */}
                  <div className="flex flex-wrap gap-1.5 mb-3">
                    <span className={cn("px-2 py-0.5 rounded text-xs font-medium", statusBadge.class)}>
                      {statusBadge.label}
                    </span>
                    <span className={cn("px-2 py-0.5 rounded text-xs font-medium border capitalize", getEnvBadge(app.environment))}>
                      {app.environment}
                    </span>
                  </div>

                  {/* Info */}
                  <div className="space-y-1.5 text-sm">
                    <div className="flex items-center justify-between text-slate-500">
                      <span className="flex items-center gap-1.5">
                        <Activity className="h-3.5 w-3.5" />
                        Last used
                      </span>
                      <span className="text-slate-600">{getRelativeTime(app.last_used_at)}</span>
                    </div>
                    <div className="flex items-center justify-between text-slate-500">
                      <span className="flex items-center gap-1.5">
                        <Calendar className="h-3.5 w-3.5" />
                        Expires
                      </span>
                      <span className={cn("text-slate-600", expires.urgent && "text-orange-500")}>
                        {expires.text}
                      </span>
                    </div>
                  </div>

                  {/* Contexts */}
                  <div className="mt-3 pt-3 border-t border-slate-100">
                    <div className="text-xs text-slate-400">
                      {app.allowed_contexts.length} context{app.allowed_contexts.length !== 1 ? "s" : ""}
                    </div>
                  </div>
                </Link>
              );
            })}
          </div>
        ) : (
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="bg-slate-50 text-left text-sm font-medium text-slate-500 border-b border-slate-200">
                  <th className="px-4 py-3">Application</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Environment</th>
                  <th className="px-4 py-3">Team</th>
                  <th className="px-4 py-3">Last Used</th>
                  <th className="px-4 py-3">Expires</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredApps.map((app) => {
                  const statusBadge = getStatusBadge(app.status);
                  const expires = getExpiresIn(app.expires_at);

                  return (
                    <tr key={app.id} className="hover:bg-slate-50/50 transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-3">
                          <div className={cn(
                            "h-8 w-8 rounded-lg flex items-center justify-center shrink-0",
                            app.status === "active" ? "bg-green-50" :
                            app.status === "expired" ? "bg-amber-50" : "bg-rose-50"
                          )}>
                            <Key className={cn(
                              "h-4 w-4",
                              app.status === "active" ? "text-green-500" :
                              app.status === "expired" ? "text-amber-500" : "text-rose-500"
                            )} />
                          </div>
                          <div>
                            <div className="font-medium text-slate-800">{app.name}</div>
                            <div className="text-xs text-slate-400 font-mono">{app.id.slice(0, 12)}...</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={cn("px-2 py-0.5 rounded text-xs font-medium", statusBadge.class)}>
                          {statusBadge.label}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={cn("px-2 py-0.5 rounded text-xs font-medium border capitalize", getEnvBadge(app.environment))}>
                          {app.environment}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-500">{app.team}</td>
                      <td className="px-4 py-3 text-sm text-slate-500">{getRelativeTime(app.last_used_at)}</td>
                      <td className="px-4 py-3">
                        <span className={cn("text-sm", expires.urgent ? "text-orange-500" : "text-slate-500")}>
                          {expires.text}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <Link
                          href={`/applications/${app.id}/tokens`}
                          className="text-blue-500 hover:text-blue-600 text-sm font-medium flex items-center gap-1"
                        >
                          View <ChevronRight className="h-3 w-3" />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )
      ) : (
        <div className="text-center py-16 bg-slate-50/50 rounded-xl border border-dashed border-slate-200">
          <Key className="h-12 w-12 text-slate-300 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-700 mb-2">
            {applications.length === 0 ? "No applications registered" : "No matching applications"}
          </h3>
          <p className="text-slate-400 max-w-md mx-auto mb-6">
            {applications.length === 0
              ? "Get started by registering your first application using the CLI."
              : "Try adjusting your filters or search query."}
          </p>
          {applications.length === 0 && (
            <div className="bg-slate-100 rounded-lg p-4 max-w-sm mx-auto text-left font-mono text-sm text-slate-600">
              <div className="text-slate-400 text-xs mb-2"># Install and register</div>
              <div>pip install cryptoserve</div>
              <div>cryptoserve register my-app</div>
            </div>
          )}
        </div>
      )}
    </AdminLayout>
  );
}
