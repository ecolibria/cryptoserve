"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import {
  Download,
  CheckCircle2,
  XCircle,
  Clock,
  Filter,
  ChevronDown,
  Lock,
  Unlock,
  FileSignature,
  ShieldCheck,
  Activity,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AdminLayout } from "@/components/admin-layout";
import { SearchInput } from "@/components/ui/search-input";
import { DateRangePicker } from "@/components/ui/date-range-picker";
import { DataTable } from "@/components/ui/data-table";
import { StatCard } from "@/components/ui/stat-card";
import { api, AuditLog } from "@/lib/api";
import { cn } from "@/lib/utils";

type SuccessFilter = "all" | "success" | "failed";
type OperationFilter = "all" | "encrypt" | "decrypt" | "sign" | "verify";

const operationConfig: Record<string, { icon: typeof Lock; label: string; color: string; bgColor: string }> = {
  encrypt: { icon: Lock, label: "Encrypt", color: "text-blue-600", bgColor: "bg-blue-100" },
  decrypt: { icon: Unlock, label: "Decrypt", color: "text-green-600", bgColor: "bg-green-100" },
  sign: { icon: FileSignature, label: "Sign", color: "text-purple-600", bgColor: "bg-purple-100" },
  verify: { icon: ShieldCheck, label: "Verify", color: "text-emerald-600", bgColor: "bg-emerald-100" },
};

export default function AdminAuditPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [successFilter, setSuccessFilter] = useState<SuccessFilter>("all");
  const [operationFilter, setOperationFilter] = useState<OperationFilter>("all");
  const [contextFilter, setContextFilter] = useState("");
  const [page, setPage] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [showFilters, setShowFilters] = useState(false);
  const pageSize = 50;

  // Summary stats
  const [totalOps, setTotalOps] = useState(0);
  const [successOps, setSuccessOps] = useState(0);
  const [failedOps, setFailedOps] = useState(0);

  // Filter logs by operation type client-side
  const filteredLogs = useMemo(() => {
    if (operationFilter === "all") return logs;
    return logs.filter(log => log.operation === operationFilter);
  }, [logs, operationFilter]);

  // Operation breakdown stats
  const operationStats = useMemo(() => {
    const stats = { encrypt: 0, decrypt: 0, sign: 0, verify: 0 };
    logs.forEach(log => {
      if (log.operation in stats) {
        stats[log.operation as keyof typeof stats]++;
      }
    });
    return stats;
  }, [logs]);

  const loadLogs = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.getGlobalAuditLogs({
        identity_id: search || undefined,
        context: contextFilter || undefined,
        success: successFilter === "all" ? undefined : successFilter === "success",
        start_date: startDate || undefined,
        end_date: endDate || undefined,
        limit: pageSize,
        offset: page * pageSize,
      });
      setLogs(data);
      setHasMore(data.length === pageSize);

      // Calculate summary stats from the page data (simplified)
      const total = data.length;
      const success = data.filter(l => l.success).length;
      setTotalOps(total);
      setSuccessOps(success);
      setFailedOps(total - success);
    } catch (error) {
      console.error("Failed to load audit logs:", error);
    } finally {
      setLoading(false);
    }
  }, [search, contextFilter, successFilter, startDate, endDate, page]);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  const handleSearchChange = (value: string) => {
    setSearch(value);
    setPage(0);
  };

  const handleDateChange = (start: string, end: string) => {
    setStartDate(start);
    setEndDate(end);
    setPage(0);
  };

  const handleExport = (format: "csv" | "json") => {
    const url = api.exportAuditLogs(format, {
      start_date: startDate || undefined,
      end_date: endDate || undefined,
    });
    window.open(url, "_blank");
  };

  const formatTimestamp = (ts: string) => {
    const date = new Date(ts);
    return (
      <div>
        <p className="text-sm">{date.toLocaleDateString()}</p>
        <p className="text-xs text-slate-500">{date.toLocaleTimeString()}</p>
      </div>
    );
  };

  const formatSize = (bytes: number | null) => {
    if (bytes === null || bytes === undefined) return "-";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const columns = [
    {
      key: "timestamp",
      header: "Time",
      sortable: true,
      className: "w-32",
      render: (log: AuditLog) => formatTimestamp(log.timestamp),
    },
    {
      key: "operation",
      header: "Operation",
      sortable: true,
      render: (log: AuditLog) => {
        const config = operationConfig[log.operation] || operationConfig.encrypt;
        const Icon = config.icon;
        return (
          <span className={cn(
            "inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium",
            config.bgColor,
            config.color
          )}>
            <Icon className="h-3 w-3" />
            {config.label}
          </span>
        );
      },
    },
    {
      key: "context",
      header: "Context",
      sortable: true,
      render: (log: AuditLog) => (
        <span className="px-2 py-1 rounded text-xs bg-slate-100 text-slate-700">
          {log.context}
        </span>
      ),
    },
    {
      key: "identity_name",
      header: "Identity",
      sortable: true,
      render: (log: AuditLog) => (
        <div>
          <p className="font-medium text-sm">{log.identity_name || "Unknown"}</p>
          {log.team && (
            <p className="text-xs text-slate-500">{log.team}</p>
          )}
        </div>
      ),
    },
    {
      key: "success",
      header: "Status",
      sortable: true,
      render: (log: AuditLog) => (
        log.success ? (
          <span className="inline-flex items-center gap-1 text-green-600">
            <CheckCircle2 className="h-4 w-4" />
            <span className="text-xs">Success</span>
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 text-red-600">
            <XCircle className="h-4 w-4" />
            <span className="text-xs">Failed</span>
          </span>
        )
      ),
    },
    {
      key: "latency_ms",
      header: "Latency",
      sortable: true,
      className: "text-right",
      render: (log: AuditLog) => (
        <span className={cn(
          "text-sm tabular-nums",
          log.latency_ms && log.latency_ms > 100 ? "text-amber-600" : "text-slate-600"
        )}>
          {log.latency_ms ? `${log.latency_ms}ms` : "-"}
        </span>
      ),
    },
    {
      key: "input_size_bytes",
      header: "Input",
      className: "text-right",
      render: (log: AuditLog) => (
        <span className="text-xs text-slate-500 tabular-nums">
          {formatSize(log.input_size_bytes)}
        </span>
      ),
    },
    {
      key: "output_size_bytes",
      header: "Output",
      className: "text-right",
      render: (log: AuditLog) => (
        <span className="text-xs text-slate-500 tabular-nums">
          {formatSize(log.output_size_bytes)}
        </span>
      ),
    },
  ];

  // Expandable row for error details
  const expandedColumns = [
    ...columns,
    {
      key: "error_message",
      header: "",
      render: (log: AuditLog) => (
        log.error_message ? (
          <div className="text-xs text-red-600 max-w-xs truncate" title={log.error_message}>
            {log.error_message}
          </div>
        ) : null
      ),
    },
  ];

  return (
    <AdminLayout
      title="Audit & Compliance"
      subtitle="Global audit trail for all cryptographic operations"
      onRefresh={loadLogs}
      actions={
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => handleExport("csv")}
          >
            <Download className="h-4 w-4 mr-1" />
            CSV
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => handleExport("json")}
          >
            <Download className="h-4 w-4 mr-1" />
            JSON
          </Button>
        </div>
      }
    >
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatCard
          title="Total Operations"
          value={totalOps}
          subtitle={startDate ? `Since ${startDate}` : "All time"}
          icon={<Activity className="h-5 w-5 text-blue-500" />}
        />
        <StatCard
          title="Successful"
          value={successOps}
          subtitle={`${totalOps > 0 ? Math.round((successOps / totalOps) * 100) : 0}% success rate`}
          icon={<CheckCircle2 className="h-5 w-5 text-green-500" />}
          color="green"
        />
        <StatCard
          title="Failed"
          value={failedOps}
          subtitle={failedOps > 0 ? "Requires attention" : "All operations successful"}
          icon={<XCircle className="h-5 w-5 text-red-500" />}
          color={failedOps > 0 ? "rose" : "default"}
        />
        <StatCard
          title="Unique Contexts"
          value={new Set(logs.map(l => l.context)).size}
          subtitle="In current view"
          icon={<Filter className="h-5 w-5 text-slate-500" />}
        />
      </div>

      {/* Operation Breakdown Quick Stats */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        {(Object.entries(operationConfig) as [string, typeof operationConfig.encrypt][]).map(([key, config]) => {
          const Icon = config.icon;
          const count = operationStats[key as keyof typeof operationStats] || 0;
          const isActive = operationFilter === key;
          return (
            <button
              key={key}
              onClick={() => setOperationFilter(isActive ? "all" : key as OperationFilter)}
              className={cn(
                "flex items-center gap-2 p-3 rounded-lg border transition-all",
                isActive
                  ? "border-slate-900 bg-slate-900 text-white shadow-sm"
                  : "border-slate-200 bg-white hover:border-slate-300 hover:shadow-sm"
              )}
            >
              <div className={cn(
                "h-8 w-8 rounded-lg flex items-center justify-center",
                isActive ? "bg-white/20" : config.bgColor
              )}>
                <Icon className={cn("h-4 w-4", isActive ? "text-white" : config.color)} />
              </div>
              <div className="text-left">
                <p className={cn("text-lg font-semibold tabular-nums", isActive ? "text-white" : "text-slate-900")}>
                  {count}
                </p>
                <p className={cn("text-xs", isActive ? "text-white/70" : "text-slate-500")}>
                  {config.label}
                </p>
              </div>
            </button>
          );
        })}
      </div>

      {/* Filters */}
      <div className="mb-6 space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
          <SearchInput
            placeholder="Search by identity ID..."
            value={search}
            onChange={handleSearchChange}
            className="w-full sm:max-w-md"
          />
          <DateRangePicker
            startDate={startDate}
            endDate={endDate}
            onChange={handleDateChange}
          />
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="flex items-center gap-1 px-3 py-2 text-sm text-slate-600 hover:text-slate-900 transition-colors"
          >
            <Filter className="h-4 w-4" />
            More Filters
            <ChevronDown className={cn("h-4 w-4 transition-transform", showFilters && "rotate-180")} />
          </button>
        </div>

        {showFilters && (
          <div className="flex flex-wrap gap-4 p-4 bg-slate-50 rounded-lg">
            <div>
              <label className="text-xs font-medium text-slate-600 mb-1 block">Status</label>
              <div className="flex gap-2">
                {(["all", "success", "failed"] as SuccessFilter[]).map((filter) => (
                  <button
                    key={filter}
                    onClick={() => {
                      setSuccessFilter(filter);
                      setPage(0);
                    }}
                    className={cn(
                      "px-3 py-1.5 rounded text-xs font-medium transition-colors",
                      successFilter === filter
                        ? "bg-slate-900 text-white"
                        : "bg-white border text-slate-600 hover:bg-slate-100"
                    )}
                  >
                    {filter.charAt(0).toUpperCase() + filter.slice(1)}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="text-xs font-medium text-slate-600 mb-1 block">Context</label>
              <input
                type="text"
                value={contextFilter}
                onChange={(e) => {
                  setContextFilter(e.target.value);
                  setPage(0);
                }}
                placeholder="Filter by context..."
                className="px-3 py-1.5 border rounded text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>
          </div>
        )}
      </div>

      {/* Audit Logs Table */}
      <Card>
        <CardHeader className="py-3 px-4 border-b border-slate-100">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-medium text-slate-700">
              {operationFilter !== "all" && (
                <span className="mr-2">
                  Filtered by: <span className="font-semibold">{operationConfig[operationFilter]?.label}</span>
                </span>
              )}
              {filteredLogs.length} {filteredLogs.length === 1 ? "entry" : "entries"}
            </CardTitle>
            {operationFilter !== "all" && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setOperationFilter("all")}
                className="text-xs h-7"
              >
                Clear filter
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <DataTable
            data={filteredLogs}
            columns={expandedColumns}
            keyField="id"
            loading={loading}
            emptyMessage={operationFilter !== "all" ? `No ${operationFilter} operations found` : "No audit logs found"}
          />
        </CardContent>
      </Card>

      {/* Pagination */}
      {(page > 0 || hasMore) && (
        <div className="mt-4 flex items-center justify-between">
          <p className="text-sm text-slate-500">
            Showing {page * pageSize + 1} - {page * pageSize + filteredLogs.length} logs
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(p => p - 1)}
              disabled={page === 0}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(p => p + 1)}
              disabled={!hasMore}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </AdminLayout>
  );
}
