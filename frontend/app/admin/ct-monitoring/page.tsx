"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Shield,
  Search,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Building2,
  Globe,
  FileKey,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  RefreshCw,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AdminLayout } from "@/components/admin-layout";
import { StatCard } from "@/components/ui/stat-card";
import { DataTable } from "@/components/ui/data-table";
import {
  api,
  CTCertificate,
  CTAlert,
  CTMonitoringSummary,
  CTScanResponse,
  CTIssuerStats,
} from "@/lib/api";
import { cn } from "@/lib/utils";

type ViewMode = "search" | "results" | "details";

export default function CTMonitoringPage() {
  // State
  const [viewMode, setViewMode] = useState<ViewMode>("search");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Search state
  const [domain, setDomain] = useState("");
  const [includeSubdomains, setIncludeSubdomains] = useState(true);
  const [recentDays, setRecentDays] = useState(7);

  // Results state
  const [scanResult, setScanResult] = useState<CTScanResponse | null>(null);
  const [issuers, setIssuers] = useState<CTIssuerStats[]>([]);

  // Filters
  const [showExpired, setShowExpired] = useState(false);
  const [showAlertsOnly, setShowAlertsOnly] = useState(false);
  const [selectedIssuer, setSelectedIssuer] = useState<string | null>(null);

  // Expanded sections
  const [expandedAlerts, setExpandedAlerts] = useState(true);
  const [expandedCerts, setExpandedCerts] = useState(true);

  const handleSearch = useCallback(async () => {
    if (!domain.trim()) {
      setError("Please enter a domain to search");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const [scanData, issuerData] = await Promise.all([
        api.scanCTDomain(domain.trim(), { includeSubdomains }),
        api.getCTIssuers(domain.trim(), includeSubdomains),
      ]);

      setScanResult(scanData);
      setIssuers(issuerData.issuers);
      setViewMode("results");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to scan domain");
    } finally {
      setLoading(false);
    }
  }, [domain, includeSubdomains]);

  const handleRefresh = useCallback(async () => {
    if (domain && viewMode === "results") {
      await handleSearch();
    }
  }, [domain, viewMode, handleSearch]);

  // Filter certificates
  const filteredCerts = scanResult?.certificates.filter((cert) => {
    if (!showExpired && cert.isExpired) return false;
    if (selectedIssuer && cert.issuerName !== selectedIssuer) return false;
    return true;
  }) || [];

  // Filter alerts
  const filteredAlerts = showAlertsOnly
    ? scanResult?.alerts.filter((a) => a.severity === "critical" || a.severity === "high")
    : scanResult?.alerts || [];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-rose-100 text-rose-700 border-rose-200";
      case "high":
        return "bg-amber-100 text-amber-700 border-amber-200";
      case "medium":
        return "bg-yellow-100 text-yellow-700 border-yellow-200";
      case "low":
        return "bg-slate-100 text-slate-600 border-slate-200";
      default:
        return "bg-blue-100 text-blue-600 border-blue-200";
    }
  };

  const getAlertTypeLabel = (type: string) => {
    const labels: Record<string, string> = {
      unexpected_issuer: "Unexpected Issuer",
      unexpected_domain: "Unexpected Domain",
      expired_cert: "Expired Certificate",
      expiring_soon: "Expiring Soon",
      new_cert_issued: "New Certificate",
      wildcard_issued: "Wildcard Certificate",
      revoked_cert: "Revoked Certificate",
      duplicate_serial: "Duplicate Serial",
      weak_algorithm: "Weak Algorithm",
    };
    return labels[type] || type;
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  };

  const certColumns = [
    {
      key: "commonName",
      header: "Common Name",
      sortable: true,
      render: (cert: CTCertificate) => (
        <div className="flex items-center gap-2">
          <FileKey className="h-4 w-4 text-slate-400" />
          <div>
            <div className="font-medium text-slate-900">{cert.commonName}</div>
            {cert.isWildcard && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-purple-100 text-purple-700">
                Wildcard
              </span>
            )}
          </div>
        </div>
      ),
    },
    {
      key: "issuerName",
      header: "Issuer",
      sortable: true,
      render: (cert: CTCertificate) => (
        <div className="flex items-center gap-2">
          <Building2 className="h-4 w-4 text-slate-400" />
          <span className="text-slate-700">{cert.issuerName}</span>
        </div>
      ),
    },
    {
      key: "notAfter",
      header: "Expires",
      sortable: true,
      render: (cert: CTCertificate) => (
        <div className="flex items-center gap-2">
          {cert.isExpired ? (
            <AlertTriangle className="h-4 w-4 text-rose-500" />
          ) : cert.daysUntilExpiry <= 30 ? (
            <Clock className="h-4 w-4 text-amber-500" />
          ) : (
            <CheckCircle2 className="h-4 w-4 text-emerald-500" />
          )}
          <div>
            <div className={cn(
              "font-medium",
              cert.isExpired ? "text-rose-600" : cert.daysUntilExpiry <= 30 ? "text-amber-600" : "text-slate-900"
            )}>
              {formatDate(cert.notAfter)}
            </div>
            <div className="text-xs text-slate-500">
              {cert.isExpired
                ? "Expired"
                : `${cert.daysUntilExpiry} days left`}
            </div>
          </div>
        </div>
      ),
    },
    {
      key: "domains",
      header: "SANs",
      render: (cert: CTCertificate) => (
        <div className="text-sm text-slate-600">
          {cert.domains.length} domain{cert.domains.length !== 1 ? "s" : ""}
        </div>
      ),
    },
    {
      key: "actions",
      header: "",
      render: (cert: CTCertificate) => (
        <a
          href={`https://crt.sh/?id=${cert.id}`}
          target="_blank"
          rel="noopener noreferrer"
          className="text-indigo-600 hover:text-indigo-800 flex items-center gap-1 text-sm"
        >
          crt.sh <ExternalLink className="h-3 w-3" />
        </a>
      ),
    },
  ];

  return (
    <AdminLayout
      title="CT Monitoring"
      subtitle="Monitor Certificate Transparency logs for your domains"
      onRefresh={viewMode === "results" ? handleRefresh : undefined}
      refreshInterval={0}
    >
      {/* Search Section */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5 text-indigo-600" />
            Domain Search
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1">
              <label className="block text-sm font-medium text-slate-700 mb-1">
                Domain
              </label>
              <div className="relative">
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                  placeholder="example.com"
                  className="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                />
              </div>
            </div>
            <div className="flex items-end gap-4">
              <label className="flex items-center gap-2 text-sm text-slate-700">
                <input
                  type="checkbox"
                  checked={includeSubdomains}
                  onChange={(e) => setIncludeSubdomains(e.target.checked)}
                  className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                />
                Include subdomains
              </label>
              <Button
                onClick={handleSearch}
                disabled={loading || !domain.trim()}
                className="flex items-center gap-2"
              >
                {loading ? (
                  <RefreshCw className="h-4 w-4 animate-spin" />
                ) : (
                  <Search className="h-4 w-4" />
                )}
                Search
              </Button>
            </div>
          </div>

          {error && (
            <div className="mt-4 p-3 bg-rose-50 border border-rose-200 rounded-lg text-rose-700 text-sm">
              {error}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Results Section */}
      {viewMode === "results" && scanResult && (
        <>
          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <StatCard
              title="Total Certificates"
              value={scanResult.summary.totalCerts}
              icon={<FileKey className="h-5 w-5" />}
              color="blue"
            />
            <StatCard
              title="Active"
              value={scanResult.summary.activeCerts}
              icon={<CheckCircle2 className="h-5 w-5" />}
              color="green"
            />
            <StatCard
              title="Expired"
              value={scanResult.summary.expiredCerts}
              icon={<AlertTriangle className="h-5 w-5" />}
              color={scanResult.summary.expiredCerts > 0 ? "amber" : "default"}
            />
            <StatCard
              title="Alerts"
              value={scanResult.summary.alertCount}
              subtitle={
                scanResult.summary.criticalAlerts > 0
                  ? `${scanResult.summary.criticalAlerts} critical`
                  : undefined
              }
              icon={<Shield className="h-5 w-5" />}
              color={scanResult.summary.criticalAlerts > 0 ? "rose" : scanResult.summary.highAlerts > 0 ? "amber" : "default"}
            />
          </div>

          {/* Issuers Breakdown */}
          {issuers.length > 0 && (
            <Card className="mb-6">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Building2 className="h-5 w-5 text-indigo-600" />
                  Certificate Authorities
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {issuers.map((issuer) => (
                    <button
                      key={issuer.name}
                      onClick={() =>
                        setSelectedIssuer(
                          selectedIssuer === issuer.name ? null : issuer.name
                        )
                      }
                      className={cn(
                        "flex items-center justify-between p-3 rounded-lg border transition-all text-left",
                        selectedIssuer === issuer.name
                          ? "border-indigo-500 bg-indigo-50"
                          : "border-slate-200 hover:border-slate-300 hover:bg-slate-50"
                      )}
                    >
                      <div>
                        <div className="font-medium text-slate-900 text-sm">
                          {issuer.name}
                        </div>
                        <div className="text-xs text-slate-500">
                          {issuer.activeCerts} active, {issuer.expiredCerts} expired
                        </div>
                      </div>
                      <div className="text-lg font-semibold text-slate-700">
                        {issuer.count}
                      </div>
                    </button>
                  ))}
                </div>
                {selectedIssuer && (
                  <div className="mt-3 flex justify-end">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setSelectedIssuer(null)}
                    >
                      Clear filter
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Alerts Section */}
          {scanResult.alerts.length > 0 && (
            <Card className="mb-6">
              <CardHeader
                className="cursor-pointer"
                onClick={() => setExpandedAlerts(!expandedAlerts)}
              >
                <CardTitle className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-amber-600" />
                    Alerts ({scanResult.alerts.length})
                  </div>
                  {expandedAlerts ? (
                    <ChevronUp className="h-5 w-5 text-slate-400" />
                  ) : (
                    <ChevronDown className="h-5 w-5 text-slate-400" />
                  )}
                </CardTitle>
              </CardHeader>
              {expandedAlerts && (
                <CardContent>
                  <div className="flex items-center gap-4 mb-4">
                    <label className="flex items-center gap-2 text-sm text-slate-700">
                      <input
                        type="checkbox"
                        checked={showAlertsOnly}
                        onChange={(e) => setShowAlertsOnly(e.target.checked)}
                        className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                      />
                      Show critical/high only
                    </label>
                  </div>
                  <div className="space-y-3">
                    {filteredAlerts?.map((alert, idx) => (
                      <div
                        key={idx}
                        className={cn(
                          "p-4 rounded-lg border",
                          getSeverityColor(alert.severity)
                        )}
                      >
                        <div className="flex items-start justify-between gap-4">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <span className="font-medium">
                                {getAlertTypeLabel(alert.alertType)}
                              </span>
                              <span
                                className={cn(
                                  "text-xs px-2 py-0.5 rounded-full uppercase font-medium",
                                  getSeverityColor(alert.severity)
                                )}
                              >
                                {alert.severity}
                              </span>
                            </div>
                            <p className="text-sm">{alert.message}</p>
                          </div>
                          <div className="text-xs text-slate-500 whitespace-nowrap">
                            {formatDate(alert.createdAt)}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              )}
            </Card>
          )}

          {/* Certificates Table */}
          <Card>
            <CardHeader
              className="cursor-pointer"
              onClick={() => setExpandedCerts(!expandedCerts)}
            >
              <CardTitle className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileKey className="h-5 w-5 text-indigo-600" />
                  Certificates ({filteredCerts.length})
                  {selectedIssuer && (
                    <span className="text-sm font-normal text-slate-500">
                      filtered by {selectedIssuer}
                    </span>
                  )}
                </div>
                {expandedCerts ? (
                  <ChevronUp className="h-5 w-5 text-slate-400" />
                ) : (
                  <ChevronDown className="h-5 w-5 text-slate-400" />
                )}
              </CardTitle>
            </CardHeader>
            {expandedCerts && (
              <CardContent>
                <div className="flex items-center gap-4 mb-4">
                  <label className="flex items-center gap-2 text-sm text-slate-700">
                    <input
                      type="checkbox"
                      checked={showExpired}
                      onChange={(e) => setShowExpired(e.target.checked)}
                      className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                    />
                    Show expired certificates
                  </label>
                </div>
                <DataTable
                  data={filteredCerts}
                  columns={certColumns}
                  keyField="id"
                  loading={loading}
                  emptyMessage="No certificates found"
                />
              </CardContent>
            )}
          </Card>
        </>
      )}

      {/* Empty State */}
      {viewMode === "search" && (
        <Card>
          <CardContent className="py-12">
            <div className="text-center">
              <Globe className="h-12 w-12 text-slate-300 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-slate-900 mb-2">
                Search Certificate Transparency Logs
              </h3>
              <p className="text-slate-500 max-w-md mx-auto mb-6">
                Enter a domain above to search public CT logs for all certificates
                ever issued for that domain. This helps detect unauthorized
                certificate issuance.
              </p>
              <div className="flex flex-wrap justify-center gap-2">
                <span className="text-xs px-2 py-1 rounded bg-slate-100 text-slate-600">
                  Detect rogue certificates
                </span>
                <span className="text-xs px-2 py-1 rounded bg-slate-100 text-slate-600">
                  Monitor CA relationships
                </span>
                <span className="text-xs px-2 py-1 rounded bg-slate-100 text-slate-600">
                  Track certificate expiration
                </span>
                <span className="text-xs px-2 py-1 rounded bg-slate-100 text-slate-600">
                  Identify unauthorized issuers
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </AdminLayout>
  );
}
