"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, RefreshCw, AlertTriangle, CheckCircle, Clock, Key, Shield, XCircle, Pencil, Save, X, Plus, Trash2 } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { api, Application, TokenInfo } from "@/lib/api";

export default function TokenManagementPage() {
  const params = useParams();
  const appId = params.id as string;

  const [application, setApplication] = useState<Application | null>(null);
  const [tokenInfo, setTokenInfo] = useState<TokenInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [rotating, setRotating] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rotateResult, setRotateResult] = useState<{ token: string; expires: string } | null>(null);

  // Edit mode state
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editContexts, setEditContexts] = useState<string[]>([]);
  const [newContext, setNewContext] = useState("");

  useEffect(() => {
    loadData();
  }, [appId]);

  const loadData = async () => {
    try {
      const [app, info] = await Promise.all([
        api.getApplication(appId),
        api.getTokenInfo(appId),
      ]);
      setApplication(app);
      setTokenInfo(info);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load application");
    } finally {
      setLoading(false);
    }
  };

  const handleRotate = async () => {
    if (!confirm("Are you sure you want to rotate the refresh token? You will need to update the CRYPTOSERVE_REFRESH_TOKEN environment variable in your application.")) {
      return;
    }

    setRotating(true);
    setError(null);

    try {
      const result = await api.rotateTokens(appId);
      setRotateResult({ token: result.refresh_token, expires: result.expires_at });
      await loadData(); // Refresh the token info
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to rotate tokens");
    } finally {
      setRotating(false);
    }
  };

  const handleRevoke = async () => {
    if (!confirm("Are you sure you want to revoke ALL tokens? This will immediately invalidate all access and refresh tokens. The application will not be able to make any API calls until new tokens are issued.")) {
      return;
    }

    setRevoking(true);
    setError(null);

    try {
      await api.revokeTokens(appId);
      await loadData();
      alert("All tokens have been revoked. The application status has been updated.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke tokens");
    } finally {
      setRevoking(false);
    }
  };

  const startEditing = () => {
    if (application) {
      setEditName(application.name);
      setEditDescription(application.description || "");
      setEditContexts([...application.allowed_contexts]);
      setEditing(true);
    }
  };

  const cancelEditing = () => {
    setEditing(false);
    setNewContext("");
  };

  const handleSaveEdit = async () => {
    if (!application) return;

    setSaving(true);
    setError(null);

    try {
      const updated = await api.updateApplication(appId, {
        name: editName,
        description: editDescription || undefined,
        allowed_contexts: editContexts,
      });
      setApplication(updated);
      setEditing(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update application");
    } finally {
      setSaving(false);
    }
  };

  const addContext = () => {
    const ctx = newContext.trim().toLowerCase().replace(/\s+/g, "-");
    if (ctx && !editContexts.includes(ctx)) {
      setEditContexts([...editContexts, ctx]);
      setNewContext("");
    }
  };

  const removeContext = (ctx: string) => {
    setEditContexts(editContexts.filter((c) => c !== ctx));
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return "N/A";
    return new Date(dateStr).toLocaleString();
  };

  const getDaysUntilExpiry = (dateStr: string | null) => {
    if (!dateStr) return null;
    const expiry = new Date(dateStr);
    const now = new Date();
    const diffMs = expiry.getTime() - now.getTime();
    return Math.floor(diffMs / (1000 * 60 * 60 * 24));
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      </DashboardLayout>
    );
  }

  if (error && !application) {
    return (
      <DashboardLayout>
        <div className="max-w-3xl mx-auto">
          <Card className="border-red-200">
            <CardContent className="py-8 text-center">
              <XCircle className="h-12 w-12 mx-auto text-red-500 mb-4" />
              <h2 className="text-lg font-medium mb-2">Error Loading Application</h2>
              <p className="text-slate-600 mb-4">{error}</p>
              <Link href="/applications">
                <Button variant="outline">
                  <ArrowLeft className="h-4 w-4 mr-2" />
                  Back to Applications
                </Button>
              </Link>
            </CardContent>
          </Card>
        </div>
      </DashboardLayout>
    );
  }

  const refreshDays = tokenInfo?.refresh_token_expires_at
    ? getDaysUntilExpiry(tokenInfo.refresh_token_expires_at)
    : null;

  return (
    <DashboardLayout>
      <div className="max-w-3xl mx-auto space-y-8">
        <div className="flex items-center gap-4">
          <Link href="/applications">
            <Button variant="ghost" size="sm">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back
            </Button>
          </Link>
          <div>
            <h1 className="text-2xl font-bold">{application?.name}</h1>
            <p className="text-slate-600">Token Management</p>
          </div>
        </div>

        {error && (
          <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
            {error}
          </div>
        )}

        {rotateResult && (
          <Card className="border-green-200 bg-green-50">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <CheckCircle className="h-5 w-5 text-green-500" />
                New Refresh Token Generated
              </CardTitle>
              <CardDescription>
                Update your application&apos;s environment variable with this new token
              </CardDescription>
            </CardHeader>
            <CardContent>
              <pre className="bg-slate-900 text-slate-100 p-4 rounded-lg text-sm overflow-x-auto">
                <code>export CRYPTOSERVE_REFRESH_TOKEN=&quot;{rotateResult.token}&quot;</code>
              </pre>
              <p className="text-sm text-slate-600 mt-2">
                Expires: {formatDate(rotateResult.expires)}
              </p>
              <Button
                variant="outline"
                size="sm"
                className="mt-4"
                onClick={() => {
                  navigator.clipboard.writeText(`export CRYPTOSERVE_REFRESH_TOKEN="${rotateResult.token}"`);
                }}
              >
                Copy to Clipboard
              </Button>
            </CardContent>
          </Card>
        )}

        {/* Access Token */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" />
              Access Token
            </CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-2 gap-4">
              <div>
                <dt className="text-sm text-slate-500">Status</dt>
                <dd className="flex items-center gap-2 mt-1">
                  {application?.status === "active" ? (
                    <>
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <span className="text-green-700">Active</span>
                    </>
                  ) : (
                    <>
                      <XCircle className="h-4 w-4 text-red-500" />
                      <span className="text-red-700">Revoked</span>
                    </>
                  )}
                </dd>
              </div>
              <div>
                <dt className="text-sm text-slate-500">Lifetime</dt>
                <dd className="mt-1">
                  {tokenInfo?.access_token_lifetime_seconds ? (
                    <span>{Math.floor(tokenInfo.access_token_lifetime_seconds / 60)} minutes</span>
                  ) : (
                    <span>1 hour</span>
                  )}
                  <span className="text-xs text-slate-400 ml-1">(auto-refreshed by SDK)</span>
                </dd>
              </div>
              <div>
                <dt className="text-sm text-slate-500">Algorithm</dt>
                <dd className="mt-1">
                  <Badge variant="secondary">{tokenInfo?.access_token_algorithm || "Ed25519"}</Badge>
                </dd>
              </div>
              <div>
                <dt className="text-sm text-slate-500">Last Used</dt>
                <dd className="mt-1 flex items-center gap-1">
                  <Clock className="h-3 w-3 text-slate-400" />
                  {tokenInfo?.last_used_at ? formatDate(tokenInfo.last_used_at) : "Never"}
                </dd>
              </div>
            </dl>
          </CardContent>
        </Card>

        {/* Refresh Token */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <RefreshCw className="h-5 w-5" />
              Refresh Token
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <dl className="grid grid-cols-2 gap-4">
              <div>
                <dt className="text-sm text-slate-500">Status</dt>
                <dd className="flex items-center gap-2 mt-1">
                  {tokenInfo?.refresh_token_active ? (
                    <>
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <span className="text-green-700">Active</span>
                    </>
                  ) : (
                    <>
                      <XCircle className="h-4 w-4 text-red-500" />
                      <span className="text-red-700">Inactive</span>
                    </>
                  )}
                </dd>
              </div>
              <div>
                <dt className="text-sm text-slate-500">Expires</dt>
                <dd className="mt-1 flex items-center gap-2">
                  {tokenInfo?.refresh_token_expires_at ? (
                    <>
                      <span>{formatDate(tokenInfo.refresh_token_expires_at)}</span>
                      {refreshDays !== null && refreshDays < 7 && (
                        <Badge variant="warning" className="text-xs">
                          {refreshDays} days left
                        </Badge>
                      )}
                    </>
                  ) : (
                    <span className="text-slate-400">N/A</span>
                  )}
                </dd>
              </div>
              <div>
                <dt className="text-sm text-slate-500">Last Rotated</dt>
                <dd className="mt-1">
                  {tokenInfo?.refresh_token_rotated_at
                    ? formatDate(tokenInfo.refresh_token_rotated_at)
                    : "Never"}
                </dd>
              </div>
              <div>
                <dt className="text-sm text-slate-500">Lifetime</dt>
                <dd className="mt-1">30 days</dd>
              </div>
            </dl>

            <div className="flex gap-3 pt-4 border-t">
              <Button
                variant="outline"
                onClick={handleRotate}
                disabled={rotating || application?.status !== "active"}
              >
                {rotating ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary mr-2" />
                    Rotating...
                  </>
                ) : (
                  <>
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Rotate Token
                  </>
                )}
              </Button>
              <Button
                variant="destructive"
                onClick={handleRevoke}
                disabled={revoking || application?.status !== "active"}
              >
                {revoking ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                    Revoking...
                  </>
                ) : (
                  <>
                    <XCircle className="h-4 w-4 mr-2" />
                    Revoke All Tokens
                  </>
                )}
              </Button>
            </div>

            <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-lg text-sm text-yellow-800 flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
              <div>
                <strong>Warning:</strong> Rotating tokens will require updating the{" "}
                <code className="bg-yellow-100 px-1 rounded">CRYPTOSERVE_REFRESH_TOKEN</code>{" "}
                environment variable in your application.
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Application Info */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Application Details
              </CardTitle>
              {!editing && application?.status === "active" && (
                <Button variant="outline" size="sm" onClick={startEditing}>
                  <Pencil className="h-4 w-4 mr-2" />
                  Edit
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent>
            {editing ? (
              <div className="space-y-4">
                <div>
                  <label className="text-sm text-slate-500 block mb-1">Name</label>
                  <Input
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                    placeholder="Application name"
                  />
                </div>
                <div>
                  <label className="text-sm text-slate-500 block mb-1">Description</label>
                  <Textarea
                    value={editDescription}
                    onChange={(e) => setEditDescription(e.target.value)}
                    placeholder="Optional description"
                    rows={2}
                  />
                </div>
                <div>
                  <label className="text-sm text-slate-500 block mb-1">Allowed Contexts</label>
                  <div className="flex gap-1 flex-wrap mb-2">
                    {editContexts.map((ctx) => (
                      <Badge key={ctx} variant="secondary" className="pr-1">
                        {ctx}
                        <button
                          onClick={() => removeContext(ctx)}
                          className="ml-1 hover:text-red-500"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </Badge>
                    ))}
                  </div>
                  <div className="flex gap-2">
                    <Input
                      value={newContext}
                      onChange={(e) => setNewContext(e.target.value)}
                      placeholder="Add context (e.g., user-pii)"
                      className="flex-1"
                      onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addContext())}
                    />
                    <Button type="button" variant="outline" size="sm" onClick={addContext}>
                      <Plus className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
                <div className="flex gap-2 pt-2 border-t">
                  <Button onClick={handleSaveEdit} disabled={saving || !editName.trim()}>
                    {saving ? (
                      <>
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                        Saving...
                      </>
                    ) : (
                      <>
                        <Save className="h-4 w-4 mr-2" />
                        Save Changes
                      </>
                    )}
                  </Button>
                  <Button variant="outline" onClick={cancelEditing} disabled={saving}>
                    Cancel
                  </Button>
                </div>
              </div>
            ) : (
              <dl className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <dt className="text-slate-500">Application ID</dt>
                  <dd className="font-mono text-xs mt-1">{application?.id}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Team</dt>
                  <dd className="mt-1">{application?.team}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Environment</dt>
                  <dd className="mt-1">
                    <Badge variant="outline">{application?.environment}</Badge>
                  </dd>
                </div>
                <div>
                  <dt className="text-slate-500">Created</dt>
                  <dd className="mt-1">{formatDate(application?.created_at || null)}</dd>
                </div>
                {application?.description && (
                  <div className="col-span-2">
                    <dt className="text-slate-500">Description</dt>
                    <dd className="mt-1">{application.description}</dd>
                  </div>
                )}
                <div className="col-span-2">
                  <dt className="text-slate-500 mb-1">Allowed Contexts</dt>
                  <dd className="flex gap-1 flex-wrap">
                    {application?.allowed_contexts.map((ctx) => (
                      <Badge key={ctx} variant="secondary">
                        {ctx}
                      </Badge>
                    ))}
                  </dd>
                </div>
              </dl>
            )}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
