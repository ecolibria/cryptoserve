"use client";

import { useEffect, useState } from "react";
import {
  Globe,
  Plus,
  Trash2,
  Shield,
  AlertTriangle,
  Check,
  Building2,
  Mail,
  Users,
} from "lucide-react";
import { AdminLayout } from "@/components/admin-layout";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { api, OrganizationSettingsResponse } from "@/lib/api";
import { cn } from "@/lib/utils";

export default function AdminSettingsPage() {
  const [settings, setSettings] = useState<OrganizationSettingsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [newDomain, setNewDomain] = useState("");
  const [addingDomain, setAddingDomain] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const data = await api.getOrgSettings();
      setSettings(data);
    } catch (err) {
      setError("Failed to load organization settings");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleAddDomain = async () => {
    if (!newDomain.trim()) return;

    setAddingDomain(true);
    setError(null);
    try {
      const result = await api.addAllowedDomain(newDomain.trim());
      setSettings((prev) =>
        prev ? { ...prev, allowed_domains: result.domains } : prev
      );
      setNewDomain("");
      setSuccess(`Domain "${newDomain.trim()}" added successfully`);
      setTimeout(() => setSuccess(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add domain");
    } finally {
      setAddingDomain(false);
    }
  };

  const handleRemoveDomain = async (domain: string) => {
    setError(null);
    try {
      const result = await api.removeAllowedDomain(domain);
      setSettings((prev) =>
        prev ? { ...prev, allowed_domains: result.domains } : prev
      );
      setSuccess(`Domain "${domain}" removed`);
      setTimeout(() => setSuccess(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove domain");
    }
  };

  const handleToggleSetting = async (
    key: "require_domain_match" | "allow_any_github_user",
    value: boolean
  ) => {
    setSaving(true);
    setError(null);
    try {
      const updated = await api.updateOrgSettings({ [key]: value });
      setSettings(updated);
      setSuccess("Settings updated");
      setTimeout(() => setSuccess(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update settings");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <AdminLayout title="Settings" subtitle="Organization configuration">
        <div className="flex justify-center py-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </AdminLayout>
    );
  }

  return (
    <AdminLayout
      title="Organization Settings"
      subtitle="Configure authentication and access control"
    >
      <div className="space-y-6 max-w-4xl">
        {/* Status Messages */}
        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-red-500 shrink-0" />
            <p className="text-sm text-red-700">{error}</p>
          </div>
        )}
        {success && (
          <div className="bg-green-50 border border-green-200 rounded-lg p-4 flex items-center gap-3">
            <Check className="h-5 w-5 text-green-500 shrink-0" />
            <p className="text-sm text-green-700">{success}</p>
          </div>
        )}

        {/* Organization Info */}
        {settings?.organization_name && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Building2 className="h-5 w-5" />
                Organization
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-lg font-medium">{settings.organization_name}</p>
              {settings.admin_email && (
                <p className="text-sm text-slate-500 flex items-center gap-2 mt-1">
                  <Mail className="h-4 w-4" />
                  Admin: {settings.admin_email}
                </p>
              )}
            </CardContent>
          </Card>
        )}

        {/* Allowed Email Domains */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Globe className="h-5 w-5" />
              Allowed Email Domains
            </CardTitle>
            <CardDescription>
              Users with verified emails from these domains can sign in via GitHub OAuth.
              Leave empty to allow all domains (open access).
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Current Domains */}
            {settings?.allowed_domains && settings.allowed_domains.length > 0 ? (
              <div className="space-y-2">
                {settings.allowed_domains.map((domain) => (
                  <div
                    key={domain}
                    className="flex items-center justify-between px-4 py-3 bg-slate-50 rounded-lg"
                  >
                    <div className="flex items-center gap-3">
                      <Globe className="h-4 w-4 text-slate-400" />
                      <span className="font-mono text-sm">{domain}</span>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleRemoveDomain(domain)}
                      className="text-red-600 hover:text-red-700 hover:bg-red-50"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-6 text-center text-slate-500">
                <Users className="h-8 w-8 mx-auto mb-2 text-slate-400" />
                <p className="text-sm">No domain restrictions configured</p>
                <p className="text-xs mt-1">Any GitHub user can sign in</p>
              </div>
            )}

            {/* Add Domain Form */}
            <div className="flex gap-2 pt-2">
              <Input
                placeholder="example.com"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleAddDomain()}
                className="flex-1"
              />
              <Button
                onClick={handleAddDomain}
                disabled={!newDomain.trim() || addingDomain}
              >
                <Plus className="h-4 w-4 mr-2" />
                Add Domain
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Access Control Settings */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Access Control
            </CardTitle>
            <CardDescription>
              Configure how domain restrictions are enforced during authentication.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Require Domain Match */}
            <div className="flex items-start justify-between">
              <div className="space-y-1">
                <Label className="text-sm font-medium">
                  Require Domain Match
                </Label>
                <p className="text-sm text-slate-500">
                  When enabled, users must have a verified email from an allowed domain to sign in.
                </p>
              </div>
              <button
                onClick={() =>
                  handleToggleSetting(
                    "require_domain_match",
                    !settings?.require_domain_match
                  )
                }
                disabled={saving}
                className={cn(
                  "relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
                  "disabled:cursor-not-allowed disabled:opacity-50",
                  settings?.require_domain_match ? "bg-primary" : "bg-slate-200"
                )}
              >
                <span
                  className={cn(
                    "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition",
                    settings?.require_domain_match ? "translate-x-5" : "translate-x-0"
                  )}
                />
              </button>
            </div>

            {/* Allow Any GitHub User */}
            <div className="flex items-start justify-between pt-4 border-t">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Label className="text-sm font-medium">
                    Allow Any GitHub User
                  </Label>
                  <Badge variant="outline" className="text-xs text-amber-600 border-amber-300">
                    Development
                  </Badge>
                </div>
                <p className="text-sm text-slate-500">
                  Bypass domain restrictions entirely. Useful for development and testing.
                </p>
                {settings?.allow_any_github_user && (
                  <div className="flex items-center gap-2 mt-2 text-amber-600">
                    <AlertTriangle className="h-4 w-4" />
                    <span className="text-xs font-medium">
                      Warning: Any GitHub user can currently access the platform
                    </span>
                  </div>
                )}
              </div>
              <button
                onClick={() =>
                  handleToggleSetting(
                    "allow_any_github_user",
                    !settings?.allow_any_github_user
                  )
                }
                disabled={saving}
                className={cn(
                  "relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors",
                  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
                  "disabled:cursor-not-allowed disabled:opacity-50",
                  settings?.allow_any_github_user ? "bg-amber-500" : "bg-slate-200"
                )}
              >
                <span
                  className={cn(
                    "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition",
                    settings?.allow_any_github_user ? "translate-x-5" : "translate-x-0"
                  )}
                />
              </button>
            </div>
          </CardContent>
        </Card>

        {/* Info Card */}
        <Card className="bg-blue-50 border-blue-200">
          <CardContent className="py-4">
            <div className="flex gap-3">
              <Shield className="h-5 w-5 text-blue-600 shrink-0 mt-0.5" />
              <div className="text-sm text-blue-800">
                <p className="font-medium mb-1">How domain-based access works</p>
                <ul className="list-disc list-inside space-y-1 text-blue-700">
                  <li>Users sign in with GitHub OAuth as usual</li>
                  <li>We check their verified GitHub emails against allowed domains</li>
                  <li>If no verified email matches, they see an access denied message</li>
                  <li>Existing users who previously logged in retain access</li>
                  <li>The first user to sign in (or ADMIN_EMAIL) becomes admin</li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </AdminLayout>
  );
}
