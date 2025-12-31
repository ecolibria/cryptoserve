"use client";

import { useEffect, useState } from "react";
import { Plus, Copy, Check, Trash2, Download } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard-layout";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { api, Identity, Context, IdentityCreateResponse } from "@/lib/api";

export default function IdentitiesPage() {
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [contexts, setContexts] = useState<Context[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newIdentity, setNewIdentity] = useState<IdentityCreateResponse | null>(
    null
  );
  const [copied, setCopied] = useState(false);

  // Form state
  const [formData, setFormData] = useState({
    name: "",
    type: "developer" as "developer" | "service",
    team: "",
    environment: "development",
    allowed_contexts: [] as string[],
    expires_in_days: 90,
  });
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    Promise.all([api.listIdentities(), api.listContexts()])
      .then(([ids, ctxs]) => {
        setIdentities(ids);
        setContexts(ctxs);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);

    try {
      const result = await api.createIdentity(formData);
      setNewIdentity(result);
      setIdentities([result.identity, ...identities]);
      setFormData({
        name: "",
        type: "developer",
        team: "",
        environment: "development",
        allowed_contexts: [],
        expires_in_days: 90,
      });
    } catch (error) {
      alert(error instanceof Error ? error.message : "Failed to create identity");
    } finally {
      setCreating(false);
    }
  };

  const handleRevoke = async (id: string) => {
    if (!confirm("Are you sure you want to revoke this identity?")) return;

    try {
      await api.revokeIdentity(id);
      setIdentities(
        identities.map((i) =>
          i.id === id ? { ...i, status: "revoked" as const } : i
        )
      );
    } catch (error) {
      alert(error instanceof Error ? error.message : "Failed to revoke identity");
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const toggleContext = (name: string) => {
    setFormData((prev) => ({
      ...prev,
      allowed_contexts: prev.allowed_contexts.includes(name)
        ? prev.allowed_contexts.filter((c) => c !== name)
        : [...prev.allowed_contexts, name],
    }));
  };

  return (
    <DashboardLayout>
      <div className="space-y-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Identities</h1>
            <p className="text-slate-600">
              Manage SDK identities and download personalized packages
            </p>
          </div>
          <Button onClick={() => setShowCreate(!showCreate)}>
            <Plus className="h-4 w-4 mr-2" />
            New Identity
          </Button>
        </div>

        {/* Success message after creating */}
        {newIdentity && (
          <Card className="border-green-200 bg-green-50">
            <CardHeader>
              <CardTitle className="text-green-800">
                Identity Created Successfully
              </CardTitle>
              <CardDescription className="text-green-700">
                Install your personalized SDK with the command below
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="bg-white rounded-lg p-4 border">
                <p className="text-sm text-slate-600 mb-2">
                  Install command (copy this):
                </p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-sm bg-slate-100 p-2 rounded overflow-x-auto">
                    pip install {newIdentity.sdk_download_url}
                  </code>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      copyToClipboard(
                        `pip install ${newIdentity.sdk_download_url}`
                      )
                    }
                  >
                    {copied ? (
                      <Check className="h-4 w-4" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </div>

              <div className="bg-white rounded-lg p-4 border">
                <p className="text-sm text-slate-600 mb-2">Usage:</p>
                <pre className="text-sm bg-slate-100 p-2 rounded overflow-x-auto">
{`from cryptoserve import crypto

ciphertext = crypto.encrypt(b"data", context="${newIdentity.identity.allowed_contexts[0] || "your-context"}")
plaintext = crypto.decrypt(ciphertext, context="${newIdentity.identity.allowed_contexts[0] || "your-context"}")`}
                </pre>
              </div>

              <Button variant="outline" onClick={() => setNewIdentity(null)}>
                Dismiss
              </Button>
            </CardContent>
          </Card>
        )}

        {/* Create form */}
        {showCreate && !newIdentity && (
          <Card>
            <CardHeader>
              <CardTitle>Create New Identity</CardTitle>
              <CardDescription>
                Generate a new SDK with embedded credentials
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleCreate} className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <div>
                    <label className="block text-sm font-medium mb-1">
                      Name
                    </label>
                    <input
                      type="text"
                      required
                      className="w-full px-3 py-2 border rounded-lg"
                      placeholder="My App - Production"
                      value={formData.name}
                      onChange={(e) =>
                        setFormData({ ...formData, name: e.target.value })
                      }
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">
                      Type
                    </label>
                    <select
                      className="w-full px-3 py-2 border rounded-lg"
                      value={formData.type}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          type: e.target.value as "developer" | "service",
                        })
                      }
                    >
                      <option value="developer">Developer</option>
                      <option value="service">Service</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">
                      Team
                    </label>
                    <input
                      type="text"
                      required
                      className="w-full px-3 py-2 border rounded-lg"
                      placeholder="engineering"
                      value={formData.team}
                      onChange={(e) =>
                        setFormData({ ...formData, team: e.target.value })
                      }
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">
                      Environment
                    </label>
                    <select
                      className="w-full px-3 py-2 border rounded-lg"
                      value={formData.environment}
                      onChange={(e) =>
                        setFormData({ ...formData, environment: e.target.value })
                      }
                    >
                      <option value="development">Development</option>
                      <option value="staging">Staging</option>
                      <option value="production">Production</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium mb-1">
                      Expires In
                    </label>
                    <select
                      className="w-full px-3 py-2 border rounded-lg"
                      value={formData.expires_in_days}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          expires_in_days: parseInt(e.target.value),
                        })
                      }
                    >
                      <option value="30">30 days</option>
                      <option value="90">90 days</option>
                      <option value="180">180 days</option>
                      <option value="365">1 year</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium mb-2">
                    Allowed Contexts
                  </label>
                  <div className="grid gap-2 md:grid-cols-2 lg:grid-cols-3">
                    {contexts.map((ctx) => (
                      <label
                        key={ctx.name}
                        className={`flex items-start p-3 border rounded-lg cursor-pointer transition-colors ${
                          formData.allowed_contexts.includes(ctx.name)
                            ? "border-blue-500 bg-blue-50"
                            : "hover:bg-slate-50"
                        }`}
                      >
                        <input
                          type="checkbox"
                          className="mt-1 mr-3"
                          checked={formData.allowed_contexts.includes(ctx.name)}
                          onChange={() => toggleContext(ctx.name)}
                        />
                        <div>
                          <p className="font-medium">{ctx.display_name}</p>
                          <p className="text-xs text-slate-500 mt-1">
                            {ctx.data_examples?.slice(0, 3).join(", ")}
                          </p>
                          <p className="text-xs text-blue-600 mt-1 font-mono">
                            {ctx.algorithm}
                          </p>
                          {ctx.compliance_tags &&
                            ctx.compliance_tags.length > 0 && (
                              <div className="flex gap-1 mt-1">
                                {ctx.compliance_tags.map((tag) => (
                                  <Badge
                                    key={tag}
                                    variant="secondary"
                                    className="text-xs"
                                  >
                                    {tag}
                                  </Badge>
                                ))}
                              </div>
                            )}
                        </div>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="flex gap-2">
                  <Button
                    type="submit"
                    disabled={
                      creating || formData.allowed_contexts.length === 0
                    }
                  >
                    {creating ? "Creating..." : "Create Identity"}
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setShowCreate(false)}
                  >
                    Cancel
                  </Button>
                </div>
              </form>
            </CardContent>
          </Card>
        )}

        {/* Identities list */}
        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          </div>
        ) : identities.length === 0 ? (
          <Card>
            <CardContent className="py-12 text-center">
              <p className="text-slate-600">No identities yet.</p>
              <Button className="mt-4" onClick={() => setShowCreate(true)}>
                <Plus className="h-4 w-4 mr-2" />
                Create Your First Identity
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-4">
            {identities.map((identity) => (
              <Card key={identity.id}>
                <CardContent className="py-4">
                  <div className="flex items-center justify-between">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <h3 className="font-semibold">{identity.name}</h3>
                        <Badge
                          variant={
                            identity.status === "active"
                              ? "success"
                              : "destructive"
                          }
                        >
                          {identity.status}
                        </Badge>
                        <Badge variant="outline">{identity.type}</Badge>
                      </div>
                      <p className="text-sm text-slate-500">
                        {identity.team} / {identity.environment}
                      </p>
                      <div className="flex gap-1 flex-wrap mt-2">
                        {identity.allowed_contexts.map((ctx) => (
                          <Badge key={ctx} variant="secondary">
                            {ctx}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <div className="text-right text-sm text-slate-500 mr-4">
                        <p>ID: {identity.id}</p>
                        <p>
                          Expires:{" "}
                          {new Date(identity.expires_at).toLocaleDateString()}
                        </p>
                      </div>
                      {identity.status === "active" && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleRevoke(identity.id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
