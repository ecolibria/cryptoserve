"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, ArrowRight, Server, Smartphone, Terminal, Check, Copy, CheckCircle } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { api, ApplicationCreateResponse, Context } from "@/lib/api";

type AppType = "backend" | "mobile" | "script";

interface DataTypeOption {
  id: string;
  label: string;
  description: string;
  contexts: string[];
}

const DATA_TYPES: DataTypeOption[] = [
  {
    id: "pii",
    label: "User emails, names, addresses (PII)",
    description: "Personal Identifiable Information requiring GDPR, CCPA compliance",
    contexts: ["user-pii"],
  },
  {
    id: "payment",
    label: "Credit cards, bank accounts (Payment)",
    description: "Payment card data requiring PCI-DSS compliance",
    contexts: ["payment-data"],
  },
  {
    id: "health",
    label: "Medical records, prescriptions (Health)",
    description: "Protected Health Information requiring HIPAA compliance",
    contexts: ["health-data"],
  },
  {
    id: "auth",
    label: "Session tokens, API keys (Auth)",
    description: "Authentication credentials with short-lived encryption",
    contexts: ["session-tokens"],
  },
  {
    id: "secrets",
    label: "Long-term secrets, encryption keys (Secrets)",
    description: "High-security secrets requiring quantum-resistant encryption",
    contexts: ["secrets"],
  },
];

const CONTEXT_INFO: Record<string, { algorithm: string; compliance: string[]; description: string }> = {
  "user-pii": {
    algorithm: "AES-256-GCM",
    compliance: ["GDPR", "CCPA"],
    description: "For personal data like names, emails, addresses",
  },
  "payment-data": {
    algorithm: "AES-256-GCM",
    compliance: ["PCI-DSS"],
    description: "For credit cards and banking information",
  },
  "health-data": {
    algorithm: "AES-256-GCM",
    compliance: ["HIPAA"],
    description: "For medical and health records",
  },
  "session-tokens": {
    algorithm: "ChaCha20-Poly1305",
    compliance: [],
    description: "Fast encryption for auth tokens (short-lived)",
  },
  "secrets": {
    algorithm: "AES-256-GCM",
    compliance: [],
    description: "High-security secrets and encryption keys",
  },
};

export default function NewApplicationPage() {
  const router = useRouter();
  const [step, setStep] = useState(1);
  const [appType, setAppType] = useState<AppType | null>(null);
  const [selectedDataTypes, setSelectedDataTypes] = useState<string[]>([]);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [team, setTeam] = useState("");
  const [environment, setEnvironment] = useState("development");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ApplicationCreateResponse | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [copiedRefresh, setCopiedRefresh] = useState(false);

  const recommendedContexts = selectedDataTypes.flatMap((dt) => {
    const found = DATA_TYPES.find((d) => d.id === dt);
    return found?.contexts || [];
  });

  const uniqueContexts = Array.from(new Set(recommendedContexts));

  const handleDataTypeToggle = (id: string) => {
    setSelectedDataTypes((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const canProceedStep1 = appType !== null && selectedDataTypes.length > 0;
  const canProceedStep2 = name.trim() !== "" && team.trim() !== "";

  const handleCreate = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await api.createApplication({
        name: name.trim(),
        description: description.trim() || undefined,
        team: team.trim(),
        environment,
        allowed_contexts: uniqueContexts,
      });
      setResult(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create application");
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = async (text: string, type: "token" | "refresh") => {
    await navigator.clipboard.writeText(text);
    if (type === "token") {
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2000);
    } else {
      setCopiedRefresh(true);
      setTimeout(() => setCopiedRefresh(false), 2000);
    }
  };

  if (result) {
    return (
      <DashboardLayout>
        <div className="max-w-3xl mx-auto space-y-8">
          <div className="flex items-center gap-4">
            <CheckCircle className="h-10 w-10 text-green-500" />
            <div>
              <h1 className="text-2xl font-bold">Application Created</h1>
              <p className="text-slate-600">{result.application.name} is ready to use</p>
            </div>
          </div>

          <Card className="border-green-200 bg-green-50">
            <CardHeader>
              <CardTitle className="text-lg">Setup Instructions</CardTitle>
              <CardDescription>Follow these steps to start using the SDK</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Step 1: Set Token */}
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Badge variant="outline">Step 1</Badge>
                  <span className="font-medium">{result.setup_instructions.step1.title}</span>
                </div>
                <div className="relative group">
                  <pre className="bg-slate-900 text-slate-100 p-4 pr-24 rounded-lg text-sm overflow-x-auto">
                    <code>export CRYPTOSERVE_TOKEN=&quot;{result.access_token}&quot;</code>
                  </pre>
                  <Button
                    variant="secondary"
                    size="sm"
                    className="absolute top-2 right-2"
                    onClick={() => copyToClipboard(`export CRYPTOSERVE_TOKEN="${result.access_token}"`, "token")}
                  >
                    {copiedToken ? (
                      <>
                        <Check className="h-4 w-4 mr-1" />
                        Copied!
                      </>
                    ) : (
                      <>
                        <Copy className="h-4 w-4 mr-1" />
                        Copy
                      </>
                    )}
                  </Button>
                </div>
                <p className="text-xs text-slate-500">
                  This is your access token. Store it securely - you won&apos;t be able to see it again.
                </p>
              </div>

              {/* Refresh Token */}
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Badge variant="secondary">Optional</Badge>
                  <span className="font-medium">Save Refresh Token (for auto-refresh)</span>
                </div>
                <div className="relative group">
                  <pre className="bg-slate-900 text-slate-100 p-4 pr-24 rounded-lg text-sm overflow-x-auto">
                    <code>export CRYPTOSERVE_REFRESH_TOKEN=&quot;{result.refresh_token}&quot;</code>
                  </pre>
                  <Button
                    variant="secondary"
                    size="sm"
                    className="absolute top-2 right-2"
                    onClick={() => copyToClipboard(`export CRYPTOSERVE_REFRESH_TOKEN="${result.refresh_token}"`, "refresh")}
                  >
                    {copiedRefresh ? (
                      <>
                        <Check className="h-4 w-4 mr-1" />
                        Copied!
                      </>
                    ) : (
                      <>
                        <Copy className="h-4 w-4 mr-1" />
                        Copy
                      </>
                    )}
                  </Button>
                </div>
                <p className="text-xs text-slate-500">
                  Access tokens expire in 1 hour. With a refresh token, the SDK auto-renews them (refresh tokens last 30 days).
                </p>
              </div>

              {/* Step 2: Install SDK */}
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Badge variant="outline">Step 2</Badge>
                  <span className="font-medium">{result.setup_instructions.step2.title}</span>
                </div>
                <pre className="bg-slate-900 text-slate-100 p-4 rounded-lg text-sm overflow-x-auto">
                  <code>{result.setup_instructions.step2.command}</code>
                </pre>
              </div>

              {/* Step 3: Use in Code */}
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Badge variant="outline">Step 3</Badge>
                  <span className="font-medium">{result.setup_instructions.step3.title}</span>
                </div>
                <pre className="bg-slate-900 text-slate-100 p-4 rounded-lg text-sm overflow-x-auto">
                  <code>{result.setup_instructions.step3.code}</code>
                </pre>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Application Details</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <dt className="text-slate-500">Name</dt>
                  <dd className="font-medium">{result.application.name}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Team</dt>
                  <dd className="font-medium">{result.application.team}</dd>
                </div>
                <div>
                  <dt className="text-slate-500">Environment</dt>
                  <dd><Badge variant="outline">{result.application.environment}</Badge></dd>
                </div>
                <div>
                  <dt className="text-slate-500">Status</dt>
                  <dd><Badge variant="success">{result.application.status}</Badge></dd>
                </div>
                <div className="col-span-2">
                  <dt className="text-slate-500 mb-1">Allowed Contexts</dt>
                  <dd className="flex gap-1 flex-wrap">
                    {result.application.allowed_contexts.map((ctx) => (
                      <Badge key={ctx} variant="secondary">{ctx}</Badge>
                    ))}
                  </dd>
                </div>
              </dl>
            </CardContent>
          </Card>

          <div className="flex justify-between">
            <Link href="/applications">
              <Button variant="outline">
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to Applications
              </Button>
            </Link>
            <Link href={`/applications/${result.application.id}/tokens`}>
              <Button>
                Manage Tokens
                <ArrowRight className="h-4 w-4 ml-2" />
              </Button>
            </Link>
          </div>
        </div>
      </DashboardLayout>
    );
  }

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
            <h1 className="text-2xl font-bold">Create Application</h1>
            <p className="text-slate-600">Step {step} of 2</p>
          </div>
        </div>

        {/* Progress bar */}
        <div className="flex gap-2">
          <div className={`h-1 flex-1 rounded ${step >= 1 ? "bg-blue-500" : "bg-slate-200"}`} />
          <div className={`h-1 flex-1 rounded ${step >= 2 ? "bg-blue-500" : "bg-slate-200"}`} />
        </div>

        {step === 1 && (
          <div className="space-y-8">
            {/* Application Type */}
            <Card>
              <CardHeader>
                <CardTitle>What are you building?</CardTitle>
                <CardDescription>Select the type of application</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-3 gap-4">
                  <button
                    onClick={() => setAppType("backend")}
                    className={`p-4 border-2 rounded-lg text-center transition-colors ${
                      appType === "backend"
                        ? "border-blue-500 bg-blue-50"
                        : "border-slate-200 hover:border-slate-300"
                    }`}
                  >
                    <Server className="h-8 w-8 mx-auto mb-2 text-slate-600" />
                    <span className="font-medium">Backend Service</span>
                  </button>
                  <button
                    onClick={() => setAppType("mobile")}
                    className={`p-4 border-2 rounded-lg text-center transition-colors ${
                      appType === "mobile"
                        ? "border-blue-500 bg-blue-50"
                        : "border-slate-200 hover:border-slate-300"
                    }`}
                  >
                    <Smartphone className="h-8 w-8 mx-auto mb-2 text-slate-600" />
                    <span className="font-medium">Mobile App</span>
                  </button>
                  <button
                    onClick={() => setAppType("script")}
                    className={`p-4 border-2 rounded-lg text-center transition-colors ${
                      appType === "script"
                        ? "border-blue-500 bg-blue-50"
                        : "border-slate-200 hover:border-slate-300"
                    }`}
                  >
                    <Terminal className="h-8 w-8 mx-auto mb-2 text-slate-600" />
                    <span className="font-medium">Script / Job</span>
                  </button>
                </div>
              </CardContent>
            </Card>

            {/* Data Types */}
            <Card>
              <CardHeader>
                <CardTitle>What data will you encrypt?</CardTitle>
                <CardDescription>Select all that apply - this determines which cryptographic contexts you can use</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {DATA_TYPES.map((dt) => (
                    <label
                      key={dt.id}
                      className={`flex items-start gap-3 p-3 border rounded-lg cursor-pointer transition-colors ${
                        selectedDataTypes.includes(dt.id)
                          ? "border-blue-500 bg-blue-50"
                          : "border-slate-200 hover:border-slate-300"
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={selectedDataTypes.includes(dt.id)}
                        onChange={() => handleDataTypeToggle(dt.id)}
                        className="mt-1"
                      />
                      <div>
                        <div className="font-medium">{dt.label}</div>
                        <div className="text-sm text-slate-500">{dt.description}</div>
                      </div>
                    </label>
                  ))}
                </div>
              </CardContent>
            </Card>

            <div className="flex justify-end">
              <Button onClick={() => setStep(2)} disabled={!canProceedStep1}>
                Continue
                <ArrowRight className="h-4 w-4 ml-2" />
              </Button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-8">
            {/* Application Details */}
            <Card>
              <CardHeader>
                <CardTitle>Application Details</CardTitle>
                <CardDescription>Configure your application</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="name">Application Name *</Label>
                    <Input
                      id="name"
                      placeholder="e.g., Production Backend"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="team">Team *</Label>
                    <Input
                      id="team"
                      placeholder="e.g., backend, mobile, data"
                      value={team}
                      onChange={(e) => setTeam(e.target.value)}
                    />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="environment">Environment</Label>
                    <select
                      id="environment"
                      value={environment}
                      onChange={(e) => setEnvironment(e.target.value)}
                      className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                    >
                      <option value="development">Development</option>
                      <option value="staging">Staging</option>
                      <option value="production">Production</option>
                    </select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="description">Description (optional)</Label>
                    <Input
                      id="description"
                      placeholder="What is this application for?"
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                    />
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Recommended Contexts */}
            <Card>
              <CardHeader>
                <CardTitle>Recommended Contexts</CardTitle>
                <CardDescription>Based on your data type selections</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {uniqueContexts.map((ctx) => {
                    const info = CONTEXT_INFO[ctx];
                    return (
                      <div key={ctx} className="flex items-start gap-3 p-3 border border-green-200 bg-green-50 rounded-lg">
                        <Check className="h-5 w-5 text-green-500 mt-0.5" />
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="font-medium">{ctx}</span>
                            <Badge variant="secondary">{info?.algorithm || "AES-256-GCM"}</Badge>
                            {info?.compliance.map((c) => (
                              <Badge key={c} variant="outline" className="text-xs">{c}</Badge>
                            ))}
                          </div>
                          <div className="text-sm text-slate-600 mt-1">
                            {info?.description || "Encryption context for your data"}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>

            {error && (
              <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
                {error}
              </div>
            )}

            <div className="flex justify-between">
              <Button variant="outline" onClick={() => setStep(1)}>
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back
              </Button>
              <Button onClick={handleCreate} disabled={!canProceedStep2 || loading}>
                {loading ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                    Creating...
                  </>
                ) : (
                  "Create Application"
                )}
              </Button>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
