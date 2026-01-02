"use client";

import React, { useEffect, useState, useCallback } from "react";
import {
  Lock,
  Copy,
  Check,
  ExternalLink,
  Code,
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Key,
  FileSignature,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { DashboardLayout } from "@/components/dashboard-layout";
import { api, Context, ContextFullResponse } from "@/lib/api";
import { cn } from "@/lib/utils";

const classificationConfig: Record<string, {
  icon: React.ElementType;
  label: string;
  color: string;
  bgColor: string;
}> = {
  public: {
    icon: Shield,
    label: "Public",
    color: "text-slate-600",
    bgColor: "bg-slate-100",
  },
  internal: {
    icon: ShieldCheck,
    label: "Internal",
    color: "text-blue-600",
    bgColor: "bg-blue-100",
  },
  sensitive: {
    icon: ShieldAlert,
    label: "Sensitive",
    color: "text-amber-600",
    bgColor: "bg-amber-100",
  },
  critical: {
    icon: ShieldX,
    label: "Critical",
    color: "text-red-600",
    bgColor: "bg-red-100",
  },
  // Map sensitivity levels
  low: {
    icon: Shield,
    label: "Low",
    color: "text-green-600",
    bgColor: "bg-green-100",
  },
  medium: {
    icon: ShieldCheck,
    label: "Medium",
    color: "text-blue-600",
    bgColor: "bg-blue-100",
  },
  high: {
    icon: ShieldAlert,
    label: "High",
    color: "text-amber-600",
    bgColor: "bg-amber-100",
  },
};

interface ContextWithSnippets extends Context {
  pythonSnippet: string;
  typescriptSnippet: string;
  curlSnippet: string;
}

export default function MyContextsPage() {
  const [contexts, setContexts] = useState<ContextWithSnippets[]>([]);
  const [loading, setLoading] = useState(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [selectedLanguage, setSelectedLanguage] = useState<"python" | "typescript" | "curl">("python");

  const loadContexts = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.listContexts();

      // Generate code snippets for each context
      const contextsWithSnippets: ContextWithSnippets[] = data.map((ctx) => ({
        ...ctx,
        pythonSnippet: generatePythonSnippet(ctx.name),
        typescriptSnippet: generateTypescriptSnippet(ctx.name),
        curlSnippet: generateCurlSnippet(ctx.name),
      }));

      setContexts(contextsWithSnippets);
    } catch (error) {
      console.error("Failed to load contexts:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadContexts();
  }, [loadContexts]);

  const generatePythonSnippet = (contextName: string) => {
    return `from cryptoserve import crypto

# Encrypt data using the "${contextName}" context
ciphertext = crypto.encrypt(
    data=your_data,
    context="${contextName}"
)

# Decrypt data
plaintext = crypto.decrypt(
    ciphertext=ciphertext,
    context="${contextName}"
)`;
  };

  const generateTypescriptSnippet = (contextName: string) => {
    return `import { CryptoServe } from '@cryptoserve/sdk';

const crypto = new CryptoServe();

// Encrypt data using the "${contextName}" context
const ciphertext = await crypto.encrypt({
  data: yourData,
  context: "${contextName}"
});

// Decrypt data
const plaintext = await crypto.decrypt({
  ciphertext,
  context: "${contextName}"
});`;
  };

  const generateCurlSnippet = (contextName: string) => {
    return `# Encrypt data
curl -X POST https://api.cryptoserve.io/v1/encrypt \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "plaintext": "base64_encoded_data",
    "context": "${contextName}"
  }'

# Decrypt data
curl -X POST https://api.cryptoserve.io/v1/decrypt \\
  -H "Authorization: Bearer $TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "ciphertext": "encrypted_data",
    "context": "${contextName}"
  }'`;
  };

  const handleCopyId = async (contextName: string) => {
    await navigator.clipboard.writeText(contextName);
    setCopiedId(contextName);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleCopySnippet = async (snippet: string, contextName: string) => {
    await navigator.clipboard.writeText(snippet);
    setCopiedId(`snippet-${contextName}`);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getSnippet = (ctx: ContextWithSnippets) => {
    switch (selectedLanguage) {
      case "python":
        return ctx.pythonSnippet;
      case "typescript":
        return ctx.typescriptSnippet;
      case "curl":
        return ctx.curlSnippet;
      default:
        return ctx.pythonSnippet;
    }
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-slate-600" />
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="px-4 sm:px-6 lg:px-8 py-8 max-w-7xl mx-auto">
        {/* Page Header */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-slate-900">My Contexts</h1>
          <p className="text-slate-500 mt-1">
            Contexts available for your applications with quick-start code snippets
          </p>
        </div>

        {/* Language Selector */}
        <div className="mb-6 flex items-center gap-2">
          <span className="text-sm text-slate-500">Code examples:</span>
          <div className="flex gap-1 p-1 bg-slate-100 rounded-lg">
            {(["python", "typescript", "curl"] as const).map((lang) => (
              <button
                key={lang}
                onClick={() => setSelectedLanguage(lang)}
                className={cn(
                  "px-3 py-1.5 text-sm font-medium rounded-md transition-colors",
                  selectedLanguage === lang
                    ? "bg-white text-slate-900 shadow-sm"
                    : "text-slate-600 hover:text-slate-900"
                )}
              >
                {lang === "python" ? "Python" : lang === "typescript" ? "TypeScript" : "cURL"}
              </button>
            ))}
          </div>
        </div>

        {/* Context Cards */}
        {contexts.length === 0 ? (
          <Card>
            <CardContent className="py-12 text-center">
              <Lock className="h-12 w-12 text-slate-300 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-slate-900 mb-2">No contexts available</h3>
              <p className="text-slate-500 mb-4">
                Contact your administrator to get access to encryption contexts.
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-6">
            {contexts.map((ctx) => {
              const sensitivity = ctx.sensitivity || "medium";
              const config = classificationConfig[sensitivity.toLowerCase()] || classificationConfig.medium;
              const ClassIcon = config.icon;

              return (
                <Card key={ctx.name} className="overflow-hidden">
                  <CardHeader className="pb-3 border-b border-slate-100">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className={cn("h-10 w-10 rounded-lg flex items-center justify-center", config.bgColor)}>
                          <Lock className={cn("h-5 w-5", config.color)} />
                        </div>
                        <div>
                          <CardTitle className="text-base font-semibold flex items-center gap-2">
                            {ctx.display_name}
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleCopyId(ctx.name)}
                              className="h-6 px-2 text-xs"
                            >
                              {copiedId === ctx.name ? (
                                <>
                                  <Check className="h-3 w-3 mr-1 text-green-600" />
                                  Copied
                                </>
                              ) : (
                                <>
                                  <Copy className="h-3 w-3 mr-1" />
                                  Copy ID
                                </>
                              )}
                            </Button>
                          </CardTitle>
                          <p className="text-sm text-slate-500 mt-0.5">{ctx.description}</p>
                        </div>
                      </div>
                      <Badge variant="secondary" className={cn(config.color, config.bgColor)}>
                        <ClassIcon className="h-3 w-3 mr-1" />
                        {config.label}
                      </Badge>
                    </div>
                  </CardHeader>

                  <CardContent className="pt-4 space-y-4">
                    {/* Algorithm Info */}
                    <div className="flex flex-wrap items-center gap-3 text-sm">
                      <div className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-100 rounded-md">
                        <Key className="h-3.5 w-3.5 text-slate-500" />
                        <span className="font-mono text-slate-600">{ctx.algorithm}</span>
                      </div>
                      {ctx.quantum_resistant && (
                        <Badge variant="outline" className="text-purple-600 border-purple-300 bg-purple-50">
                          Quantum-Safe
                        </Badge>
                      )}
                      {ctx.compliance_tags && ctx.compliance_tags.map((tag) => (
                        <Badge key={tag} variant="outline" className="text-emerald-600 border-emerald-300 bg-emerald-50">
                          {tag}
                        </Badge>
                      ))}
                    </div>

                    {/* Code Snippet */}
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-medium text-slate-500 uppercase tracking-wide">
                          Quick Start
                        </span>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleCopySnippet(getSnippet(ctx), ctx.name)}
                          className="h-6 px-2 text-xs"
                        >
                          {copiedId === `snippet-${ctx.name}` ? (
                            <>
                              <Check className="h-3 w-3 mr-1 text-green-600" />
                              Copied
                            </>
                          ) : (
                            <>
                              <Copy className="h-3 w-3 mr-1" />
                              Copy
                            </>
                          )}
                        </Button>
                      </div>
                      <div className="relative">
                        <pre className="bg-slate-900 text-slate-100 p-4 rounded-lg text-xs font-mono overflow-x-auto">
                          <code>{getSnippet(ctx)}</code>
                        </pre>
                      </div>
                    </div>

                    {/* Data Examples */}
                    {ctx.data_examples && ctx.data_examples.length > 0 && (
                      <div className="pt-3 border-t border-slate-100">
                        <span className="text-xs font-medium text-slate-500 uppercase tracking-wide block mb-2">
                          Example Data Types
                        </span>
                        <div className="flex flex-wrap gap-2">
                          {ctx.data_examples.map((example, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-1 bg-slate-100 rounded text-xs text-slate-600"
                            >
                              {example}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Footer Actions */}
                    <div className="flex justify-end pt-2">
                      <Button variant="outline" size="sm" asChild>
                        <a href="/docs/sdk" target="_blank" rel="noopener noreferrer">
                          <ExternalLink className="h-3.5 w-3.5 mr-1.5" />
                          View Documentation
                        </a>
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
