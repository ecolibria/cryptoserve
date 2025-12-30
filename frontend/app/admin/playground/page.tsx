"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Play,
  Lock,
  Unlock,
  Zap,
  Clock,
  Copy,
  Check,
  AlertCircle,
  Info,
  ChevronDown,
  Shield,
  Terminal,
  Code,
  FileCode,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AdminLayout } from "@/components/admin-layout";
import { api, Context, PlaygroundResponse } from "@/lib/api";
import { cn } from "@/lib/utils";

export default function PlaygroundPage() {
  const [loading, setLoading] = useState(true);
  const [contexts, setContexts] = useState<Context[]>([]);
  const [operation, setOperation] = useState<"encrypt" | "decrypt">("encrypt");
  const [inputData, setInputData] = useState("");
  const [selectedContext, setSelectedContext] = useState("");
  const [result, setResult] = useState<PlaygroundResponse | null>(null);
  const [executing, setExecuting] = useState(false);
  const [copied, setCopied] = useState(false);
  const [showSdkCode, setShowSdkCode] = useState(false);

  const loadContexts = useCallback(async () => {
    try {
      const data = await api.listContexts();
      setContexts(data);
      if (data.length > 0) {
        setSelectedContext(data[0].name);
      }
    } catch (error) {
      console.error("Failed to load contexts:", error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadContexts();
  }, [loadContexts]);

  const executeOperation = async () => {
    if (!inputData.trim() || !selectedContext) return;

    setExecuting(true);
    setResult(null);

    try {
      const response = await api.playground({
        operation,
        data: inputData,
        context: selectedContext,
      });
      setResult(response);
    } catch (error) {
      setResult({
        success: false,
        result: null,
        algorithm: "",
        latency_ms: 0,
        error: error instanceof Error ? error.message : "Operation failed",
      });
    } finally {
      setExecuting(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSdkCode = () => {
    const escapedData = inputData.replace(/"/g, '\\"');
    if (operation === "encrypt") {
      return `from cryptoserve import crypto

# Encrypt data
ciphertext = crypto.encrypt_string(
    "${escapedData}",
    context="${selectedContext}"
)
print(ciphertext)`;
    } else {
      return `from cryptoserve import crypto

# Decrypt data
plaintext = crypto.decrypt_string(
    "${escapedData}",
    context="${selectedContext}"
)
print(plaintext)`;
    }
  };

  if (loading) {
    return (
      <AdminLayout title="Crypto Playground" subtitle="Loading...">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </AdminLayout>
    );
  }

  return (
    <AdminLayout
      title="Crypto Playground"
      subtitle="Test encryption and decryption in real-time"
    >
      {/* Info Banner */}
      <div className="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-lg flex items-start gap-3">
        <Info className="h-5 w-5 text-blue-500 mt-0.5 flex-shrink-0" />
        <div>
          <h3 className="font-medium text-blue-900">Interactive Testing</h3>
          <p className="text-sm text-blue-700 mt-1">
            This playground lets you test encryption operations without writing code.
            Perfect for verifying your contexts work correctly before integrating the SDK.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Panel */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Code className="h-5 w-5 text-violet-500" />
              Input
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Operation Toggle */}
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">Operation</label>
              <div className="flex rounded-lg overflow-hidden border">
                <button
                  onClick={() => {
                    setOperation("encrypt");
                    setResult(null);
                  }}
                  className={cn(
                    "flex-1 flex items-center justify-center gap-2 py-3 px-4 transition-colors",
                    operation === "encrypt"
                      ? "bg-green-600 text-white"
                      : "bg-white text-slate-600 hover:bg-slate-50"
                  )}
                >
                  <Lock className="h-4 w-4" />
                  Encrypt
                </button>
                <button
                  onClick={() => {
                    setOperation("decrypt");
                    setResult(null);
                  }}
                  className={cn(
                    "flex-1 flex items-center justify-center gap-2 py-3 px-4 transition-colors",
                    operation === "decrypt"
                      ? "bg-blue-600 text-white"
                      : "bg-white text-slate-600 hover:bg-slate-50"
                  )}
                >
                  <Unlock className="h-4 w-4" />
                  Decrypt
                </button>
              </div>
            </div>

            {/* Context Selector */}
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">
                Crypto Context
              </label>
              <div className="relative">
                <select
                  value={selectedContext}
                  onChange={(e) => {
                    setSelectedContext(e.target.value);
                    setResult(null);
                  }}
                  className="w-full border rounded-lg py-3 px-4 appearance-none cursor-pointer focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                >
                  {contexts.map((ctx) => (
                    <option key={ctx.name} value={ctx.name}>
                      {ctx.display_name} ({ctx.name})
                    </option>
                  ))}
                </select>
                <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400 pointer-events-none" />
              </div>
              {selectedContext && (
                <p className="text-xs text-slate-500 mt-2">
                  Algorithm: {contexts.find((c) => c.name === selectedContext)?.algorithm}
                </p>
              )}
            </div>

            {/* Data Input */}
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2">
                {operation === "encrypt" ? "Plaintext Data" : "Encrypted Data"}
              </label>
              <textarea
                value={inputData}
                onChange={(e) => {
                  setInputData(e.target.value);
                  setResult(null);
                }}
                placeholder={
                  operation === "encrypt"
                    ? "Enter text to encrypt..."
                    : "Paste encrypted data from a previous encryption..."
                }
                className="w-full h-40 border rounded-lg py-3 px-4 placeholder-slate-400 resize-none focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 font-mono text-sm"
              />
            </div>

            {/* Execute Button */}
            <Button
              onClick={executeOperation}
              disabled={executing || !inputData.trim() || !selectedContext}
              className={cn(
                "w-full py-6",
                operation === "encrypt"
                  ? "bg-green-600 hover:bg-green-700"
                  : "bg-blue-600 hover:bg-blue-700"
              )}
            >
              {executing ? (
                <>
                  <div className="animate-spin rounded-full h-5 w-5 border-2 border-white/30 border-t-white mr-2" />
                  Processing...
                </>
              ) : (
                <>
                  <Play className="h-5 w-5 mr-2" />
                  Execute {operation === "encrypt" ? "Encryption" : "Decryption"}
                </>
              )}
            </Button>
          </CardContent>
        </Card>

        {/* Output Panel */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Zap className="h-5 w-5 text-amber-500" />
              Output
            </CardTitle>
          </CardHeader>
          <CardContent>
            {result ? (
              <div className="space-y-4">
                {/* Status */}
                <div
                  className={cn(
                    "p-4 rounded-lg border",
                    result.success
                      ? "bg-green-50 border-green-200"
                      : "bg-red-50 border-red-200"
                  )}
                >
                  <div className="flex items-center gap-2">
                    {result.success ? (
                      <Check className="h-5 w-5 text-green-600" />
                    ) : (
                      <AlertCircle className="h-5 w-5 text-red-600" />
                    )}
                    <span className={result.success ? "text-green-800" : "text-red-800"}>
                      {result.success ? "Operation Successful" : "Operation Failed"}
                    </span>
                  </div>
                  {result.error && (
                    <p className="text-sm text-red-700 mt-2">{result.error}</p>
                  )}
                </div>

                {/* Result Data */}
                {result.success && result.result && (
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <label className="text-sm font-medium text-slate-700">
                        {operation === "encrypt" ? "Encrypted Output" : "Decrypted Output"}
                      </label>
                      <button
                        onClick={() => copyToClipboard(result.result!)}
                        className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-700 transition-colors"
                      >
                        {copied ? (
                          <Check className="h-4 w-4 text-green-500" />
                        ) : (
                          <Copy className="h-4 w-4" />
                        )}
                        {copied ? "Copied!" : "Copy"}
                      </button>
                    </div>
                    <div className="bg-slate-100 rounded-lg p-4 font-mono text-sm break-all max-h-40 overflow-y-auto text-slate-900">
                      {result.result}
                    </div>
                  </div>
                )}

                {/* Metrics */}
                {result.success && (
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-slate-50 rounded-lg p-3">
                      <div className="flex items-center gap-2 text-slate-500 text-sm mb-1">
                        <Shield className="h-4 w-4" />
                        Algorithm
                      </div>
                      <div className="font-medium text-slate-900">{result.algorithm}</div>
                    </div>
                    <div className="bg-slate-50 rounded-lg p-3">
                      <div className="flex items-center gap-2 text-slate-500 text-sm mb-1">
                        <Clock className="h-4 w-4" />
                        Latency
                      </div>
                      <div className="font-medium text-slate-900">{result.latency_ms.toFixed(2)} ms</div>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-64 text-slate-500">
                <Terminal className="h-16 w-16 mb-4 text-slate-300" />
                <p className="text-lg font-medium text-slate-700">Ready to execute</p>
                <p className="text-sm mt-2">Enter data and click execute to see results</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* SDK Code Preview */}
      <Card className="mt-6">
        <CardHeader
          className="cursor-pointer"
          onClick={() => setShowSdkCode(!showSdkCode)}
        >
          <div className="flex items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">
              <FileCode className="h-5 w-5 text-amber-500" />
              SDK Code Equivalent
            </CardTitle>
            <ChevronDown
              className={cn(
                "h-5 w-5 text-slate-400 transition-transform",
                showSdkCode && "rotate-180"
              )}
            />
          </div>
        </CardHeader>
        {showSdkCode && (
          <CardContent>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-slate-500">Python SDK</span>
              <button
                onClick={() => copyToClipboard(getSdkCode())}
                className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-700 transition-colors"
              >
                <Copy className="h-4 w-4" />
                Copy Code
              </button>
            </div>
            <pre className="bg-slate-900 rounded-lg p-4 text-sm font-mono overflow-x-auto">
              <code className="text-green-400">{getSdkCode()}</code>
            </pre>
            <p className="text-xs text-slate-500 mt-3">
              Install the SDK: <code className="text-amber-600 bg-amber-50 px-1 rounded">pip install cryptoserve</code>
            </p>
          </CardContent>
        )}
      </Card>

      {/* Quick Tips */}
      <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
        <TipCard
          icon={<Lock className="h-5 w-5 text-green-600" />}
          title="Encryption"
          description="Enter plaintext, select a context, and encrypt to get an encrypted token."
        />
        <TipCard
          icon={<Unlock className="h-5 w-5 text-blue-600" />}
          title="Decryption"
          description="Paste encrypted output from above, use the same context to decrypt."
        />
        <TipCard
          icon={<Shield className="h-5 w-5 text-purple-600" />}
          title="Contexts Matter"
          description="Data encrypted with one context can only be decrypted with the same context."
        />
      </div>
    </AdminLayout>
  );
}

function TipCard({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
}) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center gap-2 mb-2">
          {icon}
          <span className="font-medium text-slate-900">{title}</span>
        </div>
        <p className="text-sm text-slate-600">{description}</p>
      </CardContent>
    </Card>
  );
}
