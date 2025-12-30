"use client";

import { useState, useEffect } from "react";
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
import { api, Context, PlaygroundResponse } from "@/lib/api";

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

  useEffect(() => {
    const loadContexts = async () => {
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
    };
    loadContexts();
  }, []);

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
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white p-6">
      {/* Header */}
      <div className="flex items-center gap-4 mb-8">
        <div className="p-3 bg-gradient-to-br from-violet-500 to-purple-600 rounded-xl shadow-lg shadow-violet-500/20">
          <Terminal className="h-8 w-8" />
        </div>
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
            Crypto Playground
          </h1>
          <p className="text-slate-400">
            Test encryption and decryption in 30 seconds
          </p>
        </div>
      </div>

      {/* Info Banner */}
      <div className="mb-8 p-4 bg-blue-500/10 border border-blue-500/30 rounded-xl flex items-start gap-3">
        <Info className="h-5 w-5 text-blue-400 mt-0.5 flex-shrink-0" />
        <div>
          <h3 className="font-medium text-blue-300">Interactive Testing</h3>
          <p className="text-sm text-slate-400 mt-1">
            This playground lets you test encryption operations without writing code.
            Perfect for verifying your contexts work correctly before integrating the SDK.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Panel */}
        <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Code className="h-5 w-5 text-violet-400" />
            Input
          </h2>

          {/* Operation Toggle */}
          <div className="mb-4">
            <label className="block text-sm text-slate-400 mb-2">Operation</label>
            <div className="flex rounded-lg overflow-hidden border border-slate-600">
              <button
                onClick={() => {
                  setOperation("encrypt");
                  setResult(null);
                }}
                className={`flex-1 flex items-center justify-center gap-2 py-3 px-4 transition-colors ${
                  operation === "encrypt"
                    ? "bg-green-600 text-white"
                    : "bg-slate-700 text-slate-400 hover:bg-slate-600"
                }`}
              >
                <Lock className="h-4 w-4" />
                Encrypt
              </button>
              <button
                onClick={() => {
                  setOperation("decrypt");
                  setResult(null);
                }}
                className={`flex-1 flex items-center justify-center gap-2 py-3 px-4 transition-colors ${
                  operation === "decrypt"
                    ? "bg-blue-600 text-white"
                    : "bg-slate-700 text-slate-400 hover:bg-slate-600"
                }`}
              >
                <Unlock className="h-4 w-4" />
                Decrypt
              </button>
            </div>
          </div>

          {/* Context Selector */}
          <div className="mb-4">
            <label className="block text-sm text-slate-400 mb-2">
              Crypto Context
            </label>
            <div className="relative">
              <select
                value={selectedContext}
                onChange={(e) => {
                  setSelectedContext(e.target.value);
                  setResult(null);
                }}
                className="w-full bg-slate-700 border border-slate-600 rounded-lg py-3 px-4 text-white appearance-none cursor-pointer focus:outline-none focus:ring-2 focus:ring-violet-500"
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
                Algorithm:{" "}
                {contexts.find((c) => c.name === selectedContext)?.algorithm}
              </p>
            )}
          </div>

          {/* Data Input */}
          <div className="mb-4">
            <label className="block text-sm text-slate-400 mb-2">
              {operation === "encrypt" ? "Plaintext Data" : "Ciphertext (Base64)"}
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
                  : "Paste base64-encoded ciphertext..."
              }
              className="w-full h-40 bg-slate-700 border border-slate-600 rounded-lg py-3 px-4 text-white placeholder-slate-500 resize-none focus:outline-none focus:ring-2 focus:ring-violet-500 font-mono text-sm"
            />
          </div>

          {/* Execute Button */}
          <button
            onClick={executeOperation}
            disabled={executing || !inputData.trim() || !selectedContext}
            className={`w-full flex items-center justify-center gap-2 py-4 rounded-lg font-semibold transition-all ${
              executing || !inputData.trim() || !selectedContext
                ? "bg-slate-600 text-slate-400 cursor-not-allowed"
                : operation === "encrypt"
                ? "bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-500 hover:to-emerald-500 text-white shadow-lg shadow-green-500/25"
                : "bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-lg shadow-blue-500/25"
            }`}
          >
            {executing ? (
              <>
                <div className="animate-spin rounded-full h-5 w-5 border-2 border-white/30 border-t-white" />
                Processing...
              </>
            ) : (
              <>
                <Play className="h-5 w-5" />
                Execute {operation === "encrypt" ? "Encryption" : "Decryption"}
              </>
            )}
          </button>
        </div>

        {/* Output Panel */}
        <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Zap className="h-5 w-5 text-yellow-400" />
            Output
          </h2>

          {result ? (
            <div className="space-y-4">
              {/* Status */}
              <div
                className={`p-4 rounded-lg border ${
                  result.success
                    ? "bg-green-500/10 border-green-500/30"
                    : "bg-red-500/10 border-red-500/30"
                }`}
              >
                <div className="flex items-center gap-2">
                  {result.success ? (
                    <Check className="h-5 w-5 text-green-500" />
                  ) : (
                    <AlertCircle className="h-5 w-5 text-red-500" />
                  )}
                  <span className={result.success ? "text-green-400" : "text-red-400"}>
                    {result.success ? "Operation Successful" : "Operation Failed"}
                  </span>
                </div>
                {result.error && (
                  <p className="text-sm text-red-400 mt-2">{result.error}</p>
                )}
              </div>

              {/* Result Data */}
              {result.success && result.result && (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-sm text-slate-400">
                      {operation === "encrypt" ? "Ciphertext (Base64)" : "Plaintext"}
                    </label>
                    <button
                      onClick={() => copyToClipboard(result.result!)}
                      className="flex items-center gap-1 text-xs text-slate-400 hover:text-white transition-colors"
                    >
                      {copied ? (
                        <Check className="h-4 w-4 text-green-500" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                      {copied ? "Copied!" : "Copy"}
                    </button>
                  </div>
                  <div className="bg-slate-700 rounded-lg p-4 font-mono text-sm break-all max-h-40 overflow-y-auto">
                    {result.result}
                  </div>
                </div>
              )}

              {/* Metrics */}
              {result.success && (
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-slate-700/50 rounded-lg p-3">
                    <div className="flex items-center gap-2 text-slate-400 text-sm mb-1">
                      <Shield className="h-4 w-4" />
                      Algorithm
                    </div>
                    <div className="font-medium">{result.algorithm}</div>
                  </div>
                  <div className="bg-slate-700/50 rounded-lg p-3">
                    <div className="flex items-center gap-2 text-slate-400 text-sm mb-1">
                      <Clock className="h-4 w-4" />
                      Latency
                    </div>
                    <div className="font-medium">{result.latency_ms.toFixed(2)} ms</div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-64 text-slate-500">
              <Terminal className="h-16 w-16 mb-4 opacity-50" />
              <p className="text-lg">Ready to execute</p>
              <p className="text-sm mt-2">
                Enter data and click execute to see results
              </p>
            </div>
          )}
        </div>
      </div>

      {/* SDK Code Preview */}
      <div className="mt-6 bg-slate-800/50 rounded-xl border border-slate-700 overflow-hidden">
        <button
          onClick={() => setShowSdkCode(!showSdkCode)}
          className="w-full p-4 flex items-center justify-between hover:bg-slate-700/30 transition-colors"
        >
          <div className="flex items-center gap-2">
            <FileCode className="h-5 w-5 text-amber-400" />
            <span className="font-semibold">SDK Code Equivalent</span>
          </div>
          <ChevronDown
            className={`h-5 w-5 text-slate-400 transition-transform ${
              showSdkCode ? "rotate-180" : ""
            }`}
          />
        </button>

        {showSdkCode && (
          <div className="p-4 border-t border-slate-700">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-slate-400">Python SDK</span>
              <button
                onClick={() => copyToClipboard(getSdkCode())}
                className="flex items-center gap-1 text-xs text-slate-400 hover:text-white transition-colors"
              >
                <Copy className="h-4 w-4" />
                Copy Code
              </button>
            </div>
            <pre className="bg-slate-900 rounded-lg p-4 text-sm font-mono overflow-x-auto">
              <code className="text-green-400">{getSdkCode()}</code>
            </pre>
            <p className="text-xs text-slate-500 mt-3">
              Install the SDK: <code className="text-amber-400">pip install cryptoserve</code>
            </p>
          </div>
        )}
      </div>

      {/* Quick Tips */}
      <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
        <TipCard
          icon={<Lock className="h-5 w-5 text-green-400" />}
          title="Encryption"
          description="Enter plaintext, select a context, and encrypt. Output is base64-encoded."
        />
        <TipCard
          icon={<Unlock className="h-5 w-5 text-blue-400" />}
          title="Decryption"
          description="Paste ciphertext from encryption, use the same context to decrypt."
        />
        <TipCard
          icon={<Shield className="h-5 w-5 text-purple-400" />}
          title="Contexts Matter"
          description="Data encrypted with one context can only be decrypted with the same context."
        />
      </div>
    </div>
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
    <div className="p-4 bg-slate-800/30 rounded-lg border border-slate-700/50">
      <div className="flex items-center gap-2 mb-2">
        {icon}
        <span className="font-medium">{title}</span>
      </div>
      <p className="text-sm text-slate-400">{description}</p>
    </div>
  );
}
