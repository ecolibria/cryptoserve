"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Shield, Github, Code, AlertTriangle, X, Loader2 } from "lucide-react";

export default function LoginPage() {
  const [devMode, setDevMode] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const searchParams = useSearchParams();

  useEffect(() => {
    // Check for error in URL params (from OAuth redirect)
    const errorParam = searchParams.get("error");
    if (errorParam === "domain_not_allowed") {
      setError(
        "Your email domain is not authorized to access this platform. Please contact your administrator."
      );
    } else if (errorParam) {
      setError(`Authentication failed: ${errorParam}`);
    }

    // Check dev mode status
    fetch("/auth/status")
      .then((res) => res.json())
      .then((data) => setDevMode(data.devMode))
      .catch(() => setDevMode(false));
  }, [searchParams]);

  const handleLogin = (url: string) => {
    setLoading(true);
    window.location.href = url;
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-800 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo & Title */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-500/20 rounded-2xl mb-4">
            <Shield className="h-8 w-8 text-blue-400" />
          </div>
          <h1 className="text-3xl font-bold text-white">CryptoServe</h1>
          <p className="text-slate-400 mt-2">Sign in to continue</p>
        </div>

        {/* Login Card */}
        <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-xl p-6">
          {/* Error Banner */}
          {error && (
            <div className="mb-6 bg-red-500/20 border border-red-500/50 rounded-lg p-4 flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
              <div className="flex-1">
                <p className="text-sm text-red-200">{error}</p>
              </div>
              <button
                onClick={() => setError(null)}
                className="text-red-400 hover:text-red-300"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          )}

          {/* Loading state */}
          {devMode === null ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 text-slate-400 animate-spin" />
            </div>
          ) : (
            <div className="space-y-4">
              {/* GitHub Login - Primary */}
              <button
                onClick={() => handleLogin("/auth/github")}
                disabled={loading}
                className="w-full flex items-center justify-center gap-3 px-4 py-3 bg-white text-slate-900 rounded-lg font-medium hover:bg-slate-100 transition-colors disabled:opacity-50"
              >
                {loading ? (
                  <Loader2 className="h-5 w-5 animate-spin" />
                ) : (
                  <Github className="h-5 w-5" />
                )}
                Sign in with GitHub
              </button>

              {/* Dev Login - Only show in dev mode */}
              {devMode && (
                <>
                  <div className="relative">
                    <div className="absolute inset-0 flex items-center">
                      <div className="w-full border-t border-slate-600" />
                    </div>
                    <div className="relative flex justify-center text-sm">
                      <span className="px-2 bg-slate-800/50 text-slate-500">
                        or
                      </span>
                    </div>
                  </div>

                  <button
                    onClick={() => handleLogin("/auth/dev-login")}
                    disabled={loading}
                    className="w-full flex items-center justify-center gap-3 px-4 py-3 bg-yellow-500/20 text-yellow-300 border border-yellow-500/30 rounded-lg font-medium hover:bg-yellow-500/30 transition-colors disabled:opacity-50"
                  >
                    <Code className="h-5 w-5" />
                    Dev Login (Local Only)
                  </button>
                </>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <p className="text-center text-slate-500 text-sm mt-6">
          Cryptographic operations with zero configuration
        </p>
      </div>
    </div>
  );
}
