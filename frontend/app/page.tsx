"use client";

import { useEffect, useState } from "react";
import { Shield, Key, Zap, Github, Code } from "lucide-react";

export default function Home() {
  const [devMode, setDevMode] = useState(false);

  useEffect(() => {
    // Use relative URL - will be proxied to backend via Next.js rewrites
    fetch("/auth/status")
      .then((res) => res.json())
      .then((data) => setDevMode(data.devMode))
      .catch(() => setDevMode(true)); // Default to dev mode on error
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-800">
      {/* Header */}
      <header className="container mx-auto px-4 py-6">
        <nav className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Shield className="h-8 w-8 text-blue-400" />
            <span className="text-xl font-bold text-white">CryptoServe</span>
          </div>
          {devMode ? (
            <a
              href="/auth/dev-login"
              className="inline-flex items-center px-4 py-2 bg-yellow-500 text-slate-900 rounded-lg font-medium hover:bg-yellow-400 transition-colors"
            >
              <Code className="h-5 w-5 mr-2" />
              Dev Login
            </a>
          ) : (
            <a
              href="/auth/github"
              className="inline-flex items-center px-4 py-2 bg-white text-slate-900 rounded-lg font-medium hover:bg-slate-100 transition-colors"
            >
              <Github className="h-5 w-5 mr-2" />
              Sign in with GitHub
            </a>
          )}
        </nav>
      </header>

      {/* Hero */}
      <main className="container mx-auto px-4 py-20">
        <div className="text-center max-w-3xl mx-auto">
          <h1 className="text-5xl font-bold text-white mb-6">
            Zero-Config Cryptography
          </h1>
          <p className="text-xl text-slate-300 mb-8">
            Download a personalized SDK with your identity baked in. No API keys,
            no environment variables—just import and encrypt.
          </p>

          <div className="bg-slate-800 rounded-lg p-6 text-left mb-12">
            <pre className="text-sm text-slate-300 overflow-x-auto">
              <code>{`from cryptoserve import crypto

# That's it. Just use it.
ciphertext = crypto.encrypt(data, context="user-pii")
plaintext = crypto.decrypt(ciphertext, context="user-pii")`}</code>
            </pre>
          </div>

          {devMode ? (
            <a
              href="/auth/dev-login"
              className="inline-flex items-center px-6 py-3 bg-yellow-500 text-slate-900 rounded-lg font-medium text-lg hover:bg-yellow-400 transition-colors"
            >
              <Code className="h-5 w-5 mr-2" />
              Get Started (Dev Mode)
            </a>
          ) : (
            <a
              href="/auth/github"
              className="inline-flex items-center px-6 py-3 bg-blue-500 text-white rounded-lg font-medium text-lg hover:bg-blue-600 transition-colors"
            >
              <Github className="h-5 w-5 mr-2" />
              Get Started with GitHub
            </a>
          )}
        </div>

        {/* Features */}
        <div className="grid md:grid-cols-3 gap-8 mt-24">
          <div className="bg-slate-800/50 rounded-lg p-6">
            <div className="h-12 w-12 bg-blue-500/20 rounded-lg flex items-center justify-center mb-4">
              <Key className="h-6 w-6 text-blue-400" />
            </div>
            <h3 className="text-lg font-semibold text-white mb-2">
              Personalized SDKs
            </h3>
            <p className="text-slate-400">
              Your identity is embedded in the SDK. No configuration needed—just
              pip install and start encrypting.
            </p>
          </div>

          <div className="bg-slate-800/50 rounded-lg p-6">
            <div className="h-12 w-12 bg-green-500/20 rounded-lg flex items-center justify-center mb-4">
              <Shield className="h-6 w-6 text-green-400" />
            </div>
            <h3 className="text-lg font-semibold text-white mb-2">
              Context-Based Policies
            </h3>
            <p className="text-slate-400">
              Define contexts like "user-pii" or "payment-data" with compliance
              tags. Developers can&apos;t make bad crypto choices.
            </p>
          </div>

          <div className="bg-slate-800/50 rounded-lg p-6">
            <div className="h-12 w-12 bg-purple-500/20 rounded-lg flex items-center justify-center mb-4">
              <Zap className="h-6 w-6 text-purple-400" />
            </div>
            <h3 className="text-lg font-semibold text-white mb-2">
              Full Audit Trail
            </h3>
            <p className="text-slate-400">
              Every operation is logged with identity, context, and timing.
              Debug issues without exposing sensitive data.
            </p>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="container mx-auto px-4 py-8 mt-20 border-t border-slate-700">
        <p className="text-center text-slate-500">
          Open source cryptographic operations server
        </p>
      </footer>
    </div>
  );
}
