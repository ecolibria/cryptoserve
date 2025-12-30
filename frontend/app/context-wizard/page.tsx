"use client";

import { useState } from "react";
import {
  Shield,
  Lock,
  Zap,
  Globe,
  Heart,
  CreditCard,
  Key,
  Briefcase,
  FileText,
  ChevronRight,
  ChevronLeft,
  Check,
  Copy,
  Terminal,
  Sparkles,
  AlertTriangle,
} from "lucide-react";
import Link from "next/link";

interface Recommendation {
  context_name: string;
  display_name: string;
  description: string;
  algorithm: string;
  quantum_ready: boolean;
  compliance_tags: string[];
  sensitivity: string;
  key_rotation_days: number;
  code_example: string;
  rationale: string[];
}

const DATA_TYPES = [
  { id: "pii", label: "Personal Information", icon: Globe, desc: "Names, emails, addresses, phone numbers" },
  { id: "financial", label: "Financial Data", icon: CreditCard, desc: "Payment cards, bank accounts, transactions" },
  { id: "health", label: "Health Records", icon: Heart, desc: "Medical data, diagnoses, prescriptions" },
  { id: "auth", label: "Authentication", icon: Key, desc: "Passwords, tokens, API keys" },
  { id: "business", label: "Business Data", icon: Briefcase, desc: "Contracts, reports, IP documents" },
  { id: "general", label: "General Sensitive", icon: FileText, desc: "Other sensitive information" },
];

const COMPLIANCE = [
  { id: "none", label: "None / Not Sure", desc: "No specific compliance requirements" },
  { id: "soc2", label: "SOC 2", desc: "Service Organization Control" },
  { id: "hipaa", label: "HIPAA", desc: "Healthcare data protection" },
  { id: "pci", label: "PCI-DSS", desc: "Payment card industry" },
  { id: "gdpr", label: "GDPR", desc: "EU data protection" },
  { id: "multiple", label: "Multiple Frameworks", desc: "SOC2 + GDPR + others" },
];

const THREAT_LEVELS = [
  { id: "standard", label: "Standard Protection", desc: "Opportunistic attackers", icon: Shield },
  { id: "elevated", label: "Elevated Security", desc: "Organized threats, sophisticated hackers", icon: AlertTriangle },
  { id: "maximum", label: "Maximum Security", desc: "Nation-state level threats", icon: Lock },
  { id: "quantum", label: "Quantum-Ready", desc: "Future-proof against quantum computers", icon: Sparkles },
];

const PERFORMANCE = [
  { id: "realtime", label: "Real-time", desc: "< 10ms latency required", ms: "< 10ms" },
  { id: "interactive", label: "Interactive", desc: "< 100ms acceptable", ms: "< 100ms" },
  { id: "batch", label: "Batch Processing", desc: "Latency not critical", ms: "Any" },
];

export default function ContextWizardPublic() {
  const [step, setStep] = useState(1);
  const [dataType, setDataType] = useState("");
  const [compliance, setCompliance] = useState("");
  const [threatLevel, setThreatLevel] = useState("");
  const [performance, setPerformance] = useState("");
  const [recommendation, setRecommendation] = useState<Recommendation | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const totalSteps = 4;

  const canProceed = () => {
    switch (step) {
      case 1: return !!dataType;
      case 2: return !!compliance;
      case 3: return !!threatLevel;
      case 4: return !!performance;
      default: return false;
    }
  };

  const getRecommendation = async () => {
    setLoading(true);
    try {
      const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8003";
      const response = await fetch(
        `${API_URL}/api/public/context-wizard?data_type=${dataType}&compliance=${compliance}&threat_level=${threatLevel}&performance=${performance}`
      );
      const data = await response.json();
      setRecommendation(data);
      setStep(5);
    } catch (error) {
      console.error("Failed to get recommendation:", error);
      // Generate a local fallback recommendation
      setRecommendation(generateLocalRecommendation());
      setStep(5);
    } finally {
      setLoading(false);
    }
  };

  const generateLocalRecommendation = (): Recommendation => {
    // Fallback if API is unavailable
    const contextMap: Record<string, { name: string; display: string; desc: string }> = {
      pii: { name: "user-pii", display: "User Personal Data", desc: "Personal identifiable information" },
      financial: { name: "payment-data", display: "Payment Data", desc: "Financial and payment data" },
      health: { name: "phi-records", display: "Health Records", desc: "Protected health information" },
      auth: { name: "auth-secrets", display: "Auth Secrets", desc: "Authentication credentials" },
      business: { name: "business-confidential", display: "Business Confidential", desc: "Business sensitive data" },
      general: { name: "sensitive-data", display: "Sensitive Data", desc: "General sensitive information" },
    };

    const ctx = contextMap[dataType] || contextMap.general;
    const algorithm = threatLevel === "quantum" ? "KYBER-1024-AES-256-GCM" : "AES-256-GCM";

    return {
      context_name: ctx.name,
      display_name: ctx.display,
      description: ctx.desc,
      algorithm,
      quantum_ready: threatLevel === "quantum",
      compliance_tags: compliance !== "none" ? [compliance.toUpperCase()] : [],
      sensitivity: ["financial", "health", "auth"].includes(dataType) ? "critical" : "high",
      key_rotation_days: threatLevel === "maximum" ? 30 : 90,
      code_example: `from cryptoserve import crypto

# Encrypt data
ciphertext = crypto.encrypt(
    plaintext=b"sensitive data",
    context="${ctx.name}"
)

# Decrypt when needed
plaintext = crypto.decrypt(ciphertext, context="${ctx.name}")`,
      rationale: [
        `${algorithm} selected for ${threatLevel} threat level`,
        compliance !== "none" ? `${compliance.toUpperCase()} compliance applied` : "Standard encryption applied",
      ],
    };
  };

  const copyCode = () => {
    if (recommendation) {
      navigator.clipboard.writeText(recommendation.code_example);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const reset = () => {
    setStep(1);
    setDataType("");
    setCompliance("");
    setThreatLevel("");
    setPerformance("");
    setRecommendation(null);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      {/* Header */}
      <header className="border-b border-slate-700">
        <div className="max-w-4xl mx-auto px-6 py-4 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2 text-slate-400 hover:text-white transition-colors">
            <Shield className="h-6 w-6" />
            <span className="font-semibold">CryptoServe</span>
          </Link>
          <div className="flex items-center gap-2 text-sm text-slate-400">
            <Terminal className="h-4 w-4" />
            <code>python -m cryptoserve wizard</code>
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-12">
        {/* Title */}
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold mb-4 bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
            Context Selection Wizard
          </h1>
          <p className="text-slate-400 text-lg">
            Answer a few questions to find the right encryption context for your data
          </p>
        </div>

        {/* Progress */}
        {step <= 4 && (
          <div className="mb-8">
            <div className="flex items-center justify-between text-sm text-slate-400 mb-2">
              <span>Step {step} of {totalSteps}</span>
              <span>{Math.round((step / totalSteps) * 100)}% complete</span>
            </div>
            <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-blue-500 to-purple-500 transition-all duration-300"
                style={{ width: `${(step / totalSteps) * 100}%` }}
              />
            </div>
          </div>
        )}

        {/* Step 1: Data Type */}
        {step === 1 && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-center mb-8">
              What type of data are you protecting?
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {DATA_TYPES.map((type) => (
                <button
                  key={type.id}
                  onClick={() => setDataType(type.id)}
                  className={`p-6 rounded-xl border text-left transition-all ${
                    dataType === type.id
                      ? "bg-blue-500/20 border-blue-500 ring-2 ring-blue-500/50"
                      : "bg-slate-800/50 border-slate-700 hover:border-slate-600"
                  }`}
                >
                  <div className="flex items-start gap-4">
                    <div className={`p-3 rounded-lg ${dataType === type.id ? "bg-blue-500/30" : "bg-slate-700"}`}>
                      <type.icon className="h-6 w-6" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-lg">{type.label}</h3>
                      <p className="text-slate-400 text-sm mt-1">{type.desc}</p>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Step 2: Compliance */}
        {step === 2 && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-center mb-8">
              Which compliance frameworks apply?
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {COMPLIANCE.map((item) => (
                <button
                  key={item.id}
                  onClick={() => setCompliance(item.id)}
                  className={`p-6 rounded-xl border text-left transition-all ${
                    compliance === item.id
                      ? "bg-green-500/20 border-green-500 ring-2 ring-green-500/50"
                      : "bg-slate-800/50 border-slate-700 hover:border-slate-600"
                  }`}
                >
                  <h3 className="font-semibold text-lg">{item.label}</h3>
                  <p className="text-slate-400 text-sm mt-1">{item.desc}</p>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Step 3: Threat Level */}
        {step === 3 && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-center mb-8">
              What's your threat model?
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {THREAT_LEVELS.map((level) => (
                <button
                  key={level.id}
                  onClick={() => setThreatLevel(level.id)}
                  className={`p-6 rounded-xl border text-left transition-all ${
                    threatLevel === level.id
                      ? "bg-purple-500/20 border-purple-500 ring-2 ring-purple-500/50"
                      : "bg-slate-800/50 border-slate-700 hover:border-slate-600"
                  }`}
                >
                  <div className="flex items-start gap-4">
                    <div className={`p-3 rounded-lg ${threatLevel === level.id ? "bg-purple-500/30" : "bg-slate-700"}`}>
                      <level.icon className="h-6 w-6" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-lg">{level.label}</h3>
                      <p className="text-slate-400 text-sm mt-1">{level.desc}</p>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Step 4: Performance */}
        {step === 4 && (
          <div className="space-y-6">
            <h2 className="text-2xl font-semibold text-center mb-8">
              What are your performance requirements?
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {PERFORMANCE.map((perf) => (
                <button
                  key={perf.id}
                  onClick={() => setPerformance(perf.id)}
                  className={`p-6 rounded-xl border text-left transition-all ${
                    performance === perf.id
                      ? "bg-amber-500/20 border-amber-500 ring-2 ring-amber-500/50"
                      : "bg-slate-800/50 border-slate-700 hover:border-slate-600"
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="font-semibold">{perf.label}</h3>
                    <span className={`text-xs px-2 py-1 rounded ${
                      performance === perf.id ? "bg-amber-500/30 text-amber-300" : "bg-slate-700 text-slate-400"
                    }`}>
                      {perf.ms}
                    </span>
                  </div>
                  <p className="text-slate-400 text-sm">{perf.desc}</p>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Step 5: Results */}
        {step === 5 && recommendation && (
          <div className="space-y-8">
            <div className="text-center">
              <div className="inline-flex items-center justify-center w-16 h-16 bg-green-500/20 rounded-full mb-4">
                <Check className="h-8 w-8 text-green-500" />
              </div>
              <h2 className="text-2xl font-semibold mb-2">Your Recommended Context</h2>
              <p className="text-slate-400">Based on your requirements, here's what we recommend</p>
            </div>

            {/* Recommendation Card */}
            <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-8">
              <div className="flex items-start justify-between mb-6">
                <div>
                  <h3 className="text-2xl font-bold">{recommendation.display_name}</h3>
                  <code className="text-slate-400">{recommendation.context_name}</code>
                </div>
                {recommendation.quantum_ready && (
                  <span className="px-3 py-1 bg-purple-500/20 text-purple-400 rounded-full text-sm flex items-center gap-1">
                    <Sparkles className="h-4 w-4" />
                    Quantum Ready
                  </span>
                )}
              </div>

              <p className="text-slate-300 mb-6">{recommendation.description}</p>

              {/* Specs Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-slate-400 text-sm mb-1">Algorithm</div>
                  <div className="font-semibold">{recommendation.algorithm}</div>
                </div>
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-slate-400 text-sm mb-1">Sensitivity</div>
                  <div className="font-semibold capitalize">{recommendation.sensitivity}</div>
                </div>
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-slate-400 text-sm mb-1">Key Rotation</div>
                  <div className="font-semibold">{recommendation.key_rotation_days} days</div>
                </div>
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-slate-400 text-sm mb-1">Compliance</div>
                  <div className="font-semibold">
                    {recommendation.compliance_tags.length > 0
                      ? recommendation.compliance_tags.join(", ")
                      : "None"}
                  </div>
                </div>
              </div>

              {/* Rationale */}
              <div className="mb-6">
                <h4 className="font-semibold mb-2">Why this recommendation?</h4>
                <ul className="space-y-1">
                  {recommendation.rationale.map((reason, idx) => (
                    <li key={idx} className="text-slate-400 text-sm flex items-start gap-2">
                      <Check className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                      {reason}
                    </li>
                  ))}
                </ul>
              </div>

              {/* Code Example */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-semibold">Code Example</h4>
                  <button
                    onClick={copyCode}
                    className="flex items-center gap-1 text-sm text-slate-400 hover:text-white transition-colors"
                  >
                    {copied ? (
                      <>
                        <Check className="h-4 w-4 text-green-500" />
                        Copied!
                      </>
                    ) : (
                      <>
                        <Copy className="h-4 w-4" />
                        Copy
                      </>
                    )}
                  </button>
                </div>
                <pre className="bg-slate-900 rounded-lg p-4 text-sm overflow-x-auto">
                  <code className="text-green-400">{recommendation.code_example}</code>
                </pre>
              </div>
            </div>

            {/* Next Steps */}
            <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-6">
              <h4 className="font-semibold mb-3 flex items-center gap-2">
                <Zap className="h-5 w-5 text-blue-400" />
                Next Steps
              </h4>
              <ol className="space-y-2 text-slate-300">
                <li className="flex items-start gap-3">
                  <span className="flex items-center justify-center w-6 h-6 bg-blue-500/20 rounded-full text-sm text-blue-400 flex-shrink-0">1</span>
                  <span>Install the SDK: <code className="text-amber-400">pip install cryptoserve</code></span>
                </li>
                <li className="flex items-start gap-3">
                  <span className="flex items-center justify-center w-6 h-6 bg-blue-500/20 rounded-full text-sm text-blue-400 flex-shrink-0">2</span>
                  <span>Request access to <code className="text-amber-400">{recommendation.context_name}</code> from your admin</span>
                </li>
                <li className="flex items-start gap-3">
                  <span className="flex items-center justify-center w-6 h-6 bg-blue-500/20 rounded-full text-sm text-blue-400 flex-shrink-0">3</span>
                  <span>Use the code example above in your application</span>
                </li>
              </ol>
            </div>

            {/* Actions */}
            <div className="flex items-center justify-center gap-4">
              <button
                onClick={reset}
                className="px-6 py-3 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
              >
                Start Over
              </button>
              <Link
                href="/dashboard"
                className="px-6 py-3 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
              >
                Go to Dashboard
              </Link>
            </div>
          </div>
        )}

        {/* Navigation */}
        {step <= 4 && (
          <div className="flex items-center justify-between mt-12">
            <button
              onClick={() => setStep(step - 1)}
              disabled={step === 1}
              className={`flex items-center gap-2 px-6 py-3 rounded-lg transition-colors ${
                step === 1
                  ? "text-slate-600 cursor-not-allowed"
                  : "bg-slate-700 hover:bg-slate-600"
              }`}
            >
              <ChevronLeft className="h-5 w-5" />
              Back
            </button>

            <button
              onClick={() => {
                if (step === 4) {
                  getRecommendation();
                } else {
                  setStep(step + 1);
                }
              }}
              disabled={!canProceed() || loading}
              className={`flex items-center gap-2 px-6 py-3 rounded-lg font-semibold transition-all ${
                canProceed()
                  ? "bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 shadow-lg"
                  : "bg-slate-700 text-slate-500 cursor-not-allowed"
              }`}
            >
              {loading ? (
                <>
                  <div className="animate-spin rounded-full h-5 w-5 border-2 border-white/30 border-t-white" />
                  Analyzing...
                </>
              ) : step === 4 ? (
                <>
                  Get Recommendation
                  <Sparkles className="h-5 w-5" />
                </>
              ) : (
                <>
                  Continue
                  <ChevronRight className="h-5 w-5" />
                </>
              )}
            </button>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-700 mt-12">
        <div className="max-w-4xl mx-auto px-6 py-6 text-center text-slate-500 text-sm">
          <p>No login required. Also available via CLI: <code className="text-slate-400">python -m cryptoserve wizard</code></p>
        </div>
      </footer>
    </div>
  );
}
