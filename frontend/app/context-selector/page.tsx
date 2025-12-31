"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  User,
  CreditCard,
  Shield,
  HeartPulse,
  Lock,
  FileText,
  Key,
  Server,
  ArrowRight,
  ArrowLeft,
  Check,
  Copy,
  ExternalLink,
  Sparkles,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { DashboardLayout } from "@/components/dashboard-layout";
import { cn } from "@/lib/utils";
import { api, Context, ContextFullResponse, DerivedRequirements } from "@/lib/api";

interface DataType {
  id: string;
  name: string;
  description: string;
  icon: React.ReactNode;
  examples: string[];
}

interface ContextRecommendation {
  context: string;
  displayName: string;
  description: string;
  algorithm: string;
  compliance: string[];
  icon: React.ReactNode;
  matchScore: number;
  reasons: string[];
  isCustom?: boolean;
  quantumResistant?: boolean;
  sensitivity?: string;
}

const DATA_TYPES: DataType[] = [
  {
    id: "personal",
    name: "Personal Data",
    description: "Names, emails, addresses, phone numbers, SSN",
    icon: <User className="h-6 w-6" />,
    examples: ["email", "phone", "SSN", "address", "date of birth"],
  },
  {
    id: "payment",
    name: "Payment Data",
    description: "Credit cards, bank accounts, billing info",
    icon: <CreditCard className="h-6 w-6" />,
    examples: ["credit card", "bank account", "CVV", "billing address"],
  },
  {
    id: "health",
    name: "Health Records",
    description: "Medical history, diagnoses, prescriptions",
    icon: <HeartPulse className="h-6 w-6" />,
    examples: ["diagnosis", "prescriptions", "medical history", "insurance ID"],
  },
  {
    id: "auth",
    name: "Auth & Sessions",
    description: "Tokens, session IDs, API keys",
    icon: <Key className="h-6 w-6" />,
    examples: ["JWT tokens", "session IDs", "refresh tokens", "API keys"],
  },
  {
    id: "secrets",
    name: "Long-term Secrets",
    description: "Encryption keys, certificates, passwords",
    icon: <Lock className="h-6 w-6" />,
    examples: ["master keys", "certificates", "private keys", "database passwords"],
  },
  {
    id: "business",
    name: "Business Documents",
    description: "Contracts, reports, internal files",
    icon: <FileText className="h-6 w-6" />,
    examples: ["contracts", "financial reports", "HR documents", "IP"],
  },
  {
    id: "logs",
    name: "Application Logs",
    description: "System logs, audit trails, metrics",
    icon: <Server className="h-6 w-6" />,
    examples: ["error logs", "access logs", "audit trails", "metrics"],
  },
  {
    id: "backup",
    name: "Backups & Archives",
    description: "Database backups, disaster recovery",
    icon: <Server className="h-6 w-6" />,
    examples: ["database backups", "file archives", "snapshots"],
  },
];

const CONTEXT_MAPPING: Record<string, ContextRecommendation> = {
  "user-pii": {
    context: "user-pii",
    displayName: "User Personal Data",
    description: "For personally identifiable information that can identify an individual",
    algorithm: "AES-256-GCM",
    compliance: ["GDPR", "CCPA"],
    icon: <User className="h-5 w-5" />,
    matchScore: 0,
    reasons: [],
  },
  "payment-data": {
    context: "payment-data",
    displayName: "Payment & Financial",
    description: "For payment card data and financial account information",
    algorithm: "AES-256-GCM",
    compliance: ["PCI-DSS"],
    icon: <CreditCard className="h-5 w-5" />,
    matchScore: 0,
    reasons: [],
  },
  "health-data": {
    context: "health-data",
    displayName: "Health Information",
    description: "For protected health information and medical records",
    algorithm: "AES-256-GCM",
    compliance: ["HIPAA"],
    icon: <HeartPulse className="h-5 w-5" />,
    matchScore: 0,
    reasons: [],
  },
  "session-tokens": {
    context: "session-tokens",
    displayName: "Session & Auth Tokens",
    description: "For temporary authentication and session data",
    algorithm: "ChaCha20-Poly1305",
    compliance: ["OWASP"],
    icon: <Key className="h-5 w-5" />,
    matchScore: 0,
    reasons: [],
  },
  "internal-logs": {
    context: "internal-logs",
    displayName: "Application Logs",
    description: "For system logs, audit trails, and application metrics",
    algorithm: "ChaCha20-Poly1305",
    compliance: ["SOC2"],
    icon: <Server className="h-5 w-5" />,
    matchScore: 0,
    reasons: [],
  },
  "api-secrets": {
    context: "api-secrets",
    displayName: "API & Service Secrets",
    description: "For API keys, service credentials, and integration secrets",
    algorithm: "AES-256-GCM",
    compliance: ["SOC2", "OWASP"],
    icon: <Key className="h-5 w-5" />,
    matchScore: 0,
    reasons: [],
  },
  "business-documents": {
    context: "business-documents",
    displayName: "Business Confidential",
    description: "For contracts, reports, IP, and business-sensitive documents",
    algorithm: "AES-256-GCM",
    compliance: ["SOX", "SOC2"],
    icon: <FileText className="h-5 w-5" />,
    matchScore: 0,
    reasons: [],
  },
  "backup-data": {
    context: "backup-data",
    displayName: "Backup & Archives",
    description: "For database backups, file archives, and disaster recovery",
    algorithm: "AES-256-GCM",
    compliance: ["GDPR", "HIPAA", "PCI-DSS", "SOC2"],
    icon: <Server className="h-5 w-5" />,
    matchScore: 0,
    reasons: [],
  },
  "quantum-ready": {
    context: "quantum-ready",
    displayName: "Quantum-Ready Secrets",
    description: "For long-term secrets requiring post-quantum protection",
    algorithm: "AES-256-GCM + ML-KEM-768",
    compliance: ["NIST PQC"],
    icon: <Shield className="h-5 w-5" />,
    matchScore: 0,
    reasons: [],
    quantumResistant: true,
    sensitivity: "critical",
  },
};

// Map data types to contexts (for built-in contexts)
const TYPE_TO_CONTEXT: Record<string, { context: string; reason: string }[]> = {
  personal: [{ context: "user-pii", reason: "Best for PII protection with GDPR/CCPA compliance" }],
  payment: [{ context: "payment-data", reason: "PCI-DSS compliant encryption for card data" }],
  health: [{ context: "health-data", reason: "HIPAA-compliant PHI protection" }],
  auth: [
    { context: "session-tokens", reason: "High-performance encryption for short-lived tokens" },
    { context: "api-secrets", reason: "Strong protection for long-lived API credentials" },
  ],
  secrets: [
    { context: "api-secrets", reason: "Secure storage for service credentials" },
    { context: "quantum-ready", reason: "Post-quantum protection for long-term secrets" },
  ],
  business: [
    { context: "business-documents", reason: "SOX/SOC2 compliant for business-sensitive data" },
  ],
  logs: [{ context: "internal-logs", reason: "High-throughput encryption for log data with SOC2 compliance" }],
  backup: [{ context: "backup-data", reason: "Multi-compliance encryption for backup archives" }],
};

// Keyword-based matching for dynamic contexts
const TYPE_KEYWORDS: Record<string, string[]> = {
  personal: ["pii", "personal", "user", "gdpr", "ccpa"],
  payment: ["payment", "financial", "pci", "card", "billing"],
  health: ["health", "medical", "hipaa", "phi"],
  auth: ["auth", "session", "token", "credential"],
  secrets: ["secret", "key", "api-key", "quantum"],
  business: ["business", "contract", "document", "sox", "confidential"],
  logs: ["log", "audit", "metric", "trace"],
  backup: ["backup", "archive", "disaster", "recovery"],
};

function getRecommendations(
  selectedTypes: string[],
  dynamicContexts: Context[]
): ContextRecommendation[] {
  const recommendations: ContextRecommendation[] = [];
  const contextScores: Record<string, { score: number; reasons: string[]; fromApi: boolean }> = {};

  // Score built-in contexts
  selectedTypes.forEach((type) => {
    const mappings = TYPE_TO_CONTEXT[type] || [];
    mappings.forEach(({ context, reason }) => {
      if (!contextScores[context]) {
        contextScores[context] = { score: 0, reasons: [], fromApi: false };
      }
      contextScores[context].score += 1;
      contextScores[context].reasons.push(reason);
    });
  });

  // Score dynamic contexts from API (including wizard-created ones)
  dynamicContexts.forEach((ctx) => {
    // Skip if it's already in built-in contexts
    if (CONTEXT_MAPPING[ctx.name]) return;

    let matchScore = 0;
    const reasons: string[] = [];
    const contextLower = `${ctx.name} ${ctx.display_name} ${ctx.description}`.toLowerCase();
    const complianceLower = (ctx.compliance_tags || []).join(" ").toLowerCase();

    selectedTypes.forEach((type) => {
      const keywords = TYPE_KEYWORDS[type] || [];
      const hasMatch = keywords.some(
        (kw) => contextLower.includes(kw) || complianceLower.includes(kw)
      );
      if (hasMatch) {
        matchScore += 1;
        reasons.push(`Matches your ${type} data requirements`);
      }
    });

    if (matchScore > 0) {
      contextScores[ctx.name] = { score: matchScore, reasons, fromApi: true };
    }
  });

  // Build recommendations sorted by score
  Object.entries(contextScores)
    .sort(([, a], [, b]) => b.score - a.score)
    .forEach(([contextId, { score, reasons, fromApi }]) => {
      if (fromApi) {
        // Dynamic context from API
        const ctx = dynamicContexts.find((c) => c.name === contextId);
        if (ctx) {
          recommendations.push({
            context: ctx.name,
            displayName: ctx.display_name,
            description: ctx.description,
            algorithm: ctx.algorithm,
            compliance: ctx.compliance_tags || [],
            icon: <Sparkles className="h-5 w-5" />,
            matchScore: score,
            reasons: Array.from(new Set(reasons)),
            isCustom: true,
            quantumResistant: ctx.quantum_resistant || false,
            sensitivity: ctx.sensitivity,
          });
        }
      } else {
        // Built-in context
        const base = CONTEXT_MAPPING[contextId];
        if (base) {
          recommendations.push({
            ...base,
            matchScore: score,
            reasons: Array.from(new Set(reasons)),
            isCustom: false,
          });
        }
      }
    });

  return recommendations;
}

export default function ContextSelectorPage() {
  const router = useRouter();
  const [step, setStep] = useState(1);
  const [selectedTypes, setSelectedTypes] = useState<string[]>([]);
  const [selectedContext, setSelectedContext] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [contexts, setContexts] = useState<Context[]>([]);
  const [loadingContexts, setLoadingContexts] = useState(true);
  const [contextDetails, setContextDetails] = useState<ContextFullResponse | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);

  // Fetch contexts from API
  useEffect(() => {
    api
      .listContexts()
      .then(setContexts)
      .catch(console.error)
      .finally(() => setLoadingContexts(false));
  }, []);

  // Fetch full context details when a context is selected
  useEffect(() => {
    if (selectedContext) {
      setLoadingDetails(true);
      api
        .getContextDetail(selectedContext)
        .then(setContextDetails)
        .catch(console.error)
        .finally(() => setLoadingDetails(false));
    } else {
      setContextDetails(null);
    }
  }, [selectedContext]);

  const recommendations = getRecommendations(selectedTypes, contexts);

  const toggleType = (typeId: string) => {
    setSelectedTypes((prev) =>
      prev.includes(typeId) ? prev.filter((t) => t !== typeId) : [...prev, typeId]
    );
  };

  const copyCode = () => {
    const contextName = CONTEXT_MAPPING[selectedContext || ""]?.displayName || selectedContext;
    const code = `from cryptoserve import CryptoClient

client = CryptoClient()

# Encrypt using the ${contextName} context
encrypted = client.encrypt(
    data="your sensitive data",
    context="${selectedContext}"
)

# Decrypt when needed
decrypted = client.decrypt(encrypted)`;

    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <DashboardLayout>
      {/* Page Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-slate-900">Context Selector</h1>
        <p className="text-slate-500 mt-1">Find the right encryption context for your data</p>
      </div>

      {/* Progress indicator */}
      <div className="mb-8">
        <div className="flex items-center justify-between max-w-2xl mx-auto">
          {[1, 2, 3].map((s) => (
            <div key={s} className="flex items-center">
              <div
                className={cn(
                  "w-10 h-10 rounded-full flex items-center justify-center font-medium transition-colors",
                  step >= s
                    ? "bg-primary text-primary-foreground"
                    : "bg-muted text-muted-foreground"
                )}
              >
                {step > s ? <Check className="h-5 w-5" /> : s}
              </div>
              {s < 3 && (
                <div
                  className={cn(
                    "w-24 h-1 mx-2",
                    step > s ? "bg-primary" : "bg-muted"
                  )}
                />
              )}
            </div>
          ))}
        </div>
        <div className="flex justify-between max-w-2xl mx-auto mt-2 text-sm text-muted-foreground">
          <span>Select Data Type</span>
          <span>Get Recommendation</span>
          <span>Start Using</span>
        </div>
      </div>

      {/* Step 1: Select Data Types */}
      {step === 1 && (
        <div className="space-y-6">
          <div className="text-center mb-8">
            <h2 className="text-2xl font-semibold mb-2">What type of data are you encrypting?</h2>
            <p className="text-muted-foreground">
              Select all that apply. We'll recommend the best context for your needs.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 max-w-5xl mx-auto">
            {DATA_TYPES.map((type) => (
              <Card
                key={type.id}
                className={cn(
                  "cursor-pointer transition-all hover:shadow-md",
                  selectedTypes.includes(type.id)
                    ? "ring-2 ring-primary bg-primary/5"
                    : "hover:bg-muted/50"
                )}
                onClick={() => toggleType(type.id)}
              >
                <CardContent className="p-4">
                  <div className="flex items-start gap-3">
                    <div
                      className={cn(
                        "p-2 rounded-lg",
                        selectedTypes.includes(type.id)
                          ? "bg-primary text-primary-foreground"
                          : "bg-muted"
                      )}
                    >
                      {type.icon}
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="font-medium">{type.name}</h3>
                      <p className="text-sm text-muted-foreground mt-0.5">
                        {type.description}
                      </p>
                      <div className="flex flex-wrap gap-1 mt-2">
                        {type.examples.slice(0, 3).map((ex) => (
                          <Badge key={ex} variant="outline" className="text-xs">
                            {ex}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          <div className="flex justify-center mt-8">
            <Button
              size="lg"
              onClick={() => setStep(2)}
              disabled={selectedTypes.length === 0}
            >
              Get Recommendations
              <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      {/* Step 2: Show Recommendations */}
      {step === 2 && (
        <div className="space-y-6">
          <div className="text-center mb-8">
            <h2 className="text-2xl font-semibold mb-2">Recommended Contexts</h2>
            <p className="text-muted-foreground">
              Based on your data types, here are the best contexts for your needs.
            </p>
          </div>

          <div className="max-w-3xl mx-auto space-y-4">
            {recommendations.map((rec, idx) => (
              <Card
                key={rec.context}
                className={cn(
                  "cursor-pointer transition-all",
                  selectedContext === rec.context
                    ? "ring-2 ring-primary bg-primary/5"
                    : "hover:bg-muted/50"
                )}
                onClick={() => setSelectedContext(rec.context)}
              >
                <CardContent className="p-4">
                  <div className="flex items-start gap-4">
                    <div className="flex items-center justify-center w-10 h-10 rounded-full bg-primary/10 text-primary font-bold">
                      {idx + 1}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        {rec.icon}
                        <h3 className="font-semibold">{rec.displayName}</h3>
                        {idx === 0 && (
                          <Badge className="bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">
                            Best Match
                          </Badge>
                        )}
                        {rec.isCustom && (
                          <Badge className="bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400">
                            <Sparkles className="h-3 w-3 mr-1" />
                            Custom Policy
                          </Badge>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">
                        {rec.description}
                      </p>
                      <div className="flex flex-wrap gap-2 mt-3">
                        <Badge variant="secondary">
                          Algorithm: {rec.algorithm}
                        </Badge>
                        {rec.quantumResistant && (
                          <Badge className="bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400">
                            <Shield className="h-3 w-3 mr-1" />
                            Quantum-Resistant
                          </Badge>
                        )}
                        {rec.sensitivity && (
                          <Badge variant={
                            rec.sensitivity === "critical" ? "destructive" :
                            rec.sensitivity === "high" ? "default" : "secondary"
                          }>
                            {rec.sensitivity.toUpperCase()}
                          </Badge>
                        )}
                        {rec.compliance.map((c) => (
                          <Badge key={c} variant="outline">
                            {c}
                          </Badge>
                        ))}
                      </div>
                      <div className="mt-3 text-sm">
                        <span className="text-muted-foreground">Why this context: </span>
                        {rec.reasons.join(". ")}
                      </div>
                    </div>
                    {selectedContext === rec.context && (
                      <Check className="h-6 w-6 text-primary" />
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          <div className="flex justify-center gap-4 mt-8">
            <Button variant="outline" onClick={() => setStep(1)}>
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
            <Button
              size="lg"
              onClick={() => setStep(3)}
              disabled={!selectedContext}
            >
              Use This Context
              <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          </div>
        </div>
      )}

      {/* Step 3: Integration Guide */}
      {step === 3 && selectedContext && (() => {
        // Find the selected context details from recommendations or mapping
        const selectedRec = recommendations.find((r) => r.context === selectedContext) ||
          CONTEXT_MAPPING[selectedContext];
        const displayName = selectedRec?.displayName || selectedContext;
        const algorithm = selectedRec?.algorithm || "AES-256-GCM";
        const compliance = selectedRec?.compliance || [];
        const isCustom = (selectedRec as ContextRecommendation)?.isCustom || false;

        return (
        <div className="space-y-6">
          <div className="text-center mb-8">
            <h2 className="text-2xl font-semibold mb-2">
              Start Using {displayName}
              {isCustom && (
                <Badge className="ml-2 bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400">
                  <Sparkles className="h-3 w-3 mr-1" />
                  Custom Policy
                </Badge>
              )}
            </h2>
            <p className="text-muted-foreground">
              Create an identity with access to this context and integrate with your code.
            </p>
          </div>

          <div className="max-w-3xl mx-auto space-y-6">
            {/* Quick Start Code */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Quick Start Code</CardTitle>
                <CardDescription>
                  Copy this code to start encrypting with the <code className="bg-slate-100 dark:bg-slate-800 px-1 rounded">{selectedContext}</code> context
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="relative">
                  <pre className="bg-slate-950 text-slate-50 p-4 rounded-lg overflow-x-auto text-sm">
                    <code>
{`from cryptoserve import CryptoClient

client = CryptoClient()

# Encrypt using the ${displayName} context
encrypted = client.encrypt(
    data="your sensitive data",
    context="${selectedContext}"
)

# Decrypt when needed
decrypted = client.decrypt(encrypted)`}
                    </code>
                  </pre>
                  <Button
                    size="sm"
                    variant="secondary"
                    className="absolute top-2 right-2"
                    onClick={copyCode}
                  >
                    {copied ? (
                      <Check className="h-4 w-4" />
                    ) : (
                      <Copy className="h-4 w-4" />
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Next Steps */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Next Steps</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center gap-4 p-3 rounded-lg bg-muted/50">
                  <div className="w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center font-bold">
                    1
                  </div>
                  <div className="flex-1">
                    <h4 className="font-medium">Create an Identity</h4>
                    <p className="text-sm text-muted-foreground">
                      Generate credentials with access to the {selectedContext} context
                    </p>
                  </div>
                  <Button variant="outline" size="sm" onClick={() => router.push("/identities")}>
                    Create
                    <ExternalLink className="ml-2 h-3 w-3" />
                  </Button>
                </div>

                <div className="flex items-center gap-4 p-3 rounded-lg bg-muted/50">
                  <div className="w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center font-bold">
                    2
                  </div>
                  <div className="flex-1">
                    <h4 className="font-medium">Download SDK</h4>
                    <p className="text-sm text-muted-foreground">
                      Get your personalized SDK with embedded credentials
                    </p>
                  </div>
                  <Badge variant="secondary">After identity creation</Badge>
                </div>

                <div className="flex items-center gap-4 p-3 rounded-lg bg-muted/50">
                  <div className="w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center font-bold">
                    3
                  </div>
                  <div className="flex-1">
                    <h4 className="font-medium">Integrate & Test</h4>
                    <p className="text-sm text-muted-foreground">
                      Install the SDK and test encryption in your environment
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Context Details - 5-Layer Model */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Context Details</CardTitle>
                <CardDescription>
                  Full security configuration derived from the 5-layer model
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {loadingDetails ? (
                  <div className="text-center py-4 text-muted-foreground">Loading context details...</div>
                ) : (
                  <>
                    {/* Basic Info */}
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-muted-foreground">Context ID:</span>
                        <span className="ml-2 font-mono">{selectedContext}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Algorithm:</span>
                        <span className="ml-2">{contextDetails?.derived?.resolved_algorithm || algorithm}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Compliance:</span>
                        <span className="ml-2">{contextDetails?.config?.regulatory?.frameworks?.join(", ") || compliance.join(", ") || "None"}</span>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Security Bits:</span>
                        <span className="ml-2">{contextDetails?.derived?.minimum_security_bits || 256}-bit</span>
                      </div>
                    </div>

                    {/* Derived Requirements */}
                    {contextDetails?.derived && (
                      <div className="border-t pt-4">
                        <h4 className="font-medium mb-1 flex items-center gap-2">
                          <Shield className="h-4 w-4" />
                          Derived Security Requirements
                        </h4>
                        <p className="text-xs text-muted-foreground mb-3">
                          Automatically enforced by CryptoServe for this context
                        </p>
                        <div className="grid grid-cols-2 gap-3 text-sm">
                          <div className="flex items-center gap-2">
                            <div className={cn(
                              "w-2 h-2 rounded-full",
                              contextDetails.derived.quantum_resistant ? "bg-green-500" : "bg-amber-500"
                            )} />
                            <span className="text-muted-foreground">Quantum Resistant:</span>
                            <span>{contextDetails.derived.quantum_resistant ? "Yes" : "No"}</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Key Rotation:</span>
                            <span className="ml-2">{contextDetails.derived.key_rotation_days} days</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Audit Level:</span>
                            <span className="ml-2 capitalize">{contextDetails.derived.audit_level}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <div className={cn(
                              "w-2 h-2 rounded-full",
                              contextDetails.derived.hardware_acceleration ? "bg-green-500" : "bg-slate-300"
                            )} />
                            <span className="text-muted-foreground">HW Acceleration:</span>
                            <span>{contextDetails.derived.hardware_acceleration ? "Enabled" : "Optional"}</span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Data Identity */}
                    {contextDetails?.config?.data_identity && (
                      <div className="border-t pt-4">
                        <h4 className="font-medium mb-3 flex items-center gap-2">
                          <User className="h-4 w-4" />
                          Data Classification
                        </h4>
                        <div className="flex flex-wrap gap-2 mb-2">
                          <Badge variant={
                            contextDetails.config.data_identity.sensitivity === "critical" ? "destructive" :
                            contextDetails.config.data_identity.sensitivity === "high" ? "default" :
                            contextDetails.config.data_identity.sensitivity === "medium" ? "secondary" : "outline"
                          }>
                            {contextDetails.config.data_identity.sensitivity?.toUpperCase()} Sensitivity
                          </Badge>
                          {contextDetails.config.data_identity.pii && <Badge variant="outline">PII</Badge>}
                          {contextDetails.config.data_identity.phi && <Badge variant="outline">PHI</Badge>}
                          {contextDetails.config.data_identity.pci && <Badge variant="outline">PCI</Badge>}
                        </div>
                        <p className="text-sm text-muted-foreground">
                          Category: {contextDetails.config.data_identity.category?.replace(/_/g, " ")}
                        </p>
                      </div>
                    )}

                    {/* Threat Model */}
                    {contextDetails?.config?.threat_model && (
                      <div className="border-t pt-4">
                        <h4 className="font-medium mb-3 flex items-center gap-2">
                          <Shield className="h-4 w-4" />
                          Threat Model
                        </h4>
                        <div className="text-sm space-y-2">
                          <div className="flex flex-wrap gap-2">
                            {contextDetails.config.threat_model.adversaries?.map((adv) => (
                              <Badge key={adv} variant="secondary">
                                {adv.replace(/_/g, " ")}
                              </Badge>
                            ))}
                          </div>
                          <p className="text-muted-foreground">
                            Protection lifetime: {contextDetails.config.threat_model.protection_lifetime_years} years
                          </p>
                        </div>
                      </div>
                    )}

                    {/* Algorithm Rationale */}
                    {contextDetails?.derived?.rationale && contextDetails.derived.rationale.length > 0 && (
                      <div className="border-t pt-4">
                        <h4 className="font-medium mb-2 flex items-center gap-2">
                          <Sparkles className="h-4 w-4" />
                          Why We Chose This Algorithm
                        </h4>
                        <p className="text-xs text-muted-foreground mb-3">
                          No action needed - CryptoServe handles all cryptographic decisions automatically.
                        </p>
                        <ul className="text-sm text-muted-foreground space-y-1">
                          {contextDetails.derived.rationale.map((reason, idx) => (
                            <li key={idx} className="flex items-start gap-2">
                              <Check className="h-3 w-3 mt-1 text-green-500 flex-shrink-0" />
                              {reason}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </>
                )}
              </CardContent>
            </Card>
          </div>

          <div className="flex justify-center gap-4 mt-8">
            <Button variant="outline" onClick={() => setStep(2)}>
              <ArrowLeft className="mr-2 h-4 w-4" />
              Choose Different
            </Button>
            <Button size="lg" onClick={() => router.push("/identities")}>
              Create Identity
              <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          </div>
        </div>
        );
      })()}
    </DashboardLayout>
  );
}
