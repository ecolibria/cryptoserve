"use client";

import { useState } from "react";
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
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { DashboardLayout } from "@/components/dashboard-layout";
import { cn } from "@/lib/utils";

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
  "quantum-ready": {
    context: "quantum-ready",
    displayName: "Quantum-Ready Secrets",
    description: "For long-term secrets requiring post-quantum protection",
    algorithm: "AES-256-GCM + ML-KEM-768",
    compliance: ["NIST PQC"],
    icon: <Shield className="h-5 w-5" />,
    matchScore: 0,
    reasons: [],
  },
};

function getRecommendations(selectedTypes: string[]): ContextRecommendation[] {
  const recommendations: ContextRecommendation[] = [];

  // Map data types to contexts
  const typeToContext: Record<string, { context: string; reason: string }[]> = {
    personal: [{ context: "user-pii", reason: "Best for PII protection with GDPR/CCPA compliance" }],
    payment: [{ context: "payment-data", reason: "PCI-DSS compliant encryption for card data" }],
    health: [{ context: "health-data", reason: "HIPAA-compliant PHI protection" }],
    auth: [{ context: "session-tokens", reason: "High-performance encryption for tokens" }],
    secrets: [{ context: "quantum-ready", reason: "Post-quantum protection for long-term secrets" }],
    business: [{ context: "user-pii", reason: "Strong encryption for confidential documents" }],
    logs: [{ context: "session-tokens", reason: "Fast encryption for high-volume log data" }],
  };

  const contextScores: Record<string, { score: number; reasons: string[] }> = {};

  selectedTypes.forEach((type) => {
    const mappings = typeToContext[type] || [];
    mappings.forEach(({ context, reason }) => {
      if (!contextScores[context]) {
        contextScores[context] = { score: 0, reasons: [] };
      }
      contextScores[context].score += 1;
      contextScores[context].reasons.push(reason);
    });
  });

  // Build recommendations sorted by score
  Object.entries(contextScores)
    .sort(([, a], [, b]) => b.score - a.score)
    .forEach(([contextId, { score, reasons }]) => {
      const base = CONTEXT_MAPPING[contextId];
      if (base) {
        recommendations.push({
          ...base,
          matchScore: score,
          reasons: Array.from(new Set(reasons)),
        });
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

  const recommendations = getRecommendations(selectedTypes);

  const toggleType = (typeId: string) => {
    setSelectedTypes((prev) =>
      prev.includes(typeId) ? prev.filter((t) => t !== typeId) : [...prev, typeId]
    );
  };

  const copyCode = () => {
    const code = `from cryptoserve import CryptoClient

client = CryptoClient()

# Encrypt using the recommended context
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
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">
                        {rec.description}
                      </p>
                      <div className="flex flex-wrap gap-2 mt-3">
                        <Badge variant="secondary">
                          Algorithm: {rec.algorithm}
                        </Badge>
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
      {step === 3 && selectedContext && (
        <div className="space-y-6">
          <div className="text-center mb-8">
            <h2 className="text-2xl font-semibold mb-2">Start Using {CONTEXT_MAPPING[selectedContext]?.displayName}</h2>
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
                  Copy this code to start encrypting with the {selectedContext} context
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="relative">
                  <pre className="bg-slate-950 text-slate-50 p-4 rounded-lg overflow-x-auto text-sm">
                    <code>{`from cryptoserve import CryptoClient

client = CryptoClient()

# Encrypt using the recommended context
encrypted = client.encrypt(
    data="your sensitive data",
    context="${selectedContext}"
)

# Decrypt when needed
decrypted = client.decrypt(encrypted)`}</code>
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

            {/* Context Details */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Context Details</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">Context ID:</span>
                    <span className="ml-2 font-mono">{selectedContext}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Algorithm:</span>
                    <span className="ml-2">{CONTEXT_MAPPING[selectedContext]?.algorithm}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Compliance:</span>
                    <span className="ml-2">{CONTEXT_MAPPING[selectedContext]?.compliance.join(", ")}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Security:</span>
                    <span className="ml-2">256-bit</span>
                  </div>
                </div>
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
      )}
    </DashboardLayout>
  );
}
