"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  ArrowRight,
  ArrowLeft,
  Check,
  Shield,
  Users,
  Globe,
  Clock,
  Zap,
  AlertTriangle,
  Sparkles,
  Eye,
  Send,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AdminLayout } from "@/components/admin-layout";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

// Step 1: Data Classification
const DATA_TYPES = [
  {
    id: "pii",
    name: "Personal Identifiable Information",
    description: "Names, emails, addresses, phone numbers, SSN",
    icon: <Users className="h-6 w-6" />,
    sensitivity: "critical",
  },
  {
    id: "financial",
    name: "Financial & Payment Data",
    description: "Credit cards, bank accounts, transactions",
    icon: <Shield className="h-6 w-6" />,
    sensitivity: "critical",
  },
  {
    id: "health",
    name: "Health Information (PHI)",
    description: "Medical records, diagnoses, prescriptions",
    icon: <Shield className="h-6 w-6" />,
    sensitivity: "critical",
  },
  {
    id: "auth",
    name: "Authentication & Secrets",
    description: "Passwords, API keys, tokens, credentials",
    icon: <Shield className="h-6 w-6" />,
    sensitivity: "high",
  },
  {
    id: "business",
    name: "Business Confidential",
    description: "Contracts, IP, internal documents",
    icon: <Shield className="h-6 w-6" />,
    sensitivity: "high",
  },
  {
    id: "internal",
    name: "Internal Data",
    description: "Logs, metrics, internal IDs",
    icon: <Shield className="h-6 w-6" />,
    sensitivity: "medium",
  },
];

// Step 2: Compliance Frameworks
const COMPLIANCE_FRAMEWORKS = [
  { id: "gdpr", name: "GDPR", description: "EU General Data Protection Regulation" },
  { id: "ccpa", name: "CCPA", description: "California Consumer Privacy Act" },
  { id: "hipaa", name: "HIPAA", description: "Health Insurance Portability Act" },
  { id: "pci-dss", name: "PCI-DSS", description: "Payment Card Industry Standard" },
  { id: "sox", name: "SOX", description: "Sarbanes-Oxley Act" },
  { id: "soc2", name: "SOC2", description: "Service Organization Control 2" },
  { id: "none", name: "No specific framework", description: "Internal security best practices" },
];

// Step 3: Threat Model (plain language)
const THREAT_LEVELS = [
  {
    id: "standard",
    name: "Standard Protection",
    description: "Protection against common threats like opportunistic attackers",
    adversaries: ["Opportunistic hackers", "Script kiddies"],
    protectionYears: 5,
  },
  {
    id: "elevated",
    name: "Elevated Protection",
    description: "Protection against organized crime and insider threats",
    adversaries: ["Organized crime", "Malicious insiders", "Competitors"],
    protectionYears: 10,
  },
  {
    id: "maximum",
    name: "Maximum Protection",
    description: "Protection against nation-state actors and future quantum computers",
    adversaries: ["Nation-state actors", "Advanced persistent threats", "Quantum computers"],
    protectionYears: 30,
  },
];

// Step 4: Access Patterns
const ACCESS_PATTERNS = [
  {
    id: "high-throughput",
    name: "High Throughput",
    description: "Thousands of operations per second (APIs, real-time)",
    latencyMs: 10,
    opsPerSecond: 10000,
  },
  {
    id: "balanced",
    name: "Balanced",
    description: "Moderate volume with reasonable latency (web apps)",
    latencyMs: 50,
    opsPerSecond: 1000,
  },
  {
    id: "batch",
    name: "Batch Processing",
    description: "Large volumes, latency not critical (backups, reports)",
    latencyMs: 500,
    opsPerSecond: 100,
  },
  {
    id: "rare",
    name: "Rare Access",
    description: "Infrequent access, security over speed (archives, secrets)",
    latencyMs: 1000,
    opsPerSecond: 10,
  },
];

// Algorithm derivation logic
function deriveAlgorithm(config: {
  dataType: string;
  compliance: string[];
  threatLevel: string;
  accessPattern: string;
}): { algorithm: string; reasoning: string[] } {
  const reasoning: string[] = [];
  let algorithm = "AES-256-GCM";

  // Quantum-ready for maximum protection
  if (config.threatLevel === "maximum") {
    algorithm = "AES-256-GCM + ML-KEM-768";
    reasoning.push("Hybrid post-quantum encryption for long-term protection");
  }

  // High-throughput might prefer ChaCha20
  if (config.accessPattern === "high-throughput" && config.threatLevel !== "maximum") {
    algorithm = "ChaCha20-Poly1305";
    reasoning.push("ChaCha20 selected for high-throughput performance");
  }

  // Default reasoning
  if (reasoning.length === 0) {
    reasoning.push("AES-256-GCM provides strong authenticated encryption");
  }

  // Add compliance reasoning
  if (config.compliance.includes("pci-dss")) {
    reasoning.push("PCI-DSS requires strong encryption for cardholder data");
  }
  if (config.compliance.includes("hipaa")) {
    reasoning.push("HIPAA requires encryption for PHI at rest and in transit");
  }
  if (config.compliance.includes("gdpr")) {
    reasoning.push("GDPR Article 32 requires appropriate technical measures");
  }

  return { algorithm, reasoning };
}

function generateContextName(dataType: string, compliance: string[]): string {
  const typeNames: Record<string, string> = {
    pii: "personal-data",
    financial: "financial-data",
    health: "health-records",
    auth: "credentials",
    business: "business-docs",
    internal: "internal-data",
  };

  const base = typeNames[dataType] || "custom-data";

  // Add primary compliance suffix if applicable
  const primaryCompliance = compliance.find(c => c !== "none");
  if (primaryCompliance) {
    return `${base}-${primaryCompliance}`;
  }

  return base;
}

function generatePolicyName(dataType: string): string {
  const typeNames: Record<string, string> = {
    pii: "Personal Data Protection",
    financial: "Financial Data Security",
    health: "Health Information Protection",
    auth: "Credential Security",
    business: "Business Confidentiality",
    internal: "Internal Data Handling",
  };

  return typeNames[dataType] || "Custom Data Policy";
}

export default function PolicyCreatorWizard() {
  const router = useRouter();
  const [step, setStep] = useState(1);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Wizard state
  const [dataType, setDataType] = useState<string | null>(null);
  const [compliance, setCompliance] = useState<string[]>([]);
  const [threatLevel, setThreatLevel] = useState<string | null>(null);
  const [accessPattern, setAccessPattern] = useState<string | null>(null);
  const [policyName, setPolicyName] = useState("");
  const [contextName, setContextName] = useState("");

  const totalSteps = 5;

  // Derive algorithm when we have enough info
  const derivedConfig = dataType && threatLevel && accessPattern
    ? deriveAlgorithm({ dataType, compliance, threatLevel, accessPattern })
    : null;

  // Generate names when data type changes
  const handleDataTypeSelect = (type: string) => {
    setDataType(type);
    setPolicyName(generatePolicyName(type));
  };

  const handleComplianceToggle = (id: string) => {
    if (id === "none") {
      setCompliance(["none"]);
    } else {
      setCompliance(prev => {
        const filtered = prev.filter(c => c !== "none");
        return filtered.includes(id)
          ? filtered.filter(c => c !== id)
          : [...filtered, id];
      });
    }
  };

  // Update context name when compliance changes
  const updateContextName = () => {
    if (dataType) {
      setContextName(generateContextName(dataType, compliance));
    }
  };

  const handlePublish = async () => {
    if (!dataType || !threatLevel || !accessPattern || !derivedConfig) return;

    setCreating(true);
    setError(null);

    try {
      // Use the wizard publish endpoint that creates both context and policy
      const result = await api.publishWizardPolicy({
        data_type: dataType,
        compliance: compliance,
        threat_level: threatLevel,
        access_pattern: accessPattern,
        policy_name: policyName,
        context_name: contextName.toLowerCase().replace(/\s+/g, "-"),
      });

      // Navigate to the admin contexts page with success message
      router.push(`/admin/contexts?created=${encodeURIComponent(result.context_name)}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create policy");
    } finally {
      setCreating(false);
    }
  };

  const canProceed = () => {
    switch (step) {
      case 1: return dataType !== null;
      case 2: return compliance.length > 0;
      case 3: return threatLevel !== null;
      case 4: return accessPattern !== null;
      case 5: return policyName.length > 0 && contextName.length > 0;
      default: return false;
    }
  };

  const nextStep = () => {
    if (step === 2) updateContextName();
    if (step < totalSteps) setStep(step + 1);
  };

  return (
    <AdminLayout title="Create Policy" subtitle="Guided policy creation wizard">
      {/* Progress */}
      <div className="mb-8">
        <div className="flex items-center justify-between max-w-3xl mx-auto">
          {[1, 2, 3, 4, 5].map((s) => (
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
              {s < 5 && (
                <div
                  className={cn(
                    "w-16 h-1 mx-1",
                    step > s ? "bg-primary" : "bg-muted"
                  )}
                />
              )}
            </div>
          ))}
        </div>
        <div className="flex justify-between max-w-3xl mx-auto mt-2 text-xs text-muted-foreground">
          <span>Data Type</span>
          <span>Compliance</span>
          <span>Protection</span>
          <span>Access</span>
          <span>Review</span>
        </div>
      </div>

      {/* Step 1: Data Classification */}
      {step === 1 && (
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-8">
            <h2 className="text-2xl font-semibold mb-2">What type of data needs protection?</h2>
            <p className="text-muted-foreground">
              Select the category that best describes the data you're protecting
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {DATA_TYPES.map((type) => (
              <Card
                key={type.id}
                className={cn(
                  "cursor-pointer transition-all hover:shadow-md",
                  dataType === type.id
                    ? "ring-2 ring-primary bg-primary/5"
                    : "hover:bg-muted/50"
                )}
                onClick={() => handleDataTypeSelect(type.id)}
              >
                <CardContent className="p-4">
                  <div className="flex items-start gap-3">
                    <div
                      className={cn(
                        "p-2 rounded-lg",
                        dataType === type.id
                          ? "bg-primary text-primary-foreground"
                          : "bg-muted"
                      )}
                    >
                      {type.icon}
                    </div>
                    <div>
                      <h3 className="font-medium">{type.name}</h3>
                      <p className="text-sm text-muted-foreground mt-1">
                        {type.description}
                      </p>
                      <Badge
                        variant="outline"
                        className={cn(
                          "mt-2",
                          type.sensitivity === "critical" && "border-red-500 text-red-600",
                          type.sensitivity === "high" && "border-orange-500 text-orange-600",
                          type.sensitivity === "medium" && "border-yellow-500 text-yellow-600"
                        )}
                      >
                        {type.sensitivity} sensitivity
                      </Badge>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Step 2: Compliance Frameworks */}
      {step === 2 && (
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-8">
            <h2 className="text-2xl font-semibold mb-2">Which compliance frameworks apply?</h2>
            <p className="text-muted-foreground">
              Select all frameworks that your organization must comply with
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {COMPLIANCE_FRAMEWORKS.map((framework) => (
              <Card
                key={framework.id}
                className={cn(
                  "cursor-pointer transition-all hover:shadow-md",
                  compliance.includes(framework.id)
                    ? "ring-2 ring-primary bg-primary/5"
                    : "hover:bg-muted/50"
                )}
                onClick={() => handleComplianceToggle(framework.id)}
              >
                <CardContent className="p-4 flex items-center gap-3">
                  <div
                    className={cn(
                      "w-6 h-6 rounded-full border-2 flex items-center justify-center",
                      compliance.includes(framework.id)
                        ? "bg-primary border-primary"
                        : "border-muted-foreground"
                    )}
                  >
                    {compliance.includes(framework.id) && (
                      <Check className="h-4 w-4 text-primary-foreground" />
                    )}
                  </div>
                  <div>
                    <h3 className="font-medium">{framework.name}</h3>
                    <p className="text-sm text-muted-foreground">{framework.description}</p>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Step 3: Threat Model */}
      {step === 3 && (
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-8">
            <h2 className="text-2xl font-semibold mb-2">What level of protection is needed?</h2>
            <p className="text-muted-foreground">
              Consider who might try to access this data and for how long it needs protection
            </p>
          </div>

          <div className="space-y-4">
            {THREAT_LEVELS.map((level) => (
              <Card
                key={level.id}
                className={cn(
                  "cursor-pointer transition-all hover:shadow-md",
                  threatLevel === level.id
                    ? "ring-2 ring-primary bg-primary/5"
                    : "hover:bg-muted/50"
                )}
                onClick={() => setThreatLevel(level.id)}
              >
                <CardContent className="p-4">
                  <div className="flex items-start gap-4">
                    <div
                      className={cn(
                        "p-3 rounded-lg",
                        threatLevel === level.id
                          ? "bg-primary text-primary-foreground"
                          : "bg-muted"
                      )}
                    >
                      {level.id === "standard" && <Shield className="h-6 w-6" />}
                      {level.id === "elevated" && <AlertTriangle className="h-6 w-6" />}
                      {level.id === "maximum" && <Sparkles className="h-6 w-6" />}
                    </div>
                    <div className="flex-1">
                      <h3 className="font-semibold text-lg">{level.name}</h3>
                      <p className="text-muted-foreground mt-1">{level.description}</p>
                      <div className="flex flex-wrap gap-2 mt-3">
                        <Badge variant="secondary">
                          <Clock className="h-3 w-3 mr-1" />
                          {level.protectionYears}+ years protection
                        </Badge>
                        {level.adversaries.slice(0, 2).map((adv) => (
                          <Badge key={adv} variant="outline">{adv}</Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Step 4: Access Patterns */}
      {step === 4 && (
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-8">
            <h2 className="text-2xl font-semibold mb-2">How will this data be accessed?</h2>
            <p className="text-muted-foreground">
              This helps us optimize encryption for your performance needs
            </p>
          </div>

          <div className="space-y-4">
            {ACCESS_PATTERNS.map((pattern) => (
              <Card
                key={pattern.id}
                className={cn(
                  "cursor-pointer transition-all hover:shadow-md",
                  accessPattern === pattern.id
                    ? "ring-2 ring-primary bg-primary/5"
                    : "hover:bg-muted/50"
                )}
                onClick={() => setAccessPattern(pattern.id)}
              >
                <CardContent className="p-4">
                  <div className="flex items-center gap-4">
                    <div
                      className={cn(
                        "p-3 rounded-lg",
                        accessPattern === pattern.id
                          ? "bg-primary text-primary-foreground"
                          : "bg-muted"
                      )}
                    >
                      <Zap className="h-6 w-6" />
                    </div>
                    <div className="flex-1">
                      <h3 className="font-semibold">{pattern.name}</h3>
                      <p className="text-sm text-muted-foreground">{pattern.description}</p>
                    </div>
                    <div className="text-right text-sm">
                      <div className="text-muted-foreground">Target latency</div>
                      <div className="font-medium">{pattern.latencyMs}ms</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Step 5: Review & Publish */}
      {step === 5 && derivedConfig && (
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-8">
            <h2 className="text-2xl font-semibold mb-2">Review & Publish</h2>
            <p className="text-muted-foreground">
              Review the auto-generated policy and context before publishing
            </p>
          </div>

          <div className="space-y-6">
            {/* Summary Card */}
            <Card className="bg-gradient-to-r from-primary/10 to-primary/5 border-primary/20">
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Sparkles className="h-5 w-5 text-primary" />
                  <CardTitle>Auto-Generated Configuration</CardTitle>
                </div>
                <CardDescription>
                  Based on your requirements, we recommend the following setup
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Policy Name */}
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Policy Name</label>
                  <input
                    type="text"
                    value={policyName}
                    onChange={(e) => setPolicyName(e.target.value)}
                    className="mt-1 w-full px-3 py-2 border rounded-lg bg-background"
                  />
                </div>

                {/* Context Name */}
                <div>
                  <label className="text-sm font-medium text-muted-foreground">Context ID (for developers)</label>
                  <input
                    type="text"
                    value={contextName}
                    onChange={(e) => setContextName(e.target.value)}
                    className="mt-1 w-full px-3 py-2 border rounded-lg bg-background font-mono"
                  />
                  <p className="text-xs text-muted-foreground mt-1">
                    Developers will use this ID: <code>context="{contextName}"</code>
                  </p>
                </div>

                {/* Algorithm */}
                <div className="p-4 bg-background rounded-lg border">
                  <div className="flex items-center justify-between">
                    <span className="font-medium">Selected Algorithm</span>
                    <Badge className="text-sm">{derivedConfig.algorithm}</Badge>
                  </div>
                  <ul className="mt-3 space-y-1 text-sm text-muted-foreground">
                    {derivedConfig.reasoning.map((reason, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <Check className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                        {reason}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Selected Options Summary */}
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">Data Type:</span>
                    <span className="ml-2 font-medium">
                      {DATA_TYPES.find(d => d.id === dataType)?.name}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Protection:</span>
                    <span className="ml-2 font-medium">
                      {THREAT_LEVELS.find(t => t.id === threatLevel)?.name}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Compliance:</span>
                    <span className="ml-2 font-medium">
                      {compliance.filter(c => c !== "none").join(", ") || "None"}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Access Pattern:</span>
                    <span className="ml-2 font-medium">
                      {ACCESS_PATTERNS.find(a => a.id === accessPattern)?.name}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* What Happens Next */}
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">What happens when you publish?</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3 text-sm">
                  <div className="flex items-start gap-3">
                    <div className="w-6 h-6 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center">
                      <Check className="h-4 w-4 text-green-600" />
                    </div>
                    <div>
                      <span className="font-medium">Context "{contextName}" is created</span>
                      <p className="text-muted-foreground">With the optimal algorithm configuration</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <div className="w-6 h-6 rounded-full bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center">
                      <Eye className="h-4 w-4 text-blue-600" />
                    </div>
                    <div>
                      <span className="font-medium">Developers see it in their dashboard</span>
                      <p className="text-muted-foreground">They can select this context when creating identities</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <div className="w-6 h-6 rounded-full bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center">
                      <Shield className="h-4 w-4 text-purple-600" />
                    </div>
                    <div>
                      <span className="font-medium">Policy enforcement begins</span>
                      <p className="text-muted-foreground">All operations are validated against this policy</p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {error && (
              <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-red-600 dark:text-red-400">
                {error}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Navigation */}
      <div className="flex justify-center gap-4 mt-8">
        {step > 1 && (
          <Button variant="outline" onClick={() => setStep(step - 1)}>
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back
          </Button>
        )}
        {step < totalSteps ? (
          <Button size="lg" onClick={nextStep} disabled={!canProceed()}>
            Continue
            <ArrowRight className="ml-2 h-4 w-4" />
          </Button>
        ) : (
          <Button
            size="lg"
            onClick={handlePublish}
            disabled={creating || !canProceed()}
            className="bg-green-600 hover:bg-green-700"
          >
            {creating ? (
              <>Publishing...</>
            ) : (
              <>
                <Send className="mr-2 h-4 w-4" />
                Publish Policy
              </>
            )}
          </Button>
        )}
      </div>
    </AdminLayout>
  );
}
