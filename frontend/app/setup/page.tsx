"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  Shield,
  Building2,
  Users,
  Mail,
  Check,
  ChevronRight,
  ChevronLeft,
  Plus,
  X,
  Loader2,
  Github,
  Globe,
  AlertCircle,
} from "lucide-react";
import {
  getSetupStatus,
  completeSetup,
  createInvitation,
  SetupStatus,
  Invitation,
} from "@/lib/api";

const STEPS = [
  { id: "welcome", title: "Welcome", icon: Building2 },
  { id: "access", title: "Access Control", icon: Users },
  { id: "invite", title: "Invite Team", icon: Mail },
  { id: "review", title: "Review", icon: Check },
];

const PROVISIONING_MODES = [
  {
    value: "domain",
    label: "Domain-based",
    description: "Users with matching email domains can join automatically",
  },
  {
    value: "github_org",
    label: "GitHub Organization",
    description: "Users from specified GitHub organizations can join automatically",
  },
  {
    value: "domain_and_github",
    label: "Domain or GitHub",
    description: "Users can join if they match domain OR GitHub org",
  },
  {
    value: "invitation_only",
    label: "Invitation Only",
    description: "Only invited users can join",
  },
];

const ROLES = [
  { value: "developer", label: "Developer", description: "Can create and manage contexts, keys, applications" },
  { value: "viewer", label: "Viewer", description: "Read-only access to all resources" },
];

export default function SetupWizard() {
  const router = useRouter();
  const [step, setStep] = useState(0);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Form state
  const [organizationName, setOrganizationName] = useState("");
  const [provisioningMode, setProvisioningMode] = useState("domain");
  const [allowedDomains, setAllowedDomains] = useState<string[]>([]);
  const [newDomain, setNewDomain] = useState("");
  const [allowedGithubOrgs, setAllowedGithubOrgs] = useState<string[]>([]);
  const [newGithubOrg, setNewGithubOrg] = useState("");
  const [defaultRole, setDefaultRole] = useState("developer");
  const [inviteEmails, setInviteEmails] = useState("");
  const [inviteRole, setInviteRole] = useState("developer");
  const [invitationResults, setInvitationResults] = useState<Array<{email: string; success: boolean; error?: string}>>([]);

  useEffect(() => {
    checkSetup();
  }, []);

  async function checkSetup() {
    try {
      const status = await getSetupStatus();
      if (status.setupCompleted) {
        router.push("/dashboard");
        return;
      }

      // Pre-populate with existing settings
      if (status.organizationName) setOrganizationName(status.organizationName);
      if (status.allowedDomains.length) setAllowedDomains(status.allowedDomains);
      if (status.allowedGithubOrgs.length) setAllowedGithubOrgs(status.allowedGithubOrgs);
      if (status.provisioningMode) setProvisioningMode(status.provisioningMode);
      if (status.defaultRole) setDefaultRole(status.defaultRole);

      setLoading(false);
    } catch (err) {
      // If we get an auth error, redirect to login
      router.push("/");
    }
  }

  function addDomain() {
    const domain = newDomain.trim().toLowerCase();
    if (domain && !allowedDomains.includes(domain)) {
      setAllowedDomains([...allowedDomains, domain]);
      setNewDomain("");
    }
  }

  function removeDomain(domain: string) {
    setAllowedDomains(allowedDomains.filter(d => d !== domain));
  }

  function addGithubOrg() {
    const org = newGithubOrg.trim();
    if (org && !allowedGithubOrgs.includes(org)) {
      setAllowedGithubOrgs([...allowedGithubOrgs, org]);
      setNewGithubOrg("");
    }
  }

  function removeGithubOrg(org: string) {
    setAllowedGithubOrgs(allowedGithubOrgs.filter(o => o !== org));
  }

  async function sendInvitations() {
    const emails = inviteEmails
      .split(/[,\n]/)
      .map(e => e.trim().toLowerCase())
      .filter(e => e && e.includes("@"));

    const results: Array<{email: string; success: boolean; error?: string}> = [];

    for (const email of emails) {
      try {
        await createInvitation({ email, role: inviteRole });
        results.push({ email, success: true });
      } catch (err: any) {
        results.push({ email, success: false, error: err.message });
      }
    }

    setInvitationResults(results);
  }

  async function handleComplete() {
    setSaving(true);
    setError(null);

    try {
      await completeSetup({
        organizationName: organizationName || undefined,
        allowedDomains,
        allowedGithubOrgs,
        provisioningMode,
        defaultRole,
      });

      // Send any pending invitations
      if (inviteEmails.trim()) {
        await sendInvitations();
      }

      router.push("/dashboard");
    } catch (err: any) {
      setError(err.message || "Failed to complete setup");
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-800 flex items-center justify-center">
        <Loader2 className="h-8 w-8 text-blue-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-900 to-slate-800">
      {/* Header */}
      <div className="border-b border-slate-700/50 bg-slate-900/50 backdrop-blur">
        <div className="max-w-4xl mx-auto px-6 py-4 flex items-center gap-3">
          <div className="p-2 bg-blue-500/20 rounded-lg">
            <Shield className="h-6 w-6 text-blue-400" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-white">CryptoServe Setup</h1>
            <p className="text-sm text-slate-400">Configure your organization</p>
          </div>
        </div>
      </div>

      <div className="max-w-4xl mx-auto px-6 py-8">
        {/* Progress Steps */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            {STEPS.map((s, i) => {
              const Icon = s.icon;
              const isActive = i === step;
              const isComplete = i < step;

              return (
                <div key={s.id} className="flex items-center">
                  <div
                    className={`flex items-center justify-center w-10 h-10 rounded-full border-2 transition-colors ${
                      isComplete
                        ? "bg-green-500 border-green-500"
                        : isActive
                        ? "border-blue-500 bg-blue-500/20"
                        : "border-slate-600"
                    }`}
                  >
                    {isComplete ? (
                      <Check className="h-5 w-5 text-white" />
                    ) : (
                      <Icon
                        className={`h-5 w-5 ${isActive ? "text-blue-400" : "text-slate-500"}`}
                      />
                    )}
                  </div>
                  <span
                    className={`ml-2 text-sm font-medium ${
                      isActive ? "text-white" : "text-slate-500"
                    }`}
                  >
                    {s.title}
                  </span>
                  {i < STEPS.length - 1 && (
                    <div
                      className={`w-16 h-0.5 mx-4 ${
                        isComplete ? "bg-green-500" : "bg-slate-700"
                      }`}
                    />
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Error Banner */}
        {error && (
          <div className="mb-6 bg-red-500/20 border border-red-500/50 rounded-lg p-4 flex items-start gap-3">
            <AlertCircle className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
            <p className="text-sm text-red-200">{error}</p>
            <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300 ml-auto">
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* Step Content */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
          {/* Step 1: Welcome */}
          {step === 0 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-semibold text-white mb-2">Welcome to CryptoServe</h2>
                <p className="text-slate-400">
                  Let&apos;s set up your organization. This wizard will help you configure access control
                  and invite your team.
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Organization Name (optional)
                </label>
                <input
                  type="text"
                  value={organizationName}
                  onChange={(e) => setOrganizationName(e.target.value)}
                  placeholder="Acme Corp"
                  className="w-full px-4 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
                <p className="mt-1.5 text-xs text-slate-500">
                  Used for branding in the dashboard
                </p>
              </div>
            </div>
          )}

          {/* Step 2: Access Control */}
          {step === 1 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-semibold text-white mb-2">Access Control</h2>
                <p className="text-slate-400">
                  Configure how users can join your organization.
                </p>
              </div>

              {/* Provisioning Mode */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-3">
                  Provisioning Mode
                </label>
                <div className="space-y-2">
                  {PROVISIONING_MODES.map((mode) => (
                    <label
                      key={mode.value}
                      className={`flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                        provisioningMode === mode.value
                          ? "border-blue-500 bg-blue-500/10"
                          : "border-slate-600 hover:border-slate-500"
                      }`}
                    >
                      <input
                        type="radio"
                        name="provisioning"
                        value={mode.value}
                        checked={provisioningMode === mode.value}
                        onChange={(e) => setProvisioningMode(e.target.value)}
                        className="mt-1"
                      />
                      <div>
                        <div className="text-sm font-medium text-white">{mode.label}</div>
                        <div className="text-xs text-slate-400">{mode.description}</div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              {/* Allowed Domains */}
              {(provisioningMode === "domain" || provisioningMode === "domain_and_github") && (
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    <Globe className="h-4 w-4 inline mr-1.5" />
                    Allowed Email Domains
                  </label>
                  <div className="flex gap-2 mb-2">
                    <input
                      type="text"
                      value={newDomain}
                      onChange={(e) => setNewDomain(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addDomain())}
                      placeholder="example.com"
                      className="flex-1 px-3 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <button
                      onClick={addDomain}
                      className="px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-500 transition-colors"
                    >
                      <Plus className="h-5 w-5" />
                    </button>
                  </div>
                  {allowedDomains.length > 0 && (
                    <div className="flex flex-wrap gap-2">
                      {allowedDomains.map((domain) => (
                        <span
                          key={domain}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-slate-700 rounded-full text-sm text-slate-300"
                        >
                          {domain}
                          <button
                            onClick={() => removeDomain(domain)}
                            className="text-slate-400 hover:text-red-400"
                          >
                            <X className="h-3.5 w-3.5" />
                          </button>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Allowed GitHub Orgs */}
              {(provisioningMode === "github_org" || provisioningMode === "domain_and_github") && (
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    <Github className="h-4 w-4 inline mr-1.5" />
                    Allowed GitHub Organizations
                  </label>
                  <div className="flex gap-2 mb-2">
                    <input
                      type="text"
                      value={newGithubOrg}
                      onChange={(e) => setNewGithubOrg(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addGithubOrg())}
                      placeholder="my-org"
                      className="flex-1 px-3 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <button
                      onClick={addGithubOrg}
                      className="px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-500 transition-colors"
                    >
                      <Plus className="h-5 w-5" />
                    </button>
                  </div>
                  {allowedGithubOrgs.length > 0 && (
                    <div className="flex flex-wrap gap-2">
                      {allowedGithubOrgs.map((org) => (
                        <span
                          key={org}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-slate-700 rounded-full text-sm text-slate-300"
                        >
                          {org}
                          <button
                            onClick={() => removeGithubOrg(org)}
                            className="text-slate-400 hover:text-red-400"
                          >
                            <X className="h-3.5 w-3.5" />
                          </button>
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Default Role */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Default Role for Auto-Provisioned Users
                </label>
                <select
                  value={defaultRole}
                  onChange={(e) => setDefaultRole(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  {ROLES.map((role) => (
                    <option key={role.value} value={role.value}>
                      {role.label} - {role.description}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          )}

          {/* Step 3: Invite Team */}
          {step === 2 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-semibold text-white mb-2">Invite Your Team</h2>
                <p className="text-slate-400">
                  Invite team members by email. They&apos;ll receive a link to join.
                  You can skip this step and invite later.
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Email Addresses
                </label>
                <textarea
                  value={inviteEmails}
                  onChange={(e) => setInviteEmails(e.target.value)}
                  placeholder="user1@example.com&#10;user2@example.com"
                  rows={4}
                  className="w-full px-4 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                />
                <p className="mt-1.5 text-xs text-slate-500">
                  Enter one email per line or separate with commas
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Role for Invited Users
                </label>
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  {ROLES.map((role) => (
                    <option key={role.value} value={role.value}>
                      {role.label}
                    </option>
                  ))}
                  <option value="admin">Admin - Full control except billing</option>
                </select>
              </div>

              {/* Invitation Results */}
              {invitationResults.length > 0 && (
                <div className="space-y-2">
                  <label className="block text-sm font-medium text-slate-300">Results</label>
                  {invitationResults.map((result, i) => (
                    <div
                      key={i}
                      className={`p-2 rounded-lg text-sm ${
                        result.success
                          ? "bg-green-500/20 text-green-300"
                          : "bg-red-500/20 text-red-300"
                      }`}
                    >
                      {result.email}: {result.success ? "Invited" : result.error}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Step 4: Review */}
          {step === 3 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-semibold text-white mb-2">Review & Complete</h2>
                <p className="text-slate-400">
                  Review your settings before completing the setup.
                </p>
              </div>

              <div className="space-y-4">
                {organizationName && (
                  <div className="flex justify-between items-center py-2 border-b border-slate-700">
                    <span className="text-slate-400">Organization</span>
                    <span className="text-white font-medium">{organizationName}</span>
                  </div>
                )}

                <div className="flex justify-between items-center py-2 border-b border-slate-700">
                  <span className="text-slate-400">Provisioning Mode</span>
                  <span className="text-white font-medium">
                    {PROVISIONING_MODES.find(m => m.value === provisioningMode)?.label}
                  </span>
                </div>

                {allowedDomains.length > 0 && (
                  <div className="flex justify-between items-start py-2 border-b border-slate-700">
                    <span className="text-slate-400">Allowed Domains</span>
                    <div className="text-right">
                      {allowedDomains.map((d) => (
                        <div key={d} className="text-white">{d}</div>
                      ))}
                    </div>
                  </div>
                )}

                {allowedGithubOrgs.length > 0 && (
                  <div className="flex justify-between items-start py-2 border-b border-slate-700">
                    <span className="text-slate-400">GitHub Organizations</span>
                    <div className="text-right">
                      {allowedGithubOrgs.map((o) => (
                        <div key={o} className="text-white">{o}</div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex justify-between items-center py-2 border-b border-slate-700">
                  <span className="text-slate-400">Default Role</span>
                  <span className="text-white font-medium capitalize">{defaultRole}</span>
                </div>

                {inviteEmails.trim() && (
                  <div className="flex justify-between items-center py-2 border-b border-slate-700">
                    <span className="text-slate-400">Pending Invitations</span>
                    <span className="text-white font-medium">
                      {inviteEmails.split(/[,\n]/).filter(e => e.trim()).length} users
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Navigation Buttons */}
          <div className="flex justify-between mt-8 pt-6 border-t border-slate-700">
            <button
              onClick={() => setStep(step - 1)}
              disabled={step === 0}
              className="flex items-center gap-2 px-4 py-2 text-slate-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft className="h-4 w-4" />
              Back
            </button>

            {step < STEPS.length - 1 ? (
              <button
                onClick={() => setStep(step + 1)}
                className="flex items-center gap-2 px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-500 transition-colors"
              >
                Next
                <ChevronRight className="h-4 w-4" />
              </button>
            ) : (
              <button
                onClick={handleComplete}
                disabled={saving}
                className="flex items-center gap-2 px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-500 disabled:opacity-50 transition-colors"
              >
                {saving ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Completing...
                  </>
                ) : (
                  <>
                    <Check className="h-4 w-4" />
                    Complete Setup
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
