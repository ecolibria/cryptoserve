"use client";

import { useState } from "react";
import { Award, FileText, Shield, CheckCircle, XCircle, Download, Copy, Check } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard-layout";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { api, CSRResponse, SelfSignedCertResponse, CertificateInfo } from "@/lib/api";

type Tab = "generate" | "parse" | "verify";

export default function CertificatesPage() {
  const [tab, setTab] = useState<Tab>("generate");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Generate state
  const [generateMode, setGenerateMode] = useState<"csr" | "self-signed">("self-signed");
  const [commonName, setCommonName] = useState("example.com");
  const [organization, setOrganization] = useState("Example Inc");
  const [country, setCountry] = useState("US");
  const [validityDays, setValidityDays] = useState(365);
  const [isCA, setIsCA] = useState(false);
  const [sanDomains, setSanDomains] = useState("www.example.com");
  const [csrResult, setCsrResult] = useState<CSRResponse | null>(null);
  const [certResult, setCertResult] = useState<SelfSignedCertResponse | null>(null);

  // Parse state
  const [certToParse, setCertToParse] = useState("");
  const [parsedCert, setParsedCert] = useState<CertificateInfo | null>(null);

  // Verify state
  const [certToVerify, setCertToVerify] = useState("");
  const [issuerCert, setIssuerCert] = useState("");
  const [verifyResult, setVerifyResult] = useState<{ valid: boolean; errors: string[]; warnings: string[] } | null>(null);

  const handleGenerate = async () => {
    setLoading(true);
    setError(null);
    setCsrResult(null);
    setCertResult(null);

    try {
      const sans = sanDomains.split(",").map(s => s.trim()).filter(Boolean);

      if (generateMode === "csr") {
        const res = await api.generateCSR({
          subject: { common_name: commonName, organization, country },
          san_domains: sans.length > 0 ? sans : undefined,
        });
        setCsrResult(res);
      } else {
        const res = await api.generateSelfSignedCert({
          subject: { common_name: commonName, organization, country },
          validity_days: validityDays,
          is_ca: isCA,
          san_domains: sans.length > 0 ? sans : undefined,
        });
        setCertResult(res);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Generation failed");
    } finally {
      setLoading(false);
    }
  };

  const handleParse = async () => {
    setLoading(true);
    setError(null);
    setParsedCert(null);

    try {
      const res = await api.parseCertificate({ certificate: certToParse });
      setParsedCert(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Parse failed");
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    setLoading(true);
    setError(null);
    setVerifyResult(null);

    try {
      const res = await api.verifyCertificate({
        certificate: certToVerify,
        issuer_certificate: issuerCert || undefined,
      });
      setVerifyResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed");
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <DashboardLayout>
      <div className="space-y-8">
        <div>
          <h1 className="text-2xl font-bold">Certificates</h1>
          <p className="text-slate-600">
            Generate CSRs, self-signed certificates, parse and verify certificates
          </p>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 border-b pb-2">
          <Button
            variant={tab === "generate" ? "default" : "ghost"}
            onClick={() => setTab("generate")}
          >
            <Award className="h-4 w-4 mr-2" />
            Generate
          </Button>
          <Button
            variant={tab === "parse" ? "default" : "ghost"}
            onClick={() => setTab("parse")}
          >
            <FileText className="h-4 w-4 mr-2" />
            Parse
          </Button>
          <Button
            variant={tab === "verify" ? "default" : "ghost"}
            onClick={() => setTab("verify")}
          >
            <Shield className="h-4 w-4 mr-2" />
            Verify
          </Button>
        </div>

        {error && (
          <Card className="border-red-200 bg-red-50">
            <CardContent className="py-4">
              <p className="text-red-700">{error}</p>
            </CardContent>
          </Card>
        )}

        {/* Generate Tab */}
        {tab === "generate" && (
          <div className="grid gap-6 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Generate Certificate</CardTitle>
                <CardDescription>
                  Create a CSR or self-signed certificate
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Type</label>
                  <select
                    className="w-full px-3 py-2 border rounded-lg"
                    value={generateMode}
                    onChange={(e) => setGenerateMode(e.target.value as "csr" | "self-signed")}
                  >
                    <option value="self-signed">Self-Signed Certificate</option>
                    <option value="csr">Certificate Signing Request (CSR)</option>
                  </select>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Common Name (CN)</label>
                    <input
                      type="text"
                      className="w-full px-3 py-2 border rounded-lg"
                      value={commonName}
                      onChange={(e) => setCommonName(e.target.value)}
                      placeholder="example.com"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">Organization</label>
                    <input
                      type="text"
                      className="w-full px-3 py-2 border rounded-lg"
                      value={organization}
                      onChange={(e) => setOrganization(e.target.value)}
                      placeholder="Example Inc"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Country</label>
                    <input
                      type="text"
                      className="w-full px-3 py-2 border rounded-lg"
                      value={country}
                      onChange={(e) => setCountry(e.target.value)}
                      placeholder="US"
                      maxLength={2}
                    />
                  </div>
                  {generateMode === "self-signed" && (
                    <div>
                      <label className="block text-sm font-medium mb-1">Validity (days)</label>
                      <input
                        type="number"
                        className="w-full px-3 py-2 border rounded-lg"
                        value={validityDays}
                        onChange={(e) => setValidityDays(parseInt(e.target.value))}
                        min={1}
                        max={3650}
                      />
                    </div>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium mb-1">
                    Subject Alternative Names (comma-separated)
                  </label>
                  <input
                    type="text"
                    className="w-full px-3 py-2 border rounded-lg"
                    value={sanDomains}
                    onChange={(e) => setSanDomains(e.target.value)}
                    placeholder="www.example.com, api.example.com"
                  />
                </div>

                {generateMode === "self-signed" && (
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={isCA}
                      onChange={(e) => setIsCA(e.target.checked)}
                    />
                    <span className="text-sm">Certificate Authority (CA)</span>
                  </label>
                )}

                <Button onClick={handleGenerate} disabled={loading || !commonName}>
                  {loading ? "Generating..." : "Generate"}
                </Button>
              </CardContent>
            </Card>

            {/* Results */}
            <div className="space-y-4">
              {csrResult && (
                <Card>
                  <CardHeader>
                    <CardTitle>CSR Generated</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <div className="flex justify-between items-center mb-1">
                        <label className="text-sm font-medium">CSR</label>
                        <Button variant="ghost" size="sm" onClick={() => copyToClipboard(csrResult.csr_pem)}>
                          {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                        </Button>
                      </div>
                      <textarea
                        readOnly
                        className="w-full h-32 px-3 py-2 border rounded-lg font-mono text-xs bg-slate-50"
                        value={csrResult.csr_pem}
                      />
                    </div>
                    <div>
                      <label className="text-sm font-medium text-red-600">Private Key (KEEP SECRET!)</label>
                      <textarea
                        readOnly
                        className="w-full h-32 px-3 py-2 border border-red-200 rounded-lg font-mono text-xs bg-red-50"
                        value={csrResult.private_key_pem}
                      />
                    </div>
                  </CardContent>
                </Card>
              )}

              {certResult && (
                <Card>
                  <CardHeader>
                    <CardTitle>Certificate Generated</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <div className="flex justify-between items-center mb-1">
                        <label className="text-sm font-medium">Certificate</label>
                        <Button variant="ghost" size="sm" onClick={() => copyToClipboard(certResult.certificate_pem)}>
                          {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                        </Button>
                      </div>
                      <textarea
                        readOnly
                        className="w-full h-32 px-3 py-2 border rounded-lg font-mono text-xs bg-slate-50"
                        value={certResult.certificate_pem}
                      />
                    </div>
                    <div>
                      <label className="text-sm font-medium text-red-600">Private Key (KEEP SECRET!)</label>
                      <textarea
                        readOnly
                        className="w-full h-32 px-3 py-2 border border-red-200 rounded-lg font-mono text-xs bg-red-50"
                        value={certResult.private_key_pem}
                      />
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </div>
        )}

        {/* Parse Tab */}
        {tab === "parse" && (
          <div className="grid gap-6 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Parse Certificate</CardTitle>
                <CardDescription>
                  Extract information from a PEM certificate
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Certificate (PEM)</label>
                  <textarea
                    className="w-full h-48 px-3 py-2 border rounded-lg font-mono text-xs"
                    value={certToParse}
                    onChange={(e) => setCertToParse(e.target.value)}
                    placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                  />
                </div>
                <Button onClick={handleParse} disabled={loading || !certToParse}>
                  {loading ? "Parsing..." : "Parse Certificate"}
                </Button>
              </CardContent>
            </Card>

            {parsedCert && (
              <Card>
                <CardHeader>
                  <CardTitle>Certificate Information</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className={`p-3 rounded-lg ${parsedCert.days_until_expiry < 0 ? "bg-red-50" : parsedCert.days_until_expiry < 30 ? "bg-yellow-50" : "bg-green-50"}`}>
                      <p className="text-sm font-medium">Status</p>
                      <p className={`font-bold ${parsedCert.days_until_expiry < 0 ? "text-red-600" : parsedCert.days_until_expiry < 30 ? "text-yellow-600" : "text-green-600"}`}>
                        {parsedCert.days_until_expiry < 0 ? "Expired" : parsedCert.days_until_expiry < 30 ? `Expires in ${parsedCert.days_until_expiry} days` : "Valid"}
                      </p>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-50">
                      <p className="text-sm font-medium">Type</p>
                      <p className="font-bold">
                        {parsedCert.is_ca ? "CA Certificate" : "End Entity"}
                      </p>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div>
                      <p className="text-sm font-medium text-slate-600">Subject</p>
                      <p className="font-mono text-sm">
                        {Object.entries(parsedCert.subject).map(([k, v]) => `${k}=${v}`).join(", ")}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-slate-600">Issuer</p>
                      <p className="font-mono text-sm">
                        {Object.entries(parsedCert.issuer).map(([k, v]) => `${k}=${v}`).join(", ")}
                      </p>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <p className="text-slate-600">Not Before</p>
                      <p>{new Date(parsedCert.not_before).toLocaleDateString()}</p>
                    </div>
                    <div>
                      <p className="text-slate-600">Not After</p>
                      <p>{new Date(parsedCert.not_after).toLocaleDateString()}</p>
                    </div>
                    <div>
                      <p className="text-slate-600">Algorithm</p>
                      <p>{parsedCert.signature_algorithm}</p>
                    </div>
                    <div>
                      <p className="text-slate-600">Key</p>
                      <p>{parsedCert.key_type.toUpperCase()} {parsedCert.key_size ? `(${parsedCert.key_size} bits)` : ""}</p>
                    </div>
                  </div>

                  {parsedCert.san.length > 0 && (
                    <div>
                      <p className="text-sm font-medium text-slate-600 mb-1">SANs</p>
                      <div className="flex flex-wrap gap-1">
                        {parsedCert.san.map((san) => (
                          <Badge key={san} variant="outline">{san}</Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  <div>
                    <p className="text-sm font-medium text-slate-600 mb-1">Fingerprint (SHA256)</p>
                    <p className="font-mono text-xs break-all bg-slate-50 p-2 rounded">
                      {parsedCert.fingerprint_sha256}
                    </p>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        )}

        {/* Verify Tab */}
        {tab === "verify" && (
          <div className="grid gap-6 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Verify Certificate</CardTitle>
                <CardDescription>
                  Check certificate validity and chain
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Certificate (PEM)</label>
                  <textarea
                    className="w-full h-32 px-3 py-2 border rounded-lg font-mono text-xs"
                    value={certToVerify}
                    onChange={(e) => setCertToVerify(e.target.value)}
                    placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">
                    Issuer Certificate (optional, for chain verification)
                  </label>
                  <textarea
                    className="w-full h-32 px-3 py-2 border rounded-lg font-mono text-xs"
                    value={issuerCert}
                    onChange={(e) => setIssuerCert(e.target.value)}
                    placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                  />
                </div>
                <Button onClick={handleVerify} disabled={loading || !certToVerify}>
                  {loading ? "Verifying..." : "Verify Certificate"}
                </Button>
              </CardContent>
            </Card>

            {verifyResult && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    {verifyResult.valid ? (
                      <CheckCircle className="h-5 w-5 text-green-600" />
                    ) : (
                      <XCircle className="h-5 w-5 text-red-600" />
                    )}
                    Verification Result
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className={`p-4 rounded-lg ${verifyResult.valid ? "bg-green-50" : "bg-red-50"}`}>
                    <p className={`text-lg font-bold ${verifyResult.valid ? "text-green-600" : "text-red-600"}`}>
                      {verifyResult.valid ? "Certificate Valid" : "Certificate Invalid"}
                    </p>
                  </div>

                  {verifyResult.errors.length > 0 && (
                    <div className="mt-4">
                      <p className="text-sm font-medium text-red-600 mb-2">Errors</p>
                      <ul className="space-y-1">
                        {verifyResult.errors.map((err, i) => (
                          <li key={i} className="text-sm text-red-700 flex items-start gap-2">
                            <XCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                            {err}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {verifyResult.warnings.length > 0 && (
                    <div className="mt-4">
                      <p className="text-sm font-medium text-yellow-600 mb-2">Warnings</p>
                      <ul className="space-y-1">
                        {verifyResult.warnings.map((warn, i) => (
                          <li key={i} className="text-sm text-yellow-700 flex items-start gap-2">
                            <span className="text-yellow-500">!</span>
                            {warn}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
