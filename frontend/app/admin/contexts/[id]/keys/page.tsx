"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft,
  Key,
  Shield,
  Clock,
  CheckCircle2,
  AlertTriangle,
  History,
  RefreshCw,
  Settings,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AdminLayout } from "@/components/admin-layout";
import { KeyInfoCard } from "@/components/keys/key-info-card";
import { RotationModal } from "@/components/keys/rotation-modal";
import { KeyHistoryTable } from "@/components/keys/key-history-table";
import {
  api,
  KeyBundle,
  KeyHistoryEntry,
  KeyType,
  ContextFullResponse,
} from "@/lib/api";
import { cn } from "@/lib/utils";

export default function KeyBundlePage() {
  const params = useParams();
  const router = useRouter();
  const contextId = params.id as string;

  const [context, setContext] = useState<ContextFullResponse | null>(null);
  const [keyBundle, setKeyBundle] = useState<KeyBundle | null>(null);
  const [history, setHistory] = useState<KeyHistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [rotatingKey, setRotatingKey] = useState<KeyType | null>(null);

  // Modal state
  const [showRotationModal, setShowRotationModal] = useState(false);
  const [rotationKeyType, setRotationKeyType] = useState<KeyType>("ENCRYPTION");

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      // Load context details
      const contextData = await api.getContextDetail(contextId);
      setContext(contextData);

      // Load key bundle
      const bundleData = await api.getKeyBundle(contextId);
      setKeyBundle(bundleData);
    } catch (error) {
      console.error("Failed to load context:", error);
    } finally {
      setLoading(false);
    }
  }, [contextId]);

  const loadHistory = useCallback(async () => {
    try {
      setHistoryLoading(true);
      const historyData = await api.getKeyHistory(contextId);
      setHistory(historyData);
    } catch (error) {
      console.error("Failed to load history:", error);
    } finally {
      setHistoryLoading(false);
    }
  }, [contextId]);

  useEffect(() => {
    loadData();
    loadHistory();
  }, [loadData, loadHistory]);

  const handleRotate = (keyType: KeyType) => {
    setRotationKeyType(keyType);
    setShowRotationModal(true);
  };

  const handleConfirmRotation = async (reason: string, reencrypt: boolean) => {
    setRotatingKey(rotationKeyType);
    try {
      await api.rotateKey(contextId, {
        keyType: rotationKeyType,
        reason,
        reencryptExistingData: reencrypt,
      });
      // Reload data
      await loadData();
      await loadHistory();
    } catch (error) {
      console.error("Rotation failed:", error);
      // Even on error, reload to show current state
      await loadData();
    } finally {
      setRotatingKey(null);
    }
  };

  const handleEditSchedule = (keyType: KeyType) => {
    // TODO: Implement schedule edit modal
    alert(`Edit schedule for ${keyType} - coming soon`);
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  if (loading) {
    return (
      <AdminLayout title="Key Bundle Management" subtitle="Loading...">
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-slate-600" />
        </div>
      </AdminLayout>
    );
  }

  if (!context || !keyBundle) {
    return (
      <AdminLayout title="Key Bundle Management" subtitle="Context not found">
        <div className="text-center py-12">
          <AlertTriangle className="h-12 w-12 text-amber-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-900 mb-2">Context not found</h3>
          <p className="text-slate-500 mb-4">The requested context could not be loaded.</p>
          <Button onClick={() => router.push("/admin/contexts")}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Contexts
          </Button>
        </div>
      </AdminLayout>
    );
  }

  return (
    <AdminLayout
      title={context.display_name}
      subtitle="Key Bundle Management"
      onRefresh={() => { loadData(); loadHistory(); }}
      actions={
        <Button variant="outline" onClick={() => router.push("/admin/contexts")}>
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back to Contexts
        </Button>
      }
    >
      {/* Bundle Status Banner */}
      <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 mb-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="h-12 w-12 rounded-xl bg-blue-100 flex items-center justify-center">
              <Key className="h-6 w-6 text-blue-600" />
            </div>
            <div>
              <h2 className="font-semibold text-slate-900">{context.display_name}</h2>
              <p className="text-sm text-slate-500 font-mono">{context.name}</p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-4 text-sm">
            <div className="flex items-center gap-2">
              <span className="text-slate-500">Bundle Version:</span>
              <Badge variant="secondary">v{keyBundle.version}</Badge>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-slate-500">Created:</span>
              <span className="font-medium">{formatDate(keyBundle.createdAt)}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-slate-500">Status:</span>
              <Badge variant="success" className="flex items-center gap-1">
                <CheckCircle2 className="h-3 w-3" />
                {keyBundle.status}
              </Badge>
            </div>
          </div>
        </div>
      </div>

      {/* Key Cards Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <KeyInfoCard
          keyInfo={keyBundle.encryptionKey}
          keyType="ENCRYPTION"
          onRotate={() => handleRotate("ENCRYPTION")}
          onEditSchedule={() => handleEditSchedule("ENCRYPTION")}
          isRotating={rotatingKey === "ENCRYPTION"}
        />
        <KeyInfoCard
          keyInfo={keyBundle.macKey}
          keyType="MAC"
          onRotate={() => handleRotate("MAC")}
          onEditSchedule={() => handleEditSchedule("MAC")}
          isRotating={rotatingKey === "MAC"}
        />
        <KeyInfoCard
          keyInfo={keyBundle.signingKey}
          keyType="SIGNING"
          onRotate={() => handleRotate("SIGNING")}
          onEditSchedule={() => handleEditSchedule("SIGNING")}
          isRotating={rotatingKey === "SIGNING"}
        />
      </div>

      {/* Key History */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">
              <History className="h-5 w-5 text-slate-500" />
              Key History
            </CardTitle>
            <Button variant="ghost" size="sm" onClick={loadHistory}>
              <RefreshCw className={cn("h-4 w-4", historyLoading && "animate-spin")} />
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <KeyHistoryTable history={history} isLoading={historyLoading} />
        </CardContent>
      </Card>

      {/* Rotation Modal */}
      <RotationModal
        isOpen={showRotationModal}
        onClose={() => setShowRotationModal(false)}
        onConfirm={handleConfirmRotation}
        keyType={rotationKeyType}
        contextName={context.display_name}
        currentVersion={
          rotationKeyType === "ENCRYPTION"
            ? keyBundle.encryptionKey.version
            : rotationKeyType === "MAC"
            ? keyBundle.macKey.version
            : keyBundle.signingKey.version
        }
      />
    </AdminLayout>
  );
}
