"use client";

import { useEffect, useState, useCallback } from "react";
import {
  UserPlus,
  Mail,
  X,
  Check,
  Clock,
  Copy,
  ChevronDown,
  ChevronUp,
  Loader2,
  AlertCircle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AdminLayout } from "@/components/admin-layout";
import { SearchInput } from "@/components/ui/search-input";
import { DataTable } from "@/components/ui/data-table";
import {
  api,
  AdminUserSummary,
  createInvitation,
  listInvitations,
  revokeInvitation,
  Invitation,
} from "@/lib/api";
import { cn } from "@/lib/utils";

const ROLES = [
  { value: "viewer", label: "Viewer" },
  { value: "developer", label: "Developer" },
  { value: "admin", label: "Admin" },
];

export default function AdminUsersPage() {
  const [users, setUsers] = useState<AdminUserSummary[]>([]);
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [showInvitations, setShowInvitations] = useState(false);
  const pageSize = 25;

  // Invite modal state
  const [inviteEmails, setInviteEmails] = useState("");
  const [inviteRole, setInviteRole] = useState("developer");
  const [inviting, setInviting] = useState(false);
  const [inviteResults, setInviteResults] = useState<Array<{email: string; success: boolean; error?: string; token?: string}>>([]);
  const [copiedToken, setCopiedToken] = useState<string | null>(null);

  const loadUsers = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.listAllUsers({
        search: search || undefined,
        limit: pageSize,
        offset: page * pageSize,
      });
      setUsers(data);
      setHasMore(data.length === pageSize);
    } catch (error) {
      console.error("Failed to load users:", error);
    } finally {
      setLoading(false);
    }
  }, [search, page]);

  const loadInvitations = useCallback(async () => {
    try {
      const data = await listInvitations("pending");
      setInvitations(data);
    } catch (error) {
      console.error("Failed to load invitations:", error);
    }
  }, []);

  useEffect(() => {
    loadUsers();
    loadInvitations();
  }, [loadUsers, loadInvitations]);

  const handleSearchChange = (value: string) => {
    setSearch(value);
    setPage(0);
  };

  const handleInvite = async () => {
    const emails = inviteEmails
      .split(/[,\n]/)
      .map(e => e.trim().toLowerCase())
      .filter(e => e && e.includes("@"));

    if (emails.length === 0) return;

    setInviting(true);
    const results: Array<{email: string; success: boolean; error?: string; token?: string}> = [];

    for (const email of emails) {
      try {
        const invitation = await createInvitation({ email, role: inviteRole });
        results.push({ email, success: true, token: invitation.token });
      } catch (err: any) {
        results.push({ email, success: false, error: err.message });
      }
    }

    setInviteResults(results);
    setInviting(false);
    loadInvitations();
  };

  const handleRevokeInvitation = async (id: string) => {
    try {
      await revokeInvitation(id);
      loadInvitations();
    } catch (error) {
      console.error("Failed to revoke invitation:", error);
    }
  };

  const copyInviteLink = (token: string) => {
    const link = `${window.location.origin}/?invite=${token}`;
    navigator.clipboard.writeText(link);
    setCopiedToken(token);
    setTimeout(() => setCopiedToken(null), 2000);
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return "Never";
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (hours < 1) return "Just now";
    if (hours < 24) return `${hours}h ago`;
    if (days < 7) return `${days}d ago`;
    return date.toLocaleDateString();
  };

  const formatExpiresAt = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const diff = date.getTime() - now.getTime();
    const days = Math.ceil(diff / (1000 * 60 * 60 * 24));

    if (days < 0) return "Expired";
    if (days === 0) return "Today";
    if (days === 1) return "Tomorrow";
    return `${days} days`;
  };

  const getRoleBadgeColor = (role: string | undefined) => {
    switch (role) {
      case "owner":
        return "bg-purple-100 text-purple-700";
      case "admin":
        return "bg-blue-100 text-blue-700";
      case "developer":
        return "bg-green-100 text-green-700";
      case "viewer":
        return "bg-slate-100 text-slate-600";
      default:
        return "bg-slate-100 text-slate-600";
    }
  };

  const getProvisioningBadge = (source: string | undefined) => {
    switch (source) {
      case "first_user":
        return { label: "First Admin", color: "bg-purple-100 text-purple-700" };
      case "domain":
        return { label: "Auto (Domain)", color: "bg-blue-100 text-blue-700" };
      case "github_org":
        return { label: "Auto (GitHub)", color: "bg-slate-100 text-slate-600" };
      case "invitation":
        return { label: "Invited", color: "bg-green-100 text-green-700" };
      default:
        return { label: "Legacy", color: "bg-slate-100 text-slate-500" };
    }
  };

  const columns = [
    {
      key: "avatar",
      header: "",
      className: "w-12",
      render: (user: AdminUserSummary) => (
        <div className="flex items-center justify-center">
          {user.avatar_url ? (
            <img
              src={user.avatar_url}
              alt={user.github_username}
              className="h-8 w-8 rounded-full"
            />
          ) : (
            <div className="h-8 w-8 rounded-full bg-slate-200 flex items-center justify-center text-slate-600 text-sm font-medium">
              {user.github_username[0].toUpperCase()}
            </div>
          )}
        </div>
      ),
    },
    {
      key: "github_username",
      header: "Username",
      sortable: true,
      render: (user: AdminUserSummary) => (
        <div>
          <span className="font-medium">@{user.github_username}</span>
          {user.email && (
            <div className="text-xs text-slate-500">{user.email}</div>
          )}
        </div>
      ),
    },
    {
      key: "role",
      header: "Role",
      sortable: true,
      render: (user: AdminUserSummary) => {
        const role = user.is_admin ? "admin" : (user as any).role || "developer";
        return (
          <span className={cn(
            "px-2 py-1 rounded text-xs font-medium capitalize",
            getRoleBadgeColor(role)
          )}>
            {role}
          </span>
        );
      },
    },
    {
      key: "provisioning_source",
      header: "Source",
      render: (user: AdminUserSummary) => {
        const badge = getProvisioningBadge((user as any).provisioning_source);
        return (
          <span className={cn(
            "px-2 py-1 rounded text-xs font-medium",
            badge.color
          )}>
            {badge.label}
          </span>
        );
      },
    },
    {
      key: "identity_count",
      header: "Identities",
      sortable: true,
      className: "text-center",
      render: (user: AdminUserSummary) => (
        <span className={cn(
          "px-2 py-1 rounded text-xs font-medium",
          user.identity_count > 0
            ? "bg-green-100 text-green-700"
            : "bg-slate-100 text-slate-600"
        )}>
          {user.identity_count}
        </span>
      ),
    },
    {
      key: "last_login_at",
      header: "Last Active",
      sortable: true,
      render: (user: AdminUserSummary) => (
        <span className="text-slate-600">
          {formatDate(user.last_login_at)}
        </span>
      ),
    },
    {
      key: "created_at",
      header: "Joined",
      sortable: true,
      render: (user: AdminUserSummary) => (
        <span className="text-slate-500 text-xs">
          {new Date(user.created_at).toLocaleDateString()}
        </span>
      ),
    },
  ];

  return (
    <AdminLayout
      title="User Management"
      subtitle={`${users.length} users${search ? ` matching "${search}"` : ""}`}
      onRefresh={() => { loadUsers(); loadInvitations(); }}
      actions={
        <Button onClick={() => setShowInviteModal(true)}>
          <UserPlus className="h-4 w-4 mr-2" />
          Invite Users
        </Button>
      }
    >
      {/* Pending Invitations */}
      {invitations.length > 0 && (
        <Card className="mb-6">
          <CardHeader
            className="cursor-pointer"
            onClick={() => setShowInvitations(!showInvitations)}
          >
            <div className="flex items-center justify-between">
              <CardTitle className="text-base flex items-center gap-2">
                <Mail className="h-4 w-4" />
                Pending Invitations ({invitations.length})
              </CardTitle>
              {showInvitations ? (
                <ChevronUp className="h-4 w-4 text-slate-500" />
              ) : (
                <ChevronDown className="h-4 w-4 text-slate-500" />
              )}
            </div>
          </CardHeader>
          {showInvitations && (
            <CardContent>
              <div className="space-y-2">
                {invitations.map((inv) => (
                  <div
                    key={inv.id}
                    className="flex items-center justify-between p-3 bg-slate-50 rounded-lg"
                  >
                    <div>
                      <div className="font-medium text-sm">{inv.email}</div>
                      <div className="text-xs text-slate-500">
                        Role: {inv.role} &middot; Expires: {formatExpiresAt(inv.expiresAt)} &middot; Invited by @{inv.invitedBy}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyInviteLink(inv.token)}
                        className="text-xs"
                      >
                        {copiedToken === inv.token ? (
                          <Check className="h-3 w-3 mr-1 text-green-600" />
                        ) : (
                          <Copy className="h-3 w-3 mr-1" />
                        )}
                        Copy Link
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleRevokeInvitation(inv.id)}
                        className="text-xs text-red-600 hover:text-red-700 hover:bg-red-50"
                      >
                        <X className="h-3 w-3 mr-1" />
                        Revoke
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          )}
        </Card>
      )}

      {/* Search */}
      <div className="mb-6 flex items-center gap-4">
        <SearchInput
          placeholder="Search users by username or email..."
          value={search}
          onChange={handleSearchChange}
          className="max-w-md"
        />
      </div>

      {/* Users Table */}
      <Card>
        <CardContent className="p-0">
          <DataTable
            data={users}
            columns={columns}
            keyField="id"
            loading={loading}
            emptyMessage={search ? `No users found matching "${search}"` : "No users yet"}
          />
        </CardContent>
      </Card>

      {/* Pagination */}
      {(page > 0 || hasMore) && (
        <div className="mt-4 flex items-center justify-between">
          <p className="text-sm text-slate-500">
            Showing {page * pageSize + 1} - {page * pageSize + users.length} users
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(p => p - 1)}
              disabled={page === 0}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPage(p => p + 1)}
              disabled={!hasMore}
            >
              Next
            </Button>
          </div>
        </div>
      )}

      {/* Invite Modal */}
      {showInviteModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-xl max-w-lg w-full mx-4 max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">Invite Users</h2>
                <button
                  onClick={() => {
                    setShowInviteModal(false);
                    setInviteEmails("");
                    setInviteResults([]);
                  }}
                  className="text-slate-400 hover:text-slate-600"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="p-6 space-y-4">
              {inviteResults.length === 0 ? (
                <>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">
                      Email Addresses
                    </label>
                    <textarea
                      value={inviteEmails}
                      onChange={(e) => setInviteEmails(e.target.value)}
                      placeholder="user1@example.com&#10;user2@example.com"
                      rows={4}
                      className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                    />
                    <p className="mt-1 text-xs text-slate-500">
                      Enter one email per line or separate with commas
                    </p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-1">
                      Role
                    </label>
                    <select
                      value={inviteRole}
                      onChange={(e) => setInviteRole(e.target.value)}
                      className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      {ROLES.map((role) => (
                        <option key={role.value} value={role.value}>
                          {role.label}
                        </option>
                      ))}
                    </select>
                  </div>
                </>
              ) : (
                <div className="space-y-2">
                  <h3 className="font-medium text-sm">Invitation Results</h3>
                  {inviteResults.map((result, i) => (
                    <div
                      key={i}
                      className={cn(
                        "p-3 rounded-lg text-sm",
                        result.success
                          ? "bg-green-50 border border-green-200"
                          : "bg-red-50 border border-red-200"
                      )}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          {result.success ? (
                            <Check className="h-4 w-4 text-green-600" />
                          ) : (
                            <AlertCircle className="h-4 w-4 text-red-600" />
                          )}
                          <span>{result.email}</span>
                        </div>
                        {result.success && result.token && (
                          <button
                            onClick={() => copyInviteLink(result.token!)}
                            className="text-xs text-blue-600 hover:text-blue-700 flex items-center gap-1"
                          >
                            {copiedToken === result.token ? (
                              <Check className="h-3 w-3" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                            Copy Link
                          </button>
                        )}
                      </div>
                      {!result.success && (
                        <p className="text-xs text-red-600 mt-1">{result.error}</p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="p-6 border-t bg-slate-50 flex justify-end gap-3">
              {inviteResults.length === 0 ? (
                <>
                  <Button
                    variant="outline"
                    onClick={() => setShowInviteModal(false)}
                  >
                    Cancel
                  </Button>
                  <Button
                    onClick={handleInvite}
                    disabled={inviting || !inviteEmails.trim()}
                  >
                    {inviting ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Sending...
                      </>
                    ) : (
                      <>
                        <Mail className="h-4 w-4 mr-2" />
                        Send Invitations
                      </>
                    )}
                  </Button>
                </>
              ) : (
                <Button
                  onClick={() => {
                    setShowInviteModal(false);
                    setInviteEmails("");
                    setInviteResults([]);
                  }}
                >
                  Done
                </Button>
              )}
            </div>
          </div>
        </div>
      )}
    </AdminLayout>
  );
}
