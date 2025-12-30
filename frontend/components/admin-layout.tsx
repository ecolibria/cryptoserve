"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Shield,
  LayoutDashboard,
  Users,
  Key,
  FileText,
  Settings,
  BarChart3,
  LogOut,
  Menu,
  X,
  ChevronLeft,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  ClipboardCheck,
  Play,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

interface AdminLayoutProps {
  children: React.ReactNode;
  title?: string;
  subtitle?: string;
  actions?: React.ReactNode;
  refreshInterval?: number; // in seconds, 0 to disable
  onRefresh?: () => void;
}

const adminNavItems = [
  { href: "/admin", label: "Overview", icon: LayoutDashboard },
  { href: "/admin/security", label: "Security", icon: ShieldAlert },
  { href: "/admin/users", label: "Users", icon: Users },
  { href: "/admin/identities", label: "Identities", icon: Key },
  { href: "/admin/policies", label: "Policies", icon: ShieldCheck },
  { href: "/admin/audit", label: "Audit Logs", icon: FileText },
  { href: "/admin/contexts", label: "Contexts", icon: Settings },
  { href: "/admin/compliance", label: "Compliance", icon: ClipboardCheck },
  { href: "/admin/analytics", label: "Analytics", icon: BarChart3 },
  { href: "/admin/playground", label: "Playground", icon: Play },
];

export function AdminLayout({
  children,
  title,
  subtitle,
  actions,
  refreshInterval = 30,
  onRefresh,
}: AdminLayoutProps) {
  const pathname = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<{ github_username: string; avatar_url: string | null; is_admin?: boolean } | null>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const [isRefreshing, setIsRefreshing] = useState(false);

  useEffect(() => {
    api
      .getCurrentUser()
      .then((u) => {
        setUser(u);
        // Redirect non-admins
        if (!u.is_admin) {
          router.push("/dashboard");
        }
      })
      .catch(() => {
        router.push("/");
      });
  }, [router]);

  // Auto-refresh
  useEffect(() => {
    if (refreshInterval <= 0 || !onRefresh) return;

    const timer = setInterval(() => {
      handleRefresh();
    }, refreshInterval * 1000);

    return () => clearInterval(timer);
  }, [refreshInterval, onRefresh]);

  const handleRefresh = async () => {
    if (isRefreshing) return;
    setIsRefreshing(true);
    try {
      await onRefresh?.();
      setLastRefresh(new Date());
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleLogout = async () => {
    await api.logout();
    router.push("/");
  };

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Sidebar - Desktop */}
      <aside className="hidden lg:fixed lg:inset-y-0 lg:z-50 lg:flex lg:w-64 lg:flex-col">
        <div className="flex grow flex-col gap-y-5 overflow-y-auto bg-white border-r border-slate-200 px-6 pb-4">
          {/* Logo */}
          <div className="flex h-16 shrink-0 items-center gap-2">
            <Shield className="h-8 w-8 text-indigo-600" />
            <div>
              <span className="text-xl font-bold text-slate-900">CryptoServe</span>
              <span className="ml-2 px-2 py-0.5 rounded text-xs font-medium bg-indigo-100 text-indigo-700">
                Admin
              </span>
            </div>
          </div>

          {/* Back to Dashboard */}
          <Link
            href="/dashboard"
            className="flex items-center gap-2 text-sm text-slate-500 hover:text-slate-900 transition-colors -mt-2"
          >
            <ChevronLeft className="h-4 w-4" />
            Back to Dashboard
          </Link>

          {/* Navigation */}
          <nav className="flex flex-1 flex-col">
            <ul role="list" className="flex flex-1 flex-col gap-y-1">
              {adminNavItems.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      className={cn(
                        "group flex gap-x-3 rounded-lg p-3 text-base leading-6 font-medium transition-all",
                        isActive
                          ? "bg-indigo-50 text-indigo-700 shadow-sm"
                          : "text-slate-600 hover:text-slate-900 hover:bg-slate-50"
                      )}
                    >
                      <item.icon className={cn("h-5 w-5 shrink-0", isActive ? "text-indigo-600" : "text-slate-400")} />
                      {item.label}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </nav>

          {/* User */}
          <div className="border-t border-slate-200 pt-4">
            <div className="flex items-center gap-3">
              {user.avatar_url ? (
                <img
                  src={user.avatar_url}
                  alt={user.github_username}
                  className="h-8 w-8 rounded-full ring-2 ring-slate-100"
                />
              ) : (
                <div className="h-8 w-8 rounded-full bg-indigo-100 flex items-center justify-center text-indigo-600 text-sm font-medium">
                  {user.github_username[0].toUpperCase()}
                </div>
              )}
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-slate-900 truncate">
                  {user.github_username}
                </p>
                <p className="text-xs text-slate-500">Administrator</p>
              </div>
              <button
                onClick={handleLogout}
                className="text-slate-400 hover:text-slate-600 transition-colors"
              >
                <LogOut className="h-5 w-5" />
              </button>
            </div>
          </div>
        </div>
      </aside>

      {/* Mobile menu */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div
            className="fixed inset-0 bg-slate-900/20"
            onClick={() => setMobileMenuOpen(false)}
          />
          <div className="fixed inset-y-0 left-0 w-64 bg-white border-r border-slate-200 p-6 shadow-lg">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-2">
                <Shield className="h-8 w-8 text-blue-600" />
                <span className="text-xl font-bold text-slate-900">Admin</span>
              </div>
              <button
                onClick={() => setMobileMenuOpen(false)}
                className="text-slate-400 hover:text-slate-600"
              >
                <X className="h-6 w-6" />
              </button>
            </div>
            <nav className="space-y-1">
              {adminNavItems.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={cn(
                      "flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors",
                      isActive
                        ? "bg-blue-50 text-blue-600"
                        : "text-slate-600 hover:text-slate-900 hover:bg-slate-50"
                    )}
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    <item.icon className={cn("h-5 w-5", isActive ? "text-blue-600" : "text-slate-400")} />
                    {item.label}
                  </Link>
                );
              })}
            </nav>
          </div>
        </div>
      )}

      {/* Main content */}
      <div className="lg:pl-64">
        {/* Top bar */}
        <div className="sticky top-0 z-40 flex h-16 shrink-0 items-center gap-x-4 border-b border-slate-200 bg-white px-4 sm:gap-x-6 sm:px-6 lg:px-8">
          <button
            type="button"
            className="lg:hidden text-slate-700"
            onClick={() => setMobileMenuOpen(true)}
          >
            <Menu className="h-6 w-6" />
          </button>

          <div className="flex flex-1 items-center justify-between">
            <div>
              {title && (
                <h1 className="text-xl font-semibold text-slate-900">{title}</h1>
              )}
              {subtitle && (
                <p className="text-base text-slate-500">{subtitle}</p>
              )}
            </div>

            <div className="flex items-center gap-4">
              {/* Last refresh */}
              {onRefresh && (
                <div className="flex items-center gap-2 text-sm text-slate-500">
                  <span className="hidden sm:inline">
                    Updated {lastRefresh.toLocaleTimeString()}
                  </span>
                  <button
                    onClick={handleRefresh}
                    disabled={isRefreshing}
                    className="p-1 hover:bg-slate-100 rounded transition-colors disabled:opacity-50"
                  >
                    <RefreshCw
                      className={cn(
                        "h-4 w-4",
                        isRefreshing && "animate-spin"
                      )}
                    />
                  </button>
                </div>
              )}

              {/* Page actions */}
              {actions}
            </div>
          </div>
        </div>

        {/* Page content */}
        <main className="py-8 px-4 sm:px-6 lg:px-8">{children}</main>
      </div>
    </div>
  );
}
