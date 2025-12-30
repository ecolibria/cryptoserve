"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

export default function PoliciesPage() {
  const router = useRouter();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    // Check if user is admin and redirect accordingly
    api
      .getCurrentUser()
      .then((user) => {
        if (user.is_admin) {
          // Redirect admins to admin policies page
          router.replace("/admin/policies");
        } else {
          // Redirect non-admins to dashboard
          router.replace("/dashboard");
        }
      })
      .catch(() => {
        // Not logged in, go to landing
        router.replace("/");
      })
      .finally(() => setChecking(false));
  }, [router]);

  // Show loading while checking
  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
    </div>
  );
}
