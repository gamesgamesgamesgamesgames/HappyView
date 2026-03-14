"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

import { useCurrentUser } from "@/hooks/use-current-user";

export default function SettingsPage() {
  const router = useRouter();
  const { hasPermission } = useCurrentUser();

  useEffect(() => {
    if (hasPermission("users:read")) {
      router.replace("/settings/users");
    } else if (hasPermission("script-variables:read")) {
      router.replace("/settings/env-variables");
    } else if (hasPermission("api-keys:read")) {
      router.replace("/settings/api-keys");
    }
  }, [router, hasPermission]);

  return null;
}
