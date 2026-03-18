import { useCallback, useEffect, useState } from "react";

import { useAuth } from "@/lib/auth-context";
import { getUsers } from "@/lib/api";
import type { UserSummary } from "@/types/users";

export function useCurrentUser() {
  const { did } = useAuth();
  const [currentUser, setCurrentUser] = useState<UserSummary | null>(null);

  const load = useCallback(() => {
    getUsers()
      .then((users) => setCurrentUser(users.find((u) => u.did === did) ?? null))
      .catch(() => setCurrentUser(null));
  }, [did]);

  useEffect(() => {
    load();
  }, [load]);

  const isSuper = currentUser?.is_super ?? false;

  const hasPermission = useCallback(
    (permission: string) =>
      isSuper || (currentUser?.permissions.includes(permission) ?? false),
    [currentUser, isSuper],
  );

  return { currentUser, isSuper, hasPermission, reload: load };
}
