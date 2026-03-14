"use client";

import React, { useCallback, useEffect, useState } from "react";
import { ChevronDown, ChevronRight, Shield, Trash2 } from "lucide-react";

import { useAuth } from "@/lib/auth-context";
import {
  getUsers,
  addUser,
  deleteUser,
  updateUserPermissions,
  transferSuper,
} from "@/lib/api";
import type { UserSummary } from "@/types/users";
import { SiteHeader } from "@/components/site-header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  ResponsiveDialog,
  ResponsiveDialogClose,
  ResponsiveDialogContent,
  ResponsiveDialogDescription,
  ResponsiveDialogFooter,
  ResponsiveDialogHeader,
  ResponsiveDialogTitle,
  ResponsiveDialogTrigger,
} from "@/components/ui/responsive-dialog";

const PERMISSION_CATEGORIES: Record<string, string[]> = {
  Lexicons: ["lexicons:create", "lexicons:read", "lexicons:delete"],
  Records: ["records:read", "records:delete", "records:delete-collection"],
  "Script Variables": [
    "script-variables:create",
    "script-variables:read",
    "script-variables:delete",
  ],
  Users: ["users:create", "users:read", "users:update", "users:delete"],
  "API Keys": ["api-keys:create", "api-keys:read", "api-keys:delete"],
  Backfill: ["backfill:create", "backfill:read"],
  System: ["stats:read", "events:read"],
};

const ALL_PERMISSIONS = Object.values(PERMISSION_CATEGORIES).flat();

const TEMPLATES = [
  { value: "viewer", label: "Viewer" },
  { value: "operator", label: "Operator" },
  { value: "manager", label: "Manager" },
  { value: "full_access", label: "Full Access" },
] as const;

const TEMPLATE_PERMISSIONS: Record<string, string[]> = {
  viewer: ["lexicons:read", "records:read", "script-variables:read", "users:read", "api-keys:read", "backfill:read", "stats:read", "events:read"],
  operator: ["lexicons:read", "records:read", "records:delete", "script-variables:read", "script-variables:create", "users:read", "api-keys:read", "backfill:read", "backfill:create", "stats:read", "events:read"],
  manager: ["lexicons:create", "lexicons:read", "lexicons:delete", "records:read", "records:delete", "records:delete-collection", "script-variables:create", "script-variables:read", "script-variables:delete", "users:read", "api-keys:read", "backfill:create", "backfill:read", "stats:read", "events:read"],
  full_access: ALL_PERMISSIONS,
};

export default function UsersPage() {
  const { getToken, did: currentDid } = useAuth();
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [expandedUserId, setExpandedUserId] = useState<string | null>(null);

  const currentUser = users.find((u) => u.did === currentDid);
  const isCurrentUserSuper = currentUser?.is_super ?? false;

  const load = useCallback(() => {
    getUsers(getToken)
      .then(setUsers)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [getToken]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleDelete(id: string) {
    try {
      await deleteUser(getToken, id);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function handleTogglePermission(
    user: UserSummary,
    permission: string,
    enabled: boolean
  ) {
    const grant: string[] = [];
    const revoke: string[] = [];

    const [ns, action] = permission.split(":");

    if (enabled) {
      grant.push(permission);
      // Adding a write permission also enables its read counterpart
      if (action === "create" || action === "update" || action === "delete") {
        const readPerm = `${ns}:read`;
        if (!user.permissions.includes(readPerm)) {
          grant.push(readPerm);
        }
      }
      // Adding records:delete-collection also enables records:delete
      if (permission === "records:delete-collection" && !user.permissions.includes("records:delete")) {
        grant.push("records:delete");
      }
    } else {
      revoke.push(permission);
      // Removing read also removes all write permissions in the same namespace
      if (action === "read") {
        for (const p of user.permissions) {
          if (p.startsWith(`${ns}:`) && p !== permission) {
            revoke.push(p);
          }
        }
      }
      // Removing records:delete also removes records:delete-collection
      if (permission === "records:delete" && user.permissions.includes("records:delete-collection")) {
        revoke.push("records:delete-collection");
      }
    }

    try {
      const body: { grant?: string[]; revoke?: string[] } = {};
      if (grant.length > 0) body.grant = grant;
      if (revoke.length > 0) body.revoke = revoke;
      await updateUserPermissions(getToken, user.id, body);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function handleTransferSuper(targetUserId: string) {
    try {
      await transferSuper(getToken, { target_user_id: targetUserId });
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <>
      <SiteHeader title="Users" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Users</h2>
          {(isCurrentUserSuper || currentUser?.permissions.includes("users:create")) && (
            <AddUserDialog getToken={getToken} onSuccess={load} />
          )}
        </div>

        <div className="overflow-clip rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-6" />
                <TableHead>DID</TableHead>
                <TableHead>Permissions</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Last Used</TableHead>
                <TableHead className="w-auto sticky right-0 bg-inherit z-[1]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={6}
                    className="text-muted-foreground text-center"
                  >
                    No users yet.
                  </TableCell>
                </TableRow>
              )}
              {users.map((user) => (
                <React.Fragment key={user.id}>
                    <TableRow className="cursor-pointer hover:bg-muted/50">
                      <TableCell className="w-6 pr-0">
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-6"
                            aria-label={
                              expandedUserId === user.id
                                ? "Collapse permissions"
                                : "Expand permissions"
                            }
                            onClick={() =>
                              setExpandedUserId(
                                expandedUserId === user.id ? null : user.id
                              )
                            }
                          >
                            {expandedUserId === user.id ? (
                              <ChevronDown className="size-4" />
                            ) : (
                              <ChevronRight className="size-4" />
                            )}
                          </Button>
                      </TableCell>
                      <TableCell
                        className="font-mono text-sm"
                        onClick={() =>
                          setExpandedUserId(
                            expandedUserId === user.id ? null : user.id
                          )
                        }
                      >
                        <div className="flex items-center gap-2">
                          {user.did}
                          {user.is_super && (
                            <Badge variant="secondary" className="text-xs">
                              Owner
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell
                        onClick={() =>
                          setExpandedUserId(
                            expandedUserId === user.id ? null : user.id
                          )
                        }
                      >
                        {user.is_super
                          ? `${ALL_PERMISSIONS.length}/${ALL_PERMISSIONS.length}`
                          : `${user.permissions.length}/${ALL_PERMISSIONS.length}`}
                      </TableCell>
                      <TableCell
                        onClick={() =>
                          setExpandedUserId(
                            expandedUserId === user.id ? null : user.id
                          )
                        }
                      >
                        {new Date(user.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell
                        onClick={() =>
                          setExpandedUserId(
                            expandedUserId === user.id ? null : user.id
                          )
                        }
                      >
                        {user.last_used_at
                          ? new Date(user.last_used_at).toLocaleString()
                          : "Never"}
                      </TableCell>
                      <TableCell className="sticky right-0 bg-inherit z-[1]">
                        <div className="flex items-center gap-1">
                          {isCurrentUserSuper && (
                            <TransferOwnershipDialog
                              user={user}
                              disabled={user.did === currentDid}
                              onConfirm={() => handleTransferSuper(user.id)}
                            />
                          )}
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-8 text-muted-foreground hover:text-destructive"
                            title="Delete user"
                            aria-label="Delete user"
                            disabled={user.is_super || user.did === currentDid || (!isCurrentUserSuper && !currentUser?.permissions.includes("users:delete"))}
                            onClick={() => handleDelete(user.id)}
                          >
                            <Trash2 className="size-4" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                    {expandedUserId === user.id && (
                      <TableRow className="bg-muted/30 hover:bg-muted/30">
                        <TableCell colSpan={6} className="p-4">
                          <PermissionsPanel
                            user={user}
                            isSelf={user.did === currentDid}
                            currentUserPermissions={currentUser?.permissions ?? []}
                            isCurrentUserSuper={isCurrentUserSuper}
                            onToggle={handleTogglePermission}
                          />
                        </TableCell>
                      </TableRow>
                    )}
                </React.Fragment>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>
    </>
  );
}

function PermissionsPanel({
  user,
  isSelf,
  currentUserPermissions,
  isCurrentUserSuper,
  onToggle,
}: {
  user: UserSummary;
  isSelf: boolean;
  currentUserPermissions: string[];
  isCurrentUserSuper: boolean;
  onToggle: (user: UserSummary, permission: string, enabled: boolean) => void;
}) {
  const canUpdate = isCurrentUserSuper || currentUserPermissions.includes("users:update");

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
      {Object.entries(PERMISSION_CATEGORIES).map(([category, permissions]) => (
        <div key={category} className="flex flex-col gap-2">
          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            {category}
          </p>
          <div className="flex flex-col gap-1.5">
            {permissions.map((perm) => {
              const enabled = user.is_super || user.permissions.includes(perm);
              return (
                <div key={perm} className="flex items-center gap-2">
                  <Switch
                    id={`${user.id}-${perm}`}
                    checked={enabled}
                    disabled={
                      user.is_super ||
                      isSelf ||
                      !canUpdate ||
                      (!isCurrentUserSuper && !currentUserPermissions.includes(perm))
                    }
                    onCheckedChange={(checked) =>
                      onToggle(user, perm, checked)
                    }
                    className="scale-75"
                  />
                  <Label
                    htmlFor={`${user.id}-${perm}`}
                    className="cursor-pointer font-mono text-xs"
                  >
                    {perm}
                  </Label>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

function TransferOwnershipDialog({
  user,
  disabled,
  onConfirm,
}: {
  user: UserSummary;
  disabled?: boolean;
  onConfirm: () => void;
}) {
  const [open, setOpen] = useState(false);

  async function handleConfirm() {
    onConfirm();
    setOpen(false);
  }

  return (
    <ResponsiveDialog open={open} onOpenChange={setOpen}>
      <ResponsiveDialogTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="size-8 text-muted-foreground hover:text-yellow-500"
          title="Transfer ownership to this user"
          aria-label="Transfer ownership to this user"
          disabled={disabled}
        >
          <Shield className="size-4" />
        </Button>
      </ResponsiveDialogTrigger>
      <ResponsiveDialogContent>
        <ResponsiveDialogHeader>
          <ResponsiveDialogTitle>Transfer Ownership</ResponsiveDialogTitle>
          <ResponsiveDialogDescription>
            Are you sure you want to transfer ownership to{" "}
            <span className="font-mono text-sm">{user.did}</span>? You will
            lose your owner privileges and cannot undo this action without their
            cooperation.
          </ResponsiveDialogDescription>
        </ResponsiveDialogHeader>
        <ResponsiveDialogFooter>
          <ResponsiveDialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </ResponsiveDialogClose>
          <Button variant="destructive" onClick={handleConfirm}>
            Transfer
          </Button>
        </ResponsiveDialogFooter>
      </ResponsiveDialogContent>
    </ResponsiveDialog>
  );
}

function AddUserDialog({
  getToken,
  onSuccess,
}: {
  getToken: () => Promise<string | null>;
  onSuccess: () => void;
}) {
  const [did, setDid] = useState("");
  const [template, setTemplate] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  async function handleAdd() {
    setError(null);
    try {
      const body: { did: string; template?: string } = { did };
      if (template) body.template = template;
      await addUser(getToken, body);
      setDid("");
      setTemplate("");
      setOpen(false);
      onSuccess();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <ResponsiveDialog open={open} onOpenChange={setOpen}>
      <ResponsiveDialogTrigger asChild>
        <Button>Add User</Button>
      </ResponsiveDialogTrigger>
      <ResponsiveDialogContent>
        <ResponsiveDialogHeader>
          <ResponsiveDialogTitle>Add User</ResponsiveDialogTitle>
          <ResponsiveDialogDescription>
            Add a new user by their DID and optionally assign a permission
            template.
          </ResponsiveDialogDescription>
        </ResponsiveDialogHeader>
        <div className="flex flex-col gap-4">
          {error && <p className="text-destructive text-sm">{error}</p>}
          <div className="flex flex-col gap-2">
            <Label htmlFor="user-did">DID</Label>
            <Input
              id="user-did"
              value={did}
              onChange={(e) => setDid(e.target.value)}
              placeholder="did:plc:..."
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="user-template">Template</Label>
            <Select value={template} onValueChange={setTemplate}>
              <SelectTrigger id="user-template">
                <SelectValue placeholder="No template (no permissions)" />
              </SelectTrigger>
              <SelectContent>
                {TEMPLATES.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {template && (
            <p className="text-muted-foreground text-xs">
              Grants {TEMPLATE_PERMISSIONS[template]?.length ?? 0} permissions.
            </p>
          )}
        </div>
        <ResponsiveDialogFooter>
          <ResponsiveDialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </ResponsiveDialogClose>
          <Button onClick={handleAdd} disabled={!did.trim()}>
            Add
          </Button>
        </ResponsiveDialogFooter>
      </ResponsiveDialogContent>
    </ResponsiveDialog>
  );
}
