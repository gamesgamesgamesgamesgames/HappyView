"use client";

import { useCallback, useEffect, useState } from "react";
import { Copy, Check, Trash2, Pencil } from "lucide-react";

import { useAuth } from "@/lib/auth-context";
import { useCurrentUser } from "@/hooks/use-current-user";
import {
  getScriptVariables,
  upsertScriptVariable,
  deleteScriptVariable,
  getApiKeys,
  createApiKey,
  revokeApiKey,
} from "@/lib/api";
import type { ScriptVariableSummary } from "@/types/script-variables";
import type { ApiKeySummary, CreateApiKeyResponse } from "@/types/api-keys";
import { SiteHeader } from "@/components/site-header";
import { Button } from "@/components/ui/button";
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
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";

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

export default function SettingsPage() {
  const { getToken } = useAuth();
  const { hasPermission } = useCurrentUser();
  const [vars, setVars] = useState<ScriptVariableSummary[]>([]);
  const [keys, setKeys] = useState<ApiKeySummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  const loadVars = useCallback(() => {
    getScriptVariables(getToken)
      .then(setVars)
      .catch((e) => setError(e.message));
  }, [getToken]);

  const loadKeys = useCallback(() => {
    getApiKeys(getToken)
      .then(setKeys)
      .catch((e) => setError(e.message));
  }, [getToken]);

  useEffect(() => {
    loadVars();
    loadKeys();
  }, [loadVars, loadKeys]);

  async function handleDeleteVar(key: string) {
    try {
      await deleteScriptVariable(getToken, key);
      loadVars();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function handleRevoke(id: string) {
    try {
      await revokeApiKey(getToken, id);
      loadKeys();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <>
      <SiteHeader title="Settings" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        <Tabs defaultValue={hasPermission("script-variables:read") ? "env-variables" : "api-keys"}>
          <TabsList>
            {hasPermission("script-variables:read") && (
              <TabsTrigger value="env-variables">ENV Variables</TabsTrigger>
            )}
            <TabsTrigger value="api-keys">API Keys</TabsTrigger>
          </TabsList>

          <TabsContent value="env-variables" className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold">Script Variables</h2>
                <p className="text-muted-foreground text-sm">
                  Define variables that Lua scripts can access via the{" "}
                  <code className="text-xs">env</code> global table.
                </p>
              </div>
              {hasPermission("script-variables:create") && (
                <UpsertVariableDialog getToken={getToken} onSuccess={loadVars} />
              )}
            </div>

            <div className="overflow-clip rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Key</TableHead>
                    <TableHead>Preview</TableHead>
                    <TableHead>Updated</TableHead>
                    <TableHead className="w-20 sticky right-0 bg-inherit z-[1]" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {vars.length === 0 && (
                    <TableRow>
                      <TableCell
                        colSpan={4}
                        className="text-muted-foreground text-center"
                      >
                        No script variables yet.
                      </TableCell>
                    </TableRow>
                  )}
                  {vars.map((v) => (
                    <TableRow key={v.key}>
                      <TableCell className="font-mono text-sm">
                        {v.key}
                      </TableCell>
                      <TableCell className="font-mono text-sm text-muted-foreground">
                        {v.preview}
                      </TableCell>
                      <TableCell>
                        {new Date(v.updated_at).toLocaleString()}
                      </TableCell>
                      <TableCell className="w-20 sticky right-0 bg-inherit z-[1]">
                        <div className="flex gap-1">
                          <UpsertVariableDialog
                            getToken={getToken}
                            onSuccess={loadVars}
                            editKey={v.key}
                          />
                          {hasPermission("script-variables:delete") && (
                            <Button
                              variant="destructive"
                              size="icon"
                              className="size-8 text-muted-foreground hover:text-destructive"
                              title="Delete variable"
                              aria-label="Delete variable"
                              onClick={() => handleDeleteVar(v.key)}
                            >
                              <Trash2 className="size-4" />
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </TabsContent>

          <TabsContent value="api-keys" className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">API Keys</h2>
              {hasPermission("api-keys:create") && (
                <CreateApiKeyDialog getToken={getToken} onSuccess={loadKeys} />
              )}
            </div>

            <div className="overflow-clip rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Key</TableHead>
                    <TableHead>Permissions</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Last Used</TableHead>
                    <TableHead className="w-10 sticky right-0 bg-inherit z-[1]" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {keys.length === 0 && (
                    <TableRow>
                      <TableCell
                        colSpan={6}
                        className="text-muted-foreground text-center"
                      >
                        No API keys yet.
                      </TableCell>
                    </TableRow>
                  )}
                  {keys.map((key) => (
                    <TableRow
                      key={key.id}
                      className={key.revoked_at ? "opacity-50" : undefined}
                    >
                      <TableCell
                        className={key.revoked_at ? "line-through" : undefined}
                      >
                        {key.name}
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {key.key_prefix}...
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">
                          {key.permissions?.length ?? 0} perms
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {new Date(key.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        {key.last_used_at
                          ? new Date(key.last_used_at).toLocaleString()
                          : "Never"}
                      </TableCell>
                      <TableCell className="w-10 sticky right-0 bg-inherit z-[1]">
                        {!key.revoked_at && hasPermission("api-keys:delete") && (
                          <ResponsiveDialog>
                            <ResponsiveDialogTrigger asChild>
                              <Button variant="outline" size="sm">
                                Revoke
                              </Button>
                            </ResponsiveDialogTrigger>
                            <ResponsiveDialogContent>
                              <ResponsiveDialogHeader>
                                <ResponsiveDialogTitle>
                                  Revoke API Key
                                </ResponsiveDialogTitle>
                                <ResponsiveDialogDescription>
                                  This will permanently revoke the key &ldquo;
                                  {key.name}&rdquo;. Any services using this key
                                  will lose access.
                                </ResponsiveDialogDescription>
                              </ResponsiveDialogHeader>
                              <ResponsiveDialogFooter>
                                <ResponsiveDialogClose asChild>
                                  <Button variant="outline">Cancel</Button>
                                </ResponsiveDialogClose>
                                <ResponsiveDialogClose asChild>
                                  <Button
                                    variant="destructive"
                                    onClick={() => handleRevoke(key.id)}
                                  >
                                    Revoke
                                  </Button>
                                </ResponsiveDialogClose>
                              </ResponsiveDialogFooter>
                            </ResponsiveDialogContent>
                          </ResponsiveDialog>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </>
  );
}

function UpsertVariableDialog({
  getToken,
  onSuccess,
  editKey,
}: {
  getToken: () => Promise<string | null>;
  onSuccess: () => void;
  editKey?: string;
}) {
  const [key, setKey] = useState(editKey ?? "");
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  const isEdit = !!editKey;

  async function handleSave() {
    setError(null);
    try {
      await upsertScriptVariable(getToken, {
        key: isEdit ? editKey : key,
        value,
      });
      setKey(editKey ?? "");
      setValue("");
      setOpen(false);
      onSuccess();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <ResponsiveDialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) {
          setKey(editKey ?? "");
          setValue("");
          setError(null);
        }
      }}
    >
      <ResponsiveDialogTrigger asChild>
        {isEdit ? (
          <Button
            variant="ghost"
            size="icon"
            className="size-8"
            title="Edit variable"
            aria-label="Edit variable"
          >
            <Pencil className="size-4" />
          </Button>
        ) : (
          <Button>Add Variable</Button>
        )}
      </ResponsiveDialogTrigger>
      <ResponsiveDialogContent>
        <ResponsiveDialogHeader>
          <ResponsiveDialogTitle>
            {isEdit ? "Edit Variable" : "Add Variable"}
          </ResponsiveDialogTitle>
          <ResponsiveDialogDescription>
            {isEdit
              ? "Update the value for this script variable."
              : "Add a new script variable accessible via env.KEY in Lua scripts."}
          </ResponsiveDialogDescription>
        </ResponsiveDialogHeader>
        <div className="flex flex-col gap-4">
          {error && <p className="text-destructive text-sm">{error}</p>}
          <div className="flex flex-col gap-2">
            <Label htmlFor="var-key">Key</Label>
            <Input
              id="var-key"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="VARIABLE_NAME"
              disabled={isEdit}
              className={isEdit ? "font-mono" : ""}
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="var-value">Value</Label>
            <Textarea
              id="var-value"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="Enter value..."
              rows={3}
            />
          </div>
        </div>
        <ResponsiveDialogFooter>
          <ResponsiveDialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </ResponsiveDialogClose>
          <Button onClick={handleSave}>Save</Button>
        </ResponsiveDialogFooter>
      </ResponsiveDialogContent>
    </ResponsiveDialog>
  );
}

function CreateApiKeyDialog({
  getToken,
  onSuccess,
}: {
  getToken: () => Promise<string | null>;
  onSuccess: () => void;
}) {
  const [name, setName] = useState("");
  const [selectedPermissions, setSelectedPermissions] =
    useState<string[]>(ALL_PERMISSIONS);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [createdKey, setCreatedKey] = useState<CreateApiKeyResponse | null>(
    null
  );
  const [copied, setCopied] = useState(false);

  function handleOpenChange(nextOpen: boolean) {
    setOpen(nextOpen);
    if (!nextOpen) {
      setName("");
      setSelectedPermissions(ALL_PERMISSIONS);
      setError(null);
      if (createdKey) {
        setCreatedKey(null);
        onSuccess();
      }
    }
  }

  function togglePermission(perm: string) {
    setSelectedPermissions((prev) =>
      prev.includes(perm) ? prev.filter((p) => p !== perm) : [...prev, perm]
    );
  }

  function toggleCategory(perms: string[]) {
    const allSelected = perms.every((p) => selectedPermissions.includes(p));
    if (allSelected) {
      setSelectedPermissions((prev) => prev.filter((p) => !perms.includes(p)));
    } else {
      setSelectedPermissions((prev) => [
        ...prev,
        ...perms.filter((p) => !prev.includes(p)),
      ]);
    }
  }

  async function handleCreate() {
    setError(null);
    try {
      const result = await createApiKey(getToken, {
        name,
        permissions: selectedPermissions,
      });
      setCreatedKey(result);
      setCopied(false);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function handleCopy() {
    if (!createdKey) return;
    await navigator.clipboard.writeText(createdKey.key);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <ResponsiveDialog open={open} onOpenChange={handleOpenChange}>
      <ResponsiveDialogTrigger asChild>
        <Button>Create API Key</Button>
      </ResponsiveDialogTrigger>
      <ResponsiveDialogContent>
        <ResponsiveDialogHeader>
          <ResponsiveDialogTitle>
            {createdKey ? "API Key Created" : "Create API Key"}
          </ResponsiveDialogTitle>
          <ResponsiveDialogDescription>
            {createdKey
              ? "Copy your API key now. It won\u2019t be shown again."
              : "Give this key a name to identify its purpose."}
          </ResponsiveDialogDescription>
        </ResponsiveDialogHeader>

        {createdKey ? (
          <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-2">
              <Label>API Key</Label>
              <div className="flex gap-2">
                <Input
                  readOnly
                  value={createdKey.key}
                  className="font-mono text-sm"
                />
                <Button
                  variant="outline"
                  size="icon"
                  onClick={handleCopy}
                  title="Copy to clipboard"
                >
                  {copied ? (
                    <Check className="size-4" />
                  ) : (
                    <Copy className="size-4" />
                  )}
                </Button>
              </div>
              <p className="text-muted-foreground text-xs">
                Store this key securely. You will not be able to see it again.
              </p>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-4">
            {error && <p className="text-destructive text-sm">{error}</p>}
            <div className="flex flex-col gap-2">
              <Label htmlFor="api-key-name">Name</Label>
              <Input
                id="api-key-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g., CI Deploy"
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label>Permissions</Label>
              <div className="max-h-64 overflow-y-auto rounded-md border p-3 flex flex-col gap-4">
                {Object.entries(PERMISSION_CATEGORIES).map(
                  ([category, perms]) => {
                    const allSelected = perms.every((p) =>
                      selectedPermissions.includes(p)
                    );
                    const someSelected = perms.some((p) =>
                      selectedPermissions.includes(p)
                    );
                    return (
                      <div key={category} className="flex flex-col gap-2">
                        <button
                          type="button"
                          className="flex items-center gap-2 text-left"
                          onClick={() => toggleCategory(perms)}
                        >
                          <Checkbox
                            checked={allSelected}
                            data-state={
                              someSelected && !allSelected
                                ? "indeterminate"
                                : undefined
                            }
                            className="pointer-events-none"
                          />
                          <span className="text-sm font-medium">
                            {category}
                          </span>
                        </button>
                        <div className="ml-6 flex flex-col gap-1.5">
                          {perms.map((perm) => (
                            <label
                              key={perm}
                              className="flex items-center gap-2 cursor-pointer"
                            >
                              <Checkbox
                                checked={selectedPermissions.includes(perm)}
                                onCheckedChange={() => togglePermission(perm)}
                              />
                              <span className="font-mono text-xs">{perm}</span>
                            </label>
                          ))}
                        </div>
                      </div>
                    );
                  }
                )}
              </div>
              <p className="text-muted-foreground text-xs">
                {selectedPermissions.length} of {ALL_PERMISSIONS.length}{" "}
                permissions selected
              </p>
            </div>
          </div>
        )}

        <ResponsiveDialogFooter>
          <ResponsiveDialogClose asChild>
            <Button variant={createdKey ? "default" : "outline"}>
              {createdKey ? "Done" : "Cancel"}
            </Button>
          </ResponsiveDialogClose>
          {!createdKey && (
            <Button onClick={handleCreate} disabled={!name.trim()}>
              Create
            </Button>
          )}
        </ResponsiveDialogFooter>
      </ResponsiveDialogContent>
    </ResponsiveDialog>
  );
}
