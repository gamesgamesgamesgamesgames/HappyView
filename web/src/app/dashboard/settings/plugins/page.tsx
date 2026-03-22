"use client";

import { useCallback, useEffect, useState } from "react";
import { Plus, Trash2, RefreshCw, ExternalLink, Settings, Loader2, AlertTriangle } from "lucide-react";

import { useCurrentUser } from "@/hooks/use-current-user";
import { getPlugins, addPlugin, removePlugin, reloadPlugin, getPluginSecrets, updatePluginSecrets, previewPlugin, type PluginPreview } from "@/lib/api";
import type { PluginSummary } from "@/types/plugins";
import { SiteHeader } from "@/components/site-header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
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

function formatAuthType(authType: string): string {
  const formats: Record<string, string> = {
    oauth2: "OAuth 2.0",
    openid: "OpenID",
    api_key: "API Key",
  };
  return formats[authType] || authType;
}

export default function PluginsPage() {
  const { hasPermission } = useCurrentUser();
  const [plugins, setPlugins] = useState<PluginSummary[]>([]);
  const [encryptionConfigured, setEncryptionConfigured] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloading, setReloading] = useState<string | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);

  // Add plugin dialog state
  const [addOpen, setAddOpen] = useState(false);
  const [newUrl, setNewUrl] = useState("");
  const [adding, setAdding] = useState(false);
  const [previewing, setPreviewing] = useState(false);
  const [pluginPreview, setPluginPreview] = useState<PluginPreview | null>(null);

  // Configure secrets dialog state
  const [configOpen, setConfigOpen] = useState(false);
  const [configPlugin, setConfigPlugin] = useState<PluginSummary | null>(null);
  const [secretValues, setSecretValues] = useState<Record<string, string>>({});
  const [savingSecrets, setSavingSecrets] = useState(false);

  const canCreate = hasPermission("plugins:create");
  const canDelete = hasPermission("plugins:delete");

  const load = useCallback(async () => {
    try {
      const response = await getPlugins();
      setPlugins(response.plugins);
      setEncryptionConfigured(response.encryption_configured);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function handlePreview() {
    if (!newUrl.trim()) return;

    setPreviewing(true);
    setError(null);
    try {
      const preview = await previewPlugin(newUrl.trim());
      setPluginPreview(preview);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setPreviewing(false);
    }
  }

  async function handleAdd() {
    if (!pluginPreview) return;

    setAdding(true);
    setError(null);
    try {
      await addPlugin({ url: pluginPreview.wasm_url });
      setAddOpen(false);
      setNewUrl("");
      setPluginPreview(null);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setAdding(false);
    }
  }

  function handleCancelAdd() {
    setAddOpen(false);
    setNewUrl("");
    setPluginPreview(null);
    setError(null);
  }

  async function handleReload(id: string) {
    setReloading(id);
    setError(null);
    try {
      await reloadPlugin(id);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setReloading(null);
    }
  }

  async function handleRemove(id: string) {
    setRemoving(id);
    setError(null);
    try {
      await removePlugin(id);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRemoving(null);
    }
  }

  async function handleOpenConfig(plugin: PluginSummary) {
    setConfigPlugin(plugin);
    setError(null);
    try {
      const response = await getPluginSecrets(plugin.id);
      // Initialize with existing secrets (masked) and empty strings for missing ones
      const initial: Record<string, string> = {};
      for (const secret of plugin.required_secrets) {
        initial[secret.key] = response.secrets[secret.key] || "";
      }
      setSecretValues(initial);
      setConfigOpen(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function handleSaveSecrets() {
    if (!configPlugin) return;
    setSavingSecrets(true);
    setError(null);
    try {
      await updatePluginSecrets(configPlugin.id, secretValues);
      setConfigOpen(false);
      setConfigPlugin(null);
      setSecretValues({});
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSavingSecrets(false);
    }
  }

  return (
    <>
      <SiteHeader title="Plugins" />
      <div className="flex flex-1 flex-col gap-6 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        {!encryptionConfigured && (
          <div className="flex items-start gap-3 rounded-lg border border-amber-500/50 bg-amber-500/10 p-4">
            <AlertTriangle className="size-5 text-amber-500 shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-amber-500">Encryption not configured</p>
              <p className="text-sm text-muted-foreground mt-1">
                Plugin secrets cannot be stored without an encryption key. Set the{" "}
                <code className="text-xs bg-muted px-1 py-0.5 rounded">TOKEN_ENCRYPTION_KEY</code>{" "}
                environment variable to a base64-encoded 32-byte key.
              </p>
              <p className="text-sm text-muted-foreground mt-1">
                Generate one with: <code className="text-xs bg-muted px-1 py-0.5 rounded">openssl rand -base64 32</code>
              </p>
            </div>
          </div>
        )}

        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold">External Auth Plugins</h2>
            <p className="text-muted-foreground text-sm">
              Manage WASM plugins that provide authentication with external platforms.
            </p>
          </div>
          {canCreate && (
            <ResponsiveDialog open={addOpen} onOpenChange={(open) => {
              if (!open) handleCancelAdd();
              else setAddOpen(true);
            }}>
              <ResponsiveDialogTrigger asChild>
                <Button size="sm">
                  <Plus className="mr-1 size-4" />
                  Add Plugin
                </Button>
              </ResponsiveDialogTrigger>
              <ResponsiveDialogContent>
                <ResponsiveDialogHeader>
                  <ResponsiveDialogTitle>
                    {pluginPreview ? `Install ${pluginPreview.name}?` : "Add Plugin"}
                  </ResponsiveDialogTitle>
                  <ResponsiveDialogDescription>
                    {pluginPreview
                      ? "Review the plugin details below before installing."
                      : "Enter a plugin URL to preview its details."}
                  </ResponsiveDialogDescription>
                </ResponsiveDialogHeader>

                {!pluginPreview ? (
                  // Step 1: Enter URL
                  <div className="grid gap-4 py-4">
                    <div className="grid gap-2">
                      <Label htmlFor="url">Plugin URL</Label>
                      <Input
                        id="url"
                        placeholder="https://github.com/org/repo/releases/download/v1.0.0/steam.wasm"
                        value={newUrl}
                        onChange={(e) => setNewUrl(e.target.value)}
                        disabled={previewing}
                      />
                      <p className="text-muted-foreground text-xs">
                        Link to the .wasm file or manifest.json (GitHub Releases URL)
                      </p>
                    </div>
                  </div>
                ) : (
                  // Step 2: Show preview
                  <div className="grid gap-4 py-4">
                    <div className="flex items-start gap-4">
                      {pluginPreview.icon_url && (
                        <img
                          src={pluginPreview.icon_url}
                          alt=""
                          className="size-12 rounded"
                        />
                      )}
                      <div className="flex-1">
                        <h3 className="font-semibold">{pluginPreview.name}</h3>
                        <p className="text-muted-foreground text-sm">
                          {pluginPreview.description || `Version ${pluginPreview.version}`}
                        </p>
                      </div>
                      <Badge variant="secondary">{pluginPreview.version}</Badge>
                    </div>

                    <div className="grid gap-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Auth Type</span>
                        <Badge variant="outline">
                          {formatAuthType(pluginPreview.auth_type)}
                        </Badge>
                      </div>
                      {pluginPreview.required_secrets.length > 0 && (
                        <div className="grid gap-2">
                          <span className="text-muted-foreground">Required Configuration</span>
                          <div className="flex flex-col gap-2">
                            {pluginPreview.required_secrets.map((secret) => (
                              <div key={secret.key} className="bg-muted rounded p-2">
                                <div className="flex items-center justify-between">
                                  <span className="font-medium text-sm">{secret.name}</span>
                                  <code className="text-xs text-muted-foreground">{secret.key}</code>
                                </div>
                                {secret.description && (
                                  <p className="text-muted-foreground text-xs mt-1">{secret.description}</p>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                <ResponsiveDialogFooter>
                  {pluginPreview ? (
                    <>
                      <Button
                        variant="outline"
                        onClick={() => setPluginPreview(null)}
                        disabled={adding}
                      >
                        Back
                      </Button>
                      <Button onClick={handleAdd} disabled={adding}>
                        {adding ? (
                          <>
                            <Loader2 className="mr-2 size-4 animate-spin" />
                            Installing...
                          </>
                        ) : (
                          "Install Plugin"
                        )}
                      </Button>
                    </>
                  ) : (
                    <>
                      <ResponsiveDialogClose asChild>
                        <Button variant="outline" disabled={previewing}>
                          Cancel
                        </Button>
                      </ResponsiveDialogClose>
                      <Button
                        onClick={handlePreview}
                        disabled={previewing || !newUrl.trim()}
                      >
                        {previewing ? (
                          <>
                            <Loader2 className="mr-2 size-4 animate-spin" />
                            Loading...
                          </>
                        ) : (
                          "Preview Plugin"
                        )}
                      </Button>
                    </>
                  )}
                </ResponsiveDialogFooter>
              </ResponsiveDialogContent>
            </ResponsiveDialog>
          )}
        </div>

        {plugins.length === 0 ? (
          <div className="rounded-lg border border-dashed p-8 text-center">
            <p className="text-muted-foreground">No plugins loaded.</p>
            {canCreate && (
              <p className="text-muted-foreground mt-2 text-sm">
                Add a plugin to enable external account authentication.
              </p>
            )}
          </div>
        ) : (
          <div className="overflow-clip rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Plugin</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Auth Type</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Required Secrets</TableHead>
                  <TableHead className="w-32" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {plugins.map((plugin) => (
                  <TableRow key={plugin.id}>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium">{plugin.name}</span>
                        <code className="text-muted-foreground text-xs">
                          {plugin.id}
                        </code>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">{plugin.version}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{formatAuthType(plugin.auth_type)}</Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Badge variant={plugin.source === "url" ? "default" : "secondary"}>
                          {plugin.source}
                        </Badge>
                        {plugin.url && plugin.source === "url" && (
                          <a
                            href={plugin.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-muted-foreground hover:text-foreground"
                          >
                            <ExternalLink className="size-3" />
                          </a>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {plugin.required_secrets.map((secret) => (
                          <Badge key={secret.key} variant="outline" className="text-xs" title={secret.description || undefined}>
                            {secret.name}
                          </Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        {canCreate && plugin.required_secrets?.length > 0 && (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-8"
                            title={encryptionConfigured ? "Configure secrets" : "Encryption not configured"}
                            onClick={() => handleOpenConfig(plugin)}
                            disabled={!encryptionConfigured}
                          >
                            <Settings className="size-4" />
                          </Button>
                        )}
                        {canCreate && plugin.source === "url" && (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-8"
                            title="Reload plugin"
                            onClick={() => handleReload(plugin.id)}
                            disabled={reloading === plugin.id}
                          >
                            <RefreshCw
                              className={`size-4 ${reloading === plugin.id ? "animate-spin" : ""}`}
                            />
                          </Button>
                        )}
                        {canDelete && (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-8 text-destructive hover:text-destructive"
                            title="Remove plugin"
                            onClick={() => handleRemove(plugin.id)}
                            disabled={removing === plugin.id}
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
        )}

        <div className="rounded-lg border bg-muted/50 p-4">
          <h3 className="font-medium">Plugin Configuration</h3>
          <p className="text-muted-foreground mt-1 text-sm">
            Configure plugin secrets using the <Settings className="inline size-3" /> button.
            Alternatively, set environment variables like{" "}
            <code className="text-xs">PLUGIN_STEAM_API_KEY</code>.
          </p>
          <p className="text-muted-foreground mt-2 text-sm">
            Dashboard-configured secrets take precedence over environment variables.
          </p>
        </div>

        {/* Configure Secrets Dialog */}
        <ResponsiveDialog open={configOpen} onOpenChange={setConfigOpen}>
          <ResponsiveDialogContent>
            <ResponsiveDialogHeader>
              <ResponsiveDialogTitle>
                Configure {configPlugin?.name}
              </ResponsiveDialogTitle>
              <ResponsiveDialogDescription>
                Enter the required secrets for this plugin. Leave empty to use environment variables.
              </ResponsiveDialogDescription>
            </ResponsiveDialogHeader>
            <div className="grid gap-4 py-4">
              {configPlugin?.required_secrets.map((secret) => (
                <div key={secret.key} className="grid gap-2">
                  <Label htmlFor={`secret-${secret.key}`}>
                    {secret.name}
                    <code className="text-xs font-normal text-muted-foreground ml-2">{secret.key}</code>
                  </Label>
                  {secret.description && (
                    <p className="text-xs text-muted-foreground">{secret.description}</p>
                  )}
                  <Input
                    id={`secret-${secret.key}`}
                    type="password"
                    placeholder="Enter value..."
                    value={secretValues[secret.key] || ""}
                    onChange={(e) =>
                      setSecretValues((prev) => ({ ...prev, [secret.key]: e.target.value }))
                    }
                  />
                </div>
              ))}
            </div>
            <ResponsiveDialogFooter>
              <ResponsiveDialogClose asChild>
                <Button variant="outline" disabled={savingSecrets}>
                  Cancel
                </Button>
              </ResponsiveDialogClose>
              <Button onClick={handleSaveSecrets} disabled={savingSecrets}>
                {savingSecrets ? "Saving..." : "Save Secrets"}
              </Button>
            </ResponsiveDialogFooter>
          </ResponsiveDialogContent>
        </ResponsiveDialog>
      </div>
    </>
  );
}
