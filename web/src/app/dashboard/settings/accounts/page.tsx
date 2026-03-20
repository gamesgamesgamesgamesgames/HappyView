"use client";

import { useCallback, useEffect, useState } from "react";
import { Link2, Unlink, RefreshCw, ExternalLink, Key } from "lucide-react";

import {
  getExternalProviders,
  getLinkedAccounts,
  authorizeExternal,
  syncExternal,
  unlinkExternal,
  connectWithConfig,
} from "@/lib/api";
import type { ExternalProvider, LinkedAccount } from "@/types/external-accounts";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SiteHeader } from "@/components/site-header";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  ResponsiveDialog,
  ResponsiveDialogClose,
  ResponsiveDialogContent,
  ResponsiveDialogDescription,
  ResponsiveDialogFooter,
  ResponsiveDialogHeader,
  ResponsiveDialogTitle,
} from "@/components/ui/responsive-dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function LinkedAccountsPage() {
  const [providers, setProviders] = useState<ExternalProvider[]>([]);
  const [accounts, setAccounts] = useState<LinkedAccount[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [unlinkId, setUnlinkId] = useState<string | null>(null);
  const [unlinking, setUnlinking] = useState(false);
  const [syncing, setSyncing] = useState<string | null>(null);
  const [syncResult, setSyncResult] = useState<{ pluginId: string; written: number } | null>(null);
  // API key config dialog state
  const [configProvider, setConfigProvider] = useState<ExternalProvider | null>(null);
  const [configValues, setConfigValues] = useState<Record<string, string>>({});
  const [connecting, setConnecting] = useState(false);

  const load = useCallback(async () => {
    try {
      const [providerList, accountList] = await Promise.all([
        getExternalProviders(),
        getLinkedAccounts(),
      ]);
      setProviders(providerList);
      setAccounts(accountList);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function handleConnect(pluginId: string) {
    const provider = providers.find((p) => p.id === pluginId);
    if (!provider) return;

    // For API key auth, show config dialog instead of redirecting
    if (provider.auth_type === "api_key" && provider.config_schema) {
      setConfigProvider(provider);
      setConfigValues({});
      return;
    }

    // For OAuth/OpenID, redirect to provider
    try {
      const redirectUri = window.location.href;
      const result = await authorizeExternal(pluginId, redirectUri);
      window.location.href = result.authorize_url;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function handleConfigSubmit() {
    if (!configProvider) return;

    setConnecting(true);
    setError(null);
    try {
      await connectWithConfig(configProvider.id, configValues);
      setConfigProvider(null);
      setConfigValues({});
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setConnecting(false);
    }
  }

  async function handleSync(pluginId: string) {
    setSyncing(pluginId);
    setSyncResult(null);
    try {
      const result = await syncExternal(pluginId);
      setSyncResult({ pluginId, written: result.written });
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSyncing(null);
    }
  }

  async function handleUnlink(pluginId: string) {
    setUnlinking(true);
    try {
      await unlinkExternal(pluginId);
      setUnlinkId(null);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setUnlinking(false);
    }
  }

  // Build a map of linked accounts by plugin_id
  const linkedByPlugin = new Map(accounts.map((a) => [a.plugin_id, a]));

  return (
    <>
      <SiteHeader title="Linked Accounts" />
      <div className="flex flex-1 flex-col gap-6 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        {syncResult && (
          <div className="rounded-lg border border-green-200 bg-green-50 p-4 dark:border-green-900 dark:bg-green-950">
            <p className="text-green-800 dark:text-green-200">
              Sync complete: {syncResult.written} records written to your PDS
            </p>
          </div>
        )}

        <div>
          <h2 className="text-lg font-semibold">External Account Providers</h2>
          <p className="text-muted-foreground text-sm">
            Connect external platforms to sync data to your AT Protocol repository.
          </p>
        </div>

        {providers.length === 0 ? (
          <Card>
            <CardHeader>
              <CardTitle>No Providers Available</CardTitle>
              <CardDescription>
                No external account plugins are currently loaded. Contact your
                administrator to install plugins.
              </CardDescription>
            </CardHeader>
          </Card>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {providers.map((provider) => {
              const linked = linkedByPlugin.get(provider.id);
              const isSyncing = syncing === provider.id;

              return (
                <Card key={provider.id}>
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <CardTitle className="flex items-center gap-2">
                        {provider.icon_url && (
                          <img
                            src={provider.icon_url}
                            alt=""
                            className="size-6"
                          />
                        )}
                        {provider.name}
                      </CardTitle>
                      {linked && (
                        <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                          Connected
                        </Badge>
                      )}
                    </div>
                  </CardHeader>
                  <CardContent>
                    {linked ? (
                      <div className="flex flex-col gap-3">
                        <div className="text-muted-foreground text-sm">
                          <span className="font-medium">Account ID:</span>{" "}
                          <code className="text-xs">{linked.account_id}</code>
                        </div>
                        <div className="text-muted-foreground text-xs">
                          Connected {new Date(linked.created_at).toLocaleDateString()}
                        </div>
                        <div className="flex gap-2">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleSync(provider.id)}
                            disabled={isSyncing}
                          >
                            <RefreshCw
                              className={`mr-1 size-4 ${isSyncing ? "animate-spin" : ""}`}
                            />
                            {isSyncing ? "Syncing..." : "Sync Now"}
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="text-destructive hover:text-destructive"
                            onClick={() => setUnlinkId(provider.id)}
                          >
                            <Unlink className="mr-1 size-4" />
                            Unlink
                          </Button>
                        </div>
                      </div>
                    ) : (
                      <Button
                        size="sm"
                        onClick={() => handleConnect(provider.id)}
                      >
                        <Link2 className="mr-1 size-4" />
                        Connect {provider.name}
                      </Button>
                    )}
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}

        {accounts.length > 0 && (
          <>
            <div className="mt-4">
              <h2 className="text-lg font-semibold">Connected Accounts</h2>
              <p className="text-muted-foreground text-sm">
                Your linked external accounts and their sync status.
              </p>
            </div>

            <div className="overflow-clip rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Provider</TableHead>
                    <TableHead>Account ID</TableHead>
                    <TableHead>Connected</TableHead>
                    <TableHead>Last Updated</TableHead>
                    <TableHead className="w-32" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {accounts.map((account) => {
                    const provider = providers.find(
                      (p) => p.id === account.plugin_id
                    );
                    const isSyncing = syncing === account.plugin_id;

                    return (
                      <TableRow key={account.plugin_id}>
                        <TableCell className="font-medium">
                          {provider?.name ?? account.plugin_id}
                        </TableCell>
                        <TableCell>
                          <code className="text-xs">{account.account_id}</code>
                        </TableCell>
                        <TableCell>
                          {new Date(account.created_at).toLocaleString()}
                        </TableCell>
                        <TableCell>
                          {new Date(account.updated_at).toLocaleString()}
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            <Button
                              variant="ghost"
                              size="icon"
                              className="size-8"
                              title="Sync account"
                              onClick={() => handleSync(account.plugin_id)}
                              disabled={isSyncing}
                            >
                              <RefreshCw
                                className={`size-4 ${isSyncing ? "animate-spin" : ""}`}
                              />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="size-8 text-destructive hover:text-destructive"
                              title="Unlink account"
                              onClick={() => setUnlinkId(account.plugin_id)}
                            >
                              <Unlink className="size-4" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </>
        )}
      </div>

      <ResponsiveDialog
        open={!!unlinkId}
        onOpenChange={(open) => {
          if (!open) setUnlinkId(null);
        }}
      >
        <ResponsiveDialogContent>
          <ResponsiveDialogHeader>
            <ResponsiveDialogTitle>Unlink account?</ResponsiveDialogTitle>
            <ResponsiveDialogDescription>
              This will disconnect your external account and remove the stored
              credentials. You can reconnect at any time.
            </ResponsiveDialogDescription>
          </ResponsiveDialogHeader>
          {unlinkId && (
            <p className="text-muted-foreground text-sm">
              Provider:{" "}
              <span className="font-medium">
                {providers.find((p) => p.id === unlinkId)?.name ?? unlinkId}
              </span>
            </p>
          )}
          <ResponsiveDialogFooter>
            <ResponsiveDialogClose asChild>
              <Button variant="outline" disabled={unlinking}>
                Cancel
              </Button>
            </ResponsiveDialogClose>
            <Button
              variant="destructive"
              disabled={unlinking}
              onClick={() => {
                if (unlinkId) handleUnlink(unlinkId);
              }}
            >
              {unlinking ? "Unlinking..." : "Unlink"}
            </Button>
          </ResponsiveDialogFooter>
        </ResponsiveDialogContent>
      </ResponsiveDialog>

      {/* API Key / Config Dialog */}
      <ResponsiveDialog
        open={!!configProvider}
        onOpenChange={(open) => {
          if (!open) {
            setConfigProvider(null);
            setConfigValues({});
          }
        }}
      >
        <ResponsiveDialogContent>
          <ResponsiveDialogHeader>
            <ResponsiveDialogTitle className="flex items-center gap-2">
              {configProvider?.icon_url && (
                <img src={configProvider.icon_url} alt="" className="size-5" />
              )}
              Connect {configProvider?.name}
            </ResponsiveDialogTitle>
            <ResponsiveDialogDescription>
              Enter your credentials to connect this account.
            </ResponsiveDialogDescription>
          </ResponsiveDialogHeader>

          {configProvider?.config_schema && (
            <div className="grid gap-4 py-4">
              {Object.entries(configProvider.config_schema.properties).map(
                ([key, prop]) => (
                  <div key={key} className="grid gap-2">
                    <Label htmlFor={key}>{prop.title ?? key}</Label>
                    <Input
                      id={key}
                      type={prop.format === "password" ? "password" : "text"}
                      placeholder={prop.description}
                      value={configValues[key] ?? ""}
                      onChange={(e) =>
                        setConfigValues((prev) => ({
                          ...prev,
                          [key]: e.target.value,
                        }))
                      }
                    />
                    {prop.description && (
                      <p className="text-muted-foreground text-xs">
                        {prop.description}
                      </p>
                    )}
                  </div>
                )
              )}
            </div>
          )}

          <ResponsiveDialogFooter>
            <ResponsiveDialogClose asChild>
              <Button variant="outline" disabled={connecting}>
                Cancel
              </Button>
            </ResponsiveDialogClose>
            <Button disabled={connecting} onClick={handleConfigSubmit}>
              <Key className="mr-1 size-4" />
              {connecting ? "Connecting..." : "Connect"}
            </Button>
          </ResponsiveDialogFooter>
        </ResponsiveDialogContent>
      </ResponsiveDialog>
    </>
  );
}
