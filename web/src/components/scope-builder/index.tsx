"use client";

import { Check, Copy } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import {
  parseScope,
  serializeScope,
  type Permission,
} from "@/lib/oauth-scope";

import { PermissionsList } from "./permissions-list";
import { ScopeFormatReference } from "./scope-format-reference";
import { AccountTab } from "./tabs/account";
import { BlobTab } from "./tabs/blob";
import { HandleTab } from "./tabs/handle";
import { PermissionSetTab } from "./tabs/permission-set";
import { RepositoryTab } from "./tabs/repository";
import { RpcTab } from "./tabs/rpc";
import { TransitionTab } from "./tabs/transition";
import { useLexiconNsids } from "./use-lexicon-nsids";

export interface ScopeBuilderProps {
  /** Full space-separated scope string (always begins with `atproto`). */
  value: string;
  /** Receives the new scope string after each mutation. */
  onChange: (value: string) => void;
}

type TabValue =
  | "repository"
  | "rpc"
  | "blob"
  | "account"
  | "handle"
  | "transition"
  | "permission-set";

/**
 * Tabbed OAuth scope builder.  Owns its own list of `Permission` objects
 * derived from `value`, and emits `onChange` with the canonical
 * space-separated string each time the list mutates.
 */
export function ScopeBuilder({ value, onChange }: ScopeBuilderProps) {
  // Internal list of permissions, parsed from `value` on mount.
  const [perms, setPerms] = useState<Permission[]>(() => parseScope(value));

  // If the parent resets the value (e.g. dialog close/reopen), re-sync.
  // We only re-parse when the canonical serialization differs from the
  // current internal state, to avoid clobbering in-flight edits.
  useEffect(() => {
    const canonical = serializeScope(perms);
    if (canonical !== value) {
      setPerms(parseScope(value));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  // Whenever perms change, push the canonical string back up.
  useEffect(() => {
    onChange(serializeScope(perms));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [perms]);

  const [tab, setTab] = useState<TabValue>("repository");
  const [copied, setCopied] = useState(false);

  const { records, methods, permissionSets, isLoading, error } =
    useLexiconNsids();

  // NSIDs that the saved scope refers to but that are not in the registry.
  const unknownLexiconIds = useMemo(() => {
    const known = new Set<string>([...records, ...methods, ...permissionSets]);
    const unknown = new Set<string>();
    for (const p of perms) {
      switch (p.kind) {
        case "permission-set":
          if (!known.has(p.nsid) && p.nsid !== "*") unknown.add(p.nsid);
          break;
        case "repo":
          for (const c of p.collections) {
            if (c !== "*" && !records.includes(c)) unknown.add(c);
          }
          break;
        case "rpc":
          for (const l of p.lxms) {
            if (l !== "*" && !methods.includes(l)) unknown.add(l);
          }
          break;
      }
    }
    return unknown;
    // We intentionally include arrays here — they're stable per-fetch.
  }, [perms, records, methods, permissionSets]);

  const scopeString = useMemo(() => serializeScope(perms), [perms]);

  function handleAdd(perm: Permission) {
    setPerms((prev) => [...prev, perm]);
  }

  function handleRemove(index: number) {
    setPerms((prev) => prev.filter((_, i) => i !== index));
  }

  function handleClearAll() {
    setPerms([{ kind: "base" }]);
  }

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(scopeString);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API unavailable — silently ignore.
    }
  }

  const removableCount = perms.filter((p) => p.kind !== "base").length;

  return (
    <div className="flex flex-col gap-3 min-w-0 w-full">
      {/* Live preview */}
      <div className="flex flex-col gap-1.5 min-w-0">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium">Generated Scope String</span>
          <span className="text-muted-foreground text-xs">
            {removableCount + 1} permission(s)
          </span>
        </div>
        <div className="flex gap-1.5">
          <Input
            readOnly
            value={scopeString}
            className="font-mono text-xs"
            aria-label="Generated scope string"
          />
          <Button
            type="button"
            variant="outline"
            size="icon"
            onClick={handleCopy}
            title="Copy scope to clipboard"
          >
            {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
          </Button>
        </div>
      </div>

      {error && (
        <p className="text-destructive text-xs">
          Could not load lexicon list: {error}
        </p>
      )}

      {/* Builder tabs */}
      <Tabs
        value={tab}
        onValueChange={(v) => setTab(v as TabValue)}
        className="gap-3 min-w-0 w-full"
      >
        <div className="-mx-1 overflow-x-auto px-1">
          <TabsList variant="line" className="w-max justify-start">
            <TabsTrigger value="repository">Repository</TabsTrigger>
            <TabsTrigger value="rpc">RPC</TabsTrigger>
            <TabsTrigger value="blob">Blob</TabsTrigger>
            <TabsTrigger value="account">Account</TabsTrigger>
            <TabsTrigger value="handle">Handle</TabsTrigger>
            <TabsTrigger value="transition">Transition</TabsTrigger>
            <TabsTrigger value="permission-set">Permission Set</TabsTrigger>
          </TabsList>
        </div>
        <TabsContent value="repository">
          <RepositoryTab
            records={records}
            isLoading={isLoading}
            onAdd={handleAdd}
          />
        </TabsContent>
        <TabsContent value="rpc">
          <RpcTab methods={methods} isLoading={isLoading} onAdd={handleAdd} />
        </TabsContent>
        <TabsContent value="blob">
          <BlobTab onAdd={handleAdd} />
        </TabsContent>
        <TabsContent value="account">
          <AccountTab onAdd={handleAdd} />
        </TabsContent>
        <TabsContent value="handle">
          <HandleTab onAdd={handleAdd} />
        </TabsContent>
        <TabsContent value="transition">
          <TransitionTab onAdd={handleAdd} />
        </TabsContent>
        <TabsContent value="permission-set">
          <PermissionSetTab onAdd={handleAdd} />
        </TabsContent>
      </Tabs>

      {/* Added permissions list */}
      <PermissionsList
        permissions={perms}
        onRemove={handleRemove}
        onClearAll={handleClearAll}
        unknownLexiconIds={unknownLexiconIds}
      />

      {/* Scope format reference */}
      <ScopeFormatReference />
    </div>
  );
}
