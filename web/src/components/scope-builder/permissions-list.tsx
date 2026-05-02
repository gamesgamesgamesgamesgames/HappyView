"use client";

import { X } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  describePermission,
  serializeScope,
  type Permission,
} from "@/lib/oauth-scope";

export interface PermissionsListProps {
  permissions: Permission[];
  onRemove: (index: number) => void;
  onClearAll: () => void;
  /** NSIDs that are present in saved scope but not in the lexicon registry. */
  unknownLexiconIds?: ReadonlySet<string>;
}

/**
 * Renders the "Added Permissions" panel: one row per Permission with a
 * raw-token code block, a one-line description, and a remove button.  The
 * base `atproto` row is pinned and has no remove button.
 */
export function PermissionsList({
  permissions,
  onRemove,
  onClearAll,
  unknownLexiconIds,
}: PermissionsListProps) {
  const removableCount = permissions.filter((p) => p.kind !== "base").length;

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-medium">Added Permissions</h4>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={onClearAll}
          disabled={removableCount === 0}
        >
          Clear All
        </Button>
      </div>
      <ul className="flex flex-col gap-1.5">
        {permissions.map((p, index) => {
          const token = serializeOneSafe(p);
          const description = describePermission(p);
          const isBase = p.kind === "base";
          const stale = hasStaleNsid(p, unknownLexiconIds);
          return (
            <li
              key={`${index}-${token}`}
              className="flex items-start justify-between gap-3 rounded-md border bg-muted/30 px-3 py-2"
            >
              <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                <div className="flex flex-wrap items-center gap-2">
                  <code className="font-mono text-xs break-all">{token}</code>
                  {p.kind === "unknown" && (
                    <Badge variant="destructive" className="shrink-0">
                      unknown
                    </Badge>
                  )}
                  {stale && (
                    <Badge variant="outline" className="shrink-0 text-amber-600 border-amber-500/50">
                      lexicon not in registry
                    </Badge>
                  )}
                </div>
                <p className="text-muted-foreground text-xs">{description}</p>
              </div>
              {!isBase && (
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="shrink-0 size-7 text-muted-foreground hover:text-destructive"
                  title="Remove permission"
                  onClick={() => onRemove(index)}
                >
                  <X className="size-4" />
                </Button>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function serializeOneSafe(p: Permission): string {
  // Use the public serializer with just this one permission so it goes
  // through the same code path as the live preview.
  // serializeScope([base, p]) emits "atproto <token>" — strip the prefix.
  if (p.kind === "base") return "atproto";
  const out = serializeScope([{ kind: "base" }, p]);
  return out.startsWith("atproto ") ? out.slice("atproto ".length) : out;
}

function hasStaleNsid(
  p: Permission,
  unknown: ReadonlySet<string> | undefined,
): boolean {
  if (!unknown || unknown.size === 0) return false;
  switch (p.kind) {
    case "permission-set":
      return unknown.has(p.nsid);
    case "repo":
      return p.collections.some((c) => c !== "*" && unknown.has(c));
    case "rpc":
      return p.lxms.some((l) => l !== "*" && unknown.has(l));
    default:
      return false;
  }
}
