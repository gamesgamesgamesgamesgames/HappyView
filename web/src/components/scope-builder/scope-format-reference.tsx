"use client";

import { BookOpen, ChevronDown } from "lucide-react";
import { useState } from "react";

import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { cn } from "@/lib/utils";

interface Row {
  type: string;
  format: string;
  example: string;
}

const ROWS: Row[] = [
  { type: "Base", format: "atproto", example: "Required for all atproto OAuth sessions" },
  {
    type: "Permission Set",
    format: "include:nsid[?aud=…]",
    example: "include:app.bsky.authCreatePosts",
  },
  {
    type: "Repository",
    format:
      "repo[:collection][?action=…]   or   repo?collection=…&collection=…[&action=…]",
    example:
      "repo:app.bsky.feed.post?action=create&action=delete\nrepo?collection=foo.bar&collection=foo.baz",
  },
  {
    type: "RPC",
    format: "rpc[:lxm][?aud=…]   or   rpc?lxm=…&lxm=…[&aud=…]",
    example:
      "rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app\nrpc?lxm=foo.bar&lxm=baz.qux",
  },
  { type: "Blob", format: "blob[:accept]", example: "blob:image/*" },
  {
    type: "Account",
    format: "account[:attr][?action=…]",
    example: "account:email   account:repo?action=manage",
  },
  { type: "Handle", format: "identity[:attr]", example: "identity:handle   identity:*" },
  {
    type: "Transition",
    format: "transition:generic   transition:chat.bsky   transition:email",
    example: "Legacy app password equivalent access",
  },
];

/**
 * Collapsible reference table that documents the scope grammar.  Mirrors
 * the panel at the bottom of https://lexicon.garden/scope-builder.
 */
export function ScopeFormatReference() {
  const [open, setOpen] = useState(false);
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger
        className={cn(
          "group flex w-full items-center justify-between rounded-md border bg-muted/30 px-3 py-2 text-sm font-medium",
          "hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        )}
      >
        <span className="flex items-center gap-2">
          <BookOpen className="size-4" />
          Scope Format Reference
        </span>
        <ChevronDown
          className={cn(
            "size-4 transition-transform",
            open && "rotate-180",
          )}
        />
      </CollapsibleTrigger>
      <CollapsibleContent className="mt-2">
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full text-left text-xs">
            <thead className="bg-muted/50">
              <tr>
                <th className="px-3 py-2 font-medium">Type</th>
                <th className="px-3 py-2 font-medium">Format</th>
                <th className="px-3 py-2 font-medium">Example</th>
              </tr>
            </thead>
            <tbody>
              {ROWS.map((row) => (
                <tr key={row.type} className="border-t">
                  <td className="px-3 py-2 align-top">{row.type}</td>
                  <td className="px-3 py-2 align-top">
                    <code className="font-mono text-[0.7rem] whitespace-pre-wrap">
                      {row.format}
                    </code>
                  </td>
                  <td className="px-3 py-2 align-top">
                    <code className="font-mono text-[0.7rem] whitespace-pre-wrap">
                      {row.example}
                    </code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-muted-foreground mt-2 text-xs">
          <strong>Note:</strong> Partial wildcards are not supported (e.g.{" "}
          <code className="bg-muted rounded px-1">app.bsky.*</code> is invalid).
          Scopes are space-separated in the final string. See the{" "}
          <a
            className="underline"
            href="https://atproto.com/specs/oauth"
            target="_blank"
            rel="noopener noreferrer"
          >
            ATProtocol Permission Spec
          </a>{" "}
          for full details.
        </p>
      </CollapsibleContent>
    </Collapsible>
  );
}
