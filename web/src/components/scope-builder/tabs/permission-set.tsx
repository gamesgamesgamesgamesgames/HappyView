"use client";

import { CheckCircle2, Loader2, Plus, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { isValidNsid, type Permission } from "@/lib/oauth-scope";
import { resolveNsid } from "@/lib/nsid";

export interface PermissionSetTabProps {
  onAdd: (perm: Permission) => void;
}

/** Async resolution state. Each non-pending case carries the NSID it
 *  resolved so we can detect when it goes stale relative to the input. */
type AsyncState =
  | { kind: "pending" }
  | { kind: "resolving"; nsid: string }
  | { kind: "verified"; nsid: string; title?: string }
  | { kind: "wrong-type"; nsid: string; actualType: string }
  | { kind: "not-found"; nsid: string }
  | { kind: "error"; nsid: string; message: string };

/** Display state: pure derivation from current input + async state. */
type DisplayState =
  | { kind: "idle" }
  | { kind: "invalid"; reason: string }
  | AsyncState;

const DEBOUNCE_MS = 600;

export function PermissionSetTab({ onAdd }: PermissionSetTabProps) {
  const [nsid, setNsid] = useState("");
  const [aud, setAud] = useState("");
  const [asyncState, setAsyncState] = useState<AsyncState>({ kind: "pending" });

  const trimmed = nsid.trim();

  const display: DisplayState = useMemo(() => {
    if (!trimmed) return { kind: "idle" };
    if (!isValidNsid(trimmed))
      return {
        kind: "invalid",
        reason:
          "Not a valid NSID. Partial wildcards (e.g. app.bsky.*) are not supported.",
      };
    if (trimmed.split(".").length < 3)
      return {
        kind: "invalid",
        reason: "NSID must have at least three segments (e.g. app.bsky.foo).",
      };
    // Show "resolving" until the async result catches up to the current input.
    if (asyncState.kind === "pending") {
      return { kind: "resolving", nsid: trimmed };
    }
    if ("nsid" in asyncState && asyncState.nsid !== trimmed) {
      return { kind: "resolving", nsid: trimmed };
    }
    return asyncState;
  }, [trimmed, asyncState]);

  useEffect(() => {
    if (
      !trimmed ||
      !isValidNsid(trimmed) ||
      trimmed.split(".").length < 3
    ) {
      return;
    }

    const controller = new AbortController();
    const timer = setTimeout(async () => {
      try {
        const result = await resolveNsid(trimmed, controller.signal);
        if (controller.signal.aborted) return;
        if (!result.lexiconJson) {
          setAsyncState({ kind: "not-found", nsid: trimmed });
          return;
        }
        const main = (result.lexiconJson.defs as
          | Record<string, Record<string, unknown>>
          | undefined)?.main;
        const mainType = main?.type as string | undefined;
        const title = main?.title as string | undefined;
        if (mainType === "permission-set") {
          setAsyncState({ kind: "verified", nsid: trimmed, title });
        } else {
          setAsyncState({
            kind: "wrong-type",
            nsid: trimmed,
            actualType: mainType ?? "unknown",
          });
        }
      } catch (e: unknown) {
        if (controller.signal.aborted) return;
        setAsyncState({
          kind: "error",
          nsid: trimmed,
          message: e instanceof Error ? e.message : String(e),
        });
      }
    }, DEBOUNCE_MS);

    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [trimmed]);

  // Add is gated on having syntactically valid input. Verification status
  // is informational only — users may add an NSID even if it didn't resolve
  // (e.g. lexicon not yet published, DoH provider down, lexicon hosted in
  // a non-resolvable network). The OAuth server will revalidate at scope
  // enforcement time.
  const canAdd =
    display.kind !== "idle" &&
    display.kind !== "invalid" &&
    trimmed.length > 0;

  function handleAdd() {
    if (!canAdd) return;
    const trimmedAud = aud.trim();
    const perm: Permission = trimmedAud
      ? { kind: "permission-set", nsid: trimmed, aud: trimmedAud }
      : { kind: "permission-set", nsid: trimmed };
    onAdd(perm);
    setNsid("");
    setAud("");
    setAsyncState({ kind: "pending" });
  }

  const addLabel =
    display.kind === "wrong-type" ||
    display.kind === "not-found" ||
    display.kind === "error"
      ? "Add anyway"
      : "Add Permission Set";

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-1">
        <h4 className="text-sm font-medium">Include Permission Set</h4>
        <p className="text-muted-foreground text-xs">
          Bundle a published permission-set lexicon by NSID. The NSID is
          resolved through atproto lexicon resolution (DNS authority → PDS →
          lexicon record) to verify it exists and is a permission set.
        </p>
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="ps-nsid">Permission Set NSID</Label>
        <Input
          id="ps-nsid"
          value={nsid}
          onChange={(e) => setNsid(e.target.value)}
          placeholder="e.g., app.bsky.authCreatePosts"
          className="font-mono text-sm"
          autoComplete="off"
          spellCheck={false}
          aria-invalid={
            display.kind === "invalid" ||
            display.kind === "wrong-type" ||
            display.kind === "not-found" ||
            display.kind === "error"
          }
        />
        <ResolveStatus state={display} />
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="ps-aud">Audience (optional)</Label>
        <Input
          id="ps-aud"
          value={aud}
          onChange={(e) => setAud(e.target.value)}
          placeholder="e.g., did:web:api.bsky.app#atproto_appview"
          className="font-mono text-sm"
        />
        <p className="text-muted-foreground text-xs">
          Restrict this permission set to a specific service.
        </p>
      </div>

      <Button type="button" onClick={handleAdd} disabled={!canAdd}>
        <Plus className="size-4" /> {addLabel}
      </Button>
    </div>
  );
}

function ResolveStatus({ state }: { state: DisplayState }) {
  switch (state.kind) {
    case "idle":
      return null;
    case "invalid":
      return (
        <p className="text-destructive flex items-start gap-1.5 text-xs">
          <XCircle className="mt-0.5 size-3.5 shrink-0" />
          <span>{state.reason}</span>
        </p>
      );
    case "pending":
      return null;
    case "resolving":
      return (
        <p className="text-muted-foreground flex items-center gap-1.5 text-xs">
          <Loader2 className="size-3.5 shrink-0 animate-spin" />
          <span>Resolving {state.nsid}…</span>
        </p>
      );
    case "verified":
      return (
        <p className="flex items-start gap-1.5 text-xs text-emerald-600 dark:text-emerald-500">
          <CheckCircle2 className="mt-0.5 size-3.5 shrink-0" />
          <span>
            Verified as a permission set
            {state.title ? ` — ${state.title}` : ""}.
          </span>
        </p>
      );
    case "wrong-type":
      return (
        <p className="text-destructive flex items-start gap-1.5 text-xs">
          <XCircle className="mt-0.5 size-3.5 shrink-0" />
          <span>
            Resolved, but this is a <code>{state.actualType}</code> lexicon,
            not a permission set.
          </span>
        </p>
      );
    case "not-found":
      return (
        <p className="text-destructive flex items-start gap-1.5 text-xs">
          <XCircle className="mt-0.5 size-3.5 shrink-0" />
          <span>
            Could not resolve <code>{state.nsid}</code>. Check the
            authority&apos;s DNS records and that the lexicon record is
            published on its PDS.
          </span>
        </p>
      );
    case "error":
      return (
        <p className="text-destructive flex items-start gap-1.5 text-xs">
          <XCircle className="mt-0.5 size-3.5 shrink-0" />
          <span>Resolution error: {state.message}</span>
        </p>
      );
  }
}
