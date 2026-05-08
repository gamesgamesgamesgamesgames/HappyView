"use client";

import { Plus } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { validatePermission, type Permission } from "@/lib/oauth-scope";

import { NsidPicker } from "../nsid-picker";

export interface RpcTabProps {
  methods: string[];
  isLoading: boolean;
  onAdd: (perm: Permission) => void;
}

export function RpcTab({ methods, isLoading, onAdd }: RpcTabProps) {
  const [lxms, setLxms] = useState<string[]>([]);
  const [aud, setAud] = useState("");
  const [error, setError] = useState<string | null>(null);

  function handleAdd() {
    const trimmedAud = aud.trim();
    const perm: Permission =
      trimmedAud.length > 0
        ? { kind: "rpc", lxms, aud: trimmedAud }
        : { kind: "rpc", lxms };
    const err = validatePermission(perm);
    if (err) {
      setError(err);
      return;
    }
    onAdd(perm);
    setLxms([]);
    setAud("");
    setError(null);
  }

  const canSubmit = lxms.length > 0 || aud.trim().length > 0;

  return (
    <div className="flex flex-col gap-3 p-1">
      <div className="flex flex-col gap-1">
        <h4 className="text-sm font-medium">Add RPC Permission</h4>
        <p className="text-muted-foreground text-xs">
          Allow calling specific XRPC methods on remote services.
        </p>
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="rpc-lxm-picker">Lexicon Method(s) (LXM)</Label>
        <NsidPicker
          values={lxms}
          onChange={setLxms}
          options={methods}
          placeholder="Pick a lexicon method…"
          disabled={isLoading}
          inputId="rpc-lxm-picker"
          emptyHint="No query/procedure lexicons registered"
        />
        <p className="text-muted-foreground text-xs">
          Pick from registered query and procedure lexicons. Use{" "}
          <code>*</code> for all methods.
        </p>
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="rpc-aud">Audience (aud)</Label>
        <Input
          id="rpc-aud"
          value={aud}
          onChange={(e) => setAud(e.target.value)}
          placeholder="e.g., did:web:api.bsky.app#atproto_appview (or * for any)"
          className="font-mono text-sm"
        />
        <p className="text-muted-foreground text-xs">
          Service DID with optional fragment. At least one of LXM or Audience
          is required. Both cannot be <code>*</code> simultaneously.
        </p>
      </div>

      {error && <p className="text-destructive text-xs">{error}</p>}

      <Button type="button" onClick={handleAdd} disabled={!canSubmit}>
        <Plus className="size-4" /> Add RPC Permission
      </Button>
    </div>
  );
}
