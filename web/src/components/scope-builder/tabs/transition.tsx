"use client";

import { AlertTriangle, Plus } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  validatePermission,
  type Permission,
  type TransitionValue,
} from "@/lib/oauth-scope";

export interface TransitionTabProps {
  onAdd: (perm: Permission) => void;
}

export function TransitionTab({ onAdd }: TransitionTabProps) {
  const [value, setValue] = useState<TransitionValue>("generic");
  const [error, setError] = useState<string | null>(null);

  function handleAdd() {
    const perm: Permission = { kind: "transition", value };
    const err = validatePermission(perm);
    if (err) {
      setError(err);
      return;
    }
    onAdd(perm);
    setError(null);
  }

  return (
    <div className="flex flex-col gap-3 p-1">
      <div className="flex flex-col gap-1">
        <h4 className="text-sm font-medium">Add Transition Scope</h4>
        <p className="text-muted-foreground text-xs">
          Transitional scopes for migrating from password-based authentication.
        </p>
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="transition-scope">Scope</Label>
        <Select
          value={value}
          onValueChange={(v) => setValue(v as TransitionValue)}
        >
          <SelectTrigger id="transition-scope" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="generic">
              transition:generic — Broad account permissions (like App Password)
            </SelectItem>
            <SelectItem value="chat.bsky">
              transition:chat.bsky — Access to chat.bsky lexicons
            </SelectItem>
            <SelectItem value="email">
              transition:email — Access account email address
            </SelectItem>
          </SelectContent>
        </Select>
        <p className="text-muted-foreground text-xs">
          <strong>Note:</strong> <code>transition:chat.bsky</code> requires{" "}
          <code>transition:generic</code> to function.
        </p>
      </div>

      {value === "generic" && (
        <div className="flex items-start gap-3 rounded-lg border border-amber-500/50 bg-amber-500/10 p-3">
          <AlertTriangle className="size-4 text-amber-500 shrink-0 mt-0.5" />
          <p className="text-xs text-amber-500">
            <code>transition:generic</code> grants broad write access to any
            collection. Prefer specific scopes or permission sets.
          </p>
        </div>
      )}

      {error && <p className="text-destructive text-xs">{error}</p>}

      <Button type="button" onClick={handleAdd}>
        <Plus className="size-4" /> Add Transition Scope
      </Button>
    </div>
  );
}
