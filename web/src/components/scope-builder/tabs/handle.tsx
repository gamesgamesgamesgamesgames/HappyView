"use client";

import { Plus } from "lucide-react";
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
  type HandleAttr,
  type Permission,
} from "@/lib/oauth-scope";

export interface HandleTabProps {
  onAdd: (perm: Permission) => void;
}

export function HandleTab({ onAdd }: HandleTabProps) {
  const [attr, setAttr] = useState<HandleAttr>("handle");
  const [error, setError] = useState<string | null>(null);

  function handleAdd() {
    const perm: Permission = { kind: "handle", attr };
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
        <h4 className="text-sm font-medium">Add Handle Permission</h4>
        <p className="text-muted-foreground text-xs">
          Access network identity attributes.
        </p>
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="handle-attr">Attribute</Label>
        <Select
          value={attr}
          onValueChange={(v) => setAttr(v as HandleAttr)}
        >
          <SelectTrigger id="handle-attr" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="handle">handle — Manage handle</SelectItem>
            <SelectItem value="*">* — All identity attributes</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {error && <p className="text-destructive text-xs">{error}</p>}

      <Button type="button" onClick={handleAdd}>
        <Plus className="size-4" /> Add Handle Permission
      </Button>
    </div>
  );
}
