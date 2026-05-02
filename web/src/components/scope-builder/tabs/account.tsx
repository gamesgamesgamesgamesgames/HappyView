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
  type AccountAction,
  type AccountAttr,
  type Permission,
} from "@/lib/oauth-scope";

const NO_ACTION = "__none__";

export interface AccountTabProps {
  onAdd: (perm: Permission) => void;
}

export function AccountTab({ onAdd }: AccountTabProps) {
  const [attr, setAttr] = useState<AccountAttr>("email");
  const [action, setAction] = useState<AccountAction | typeof NO_ACTION>(
    NO_ACTION,
  );
  const [error, setError] = useState<string | null>(null);

  function handleAdd() {
    const perm: Permission =
      action === NO_ACTION ? { kind: "account", attr } : { kind: "account", attr, action };
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
        <h4 className="text-sm font-medium">Add Account Permission</h4>
        <p className="text-muted-foreground text-xs">
          Access account configuration attributes.
        </p>
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="account-attr">Attribute</Label>
        <Select
          value={attr}
          onValueChange={(v) => setAttr(v as AccountAttr)}
        >
          <SelectTrigger id="account-attr" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="email">email — Access account email</SelectItem>
            <SelectItem value="repo">
              repo — Access repository configuration
            </SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="account-action">Action (optional)</Label>
        <Select
          value={action}
          onValueChange={(v) => setAction(v as AccountAction | typeof NO_ACTION)}
        >
          <SelectTrigger id="account-action" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={NO_ACTION}>Default (read)</SelectItem>
            <SelectItem value="read">read — Read access</SelectItem>
            <SelectItem value="manage">
              manage — Full management access
            </SelectItem>
          </SelectContent>
        </Select>
      </div>

      {error && <p className="text-destructive text-xs">{error}</p>}

      <Button type="button" onClick={handleAdd}>
        <Plus className="size-4" /> Add Account Permission
      </Button>
    </div>
  );
}
