"use client";

import { Plus } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import {
  validatePermission,
  type Permission,
  type RepoAction,
} from "@/lib/oauth-scope";

import { NsidPicker } from "../nsid-picker";

const ACTION_LABELS: Record<RepoAction, string> = {
  create: "create — Create new records",
  update: "update — Update existing records",
  delete: "delete — Delete records",
};
const ACTIONS: RepoAction[] = ["create", "update", "delete"];

export interface RepositoryTabProps {
  records: string[];
  isLoading: boolean;
  onAdd: (perm: Permission) => void;
}

export function RepositoryTab({ records, isLoading, onAdd }: RepositoryTabProps) {
  const [collections, setCollections] = useState<string[]>([]);
  const [actions, setActions] = useState<RepoAction[]>([]);
  const [error, setError] = useState<string | null>(null);

  function toggleAction(a: RepoAction, checked: boolean) {
    setActions((prev) =>
      checked ? [...prev, a] : prev.filter((x) => x !== a),
    );
  }

  function handleAdd() {
    const perm: Permission =
      actions.length > 0
        ? { kind: "repo", collections, actions }
        : { kind: "repo", collections };
    const err = validatePermission(perm);
    if (err) {
      setError(err);
      return;
    }
    onAdd(perm);
    setCollections([]);
    setActions([]);
    setError(null);
  }

  return (
    <div className="flex flex-col gap-3 p-1">
      <div className="flex flex-col gap-1">
        <h4 className="text-sm font-medium">Add Repository Permission</h4>
        <p className="text-muted-foreground text-xs">
          Allow record operations on one or more collections.
        </p>
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="repo-nsid-picker">Collection NSID(s)</Label>
        <NsidPicker
          values={collections}
          onChange={setCollections}
          options={records}
          placeholder="Pick a collection NSID…"
          disabled={isLoading}
          inputId="repo-nsid-picker"
          emptyHint="No record lexicons registered"
        />
        <p className="text-muted-foreground text-xs">
          Pick from registered record lexicons. Use <code>*</code> for all
          collections.
        </p>
      </div>

      <div className="flex flex-col gap-2">
        <Label>Actions (optional — restrict to specific operations)</Label>
        <div className="flex flex-col gap-1.5">
          {ACTIONS.map((a) => (
            <label
              key={a}
              className="flex cursor-pointer items-center gap-2 text-sm"
            >
              <Checkbox
                checked={actions.includes(a)}
                onCheckedChange={(c) => toggleAction(a, c === true)}
              />
              <span>{ACTION_LABELS[a]}</span>
            </label>
          ))}
        </div>
        <p className="text-muted-foreground text-xs">
          <strong>Warning:</strong> If no actions selected, grants{" "}
          <em>full access</em> (any action allowed).
        </p>
      </div>

      {error && <p className="text-destructive text-xs">{error}</p>}

      <Button
        type="button"
        onClick={handleAdd}
        disabled={collections.length === 0}
      >
        <Plus className="size-4" /> Add Repository Permission
      </Button>
    </div>
  );
}
