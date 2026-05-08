"use client";

import { Plus } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { validatePermission, type Permission } from "@/lib/oauth-scope";

const PRESETS = [
  { value: "*/*", label: "*/* — All types" },
  { value: "image/*", label: "image/* — All images" },
  { value: "image/jpeg", label: "image/jpeg — JPEG images" },
  { value: "image/png", label: "image/png — PNG images" },
  { value: "image/gif", label: "image/gif — GIF images" },
  { value: "image/webp", label: "image/webp — WebP images" },
  { value: "video/*", label: "video/* — All video" },
  { value: "video/mp4", label: "video/mp4 — MP4 video" },
  { value: "audio/*", label: "audio/* — All audio" },
  { value: "custom", label: "Custom…" },
];

export interface BlobTabProps {
  onAdd: (perm: Permission) => void;
}

export function BlobTab({ onAdd }: BlobTabProps) {
  const [preset, setPreset] = useState("*/*");
  const [custom, setCustom] = useState("");
  const [error, setError] = useState<string | null>(null);

  const isCustom = preset === "custom";

  function handleAdd() {
    const accept = (isCustom ? custom : preset).trim();
    if (!accept) {
      setError("Provide a MIME type.");
      return;
    }
    const perm: Permission = { kind: "blob", accept };
    const err = validatePermission(perm);
    if (err) {
      setError(err);
      return;
    }
    onAdd(perm);
    setError(null);
    if (isCustom) setCustom("");
  }

  return (
    <div className="flex flex-col gap-3 p-1">
      <div className="flex flex-col gap-1">
        <h4 className="text-sm font-medium">Add Blob Permission</h4>
        <p className="text-muted-foreground text-xs">
          Allow uploading blobs (media files).
        </p>
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="blob-mime">Accept MIME Type</Label>
        <Select value={preset} onValueChange={setPreset}>
          <SelectTrigger id="blob-mime" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PRESETS.map((p) => (
              <SelectItem key={p.value} value={p.value}>
                {p.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {isCustom && (
        <div className="flex flex-col gap-2">
          <Label htmlFor="blob-custom">Custom MIME Type</Label>
          <Input
            id="blob-custom"
            value={custom}
            onChange={(e) => setCustom(e.target.value)}
            placeholder="e.g., application/pdf"
            className="font-mono text-sm"
          />
        </div>
      )}

      {error && <p className="text-destructive text-xs">{error}</p>}

      <Button
        type="button"
        onClick={handleAdd}
        disabled={isCustom && custom.trim().length === 0}
      >
        <Plus className="size-4" /> Add Blob Permission
      </Button>
    </div>
  );
}
