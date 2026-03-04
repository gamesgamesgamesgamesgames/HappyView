"use client";

import { useCallback, useEffect, useState } from "react";

import { useAuth } from "@/lib/auth-context";
import {
  getScriptVariables,
  upsertScriptVariable,
  deleteScriptVariable,
} from "@/lib/api";
import type { ScriptVariableSummary } from "@/types/script-variables";
import { SiteHeader } from "@/components/site-header";
import { Button } from "@/components/ui/button";
import { Trash2, Pencil } from "lucide-react";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function SettingsPage() {
  const { getToken } = useAuth();
  const [vars, setVars] = useState<ScriptVariableSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    getScriptVariables(getToken)
      .then(setVars)
      .catch((e) => setError(e.message));
  }, [getToken]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleDelete(key: string) {
    try {
      await deleteScriptVariable(getToken, key);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <>
      <SiteHeader title="Settings" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold">Script Variables</h2>
            <p className="text-muted-foreground text-sm">
              Define variables that Lua scripts can access via the{" "}
              <code className="text-xs">env</code> global table.
            </p>
          </div>
          <UpsertVariableDialog getToken={getToken} onSuccess={load} />
        </div>

        <div className="overflow-clip rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Key</TableHead>
                <TableHead>Preview</TableHead>
                <TableHead>Updated</TableHead>
                <TableHead className="w-20 sticky right-0 bg-inherit z-[1]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {vars.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={4}
                    className="text-muted-foreground text-center"
                  >
                    No script variables yet.
                  </TableCell>
                </TableRow>
              )}
              {vars.map((v) => (
                <TableRow key={v.key}>
                  <TableCell className="font-mono text-sm">{v.key}</TableCell>
                  <TableCell className="font-mono text-sm text-muted-foreground">
                    {v.preview}
                  </TableCell>
                  <TableCell>
                    {new Date(v.updated_at).toLocaleString()}
                  </TableCell>
                  <TableCell className="w-20 sticky right-0 bg-inherit z-[1]">
                    <div className="flex gap-1">
                      <UpsertVariableDialog
                        getToken={getToken}
                        onSuccess={load}
                        editKey={v.key}
                      />
                      <Button
                        variant="destructive"
                        size="icon"
                        className="size-8 text-muted-foreground hover:text-destructive"
                        title="Delete variable"
                        aria-label="Delete variable"
                        onClick={() => handleDelete(v.key)}
                      >
                        <Trash2 className="size-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>
    </>
  );
}

function UpsertVariableDialog({
  getToken,
  onSuccess,
  editKey,
}: {
  getToken: () => Promise<string | null>;
  onSuccess: () => void;
  editKey?: string;
}) {
  const [key, setKey] = useState(editKey ?? "");
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  const isEdit = !!editKey;

  async function handleSave() {
    setError(null);
    try {
      await upsertScriptVariable(getToken, {
        key: isEdit ? editKey : key,
        value,
      });
      setKey(editKey ?? "");
      setValue("");
      setOpen(false);
      onSuccess();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) {
          setKey(editKey ?? "");
          setValue("");
          setError(null);
        }
      }}
    >
      <DialogTrigger asChild>
        {isEdit ? (
          <Button
            variant="ghost"
            size="icon"
            className="size-8"
            title="Edit variable"
            aria-label="Edit variable"
          >
            <Pencil className="size-4" />
          </Button>
        ) : (
          <Button>Add Variable</Button>
        )}
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit Variable" : "Add Variable"}</DialogTitle>
          <DialogDescription>
            {isEdit
              ? "Update the value for this script variable."
              : "Add a new script variable accessible via env.KEY in Lua scripts."}
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          {error && <p className="text-destructive text-sm">{error}</p>}
          <div className="flex flex-col gap-2">
            <Label htmlFor="var-key">Key</Label>
            <Input
              id="var-key"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="VARIABLE_NAME"
              disabled={isEdit}
              className={isEdit ? "font-mono" : ""}
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="var-value">Value</Label>
            <Textarea
              id="var-value"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="Enter value..."
              rows={3}
            />
          </div>
        </div>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button onClick={handleSave}>Save</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
