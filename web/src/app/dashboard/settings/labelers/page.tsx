"use client";

import { useCallback, useEffect, useState } from "react";
import { Trash2, Pause, Play } from "lucide-react";

import { useAuth } from "@/lib/auth-context";
import { useCurrentUser } from "@/hooks/use-current-user";
import {
  getLabelers,
  addLabeler,
  updateLabeler,
  deleteLabeler,
} from "@/lib/api";
import type { LabelerSummary } from "@/types/labelers";
import { SiteHeader } from "@/components/site-header";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  ResponsiveDialog,
  ResponsiveDialogClose,
  ResponsiveDialogContent,
  ResponsiveDialogDescription,
  ResponsiveDialogFooter,
  ResponsiveDialogHeader,
  ResponsiveDialogTitle,
  ResponsiveDialogTrigger,
} from "@/components/ui/responsive-dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function LabelersPage() {
  const { getToken } = useAuth();
  const { hasPermission } = useCurrentUser();
  const [labelers, setLabelers] = useState<LabelerSummary[]>([]);
  const [handles, setHandles] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [deleteDid, setDeleteDid] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(() => {
    getLabelers(getToken)
      .then(setLabelers)
      .catch((e) => setError(e.message));
  }, [getToken]);

  useEffect(() => {
    load();
  }, [load]);

  // Resolve DIDs to handles via PLC directory
  useEffect(() => {
    const newDids = labelers.map((l) => l.did).filter((did) => !(did in handles));
    if (newDids.length === 0) return;
    for (const did of newDids) {
      fetch(`https://plc.directory/${encodeURIComponent(did)}`)
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          if (!data) return;
          const handle = data.alsoKnownAs
            ?.find((aka: string) => aka.startsWith("at://"))
            ?.replace("at://", "");
          if (handle) {
            setHandles((prev) => ({ ...prev, [did]: handle }));
          }
        })
        .catch(() => {});
    }
  }, [labelers, handles]);

  async function handleToggleStatus(labeler: LabelerSummary) {
    try {
      const newStatus = labeler.status === "active" ? "paused" : "active";
      await updateLabeler(getToken, labeler.did, { status: newStatus });
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function handleDelete(did: string) {
    setDeleting(true);
    try {
      await deleteLabeler(getToken, did);
      setDeleteDid(null);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setDeleting(false);
    }
  }

  return (
    <>
      <SiteHeader title="Labelers" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold">Labeler Subscriptions</h2>
            <p className="text-muted-foreground text-sm">
              Manage external labeler services that provide content labels.
            </p>
          </div>
          {hasPermission("labelers:create") && (
            <AddLabelerDialog getToken={getToken} onSuccess={load} />
          )}
        </div>

        <div className="overflow-clip rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>DID</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Cursor</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Updated</TableHead>
                <TableHead className="w-20 sticky right-0 bg-inherit z-[1]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {labelers.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={6}
                    className="text-muted-foreground text-center"
                  >
                    No labeler subscriptions yet.
                  </TableCell>
                </TableRow>
              )}
              {labelers.map((l) => (
                <TableRow key={l.did}>
                  <TableCell>
                    <div className="flex flex-col">
                      {handles[l.did] && (
                        <span className="font-medium">@{handles[l.did]}</span>
                      )}
                      <span className="font-mono text-muted-foreground text-xs">
                        {l.did}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge
                      className={
                        l.status === "active"
                          ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                          : "bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200"
                      }
                    >
                      {l.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {l.cursor ?? "—"}
                  </TableCell>
                  <TableCell>
                    {new Date(l.created_at).toLocaleString()}
                  </TableCell>
                  <TableCell>
                    {new Date(l.updated_at).toLocaleString()}
                  </TableCell>
                  <TableCell className="w-20 sticky right-0 bg-inherit z-[1]">
                    <div className="flex gap-1">
                      {hasPermission("labelers:create") && (
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8"
                          title={l.status === "active" ? "Pause labeler" : "Resume labeler"}
                          aria-label={l.status === "active" ? "Pause labeler" : "Resume labeler"}
                          onClick={() => handleToggleStatus(l)}
                        >
                          {l.status === "active" ? (
                            <Pause className="size-4" />
                          ) : (
                            <Play className="size-4" />
                          )}
                        </Button>
                      )}
                      {hasPermission("labelers:delete") && (
                        <Button
                          variant="destructive"
                          size="icon"
                          className="size-8 text-muted-foreground hover:text-destructive"
                          title="Delete labeler"
                          aria-label="Delete labeler"
                          onClick={() => setDeleteDid(l.did)}
                        >
                          <Trash2 className="size-4" />
                        </Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>

      <ResponsiveDialog
        open={!!deleteDid}
        onOpenChange={(open) => {
          if (!open) setDeleteDid(null);
        }}
      >
        <ResponsiveDialogContent>
          <ResponsiveDialogHeader>
            <ResponsiveDialogTitle>Delete labeler?</ResponsiveDialogTitle>
            <ResponsiveDialogDescription>
              This will remove the labeler subscription and delete all labels it
              has emitted. This action cannot be undone.
            </ResponsiveDialogDescription>
          </ResponsiveDialogHeader>
          {deleteDid && (
            <code className="text-muted-foreground block truncate text-xs">
              {deleteDid}
            </code>
          )}
          <ResponsiveDialogFooter>
            <ResponsiveDialogClose asChild>
              <Button variant="outline" disabled={deleting}>
                Cancel
              </Button>
            </ResponsiveDialogClose>
            <Button
              variant="destructive"
              disabled={deleting}
              onClick={() => {
                if (deleteDid) handleDelete(deleteDid);
              }}
            >
              {deleting ? "Deleting..." : "Delete"}
            </Button>
          </ResponsiveDialogFooter>
        </ResponsiveDialogContent>
      </ResponsiveDialog>
    </>
  );
}

function AddLabelerDialog({
  getToken,
  onSuccess,
}: {
  getToken: () => Promise<string | null>;
  onSuccess: () => void;
}) {
  const [did, setDid] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  async function handleAdd() {
    setError(null);
    try {
      await addLabeler(getToken, { did });
      setDid("");
      setOpen(false);
      onSuccess();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <ResponsiveDialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) {
          setDid("");
          setError(null);
        }
      }}
    >
      <ResponsiveDialogTrigger asChild>
        <Button>Add Labeler</Button>
      </ResponsiveDialogTrigger>
      <ResponsiveDialogContent>
        <ResponsiveDialogHeader>
          <ResponsiveDialogTitle>Add Labeler</ResponsiveDialogTitle>
          <ResponsiveDialogDescription>
            Subscribe to an external labeler service by entering its DID.
          </ResponsiveDialogDescription>
        </ResponsiveDialogHeader>
        <div className="flex flex-col gap-4">
          {error && <p className="text-destructive text-sm">{error}</p>}
          <div className="flex flex-col gap-2">
            <Label htmlFor="labeler-did">DID</Label>
            <Input
              id="labeler-did"
              value={did}
              onChange={(e) => setDid(e.target.value)}
              placeholder="did:plc:..."
              className="font-mono"
            />
          </div>
        </div>
        <ResponsiveDialogFooter>
          <ResponsiveDialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </ResponsiveDialogClose>
          <Button onClick={handleAdd} disabled={!did.trim()}>
            Add
          </Button>
        </ResponsiveDialogFooter>
      </ResponsiveDialogContent>
    </ResponsiveDialog>
  );
}
