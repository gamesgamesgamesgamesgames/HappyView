"use client";

import { useCallback, useEffect, useState } from "react";

import { useCurrentUser } from "@/hooks/use-current-user";
import { createBackfillJob, getBackfillJobs, getLexicons } from "@/lib/api";
import type { BackfillJob } from "@/types/backfill";
import { SiteHeader } from "@/components/site-header";
import { Button } from "@/components/ui/button";
import {
  Combobox,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxInput,
  ComboboxItem,
  ComboboxList,
} from "@/components/ui/combobox";
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

export default function BackfillPage() {
  const { hasPermission } = useCurrentUser();
  const [jobs, setJobs] = useState<BackfillJob[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    getBackfillJobs()
      .then(setJobs)
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // Auto-refresh every 5 seconds
  useEffect(() => {
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, [load]);

  return (
    <>
      <SiteHeader title="Backfill" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Backfill Jobs</h2>
          {hasPermission("backfill:create") && (
            <CreateDialog onSuccess={load} />
          )}
        </div>

        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Collection</TableHead>
                <TableHead>DID</TableHead>
                <TableHead>Progress</TableHead>
                <TableHead>Records</TableHead>
                <TableHead>Started</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {jobs.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={6}
                    className="text-muted-foreground text-center"
                  >
                    No backfill jobs yet.
                  </TableCell>
                </TableRow>
              )}
              {jobs.map((job) => (
                <TableRow key={job.id}>
                  <TableCell className="font-mono text-xs">
                    {job.id.slice(0, 8)}
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {job.collection ?? "All"}
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {job.did ?? "All"}
                  </TableCell>
                  <TableCell className="tabular-nums">
                    {job.processed_repos != null && job.total_repos != null
                      ? `${job.processed_repos} / ${job.total_repos}`
                      : "--"}
                  </TableCell>
                  <TableCell className="tabular-nums">
                    {job.total_records?.toLocaleString() ?? "--"}
                  </TableCell>
                  <TableCell>
                    {job.started_at
                      ? new Date(job.started_at).toLocaleString()
                      : "--"}
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

function CreateDialog({
  onSuccess,
}: {
  onSuccess: () => void;
}) {
  const [collection, setCollection] = useState<string | null>(null);
  const [did, setDid] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [recordLexicons, setRecordLexicons] = useState<string[]>([]);

  useEffect(() => {
    if (open) {
      getLexicons()
        .then((lexicons) =>
          setRecordLexicons(
            lexicons
              .filter((l) => l.lexicon_type === "record")
              .map((l) => l.id)
              .sort(),
          ),
        )
        .catch(() => {});
    }
  }, [open]);

  async function handleCreate() {
    setError(null);
    try {
      await createBackfillJob({
        collection: collection || undefined,
        did: did || undefined,
      });
      setCollection(null);
      setDid("");
      setOpen(false);
      onSuccess();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <ResponsiveDialog open={open} onOpenChange={setOpen}>
      <ResponsiveDialogTrigger asChild>
        <Button>Create Backfill Job</Button>
      </ResponsiveDialogTrigger>
      <ResponsiveDialogContent>
        <ResponsiveDialogHeader>
          <ResponsiveDialogTitle>Create Backfill Job</ResponsiveDialogTitle>
          <ResponsiveDialogDescription>
            Start a backfill for a collection or specific DID. Leave both empty
            to backfill all collections.
          </ResponsiveDialogDescription>
        </ResponsiveDialogHeader>
        <div className="flex flex-col gap-4">
          {error && <p className="text-destructive text-sm">{error}</p>}
          <div className="flex flex-col gap-2">
            <Label>Collection (optional)</Label>
            <Combobox value={collection} onValueChange={setCollection}>
              <ComboboxInput
                placeholder="Select or type a collection..."
                showClear
              />
              <ComboboxContent>
                <ComboboxList>
                  <ComboboxEmpty>No matching lexicons.</ComboboxEmpty>
                  {recordLexicons.map((id) => (
                    <ComboboxItem key={id} value={id}>
                      {id}
                    </ComboboxItem>
                  ))}
                </ComboboxList>
              </ComboboxContent>
            </Combobox>
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="bf-did">DID (optional)</Label>
            <Input
              id="bf-did"
              value={did}
              onChange={(e) => setDid(e.target.value)}
              placeholder="did:plc:..."
            />
          </div>
        </div>
        <ResponsiveDialogFooter>
          <ResponsiveDialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </ResponsiveDialogClose>
          <Button onClick={handleCreate}>Create</Button>
        </ResponsiveDialogFooter>
      </ResponsiveDialogContent>
    </ResponsiveDialog>
  );
}
