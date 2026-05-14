"use client";

import { useCallback, useEffect, useState } from "react";

import { useCurrentUser } from "@/hooks/use-current-user";
import {
  cancelBackfillJob,
  createBackfillJob,
  getBackfillJobs,
  getLexicons,
} from "@/lib/api";
import type { BackfillJob } from "@/types/backfill";
import { CheckCircle2, Circle, Loader2 } from "lucide-react";
import { SiteHeader } from "@/components/site-header";
import { Badge } from "@/components/ui/badge";
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
  Sheet,
  SheetContent,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const PROGRESS_PHASES = [
  "discovering_repos",
  "resolving_pds",
  "fetching_records",
] as const;

function statusBadge(job: BackfillJob) {
  switch (job.status) {
    case "completed":
      return (
        <Badge className="bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-500/25 border-emerald-500/20">
          completed
        </Badge>
      );
    case "failed":
      return <Badge variant="destructive">failed</Badge>;
    case "cancelled":
      return (
        <Badge className="bg-amber-500/15 text-amber-700 dark:text-amber-400 hover:bg-amber-500/25 border-amber-500/20">
          cancelled
        </Badge>
      );
    case "cancelling":
      return (
        <Badge className="bg-amber-500/15 text-amber-700 dark:text-amber-400 hover:bg-amber-500/25 border-amber-500/20">
          cancelling
        </Badge>
      );
    case "running":
      return (
        <Badge className="bg-blue-500/15 text-blue-700 dark:text-blue-400 hover:bg-blue-500/25 border-blue-500/20">
          {job.stage === "pending" ? "starting" : job.stage.replace(/_/g, " ")}
        </Badge>
      );
    default:
      return <Badge variant="secondary">{job.status}</Badge>;
  }
}

function phaseIndex(stage: string): number {
  const idx = PROGRESS_PHASES.indexOf(
    stage as (typeof PROGRESS_PHASES)[number],
  );
  return idx;
}

export default function BackfillPage() {
  const { hasPermission } = useCurrentUser();
  const [jobs, setJobs] = useState<BackfillJob[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);

  const load = useCallback(() => {
    getBackfillJobs()
      .then(setJobs)
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, [load]);

  const selectedJob = jobs.find((j) => j.id === selectedJobId) ?? null;

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
                <TableHead>Status</TableHead>
                <TableHead>Started</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {jobs.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={5}
                    className="text-muted-foreground text-center"
                  >
                    No backfill jobs yet.
                  </TableCell>
                </TableRow>
              )}
              {jobs.map((job) => (
                <TableRow
                  key={job.id}
                  className="cursor-pointer"
                  onClick={() => setSelectedJobId(job.id)}
                >
                  <TableCell className="font-mono text-xs">
                    {job.id.slice(0, 8)}
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {job.collection ?? "All"}
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {job.did ?? "All"}
                  </TableCell>
                  <TableCell>{statusBadge(job)}</TableCell>
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

        <Sheet
          open={selectedJob != null}
          onOpenChange={(open) => {
            if (!open) setSelectedJobId(null);
          }}
        >
          <SheetContent className="sm:max-w-xl overflow-hidden flex flex-col">
            {selectedJob && (
              <JobDetail
                job={selectedJob}
                canCancel={hasPermission("backfill:create")}
                onCancel={async () => {
                  await cancelBackfillJob(selectedJob.id);
                  load();
                }}
              />
            )}
          </SheetContent>
        </Sheet>
      </div>
    </>
  );
}

function JobDetail({
  job,
  canCancel,
  onCancel,
}: {
  job: BackfillJob;
  canCancel: boolean;
  onCancel: () => Promise<void>;
}) {
  const [cancelling, setCancelling] = useState(false);
  const current = phaseIndex(job.stage);
  const allDone = job.status === "completed";
  const isActive = job.status === "running" || job.status === "cancelling";

  function hasReached(phase: (typeof PROGRESS_PHASES)[number]): boolean {
    if (allDone) return true;
    return current >= phaseIndex(phase);
  }

  async function handleCancel() {
    setCancelling(true);
    try {
      await onCancel();
    } finally {
      setCancelling(false);
    }
  }

  return (
    <>
      <SheetHeader>
        <SheetTitle className="flex items-center gap-2">
          <span className="font-mono text-sm">Backfill Details</span>
        </SheetTitle>
      </SheetHeader>
      <div className="flex-1 min-h-0 overflow-y-auto px-4 flex flex-col gap-4">
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div className="col-span-2">
            <span className="text-muted-foreground">Job ID</span>
            <p className="font-mono text-xs break-all">{job.id}</p>
          </div>
          <div>
            <span className="text-muted-foreground">Collection</span>
            <p className="font-mono text-xs">{job.collection ?? "All"}</p>
          </div>
          <div>
            <span className="text-muted-foreground">DID</span>
            <p className="font-mono text-xs break-all">{job.did ?? "All"}</p>
          </div>
          <div>
            <span className="text-muted-foreground">Created</span>
            <p className="text-xs">
              {new Date(job.created_at).toLocaleString()}
            </p>
          </div>
          <div>
            <span className="text-muted-foreground">Started</span>
            <p className="text-xs">
              {job.started_at
                ? new Date(job.started_at).toLocaleString()
                : "--"}
            </p>
          </div>
          {job.completed_at && (
            <div>
              <span className="text-muted-foreground">Completed</span>
              <p className="text-xs">
                {new Date(job.completed_at).toLocaleString()}
              </p>
            </div>
          )}
        </div>

        {job.error && (
          <div>
            <span className="text-muted-foreground text-sm">Error</span>
            <div className="bg-destructive/10 text-destructive mt-1 rounded-md p-3 font-mono text-xs whitespace-pre-wrap">
              {job.error}
            </div>
          </div>
        )}

        <div>
          <span className="text-muted-foreground text-sm">Progress</span>
          <div className="mt-1 rounded-md border divide-y">
            <ProgressRow
              label="Discovering repos"
              active={isActive && job.stage === "discovering_repos"}
              reached={hasReached("discovering_repos")}
              value={job.total_repos?.toLocaleString()}
              suffix="repos found"
            />
            <ProgressRow
              label="Resolving PDS"
              active={isActive && job.stage === "resolving_pds"}
              reached={hasReached("resolving_pds")}
              value={
                hasReached("resolving_pds")
                  ? `${job.processed_repos?.toLocaleString() ?? "0"} / ${job.total_repos?.toLocaleString() ?? "0"}`
                  : undefined
              }
              suffix="resolved"
            />
            <ProgressRow
              label="Fetching records"
              active={isActive && job.stage === "fetching_records"}
              reached={hasReached("fetching_records")}
              value={
                hasReached("fetching_records")
                  ? `${job.processed_repos?.toLocaleString() ?? "0"} / ${job.total_repos?.toLocaleString() ?? "0"} repos`
                  : undefined
              }
              suffix={
                hasReached("fetching_records")
                  ? `${job.total_records?.toLocaleString() ?? "0"} records`
                  : undefined
              }
            />
          </div>
        </div>
      </div>
      {canCancel && isActive && (
        <SheetFooter className="border-t flex-row justify-end">
          <Button
            variant="destructive"
            size="sm"
            disabled={cancelling || job.status === "cancelling"}
            onClick={handleCancel}
          >
            {job.status === "cancelling" ? "Cancelling…" : "Cancel Job"}
          </Button>
        </SheetFooter>
      )}
    </>
  );
}

function ProgressRow({
  label,
  active,
  reached,
  value,
  suffix,
}: {
  label: string;
  active: boolean;
  reached: boolean;
  value?: string;
  suffix?: string;
}) {
  const done = reached && !active;

  return (
    <div
      className={`flex items-center gap-2 px-3 py-2 text-sm ${
        active
          ? "bg-blue-500/5"
          : reached
            ? ""
            : "text-muted-foreground opacity-50"
      }`}
    >
      <span className="shrink-0">
        {active ? (
          <Loader2 className="size-4 animate-spin text-blue-500" />
        ) : done ? (
          <CheckCircle2 className="size-4 text-emerald-500" />
        ) : (
          <Circle className="size-4" />
        )}
      </span>
      <span className={`flex-1 ${active ? "font-medium" : ""}`}>{label}</span>
      {reached && value && (
        <span className="tabular-nums text-xs text-muted-foreground">
          {value}
          {suffix ? ` · ${suffix}` : ""}
        </span>
      )}
    </div>
  );
}

function CreateDialog({ onSuccess }: { onSuccess: () => void }) {
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
      <ResponsiveDialogContent
        onInteractOutside={(e) => {
          const target = e.target as HTMLElement;
          if (
            target.closest(
              "[data-slot='combobox-item'], [data-slot='combobox-content']",
            )
          ) {
            e.preventDefault();
          }
        }}
      >
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
            <Combobox
              value={collection}
              onValueChange={setCollection}
              items={recordLexicons}
            >
              <ComboboxInput
                placeholder="Select or type a collection..."
                showClear
              />
              <ComboboxContent>
                <ComboboxEmpty>No matching lexicons.</ComboboxEmpty>
                <ComboboxList>
                  {(item: string) => (
                    <ComboboxItem key={item} value={item}>
                      {item}
                    </ComboboxItem>
                  )}
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
