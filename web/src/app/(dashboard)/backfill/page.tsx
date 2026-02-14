"use client"

import { useCallback, useEffect, useState } from "react"

import { useAuth } from "@/lib/auth-context"
import {
  createBackfillJob,
  getBackfillJobs,
  type BackfillJob,
} from "@/lib/api"
import { SiteHeader } from "@/components/site-header"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

function statusVariant(status: string) {
  switch (status) {
    case "completed":
      return "default" as const
    case "running":
      return "secondary" as const
    case "failed":
      return "destructive" as const
    default:
      return "outline" as const
  }
}

export default function BackfillPage() {
  const { getToken } = useAuth()
  const [jobs, setJobs] = useState<BackfillJob[]>([])
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    getBackfillJobs(getToken).then(setJobs).catch((e) => setError(e.message))
  }, [getToken])

  useEffect(() => {
    load()
  }, [load])

  // Auto-refresh every 5 seconds when there are active jobs
  useEffect(() => {
    const hasActive = jobs.some(
      (j) => j.status === "pending" || j.status === "running"
    )
    if (!hasActive) return
    const interval = setInterval(load, 5000)
    return () => clearInterval(interval)
  }, [jobs, load])

  return (
    <>
      <SiteHeader title="Backfill" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Backfill Jobs</h2>
          <CreateDialog getToken={getToken} onSuccess={load} />
        </div>

        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Collection</TableHead>
                <TableHead>DID</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Progress</TableHead>
                <TableHead>Records</TableHead>
                <TableHead>Started</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {jobs.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={7}
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
                  <TableCell>
                    <Badge variant={statusVariant(job.status)}>
                      {job.status}
                    </Badge>
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
  )
}

function CreateDialog({
  getToken,
  onSuccess,
}: {
  getToken: () => Promise<string | null>
  onSuccess: () => void
}) {
  const [collection, setCollection] = useState("")
  const [did, setDid] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)

  async function handleCreate() {
    setError(null)
    try {
      await createBackfillJob(getToken, {
        collection: collection || undefined,
        did: did || undefined,
      })
      setCollection("")
      setDid("")
      setOpen(false)
      onSuccess()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>Create Backfill Job</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create Backfill Job</DialogTitle>
          <DialogDescription>
            Start a backfill for a collection or specific DID. Leave both empty
            to backfill all collections.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          {error && <p className="text-destructive text-sm">{error}</p>}
          <div className="flex flex-col gap-2">
            <Label htmlFor="bf-collection">Collection (optional)</Label>
            <Input
              id="bf-collection"
              value={collection}
              onChange={(e) => setCollection(e.target.value)}
              placeholder="com.example.record"
            />
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
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button onClick={handleCreate}>Create</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
