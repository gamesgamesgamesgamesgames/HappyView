"use client"

import { useCallback, useEffect, useState } from "react"

import { useAuth } from "@/lib/auth-context"
import {
  addNetworkLexicon,
  deleteNetworkLexicon,
  getNetworkLexicons,
  type NetworkLexiconSummary,
} from "@/lib/api"
import { SiteHeader } from "@/components/site-header"
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

export default function NetworkLexiconsPage() {
  const { token } = useAuth()
  const [items, setItems] = useState<NetworkLexiconSummary[]>([])
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    if (!token) return
    getNetworkLexicons(token).then(setItems).catch((e) => setError(e.message))
  }, [token])

  useEffect(() => {
    load()
  }, [load])

  async function handleDelete(nsid: string) {
    if (!token) return
    try {
      await deleteNetworkLexicon(token, nsid)
      load()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <>
      <SiteHeader title="Network Lexicons" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Tracked Network Lexicons</h2>
          <AddDialog token={token!} onSuccess={load} />
        </div>

        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>NSID</TableHead>
                <TableHead>Authority DID</TableHead>
                <TableHead>Target Collection</TableHead>
                <TableHead>Last Fetched</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={5}
                    className="text-muted-foreground text-center"
                  >
                    No network lexicons tracked yet.
                  </TableCell>
                </TableRow>
              )}
              {items.map((item) => (
                <TableRow key={item.nsid}>
                  <TableCell className="font-mono text-sm">
                    {item.nsid}
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {item.authority_did}
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {item.target_collection ?? "--"}
                  </TableCell>
                  <TableCell>
                    {item.last_fetched_at
                      ? new Date(item.last_fetched_at).toLocaleString()
                      : "Never"}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => handleDelete(item.nsid)}
                    >
                      Delete
                    </Button>
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

function AddDialog({
  token,
  onSuccess,
}: {
  token: string
  onSuccess: () => void
}) {
  const [nsid, setNsid] = useState("")
  const [targetCollection, setTargetCollection] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)

  async function handleAdd() {
    setError(null)
    try {
      await addNetworkLexicon(token, {
        nsid,
        target_collection: targetCollection || undefined,
      })
      setNsid("")
      setTargetCollection("")
      setOpen(false)
      onSuccess()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>Add Network Lexicon</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add Network Lexicon</DialogTitle>
          <DialogDescription>
            Track a lexicon from the ATProto network by its NSID.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          {error && <p className="text-destructive text-sm">{error}</p>}
          <div className="flex flex-col gap-2">
            <Label htmlFor="nsid">NSID</Label>
            <Input
              id="nsid"
              value={nsid}
              onChange={(e) => setNsid(e.target.value)}
              placeholder="com.example.record"
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="nl-target-collection">
              Target Collection (optional)
            </Label>
            <Input
              id="nl-target-collection"
              value={targetCollection}
              onChange={(e) => setTargetCollection(e.target.value)}
              placeholder="com.example.record"
            />
          </div>
        </div>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button onClick={handleAdd}>Add</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
