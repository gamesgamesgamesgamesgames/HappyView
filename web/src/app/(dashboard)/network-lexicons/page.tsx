"use client"

import { useCallback, useEffect, useRef, useState } from "react"

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
  const { getToken } = useAuth()
  const [items, setItems] = useState<NetworkLexiconSummary[]>([])
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    getNetworkLexicons(getToken).then(setItems).catch((e) => setError(e.message))
  }, [getToken])

  useEffect(() => {
    load()
  }, [load])

  async function handleDelete(nsid: string) {
    try {
      await deleteNetworkLexicon(getToken, nsid)
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
          <AddDialog getToken={getToken} onSuccess={load} />
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

// Extract the authority domain from an NSID.
// e.g. "games.gamesgamesgamesgames.createGame" → "gamesgamesgamesgames.games"
function nsidToDomain(nsid: string): string | null {
  const parts = nsid.split(".")
  if (parts.length < 3) return null
  const authority = parts.slice(0, -1).reverse()
  return authority.join(".")
}

// Resolve an NSID to its lexicon's main def type by fetching from the network.
async function resolveNsidType(
  nsid: string,
  signal: AbortSignal
): Promise<string | undefined> {
  const domain = nsidToDomain(nsid)
  if (!domain) return undefined

  // Resolve handle → DID
  let did: string | undefined
  try {
    const resp = await fetch(
      `https://${domain}/.well-known/atproto-did`,
      { signal }
    )
    if (resp.ok) did = (await resp.text()).trim()
  } catch (e) {
    if (signal.aborted) return undefined
  }

  if (!did) {
    try {
      const resp = await fetch(
        `https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(domain)}`,
        { signal }
      )
      if (resp.ok) {
        const data = await resp.json()
        did = data.did
      }
    } catch (e) {
      if (signal.aborted) return undefined
    }
  }

  if (!did) return undefined

  // Resolve DID → PDS endpoint
  let pdsEndpoint: string | undefined
  try {
    const resp = await fetch(
      `https://plc.directory/${encodeURIComponent(did)}`,
      { signal }
    )
    if (resp.ok) {
      const doc = await resp.json()
      const services = doc.service as
        | { id: string; serviceEndpoint: string }[]
        | undefined
      pdsEndpoint = services?.find(
        (s) => s.id === "#atproto_pds"
      )?.serviceEndpoint
    }
  } catch (e) {
    if (signal.aborted) return undefined
  }

  if (!pdsEndpoint) return undefined

  // Fetch lexicon record from PDS
  try {
    const resp = await fetch(
      `${pdsEndpoint}/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(did)}&collection=com.atproto.lexicon.schema&rkey=${encodeURIComponent(nsid)}`,
      { signal }
    )
    if (resp.ok) {
      const data = await resp.json()
      return data.value?.defs?.main?.type as string | undefined
    }
  } catch {
    // Best-effort resolution
  }

  return undefined
}

function AddDialog({
  getToken,
  onSuccess,
}: {
  getToken: () => Promise<string | null>
  onSuccess: () => void
}) {
  const [nsid, setNsid] = useState("")
  const [targetCollection, setTargetCollection] = useState("")
  const [mainType, setMainType] = useState<string | undefined>()
  const [resolving, setResolving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)
  const abortRef = useRef<AbortController | null>(null)

  // Debounced NSID resolution
  useEffect(() => {
    abortRef.current?.abort()
    setMainType(undefined)

    // Need at least 3 segments (e.g. "com.example.thing")
    if (nsid.split(".").length < 3) return

    const debounce = setTimeout(() => {
      const controller = new AbortController()
      abortRef.current = controller
      setResolving(true)

      resolveNsidType(nsid, controller.signal)
        .then((type) => {
          if (!controller.signal.aborted) setMainType(type)
        })
        .finally(() => {
          if (!controller.signal.aborted) setResolving(false)
        })
    }, 500)

    return () => clearTimeout(debounce)
  }, [nsid])

  const showTargetCollection = mainType === "query" || mainType === "procedure"

  async function handleAdd() {
    setError(null)
    try {
      await addNetworkLexicon(getToken, {
        nsid,
        target_collection: showTargetCollection
          ? targetCollection || undefined
          : undefined,
      })
      setNsid("")
      setTargetCollection("")
      setMainType(undefined)
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
            {resolving && (
              <p className="text-muted-foreground text-xs">
                Resolving lexicon...
              </p>
            )}
          </div>
          {showTargetCollection && (
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
          )}
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
