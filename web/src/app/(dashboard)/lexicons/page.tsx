"use client"

import { useCallback, useEffect, useState } from "react"

import { useAuth } from "@/lib/auth-context"
import {
  deleteLexicon,
  getLexicon,
  getLexicons,
  uploadLexicon,
  type LexiconDetail,
  type LexiconSummary,
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
import { Switch } from "@/components/ui/switch"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"

export default function LexiconsPage() {
  const { getToken } = useAuth()
  const [lexicons, setLexicons] = useState<LexiconSummary[]>([])
  const [error, setError] = useState<string | null>(null)
  const [viewLexicon, setViewLexicon] = useState<LexiconDetail | null>(null)

  const load = useCallback(() => {
    getLexicons(getToken).then(setLexicons).catch((e) => setError(e.message))
  }, [getToken])

  useEffect(() => {
    load()
  }, [load])

  async function handleView(id: string) {
    try {
      const detail = await getLexicon(getToken, id)
      setViewLexicon(detail)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function handleDelete(id: string) {
    try {
      await deleteLexicon(getToken, id)
      load()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <>
      <SiteHeader title="Lexicons" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Uploaded Lexicons</h2>
          <UploadDialog getToken={getToken} onSuccess={load} />
        </div>

        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Backfill</TableHead>
                <TableHead>Revision</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {lexicons.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-muted-foreground text-center">
                    No lexicons uploaded yet.
                  </TableCell>
                </TableRow>
              )}
              {lexicons.map((lex) => (
                <TableRow key={lex.id}>
                  <TableCell className="font-mono text-sm">{lex.id}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{lex.lexicon_type}</Badge>
                  </TableCell>
                  <TableCell>{lex.action ?? "--"}</TableCell>
                  <TableCell>{lex.backfill ? "Yes" : "No"}</TableCell>
                  <TableCell className="tabular-nums">{lex.revision}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleView(lex.id)}
                      >
                        View
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => handleDelete(lex.id)}
                      >
                        Delete
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>

        {viewLexicon && (
          <Dialog open onOpenChange={() => setViewLexicon(null)}>
            <DialogContent className="max-w-2xl">
              <DialogHeader>
                <DialogTitle>{viewLexicon.id}</DialogTitle>
                <DialogDescription>
                  Revision {viewLexicon.revision} &middot; {viewLexicon.lexicon_type}
                </DialogDescription>
              </DialogHeader>
              <pre className="bg-muted max-h-96 overflow-auto rounded-md p-4 text-xs">
                {JSON.stringify(viewLexicon.lexicon_json, null, 2)}
              </pre>
            </DialogContent>
          </Dialog>
        )}
      </div>
    </>
  )
}

function UploadDialog({
  getToken,
  onSuccess,
}: {
  getToken: () => Promise<string | null>
  onSuccess: () => void
}) {
  const [json, setJson] = useState("")
  const [targetCollection, setTargetCollection] = useState("")
  const [action, setAction] = useState("")
  const [backfill, setBackfill] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState(false)

  async function handleUpload() {
    setError(null)
    try {
      const lexiconJson = JSON.parse(json)
      await uploadLexicon(getToken, {
        lexicon_json: lexiconJson,
        backfill,
        target_collection: targetCollection || undefined,
        action: action || undefined,
      })
      setJson("")
      setTargetCollection("")
      setAction("")
      setBackfill(true)
      setOpen(false)
      onSuccess()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>Upload Lexicon</Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Upload Lexicon</DialogTitle>
          <DialogDescription>
            Paste the lexicon JSON document below.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-4">
          {error && <p className="text-destructive text-sm">{error}</p>}
          <div className="flex flex-col gap-2">
            <Label htmlFor="lexicon-json">Lexicon JSON</Label>
            <Textarea
              id="lexicon-json"
              className="font-mono text-xs"
              rows={12}
              value={json}
              onChange={(e) => setJson(e.target.value)}
              placeholder='{"lexicon": 1, "id": "com.example.record", ...}'
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="target-collection">
              Target Collection (optional)
            </Label>
            <Input
              id="target-collection"
              value={targetCollection}
              onChange={(e) => setTargetCollection(e.target.value)}
              placeholder="com.example.record"
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="action">Action (optional)</Label>
            <Input
              id="action"
              value={action}
              onChange={(e) => setAction(e.target.value)}
              placeholder="create, put, or leave empty for auto"
            />
          </div>
          <div className="flex items-center gap-2">
            <Switch
              id="backfill"
              checked={backfill}
              onCheckedChange={setBackfill}
            />
            <Label htmlFor="backfill">Enable backfill</Label>
          </div>
        </div>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </DialogClose>
          <Button onClick={handleUpload}>Upload</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
