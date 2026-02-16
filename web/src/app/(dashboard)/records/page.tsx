"use client"

import { useCallback, useEffect, useState } from "react"

import { useAuth } from "@/lib/auth-context"
import {
  getLexicons,
  xrpcQuery,
  type LexiconSummary,
} from "@/lib/api"
import { SiteHeader } from "@/components/site-header"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

interface XrpcRecord {
  uri: string
  [key: string]: unknown
}

interface XrpcListResponse {
  records: XrpcRecord[]
  cursor?: string
}

function parseAtUri(uri: string): { did: string; rkey: string } {
  // at://did:plc:xxx/collection/rkey
  const parts = uri.replace("at://", "").split("/")
  return { did: parts[0] ?? "", rkey: parts[2] ?? "" }
}

function truncateJson(record: XrpcRecord, maxLen = 120): string {
  const { uri, ...rest } = record
  const str = JSON.stringify(rest)
  return str.length > maxLen ? str.slice(0, maxLen) + "..." : str
}

export default function RecordsPage() {
  const { getToken } = useAuth()
  const [queryLexicons, setQueryLexicons] = useState<LexiconSummary[]>([])
  const [selectedMethod, setSelectedMethod] = useState<string>("")
  const [records, setRecords] = useState<XrpcRecord[]>([])
  const [cursorStack, setCursorStack] = useState<string[]>([])
  const [nextCursor, setNextCursor] = useState<string | undefined>()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [viewRecord, setViewRecord] = useState<XrpcRecord | null>(null)

  // Load query-type lexicons for the collection selector
  useEffect(() => {
    getLexicons(getToken)
      .then((lexicons) =>
        setQueryLexicons(lexicons.filter((l) => l.lexicon_type === "query"))
      )
      .catch((e) => setError(e.message))
  }, [getToken])

  const fetchRecords = useCallback(
    async (method: string, cursor?: string) => {
      setLoading(true)
      setError(null)
      try {
        const params: Record<string, string> = { limit: "20" }
        if (cursor) params.cursor = cursor
        const data = await xrpcQuery<XrpcListResponse>(method, params)
        setRecords(data.records)
        setNextCursor(data.cursor)
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : String(e))
        setRecords([])
        setNextCursor(undefined)
      } finally {
        setLoading(false)
      }
    },
    []
  )

  function handleSelectCollection(method: string) {
    setSelectedMethod(method)
    setCursorStack([])
    setNextCursor(undefined)
    fetchRecords(method)
  }

  function handleNext() {
    if (!nextCursor || !selectedMethod) return
    setCursorStack((prev) => [...prev, nextCursor])
    fetchRecords(selectedMethod, nextCursor)
  }

  function handlePrevious() {
    if (cursorStack.length === 0 || !selectedMethod) return
    const stack = [...cursorStack]
    stack.pop() // remove current page's cursor
    const prevCursor = stack.length > 0 ? stack[stack.length - 1] : undefined
    setCursorStack(stack)
    fetchRecords(selectedMethod, prevCursor)
  }

  // Find the selected lexicon to show its target_collection label
  const selectedLexicon = queryLexicons.find((l) => l.id === selectedMethod)

  return (
    <>
      <SiteHeader title="Records" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        <div className="flex items-center gap-4">
          <Select value={selectedMethod} onValueChange={handleSelectCollection}>
            <SelectTrigger className="w-80">
              <SelectValue placeholder="Select a collection" />
            </SelectTrigger>
            <SelectContent>
              {queryLexicons.map((lex) => (
                <SelectItem key={lex.id} value={lex.id}>
                  {lex.target_collection ?? lex.id}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {selectedLexicon && (
            <span className="text-muted-foreground text-sm">
              via {selectedLexicon.id}
            </span>
          )}
        </div>

        {selectedMethod && (
          <>
            <div className="rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>DID</TableHead>
                    <TableHead>Rkey</TableHead>
                    <TableHead>Record</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loading && (
                    <TableRow>
                      <TableCell
                        colSpan={3}
                        className="text-muted-foreground text-center"
                      >
                        Loading...
                      </TableCell>
                    </TableRow>
                  )}
                  {!loading && records.length === 0 && (
                    <TableRow>
                      <TableCell
                        colSpan={3}
                        className="text-muted-foreground text-center"
                      >
                        No records found.
                      </TableCell>
                    </TableRow>
                  )}
                  {!loading &&
                    records.map((record) => {
                      const { did, rkey } = parseAtUri(record.uri)
                      return (
                        <TableRow
                          key={record.uri}
                          className="cursor-pointer"
                          onClick={() => setViewRecord(record)}
                        >
                          <TableCell className="font-mono text-xs">
                            {did}
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            {rkey}
                          </TableCell>
                          <TableCell className="max-w-md truncate font-mono text-xs">
                            {truncateJson(record)}
                          </TableCell>
                        </TableRow>
                      )
                    })}
                </TableBody>
              </Table>
            </div>

            <div className="flex items-center justify-end gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={cursorStack.length === 0}
                onClick={handlePrevious}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={!nextCursor}
                onClick={handleNext}
              >
                Next
              </Button>
            </div>
          </>
        )}

        {viewRecord && (
          <Dialog open onOpenChange={() => setViewRecord(null)}>
            <DialogContent className="max-w-2xl">
              <DialogHeader>
                <DialogTitle className="font-mono text-sm">
                  {viewRecord.uri}
                </DialogTitle>
              </DialogHeader>
              <pre className="bg-muted max-h-96 overflow-auto rounded-md p-4 text-xs">
                {JSON.stringify(viewRecord, null, 2)}
              </pre>
            </DialogContent>
          </Dialog>
        )}
      </div>
    </>
  )
}
