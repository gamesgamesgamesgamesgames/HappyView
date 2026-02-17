"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table"

import { useAuth } from "@/lib/auth-context"
import {
  getStats,
  getAdminRecords,
  type CollectionStat,
  type AdminRecord,
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

function parseAtUri(uri: string): { did: string; rkey: string } {
  const parts = uri.replace("at://", "").split("/")
  return { did: parts[0] ?? "", rkey: parts[2] ?? "" }
}

function formatCellValue(value: unknown): string {
  if (value === null || value === undefined) return ""
  if (typeof value === "string") return value
  if (typeof value === "number" || typeof value === "boolean")
    return String(value)
  return JSON.stringify(value)
}

export default function RecordsPage() {
  const { getToken } = useAuth()
  const [collections, setCollections] = useState<CollectionStat[]>([])
  const [selectedCollection, setSelectedCollection] = useState<string>("")
  const [records, setRecords] = useState<AdminRecord[]>([])
  const [cursorStack, setCursorStack] = useState<string[]>([])
  const [nextCursor, setNextCursor] = useState<string | undefined>()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [viewRecord, setViewRecord] = useState<AdminRecord | null>(null)

  useEffect(() => {
    getStats(getToken)
      .then((stats) => setCollections(stats.collections))
      .catch((e) => setError(e.message))
  }, [getToken])

  const fetchRecords = useCallback(
    async (collection: string, cursor?: string) => {
      setLoading(true)
      setError(null)
      try {
        const data = await getAdminRecords(getToken, collection, 20, cursor)
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
    [getToken]
  )

  // Build columns dynamically from the union of all record keys
  const columns = useMemo<ColumnDef<AdminRecord>[]>(() => {
    const keySet = new Set<string>()
    for (const r of records) {
      for (const key of Object.keys(r.record)) {
        keySet.add(key)
      }
    }

    const cols: ColumnDef<AdminRecord>[] = [
      {
        id: "did",
        header: "DID",
        accessorFn: (row) => parseAtUri(row.uri).did,
        cell: ({ getValue }) => (
          <span className="font-mono text-xs whitespace-nowrap">
            {getValue<string>()}
          </span>
        ),
      },
      {
        id: "rkey",
        header: "Rkey",
        accessorFn: (row) => parseAtUri(row.uri).rkey,
        cell: ({ getValue }) => (
          <span className="font-mono text-xs whitespace-nowrap">
            {getValue<string>()}
          </span>
        ),
      },
    ]

    for (const key of keySet) {
      cols.push({
        id: key,
        header: key,
        accessorFn: (row) => row.record[key],
        cell: ({ getValue }) => {
          const val = getValue<unknown>()
          const str = formatCellValue(val)
          return (
            <span
              className="font-mono text-xs block max-w-xs truncate"
              title={str}
            >
              {str}
            </span>
          )
        },
      })
    }

    return cols
  }, [records])

  const table = useReactTable({
    data: records,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (row) => row.uri,
  })

  function handleSelectCollection(collection: string) {
    setSelectedCollection(collection)
    setCursorStack([])
    setNextCursor(undefined)
    fetchRecords(collection)
  }

  function handleNext() {
    if (!nextCursor || !selectedCollection) return
    setCursorStack((prev) => [...prev, nextCursor])
    fetchRecords(selectedCollection, nextCursor)
  }

  function handlePrevious() {
    if (cursorStack.length === 0 || !selectedCollection) return
    const stack = [...cursorStack]
    stack.pop()
    const prevCursor = stack.length > 0 ? stack[stack.length - 1] : undefined
    setCursorStack(stack)
    fetchRecords(selectedCollection, prevCursor)
  }

  return (
    <>
      <SiteHeader title="Records" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        <div className="flex items-center gap-4">
          <Select
            value={selectedCollection}
            onValueChange={handleSelectCollection}
          >
            <SelectTrigger className="w-80">
              <SelectValue placeholder="Select a collection" />
            </SelectTrigger>
            <SelectContent>
              {collections.map((col) => (
                <SelectItem key={col.collection} value={col.collection}>
                  {col.collection} ({col.count.toLocaleString()})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {selectedCollection && (
          <>
            <div className="overflow-x-auto rounded-lg border">
              <Table>
                <TableHeader>
                  {table.getHeaderGroups().map((headerGroup) => (
                    <TableRow key={headerGroup.id}>
                      {headerGroup.headers.map((header) => (
                        <TableHead key={header.id} className="whitespace-nowrap">
                          {header.isPlaceholder
                            ? null
                            : flexRender(
                                header.column.columnDef.header,
                                header.getContext()
                              )}
                        </TableHead>
                      ))}
                    </TableRow>
                  ))}
                </TableHeader>
                <TableBody>
                  {loading && (
                    <TableRow>
                      <TableCell
                        colSpan={columns.length}
                        className="text-muted-foreground text-center"
                      >
                        Loading...
                      </TableCell>
                    </TableRow>
                  )}
                  {!loading && table.getRowModel().rows.length === 0 && (
                    <TableRow>
                      <TableCell
                        colSpan={columns.length}
                        className="text-muted-foreground text-center"
                      >
                        No records found.
                      </TableCell>
                    </TableRow>
                  )}
                  {!loading &&
                    table.getRowModel().rows.map((row) => (
                      <TableRow
                        key={row.id}
                        className="cursor-pointer"
                        onClick={() => setViewRecord(row.original)}
                      >
                        {row.getVisibleCells().map((cell) => (
                          <TableCell key={cell.id}>
                            {flexRender(
                              cell.column.columnDef.cell,
                              cell.getContext()
                            )}
                          </TableCell>
                        ))}
                      </TableRow>
                    ))}
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
