"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  type ColumnDef,
  type VisibilityState,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";

import { useAuth } from "@/lib/auth-context";
import {
  getStats,
  getAdminRecords,
  type CollectionStat,
  type AdminRecord,
} from "@/lib/api";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableViewOptions } from "@/components/data-table/data-table-view-options";
import { SiteHeader } from "@/components/site-header";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ChevronLeft, ChevronRight } from "lucide-react";

function parseAtUri(uri: string): { did: string; rkey: string } {
  const parts = uri.replace("at://", "").split("/");
  return { did: parts[0] ?? "", rkey: parts[2] ?? "" };
}

function formatCellValue(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  return JSON.stringify(value);
}

export default function RecordsPage() {
  const { getToken } = useAuth();
  const [collections, setCollections] = useState<CollectionStat[]>([]);
  const [selectedCollection, setSelectedCollection] = useState<string>("");
  const [records, setRecords] = useState<AdminRecord[]>([]);
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [viewRecord, setViewRecord] = useState<AdminRecord | null>(null);

  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({});

  useEffect(() => {
    getStats(getToken)
      .then((stats) => setCollections(stats.collections))
      .catch((e) => setError(e.message));
  }, [getToken]);

  const fetchRecords = useCallback(
    async (collection: string, cursor?: string) => {
      setLoading(true);
      setError(null);
      try {
        const data = await getAdminRecords(getToken, collection, 20, cursor);
        setRecords(data.records);
        setNextCursor(data.cursor);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : String(e));
        setRecords([]);
        setNextCursor(undefined);
      } finally {
        setLoading(false);
      }
    },
    [getToken],
  );

  // Build columns dynamically from the union of all record keys
  const columns = useMemo<ColumnDef<AdminRecord>[]>(() => {
    const keySet = new Set<string>();
    for (const r of records) {
      for (const key of Object.keys(r.record)) {
        keySet.add(key);
      }
    }

    const cols: ColumnDef<AdminRecord>[] = [
      {
        id: "did",
        accessorFn: (row) => parseAtUri(row.uri).did,
        header: "DID",
        cell: ({ getValue }) => (
          <span className="font-mono text-xs whitespace-nowrap">
            {getValue<string>()}
          </span>
        ),
        enableSorting: false,
        enableHiding: false,
        meta: { label: "DID" },
      },
      {
        id: "rkey",
        accessorFn: (row) => parseAtUri(row.uri).rkey,
        header: "Record Key",
        cell: ({ getValue }) => (
          <span className="font-mono text-xs whitespace-nowrap">
            {getValue<string>()}
          </span>
        ),
        enableSorting: false,
        enableHiding: false,
        meta: { label: "Record Key" },
      },
    ];

    for (const key of keySet) {
      cols.push({
        id: key,
        accessorFn: (row) => row.record[key],
        header: key,
        enableSorting: false,
        cell: ({ getValue }) => {
          const val = getValue<unknown>();
          const str = formatCellValue(val);
          return (
            <span
              className="font-mono text-xs block max-w-xs truncate"
              title={str}
            >
              {str}
            </span>
          );
        },
        meta: { label: key },
      });
    }

    return cols;
  }, [records]);

  const table = useReactTable({
    data: records,
    columns,
    state: {
      columnVisibility,
    },
    onColumnVisibilityChange: setColumnVisibility,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (row) => row.uri,
  });

  function handleSelectCollection(collection: string) {
    setSelectedCollection(collection);
    setCursorStack([]);
    setNextCursor(undefined);
    setColumnVisibility({});
    fetchRecords(collection);
  }

  function handleNext() {
    if (!nextCursor || !selectedCollection) return;
    setCursorStack((prev) => [...prev, nextCursor]);
    fetchRecords(selectedCollection, nextCursor);
  }

  function handlePrevious() {
    if (cursorStack.length === 0 || !selectedCollection) return;
    const stack = [...cursorStack];
    stack.pop();
    const prevCursor = stack.length > 0 ? stack[stack.length - 1] : undefined;
    setCursorStack(stack);
    fetchRecords(selectedCollection, prevCursor);
  }

  return (
    <>
      <SiteHeader title="Records" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        <DataTable
          table={table}
          showPagination={false}
          onRowClick={setViewRecord}
        >
          <div className="flex w-full items-center justify-between gap-2 p-1">
            <Select
              value={selectedCollection}
              onValueChange={handleSelectCollection}
            >
              <SelectTrigger className="h-8 w-80 text-sm">
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
            <DataTableViewOptions table={table} />
          </div>
        </DataTable>

        {selectedCollection && (
          <div className="flex w-full items-center justify-between gap-4 overflow-auto p-1">
            <p className="text-muted-foreground flex-1 whitespace-nowrap text-sm">
              {records.length} record(s) on this page.
            </p>
            <div className="flex items-center space-x-2">
              <Button
                aria-label="Go to previous page"
                variant="outline"
                size="icon"
                className="size-8"
                disabled={cursorStack.length === 0 || loading}
                onClick={handlePrevious}
              >
                <ChevronLeft />
              </Button>
              <Button
                aria-label="Go to next page"
                variant="outline"
                size="icon"
                className="size-8"
                disabled={!nextCursor || loading}
                onClick={handleNext}
              >
                <ChevronRight />
              </Button>
            </div>
          </div>
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
  );
}
