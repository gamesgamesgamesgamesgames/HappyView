"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type ColumnDef,
  type RowSelectionState,
  type VisibilityState,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";

import { useSearchParams } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import {
  getStats,
  getAdminRecords,
  deleteRecord,
  deleteCollectionRecords,
  type CollectionStat,
  type AdminRecord,
} from "@/lib/api";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { CodeBlock } from "@/components/code-block";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableViewOptions } from "@/components/data-table/data-table-view-options";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
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
import { Input } from "@/components/ui/input";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { ChevronLeft, ChevronRight, Trash2 } from "lucide-react";
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldLabel,
  FieldTitle,
} from "@/components/ui/field";

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
  const searchParams = useSearchParams();
  const initialCollection = searchParams.get("collection") ?? "";
  const appliedInitial = useRef(false);
  const [collections, setCollections] = useState<CollectionStat[]>([]);
  const [selectedCollection, setSelectedCollection] = useState<string>("");
  const [records, setRecords] = useState<AdminRecord[]>([]);
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const [nextCursor, setNextCursor] = useState<string | undefined>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [viewRecord, setViewRecord] = useState<AdminRecord | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteUri, setDeleteUri] = useState<string | null>(null);
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false);
  const [bulkDeleteMode, setBulkDeleteMode] = useState<"selected" | "all">(
    "selected",
  );
  const [bulkDeleteConfirm, setBulkDeleteConfirm] = useState("");
  const [deletingAll, setDeletingAll] = useState(false);

  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({});
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});

  useEffect(() => {
    getStats(getToken)
      .then((stats) => setCollections(stats.collections))
      .catch((e) => setError(e.message));
  }, [getToken]);

  // Auto-select collection from URL search param on initial load.
  useEffect(() => {
    if (appliedInitial.current || !initialCollection || collections.length === 0)
      return;
    if (collections.some((c) => c.collection === initialCollection)) {
      appliedInitial.current = true;
      handleSelectCollection(initialCollection);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [collections, initialCollection]);

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

  const handleDeleteRecord = useCallback(
    async (uri: string) => {
      setDeleting(true);
      try {
        await deleteRecord(getToken, uri);
        setDeleteUri(null);
        setViewRecord(null);
        if (selectedCollection) {
          const currentCursor =
            cursorStack.length > 0
              ? cursorStack[cursorStack.length - 1]
              : undefined;
          fetchRecords(selectedCollection, currentCursor);
        }
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setDeleting(false);
      }
    },
    [getToken, selectedCollection, cursorStack, fetchRecords],
  );

  const handleDeleteAll = useCallback(async () => {
    if (!selectedCollection) return;
    setDeletingAll(true);
    try {
      await deleteCollectionRecords(getToken, selectedCollection);
      setBulkDeleteOpen(false);
      setBulkDeleteMode("selected");
      setBulkDeleteConfirm("");
      setRowSelection({});
      // Refresh stats and records
      const stats = await getStats(getToken);
      setCollections(stats.collections);
      setCursorStack([]);
      setNextCursor(undefined);
      setRecords([]);
      setSelectedCollection("");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setDeletingAll(false);
    }
  }, [getToken, selectedCollection]);

  const handleBulkDelete = useCallback(async () => {
    setDeleting(true);
    try {
      const selectedUris = Object.keys(rowSelection);
      for (const uri of selectedUris) {
        await deleteRecord(getToken, uri);
      }
      setRowSelection({});
      setBulkDeleteOpen(false);
      if (selectedCollection) {
        const currentCursor =
          cursorStack.length > 0
            ? cursorStack[cursorStack.length - 1]
            : undefined;
        fetchRecords(selectedCollection, currentCursor);
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setDeleting(false);
    }
  }, [getToken, rowSelection, selectedCollection, cursorStack, fetchRecords]);

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
        id: "select",
        header: ({ table }) => (
          <Checkbox
            checked={
              table.getIsAllPageRowsSelected() ||
              (table.getIsSomePageRowsSelected() && "indeterminate")
            }
            onCheckedChange={(value) =>
              table.toggleAllPageRowsSelected(!!value)
            }
            aria-label="Select all"
          />
        ),
        cell: ({ row }) => (
          <Checkbox
            checked={row.getIsSelected()}
            onCheckedChange={(value) => row.toggleSelected(!!value)}
            onClick={(e) => e.stopPropagation()}
            aria-label="Select row"
          />
        ),
        enableSorting: false,
        enableHiding: false,
      },
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
      columnPinning: { left: ["select"] },
      rowSelection,
    },
    onColumnVisibilityChange: setColumnVisibility,
    onRowSelectionChange: setRowSelection,
    enableRowSelection: true,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (row) => row.uri,
  });

  function handleSelectCollection(collection: string) {
    setSelectedCollection(collection);
    setCursorStack([]);
    setNextCursor(undefined);
    setColumnVisibility({});
    setRowSelection({});
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
                    {col.collection}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <div className="flex items-center gap-2">
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-8"
                    disabled={Object.keys(rowSelection).length === 0}
                  >
                    Actions
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem
                    variant="destructive"
                    onClick={() => setBulkDeleteOpen(true)}
                  >
                    <Trash2 className="size-4" />
                    Delete
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
              <DataTableViewOptions table={table} />
            </div>
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
                title="Previous page"
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
                title="Next page"
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
            <DialogContent className="sm:max-w-4xl">
              <DialogHeader>
                <DialogTitle className="truncate font-mono text-sm">
                  {viewRecord.uri}
                </DialogTitle>
              </DialogHeader>
              <CodeBlock code={JSON.stringify(viewRecord, null, 2)} />
              <div className="flex justify-end">
                <Button
                  variant="destructive"
                  onClick={() => setDeleteUri(viewRecord.uri)}
                  disabled={deleting}
                >
                  {deleting ? "Deleting..." : "Delete Record"}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        )}

        <AlertDialog
          open={!!deleteUri}
          onOpenChange={(open) => {
            if (!open) setDeleteUri(null);
          }}
        >
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Delete record?</AlertDialogTitle>
              <AlertDialogDescription>
                This will permanently delete the record. This action cannot be
                undone.
              </AlertDialogDescription>
            </AlertDialogHeader>
            {deleteUri && (
              <code className="text-muted-foreground block truncate text-xs">
                {deleteUri}
              </code>
            )}
            <AlertDialogFooter>
              <AlertDialogCancel disabled={deleting}>Cancel</AlertDialogCancel>
              <AlertDialogAction
                variant="destructive"
                disabled={deleting}
                onClick={() => {
                  if (deleteUri) handleDeleteRecord(deleteUri);
                }}
              >
                {deleting ? "Deleting..." : "Delete"}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>

        <AlertDialog
          open={bulkDeleteOpen}
          onOpenChange={(open) => {
            if (!open) {
              setBulkDeleteOpen(false);
              setBulkDeleteMode("selected");
              setBulkDeleteConfirm("");
            }
          }}
        >
          <AlertDialogContent>
            {(() => {
              const selectedCount = Object.keys(rowSelection).length;
              const totalCount =
                collections.find((c) => c.collection === selectedCollection)
                  ?.count ?? 0;
              const allInCollection =
                table.getIsAllPageRowsSelected() &&
                selectedCount >= totalCount;

              if (allInCollection) {
                return (
                  <>
                    <AlertDialogHeader>
                      <AlertDialogTitle>
                        Delete all records in collection?
                      </AlertDialogTitle>
                      <AlertDialogDescription>
                        This will permanently delete all {totalCount} record(s)
                        in{" "}
                        <code className="font-semibold">
                          {selectedCollection}
                        </code>
                        . This action cannot be undone.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <div className="flex flex-col gap-2">
                      <label
                        className="text-sm"
                        htmlFor="bulk-delete-confirm"
                      >
                        Type{" "}
                        <code className="font-semibold">
                          {selectedCollection}
                        </code>{" "}
                        to confirm:
                      </label>
                      <Input
                        id="bulk-delete-confirm"
                        value={bulkDeleteConfirm}
                        onChange={(e) => setBulkDeleteConfirm(e.target.value)}
                        placeholder={selectedCollection}
                      />
                    </div>
                    <AlertDialogFooter>
                      <AlertDialogCancel disabled={deletingAll}>
                        Cancel
                      </AlertDialogCancel>
                      <AlertDialogAction
                        variant="destructive"
                        disabled={
                          deletingAll ||
                          bulkDeleteConfirm !== selectedCollection
                        }
                        onClick={handleDeleteAll}
                      >
                        {deletingAll ? "Deleting..." : "Delete"}
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </>
                );
              }

              if (!table.getIsAllPageRowsSelected()) {
                return (
                  <>
                    <AlertDialogHeader>
                      <AlertDialogTitle>
                        Delete {selectedCount} record(s)?
                      </AlertDialogTitle>
                      <AlertDialogDescription>
                        This action cannot be undone.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel disabled={deleting}>
                        Cancel
                      </AlertDialogCancel>
                      <AlertDialogAction
                        variant="destructive"
                        disabled={deleting}
                        onClick={handleBulkDelete}
                      >
                        {deleting ? "Deleting..." : "Delete"}
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </>
                );
              }

              return (
                <>
                  <AlertDialogHeader>
                    <AlertDialogTitle>Delete records?</AlertDialogTitle>
                    <AlertDialogDescription>
                      This action cannot be undone.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <RadioGroup
                    value={bulkDeleteMode}
                    onValueChange={(v) => {
                      setBulkDeleteMode(v as "selected" | "all");
                      setBulkDeleteConfirm("");
                    }}
                  >
                    <FieldLabel htmlFor="bulk-delete-selected">
                      <Field orientation="horizontal">
                        <RadioGroupItem
                          value="selected"
                          id="bulk-delete-selected"
                        />
                        <FieldContent>
                          <FieldTitle>Delete selected only</FieldTitle>
                          <FieldDescription>
                            {`${selectedCount} items selected`}
                          </FieldDescription>
                        </FieldContent>
                      </Field>
                    </FieldLabel>

                    <FieldLabel htmlFor="bulk-delete-all">
                      <Field orientation="horizontal">
                        <RadioGroupItem value="all" id="bulk-delete-all" />
                        <FieldContent>
                          <FieldTitle>Delete all records</FieldTitle>
                          <FieldDescription>
                            <code className="font-semibold">
                              {selectedCollection}
                            </code>
                          </FieldDescription>
                        </FieldContent>
                      </Field>
                    </FieldLabel>
                  </RadioGroup>
                  {bulkDeleteMode === "all" && (
                    <div className="flex flex-col gap-2">
                      <label
                        className="text-sm"
                        htmlFor="bulk-delete-confirm"
                      >
                        Type{" "}
                        <code className="font-semibold">
                          {selectedCollection}
                        </code>{" "}
                        to confirm:
                      </label>
                      <Input
                        id="bulk-delete-confirm"
                        value={bulkDeleteConfirm}
                        onChange={(e) => setBulkDeleteConfirm(e.target.value)}
                        placeholder={selectedCollection}
                      />
                    </div>
                  )}
                  <AlertDialogFooter>
                    <AlertDialogCancel disabled={deleting || deletingAll}>
                      Cancel
                    </AlertDialogCancel>
                    <AlertDialogAction
                      variant="destructive"
                      disabled={
                        deleting ||
                        deletingAll ||
                        (bulkDeleteMode === "all" &&
                          bulkDeleteConfirm !== selectedCollection)
                      }
                      onClick={
                        bulkDeleteMode === "all"
                          ? handleDeleteAll
                          : handleBulkDelete
                      }
                    >
                      {deleting || deletingAll ? "Deleting..." : "Delete"}
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </>
              );
            })()}
          </AlertDialogContent>
        </AlertDialog>
      </div>
    </>
  );
}
