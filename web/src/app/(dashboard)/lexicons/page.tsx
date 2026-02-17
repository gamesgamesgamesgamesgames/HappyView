"use client";

import {
  type ColumnDef,
  type ColumnFiltersState,
  type PaginationState,
  type SortingState,
  type VisibilityState,
  getCoreRowModel,
  getFacetedRowModel,
  getFacetedUniqueValues,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { useAuth } from "@/lib/auth-context";
import { CodeBlock } from "@/components/code-block";
import {
  addNetworkLexicon,
  deleteLexicon,
  deleteNetworkLexicon,
  getLexicon,
  getLexicons,
  uploadLexicon,
  type LexiconDetail,
  type LexiconSummary,
} from "@/lib/api";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { DataTableToolbar } from "@/components/data-table/data-table-toolbar";
import { SiteHeader } from "@/components/site-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";

export default function LexiconsPage() {
  const { getToken } = useAuth();
  const [lexicons, setLexicons] = useState<LexiconSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [viewLexicon, setViewLexicon] = useState<LexiconDetail | null>(null);

  const load = useCallback(() => {
    getLexicons(getToken)
      .then(setLexicons)
      .catch((e) => setError(e.message));
  }, [getToken]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleView(id: string) {
    try {
      const detail = await getLexicon(getToken, id);
      setViewLexicon(detail);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function handleDelete(lex: LexiconSummary) {
    try {
      if (lex.source === "network") {
        await deleteNetworkLexicon(getToken, lex.id);
      } else {
        await deleteLexicon(getToken, lex.id);
      }
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  const columns = useMemo<ColumnDef<LexiconSummary>[]>(
    () => [
      {
        id: "id",
        accessorKey: "id",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} label="ID" />
        ),
        cell: ({ row }) => (
          <span className="font-mono text-sm">{row.original.id}</span>
        ),
        filterFn: "includesString",
        enableColumnFilter: true,
        enableSorting: true,
        enableHiding: false,
        meta: {
          label: "ID",
          placeholder: "Filter by ID...",
          variant: "text",
        },
      },
      {
        id: "lexicon_type",
        accessorKey: "lexicon_type",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} label="Type" />
        ),
        cell: ({ row }) => (
          <Badge variant="outline">{row.original.lexicon_type}</Badge>
        ),
        filterFn: (row, columnId, filterValue) => {
          if (!Array.isArray(filterValue) || filterValue.length === 0)
            return true;
          return filterValue.includes(row.getValue(columnId));
        },
        enableColumnFilter: true,
        enableSorting: true,
        meta: {
          label: "Type",
          variant: "multiSelect",
          options: [
            { label: "Record", value: "record" },
            { label: "Query", value: "query" },
            { label: "Procedure", value: "procedure" },
          ],
        },
      },
      {
        id: "source",
        accessorKey: "source",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} label="Source" />
        ),
        cell: ({ row }) => (
          <Badge
            variant={
              row.original.source === "network" ? "secondary" : "outline"
            }
          >
            {row.original.source}
          </Badge>
        ),
        filterFn: (row, columnId, filterValue) => {
          if (!Array.isArray(filterValue) || filterValue.length === 0)
            return true;
          return filterValue.includes(row.getValue(columnId));
        },
        enableColumnFilter: true,
        enableSorting: true,
        meta: {
          label: "Source",
          variant: "select",
          options: [
            { label: "Manual", value: "manual" },
            { label: "Network", value: "network" },
          ],
        },
      },
      {
        id: "action",
        accessorKey: "action",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} label="Action" />
        ),
        cell: ({ row }) => row.original.action ?? "--",
        enableSorting: true,
      },
      {
        id: "backfill",
        accessorKey: "backfill",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} label="Backfill" />
        ),
        cell: ({ row }) => (row.original.backfill ? "Yes" : "No"),
        enableSorting: true,
      },
      {
        id: "revision",
        accessorKey: "revision",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} label="Revision" />
        ),
        cell: ({ row }) => (
          <span className="tabular-nums">{row.original.revision}</span>
        ),
        enableSorting: true,
      },
      {
        id: "actions",
        header: () => <span className="sr-only">Actions</span>,
        cell: ({ row }) => (
          <div className="flex justify-end gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleView(row.original.id)}
            >
              View
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => handleDelete(row.original)}
            >
              Delete
            </Button>
          </div>
        ),
        enableSorting: false,
        enableHiding: false,
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [getToken],
  );

  const [sorting, setSorting] = useState<SortingState>([
    { id: "id", desc: false },
  ]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({});
  const [pagination, setPagination] = useState<PaginationState>({
    pageIndex: 0,
    pageSize: 20,
  });

  const table = useReactTable({
    data: lexicons,
    columns,
    state: {
      sorting,
      columnFilters,
      columnVisibility,
      pagination,
    },
    defaultColumn: {
      enableColumnFilter: false,
    },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onColumnVisibilityChange: setColumnVisibility,
    onPaginationChange: setPagination,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getFacetedRowModel: getFacetedRowModel(),
    getFacetedUniqueValues: getFacetedUniqueValues(),
    getRowId: (row) => row.id,
  });

  return (
    <>
      <SiteHeader title="Lexicons" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        <DataTable table={table}>
          <DataTableToolbar table={table}>
            <AddLexiconDialog getToken={getToken} onSuccess={load} />
          </DataTableToolbar>
        </DataTable>

        {viewLexicon && (
          <Dialog open onOpenChange={() => setViewLexicon(null)}>
            <DialogContent className="sm:max-w-2xl">
              <DialogHeader>
                <DialogTitle>{viewLexicon.id}</DialogTitle>
                <DialogDescription>
                  Revision {viewLexicon.revision} &middot;{" "}
                  {viewLexicon.lexicon_type}
                </DialogDescription>
              </DialogHeader>
              <CodeBlock
                code={JSON.stringify(viewLexicon.lexicon_json, null, 2)}
              />
            </DialogContent>
          </Dialog>
        )}
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Unified Add Lexicon dialog
// ---------------------------------------------------------------------------

function AddLexiconDialog({
  getToken,
  onSuccess,
}: {
  getToken: () => Promise<string | null>;
  onSuccess: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Local state
  const [json, setJson] = useState("");
  const [localTargetCollection, setLocalTargetCollection] = useState("");
  const [action, setAction] = useState("");
  const [backfill, setBackfill] = useState(true);

  // Network state
  const [nsid, setNsid] = useState("");
  const [networkTargetCollection, setNetworkTargetCollection] = useState("");
  const [mainType, setMainType] = useState<string | undefined>();
  const [resolving, setResolving] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const localMainType = useMemo(() => {
    try {
      const parsed = JSON.parse(json);
      return parsed?.defs?.main?.type as string | undefined;
    } catch {
      return undefined;
    }
  }, [json]);

  const showLocalTargetCollection =
    localMainType === "query" || localMainType === "procedure";
  const showAction = localMainType === "procedure";

  // Debounced NSID resolution
  useEffect(() => {
    abortRef.current?.abort();
    setMainType(undefined);

    if (nsid.split(".").length < 3) return;

    const debounce = setTimeout(() => {
      const controller = new AbortController();
      abortRef.current = controller;
      setResolving(true);

      resolveNsidType(nsid, controller.signal)
        .then((type) => {
          if (!controller.signal.aborted) setMainType(type);
        })
        .finally(() => {
          if (!controller.signal.aborted) setResolving(false);
        });
    }, 500);

    return () => clearTimeout(debounce);
  }, [nsid]);

  const showNetworkTargetCollection =
    mainType === "query" || mainType === "procedure";

  function reset() {
    setError(null);
    setJson("");
    setLocalTargetCollection("");
    setAction("");
    setBackfill(true);
    setNsid("");
    setNetworkTargetCollection("");
    setMainType(undefined);
  }

  async function handleUploadLocal() {
    setError(null);
    try {
      const lexiconJson = JSON.parse(json);
      await uploadLexicon(getToken, {
        lexicon_json: lexiconJson,
        backfill,
        target_collection: showLocalTargetCollection
          ? localTargetCollection || undefined
          : undefined,
        action: showAction ? action || undefined : undefined,
      });
      reset();
      setOpen(false);
      onSuccess();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function handleAddNetwork() {
    setError(null);
    try {
      await addNetworkLexicon(getToken, {
        nsid,
        target_collection: showNetworkTargetCollection
          ? networkTargetCollection || undefined
          : undefined,
      });
      reset();
      setOpen(false);
      onSuccess();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        setOpen(v);
        if (!v) reset();
      }}
    >
      <DialogTrigger asChild>
        <Button>Add Lexicon</Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Add Lexicon</DialogTitle>
          <DialogDescription>
            Upload a local lexicon JSON document or track one from the network.
          </DialogDescription>
        </DialogHeader>
        <Tabs defaultValue="local">
          <TabsList className="w-full">
            <TabsTrigger value="local" className="flex-1">
              Local
            </TabsTrigger>
            <TabsTrigger value="network" className="flex-1">
              Network
            </TabsTrigger>
          </TabsList>

          <TabsContent value="local">
            <div className="flex min-w-0 flex-col gap-4 overflow-hidden pt-4">
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
              {showLocalTargetCollection && (
                <div className="flex flex-col gap-2">
                  <Label htmlFor="target-collection">
                    Target Collection (optional)
                  </Label>
                  <Input
                    id="target-collection"
                    value={localTargetCollection}
                    onChange={(e) => setLocalTargetCollection(e.target.value)}
                    placeholder="com.example.record"
                  />
                </div>
              )}
              {showAction && (
                <div className="flex flex-col gap-2">
                  <Label htmlFor="action">Action (optional)</Label>
                  <Select value={action} onValueChange={setAction}>
                    <SelectTrigger id="action" className="w-full">
                      <SelectValue placeholder="Upsert (default)" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="upsert">Upsert (default)</SelectItem>
                      <SelectItem value="create">Create</SelectItem>
                      <SelectItem value="update">Update</SelectItem>
                      <SelectItem value="delete">Delete</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}
              <div className="flex items-center gap-2">
                <Switch
                  id="backfill"
                  checked={backfill}
                  onCheckedChange={setBackfill}
                />
                <Label htmlFor="backfill">Enable backfill</Label>
              </div>
              <DialogFooter>
                <DialogClose asChild>
                  <Button variant="outline">Cancel</Button>
                </DialogClose>
                <Button onClick={handleUploadLocal}>Upload</Button>
              </DialogFooter>
            </div>
          </TabsContent>

          <TabsContent value="network">
            <div className="flex flex-col gap-4 pt-4">
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
              {showNetworkTargetCollection && (
                <div className="flex flex-col gap-2">
                  <Label htmlFor="nl-target-collection">
                    Target Collection (optional)
                  </Label>
                  <Input
                    id="nl-target-collection"
                    value={networkTargetCollection}
                    onChange={(e) => setNetworkTargetCollection(e.target.value)}
                    placeholder="com.example.record"
                  />
                </div>
              )}
              <DialogFooter>
                <DialogClose asChild>
                  <Button variant="outline">Cancel</Button>
                </DialogClose>
                <Button onClick={handleAddNetwork}>Add</Button>
              </DialogFooter>
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Network NSID resolution helpers
// ---------------------------------------------------------------------------

function nsidToDomain(nsid: string): string | null {
  const parts = nsid.split(".");
  if (parts.length < 3) return null;
  const authority = parts.slice(0, -1).reverse();
  return authority.join(".");
}

async function resolveNsidType(
  nsid: string,
  signal: AbortSignal,
): Promise<string | undefined> {
  const domain = nsidToDomain(nsid);
  if (!domain) return undefined;

  let did: string | undefined;
  try {
    const resp = await fetch(`https://${domain}/.well-known/atproto-did`, {
      signal,
    });
    if (resp.ok) did = (await resp.text()).trim();
  } catch (e) {
    if (signal.aborted) return undefined;
  }

  if (!did) {
    try {
      const resp = await fetch(
        `https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(domain)}`,
        { signal },
      );
      if (resp.ok) {
        const data = await resp.json();
        did = data.did;
      }
    } catch (e) {
      if (signal.aborted) return undefined;
    }
  }

  if (!did) return undefined;

  let pdsEndpoint: string | undefined;
  try {
    const resp = await fetch(
      `https://plc.directory/${encodeURIComponent(did)}`,
      { signal },
    );
    if (resp.ok) {
      const doc = await resp.json();
      const services = doc.service as
        | { id: string; serviceEndpoint: string }[]
        | undefined;
      pdsEndpoint = services?.find(
        (s) => s.id === "#atproto_pds",
      )?.serviceEndpoint;
    }
  } catch (e) {
    if (signal.aborted) return undefined;
  }

  if (!pdsEndpoint) return undefined;

  try {
    const resp = await fetch(
      `${pdsEndpoint}/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(did)}&collection=com.atproto.lexicon.schema&rkey=${encodeURIComponent(nsid)}`,
      { signal },
    );
    if (resp.ok) {
      const data = await resp.json();
      return data.value?.defs?.main?.type as string | undefined;
    }
  } catch {
    // Best-effort resolution
  }

  return undefined;
}
