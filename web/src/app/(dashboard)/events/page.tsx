"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type ColumnDef,
  type ColumnFiltersState,
  type VisibilityState,
  getCoreRowModel,
  getFilteredRowModel,
  getFacetedRowModel,
  getFacetedUniqueValues,
  useReactTable,
} from "@tanstack/react-table";

import { useAuth } from "@/lib/auth-context";
import { getEvents, type EventLogEntry } from "@/lib/api";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { DataTableToolbar } from "@/components/data-table/data-table-toolbar";
import { CodeBlock } from "@/components/code-block";
import { SiteHeader } from "@/components/site-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ChevronLeft, ChevronRight } from "lucide-react";

function severityBadge(severity: string) {
  switch (severity) {
    case "error":
      return <Badge variant="destructive">error</Badge>;
    case "warn":
      return (
        <Badge className="bg-amber-500/15 text-amber-700 dark:text-amber-400 hover:bg-amber-500/25 border-amber-500/20">
          warn
        </Badge>
      );
    default:
      return <Badge variant="secondary">info</Badge>;
  }
}

function timeAgo(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const seconds = Math.floor((now - then) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export default function EventsPage() {
  const { getToken } = useAuth();
  const [events, setEvents] = useState<EventLogEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [viewEvent, setViewEvent] = useState<EventLogEntry | null>(null);

  // Pagination
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);

  // Filters — driven by TanStack column filter state
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({});

  // Debounce subject filter to avoid firing on every keystroke
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(null);
  const [debouncedFilters, setDebouncedFilters] =
    useState<ColumnFiltersState>(columnFilters);

  useEffect(() => {
    const subjectFilter = columnFilters.find((f) => f.id === "subject");
    const prevSubjectFilter = debouncedFilters.find((f) => f.id === "subject");
    const subjectChanged = subjectFilter?.value !== prevSubjectFilter?.value;

    if (subjectChanged) {
      if (debounceRef.current) clearTimeout(debounceRef.current);
      debounceRef.current = setTimeout(() => {
        setDebouncedFilters(columnFilters);
      }, 300);
    } else {
      setDebouncedFilters(columnFilters);
    }
  }, [columnFilters]);

  const fetchEvents = useCallback(
    async (cursor?: string) => {
      setLoading(true);
      setError(null);
      try {
        const categoryFilter = debouncedFilters.find(
          (f) => f.id === "event_type",
        )?.value as string[] | undefined;
        const severityFilter = debouncedFilters.find((f) => f.id === "severity")
          ?.value as string[] | undefined;
        const subjectFilter = debouncedFilters.find((f) => f.id === "subject")
          ?.value as string | undefined;

        const data = await getEvents(getToken, {
          category: categoryFilter?.[0] || undefined,
          severity: severityFilter?.[0] || undefined,
          subject: subjectFilter || undefined,
          cursor,
          limit: 50,
        });
        setEvents(data.events);
        setNextCursor(data.cursor);
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : String(e));
        setEvents([]);
        setNextCursor(null);
      } finally {
        setLoading(false);
      }
    },
    [getToken, debouncedFilters],
  );

  // Fetch on mount and when filters change (reset to first page)
  useEffect(() => {
    setCursorStack([]);
    fetchEvents();
  }, [fetchEvents]);

  // Auto-refresh every 5s when on first page
  useEffect(() => {
    if (cursorStack.length > 0) return;
    const interval = setInterval(() => fetchEvents(), 5000);
    return () => clearInterval(interval);
  }, [fetchEvents, cursorStack.length]);

  function handleNext() {
    if (!nextCursor) return;
    setCursorStack((prev) => [...prev, nextCursor]);
    fetchEvents(nextCursor);
  }

  function handlePrevious() {
    if (cursorStack.length === 0) return;
    const stack = [...cursorStack];
    stack.pop();
    const prevCursor = stack.length > 0 ? stack[stack.length - 1] : undefined;
    setCursorStack(stack);
    fetchEvents(prevCursor);
  }

  const columns = useMemo<ColumnDef<EventLogEntry>[]>(
    () => [
      {
        id: "subject",
        accessorKey: "subject",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} label="Subject" />
        ),
        cell: ({ row }) => (
          <span
            className="font-mono text-xs block max-w-xs truncate"
            title={row.original.subject ?? ""}
          >
            {row.original.subject ?? "--"}
          </span>
        ),
        filterFn: "includesString",
        enableColumnFilter: true,
        enableSorting: false,
        meta: {
          label: "Subject",
          placeholder: "Filter by subject...",
          variant: "text",
        },
      },
      {
        id: "severity",
        accessorKey: "severity",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} label="Severity" />
        ),
        cell: ({ row }) => severityBadge(row.original.severity),
        filterFn: (row, columnId, filterValue) => {
          if (!Array.isArray(filterValue) || filterValue.length === 0)
            return true;
          return filterValue.includes(row.getValue(columnId));
        },
        enableColumnFilter: true,
        enableSorting: false,
        enableHiding: false,
        meta: {
          label: "Severity",
          variant: "select",
          options: [
            { label: "Info", value: "info" },
            { label: "Warn", value: "warn" },
            { label: "Error", value: "error" },
          ],
        },
      },
      {
        id: "event_type",
        accessorKey: "event_type",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} label="Event Type" />
        ),
        cell: ({ row }) => (
          <span className="font-mono text-sm">{row.original.event_type}</span>
        ),
        filterFn: (row, columnId, filterValue) => {
          if (!Array.isArray(filterValue) || filterValue.length === 0)
            return true;
          const eventType = row.getValue(columnId) as string;
          return filterValue.some(
            (cat: string) =>
              eventType === cat || eventType.startsWith(cat + "."),
          );
        },
        enableColumnFilter: true,
        enableSorting: false,
        meta: {
          label: "Category",
          variant: "select",
          options: [
            { label: "Lexicon", value: "lexicon" },
            { label: "Record", value: "record" },
            { label: "Script", value: "script" },
            { label: "Admin", value: "admin" },
            { label: "Backfill", value: "backfill" },
            { label: "Tap", value: "tap" },
          ],
        },
      },
      {
        id: "actor_did",
        accessorKey: "actor_did",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} label="Actor" />
        ),
        cell: ({ row }) => (
          <span
            className="font-mono text-xs block max-w-[200px] truncate"
            title={row.original.actor_did ?? "System"}
          >
            {row.original.actor_did ?? "System"}
          </span>
        ),
        enableSorting: false,
      },
      {
        id: "created_at",
        accessorKey: "created_at",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} label="Time" />
        ),
        cell: ({ row }) => (
          <span
            className="text-muted-foreground whitespace-nowrap text-sm tabular-nums"
            title={new Date(row.original.created_at).toLocaleString()}
          >
            {timeAgo(row.original.created_at)}
          </span>
        ),
        enableSorting: false,
      },
    ],
    [],
  );

  const table = useReactTable({
    data: events,
    columns,
    state: { columnFilters, columnVisibility },
    defaultColumn: {
      enableColumnFilter: false,
    },
    onColumnFiltersChange: setColumnFilters,
    onColumnVisibilityChange: setColumnVisibility,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getFacetedRowModel: getFacetedRowModel(),
    getFacetedUniqueValues: getFacetedUniqueValues(),
    getRowId: (row) => row.id,
  });

  return (
    <>
      <SiteHeader title="Event Logs" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        <DataTable
          table={table}
          showPagination={false}
          onRowClick={setViewEvent}
        >
          <DataTableToolbar table={table} />
        </DataTable>

        <div className="flex w-full items-center justify-between gap-4 overflow-auto p-1">
          <p className="text-muted-foreground flex-1 whitespace-nowrap text-sm">
            {events.length} event(s) on this page.
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

        {viewEvent && (
          <Dialog open onOpenChange={() => setViewEvent(null)}>
            <DialogContent className="sm:max-w-4xl">
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  {severityBadge(viewEvent.severity)}
                  <span className="font-mono text-sm">
                    {viewEvent.event_type}
                  </span>
                </DialogTitle>
              </DialogHeader>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-muted-foreground">Subject</span>
                  <p className="font-mono text-xs">
                    {viewEvent.subject ?? "--"}
                  </p>
                </div>
                <div>
                  <span className="text-muted-foreground">Actor</span>
                  <p className="font-mono text-xs">
                    {viewEvent.actor_did ?? "System"}
                  </p>
                </div>
                <div className="col-span-2">
                  <span className="text-muted-foreground">Time</span>
                  <p className="text-xs">
                    {new Date(viewEvent.created_at).toLocaleString()}
                  </p>
                </div>
              </div>
              <div>
                <span className="text-muted-foreground text-sm">Detail</span>
                <CodeBlock
                  code={JSON.stringify(viewEvent.detail, null, 2)}
                  className="mt-1 rounded-md"
                />
              </div>
            </DialogContent>
          </Dialog>
        )}
      </div>
    </>
  );
}
