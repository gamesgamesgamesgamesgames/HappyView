"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  type ColumnDef,
  type VisibilityState,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";

import { useAuth } from "@/lib/auth-context";
import { getEvents } from "@/lib/api";
import type { EventLogEntry } from "@/types/events";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { CodeBlock } from "@/components/code-block";
import { SiteHeader } from "@/components/site-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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

const CATEGORIES = [
  { label: "All", value: "" },
  { label: "Lexicon", value: "lexicon" },
  { label: "Record", value: "record" },
  { label: "Script", value: "script" },
  { label: "Admin", value: "admin" },
  { label: "Backfill", value: "backfill" },
  { label: "Tap", value: "tap" },
];

const SEVERITIES = [
  { label: "All", value: "" },
  { label: "Info", value: "info" },
  { label: "Warn", value: "warn" },
  { label: "Error", value: "error" },
];

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

  // Filters
  const [category, setCategory] = useState("");
  const [severity, setSeverity] = useState("");
  const [subject, setSubject] = useState("");
  const subjectDebounce = useRef<ReturnType<typeof setTimeout>>(null);

  // Pagination
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);

  const fetchEvents = useCallback(
    async (cursor?: string) => {
      setLoading(true);
      setError(null);
      try {
        const data = await getEvents(getToken, {
          category: category || undefined,
          severity: severity || undefined,
          subject: subject || undefined,
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
    [getToken, category, severity, subject],
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

  function handleSubjectChange(value: string) {
    if (subjectDebounce.current) clearTimeout(subjectDebounce.current);
    subjectDebounce.current = setTimeout(() => {
      setSubject(value);
    }, 300);
  }

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

  function handleReset() {
    setCategory("");
    setSeverity("");
    setSubject("");
  }

  const hasFilters = category !== "" || severity !== "" || subject !== "";

  const columns = useMemo<ColumnDef<EventLogEntry>[]>(
    () => [
      {
        id: "severity",
        accessorKey: "severity",
        header: ({ column }) => (
          <DataTableColumnHeader column={column} label="Severity" />
        ),
        cell: ({ row }) => severityBadge(row.original.severity),
        enableSorting: false,
        enableHiding: false,
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
        enableSorting: false,
      },
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
        enableSorting: false,
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

  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({});

  const table = useReactTable({
    data: events,
    columns,
    state: { columnVisibility },
    onColumnVisibilityChange: setColumnVisibility,
    getCoreRowModel: getCoreRowModel(),
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
          <div className="flex w-full flex-wrap items-center gap-2 p-1">
            <Select value={category} onValueChange={setCategory}>
              <SelectTrigger className="h-8 w-40 text-sm">
                <SelectValue placeholder="Category" />
              </SelectTrigger>
              <SelectContent>
                {CATEGORIES.map((c) => (
                  <SelectItem key={c.value} value={c.value}>
                    {c.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={severity} onValueChange={setSeverity}>
              <SelectTrigger className="h-8 w-32 text-sm">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                {SEVERITIES.map((s) => (
                  <SelectItem key={s.value} value={s.value}>
                    {s.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Input
              placeholder="Filter by subject..."
              className="h-8 w-64 text-sm"
              defaultValue={subject}
              onChange={(e) => handleSubjectChange(e.target.value)}
            />

            {hasFilters && (
              <Button
                variant="ghost"
                size="sm"
                className="h-8"
                onClick={handleReset}
              >
                Reset
              </Button>
            )}
          </div>
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
