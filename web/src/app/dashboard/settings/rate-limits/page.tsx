"use client";

import { useCallback, useEffect, useState } from "react";
import { Trash2 } from "lucide-react";

import { useAuth } from "@/lib/auth-context";
import { useCurrentUser } from "@/hooks/use-current-user";
import {
  getRateLimits,
  upsertRateLimit,
  deleteRateLimit,
  setRateLimitEnabled,
  addAllowlistEntry,
  removeAllowlistEntry,
} from "@/lib/api";
import type { RateLimitSummary, AllowlistEntry } from "@/types/rate-limits";
import { SiteHeader } from "@/components/site-header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  ResponsiveDialog,
  ResponsiveDialogClose,
  ResponsiveDialogContent,
  ResponsiveDialogDescription,
  ResponsiveDialogFooter,
  ResponsiveDialogHeader,
  ResponsiveDialogTitle,
  ResponsiveDialogTrigger,
} from "@/components/ui/responsive-dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function RateLimitsPage() {
  const { getToken } = useAuth();
  const { hasPermission } = useCurrentUser();
  const [enabled, setEnabled] = useState(false);
  const [limits, setLimits] = useState<RateLimitSummary[]>([]);
  const [allowlist, setAllowlist] = useState<AllowlistEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [toggling, setToggling] = useState(false);

  const load = useCallback(() => {
    getRateLimits(getToken)
      .then((data) => {
        setEnabled(data.enabled);
        setLimits(data.limits);
        setAllowlist(data.allowlist);
      })
      .catch((e) => setError(e.message));
  }, [getToken]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleToggleEnabled(checked: boolean) {
    setToggling(true);
    try {
      await setRateLimitEnabled(getToken, { enabled: checked });
      setEnabled(checked);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setToggling(false);
    }
  }

  async function handleDeleteLimit(id: number) {
    try {
      await deleteRateLimit(getToken, id);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function handleRemoveAllowlistEntry(id: number) {
    try {
      await removeAllowlistEntry(getToken, id);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <>
      <SiteHeader title="Rate Limits" />
      <div className="flex flex-1 flex-col gap-6 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        {/* Global toggle */}
        <div className="flex items-center gap-3">
          <Switch
            id="rate-limit-enabled"
            checked={enabled}
            disabled={toggling || !hasPermission("rate-limits:create")}
            onCheckedChange={handleToggleEnabled}
          />
          <Label htmlFor="rate-limit-enabled" className="cursor-pointer">
            Rate limiting enabled
          </Label>
        </div>

        {/* Rate limit rules */}
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold">Rate Limit Rules</h2>
              <p className="text-muted-foreground text-sm">
                Configure global defaults and per-method overrides.
              </p>
            </div>
            {hasPermission("rate-limits:create") && (
              <UpsertRuleDiag getToken={getToken} onSuccess={load} />
            )}
          </div>

          <div className="overflow-clip rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Method</TableHead>
                  <TableHead>Capacity</TableHead>
                  <TableHead>Refill Rate</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead className="w-20 sticky right-0 bg-inherit z-[1]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {limits.length === 0 && (
                  <TableRow>
                    <TableCell
                      colSpan={5}
                      className="text-muted-foreground text-center"
                    >
                      No rate limit rules yet.
                    </TableCell>
                  </TableRow>
                )}
                {limits.map((limit) => (
                  <TableRow key={limit.id}>
                    <TableCell className="font-mono text-sm">
                      {limit.method ?? (
                        <span className="text-muted-foreground italic">
                          Global default
                        </span>
                      )}
                    </TableCell>
                    <TableCell>{limit.capacity}</TableCell>
                    <TableCell>{limit.refill_rate} tokens/sec</TableCell>
                    <TableCell>
                      {new Date(limit.updated_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="w-20 sticky right-0 bg-inherit z-[1]">
                      <div className="flex gap-1">
                        {hasPermission("rate-limits:create") && (
                          <UpsertRuleDiag
                            getToken={getToken}
                            onSuccess={load}
                            existing={limit}
                          />
                        )}
                        {hasPermission("rate-limits:delete") && limit.method !== null && (
                          <DeleteConfirmDialog
                            title="Delete rule?"
                            description={`This will remove the rate limit override for "${limit.method}".`}
                            onConfirm={() => handleDeleteLimit(limit.id)}
                          />
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>

        {/* IP allowlist */}
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold">IP Allowlist</h2>
              <p className="text-muted-foreground text-sm">
                IPs or CIDRs that bypass rate limiting.
              </p>
            </div>
            {hasPermission("rate-limits:create") && (
              <AddAllowlistDialog getToken={getToken} onSuccess={load} />
            )}
          </div>

          <div className="overflow-clip rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>CIDR</TableHead>
                  <TableHead>Note</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="w-10 sticky right-0 bg-inherit z-[1]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {allowlist.length === 0 && (
                  <TableRow>
                    <TableCell
                      colSpan={4}
                      className="text-muted-foreground text-center"
                    >
                      No allowlist entries yet.
                    </TableCell>
                  </TableRow>
                )}
                {allowlist.map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell className="font-mono text-sm">
                      {entry.cidr}
                    </TableCell>
                    <TableCell className="text-sm">
                      {entry.note ?? "—"}
                    </TableCell>
                    <TableCell>
                      {new Date(entry.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="w-10 sticky right-0 bg-inherit z-[1]">
                      {hasPermission("rate-limits:delete") && (
                        <DeleteConfirmDialog
                          title="Remove entry?"
                          description={`This will remove "${entry.cidr}" from the allowlist.`}
                          onConfirm={() => handleRemoveAllowlistEntry(entry.id)}
                        />
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      </div>
    </>
  );
}

function UpsertRuleDiag({
  getToken,
  onSuccess,
  existing,
}: {
  getToken: () => Promise<string | null>;
  onSuccess: () => void;
  existing?: RateLimitSummary;
}) {
  const [method, setMethod] = useState(existing?.method ?? "");
  const [capacity, setCapacity] = useState(String(existing?.capacity ?? ""));
  const [refillRate, setRefillRate] = useState(
    String(existing?.refill_rate ?? "")
  );
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  const isEdit = !!existing;

  async function handleSubmit() {
    setError(null);
    const cap = Number(capacity);
    const rate = Number(refillRate);
    if (!cap || cap <= 0 || !rate || rate <= 0) {
      setError("Capacity and refill rate must be positive numbers.");
      return;
    }
    try {
      const body: { method?: string; capacity: number; refill_rate: number } = {
        capacity: cap,
        refill_rate: rate,
      };
      if (isEdit && existing.method !== null) {
        body.method = existing.method;
      } else if (!isEdit && method.trim()) {
        body.method = method.trim();
      }
      await upsertRateLimit(getToken, body);
      setOpen(false);
      if (!isEdit) {
        setMethod("");
        setCapacity("");
        setRefillRate("");
      }
      onSuccess();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <ResponsiveDialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) {
          setMethod(existing?.method ?? "");
          setCapacity(String(existing?.capacity ?? ""));
          setRefillRate(String(existing?.refill_rate ?? ""));
          setError(null);
        }
      }}
    >
      <ResponsiveDialogTrigger asChild>
        {isEdit ? (
          <Button variant="ghost" size="sm">
            Edit
          </Button>
        ) : (
          <Button>Add Rule</Button>
        )}
      </ResponsiveDialogTrigger>
      <ResponsiveDialogContent>
        <ResponsiveDialogHeader>
          <ResponsiveDialogTitle>
            {isEdit ? "Edit Rule" : "Add Rule"}
          </ResponsiveDialogTitle>
          <ResponsiveDialogDescription>
            {isEdit
              ? `Update rate limit for ${existing.method ?? "global default"}.`
              : "Add a rate limit rule. Leave method empty for global default."}
          </ResponsiveDialogDescription>
        </ResponsiveDialogHeader>
        <div className="flex flex-col gap-4">
          {error && <p className="text-destructive text-sm">{error}</p>}
          {!isEdit && (
            <div className="flex flex-col gap-2">
              <Label htmlFor="rule-method">Method NSID (optional)</Label>
              <Input
                id="rule-method"
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                placeholder="com.atproto.sync.getRepo"
                className="font-mono"
              />
            </div>
          )}
          <div className="flex flex-col gap-2">
            <Label htmlFor="rule-capacity">Capacity</Label>
            <Input
              id="rule-capacity"
              type="number"
              min={1}
              value={capacity}
              onChange={(e) => setCapacity(e.target.value)}
              placeholder="100"
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="rule-refill-rate">Refill Rate (tokens/sec)</Label>
            <Input
              id="rule-refill-rate"
              type="number"
              min={1}
              value={refillRate}
              onChange={(e) => setRefillRate(e.target.value)}
              placeholder="10"
            />
          </div>
        </div>
        <ResponsiveDialogFooter>
          <ResponsiveDialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </ResponsiveDialogClose>
          <Button onClick={handleSubmit} disabled={!capacity || !refillRate}>
            {isEdit ? "Update" : "Add"}
          </Button>
        </ResponsiveDialogFooter>
      </ResponsiveDialogContent>
    </ResponsiveDialog>
  );
}

function AddAllowlistDialog({
  getToken,
  onSuccess,
}: {
  getToken: () => Promise<string | null>;
  onSuccess: () => void;
}) {
  const [cidr, setCidr] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  async function handleAdd() {
    setError(null);
    try {
      const body: { cidr: string; note?: string } = { cidr: cidr.trim() };
      if (note.trim()) body.note = note.trim();
      await addAllowlistEntry(getToken, body);
      setCidr("");
      setNote("");
      setOpen(false);
      onSuccess();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <ResponsiveDialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) {
          setCidr("");
          setNote("");
          setError(null);
        }
      }}
    >
      <ResponsiveDialogTrigger asChild>
        <Button>Add Entry</Button>
      </ResponsiveDialogTrigger>
      <ResponsiveDialogContent>
        <ResponsiveDialogHeader>
          <ResponsiveDialogTitle>Add Allowlist Entry</ResponsiveDialogTitle>
          <ResponsiveDialogDescription>
            Add an IP or CIDR range that bypasses rate limiting.
          </ResponsiveDialogDescription>
        </ResponsiveDialogHeader>
        <div className="flex flex-col gap-4">
          {error && <p className="text-destructive text-sm">{error}</p>}
          <div className="flex flex-col gap-2">
            <Label htmlFor="allowlist-cidr">CIDR</Label>
            <Input
              id="allowlist-cidr"
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
              placeholder="10.0.0.0/8"
              className="font-mono"
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="allowlist-note">Note (optional)</Label>
            <Input
              id="allowlist-note"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Internal network"
            />
          </div>
        </div>
        <ResponsiveDialogFooter>
          <ResponsiveDialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </ResponsiveDialogClose>
          <Button onClick={handleAdd} disabled={!cidr.trim()}>
            Add
          </Button>
        </ResponsiveDialogFooter>
      </ResponsiveDialogContent>
    </ResponsiveDialog>
  );
}

function DeleteConfirmDialog({
  title,
  description,
  onConfirm,
}: {
  title: string;
  description: string;
  onConfirm: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);

  async function handleConfirm() {
    setDeleting(true);
    try {
      await onConfirm();
      setOpen(false);
    } finally {
      setDeleting(false);
    }
  }

  return (
    <ResponsiveDialog open={open} onOpenChange={setOpen}>
      <ResponsiveDialogTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="size-8 text-muted-foreground hover:text-destructive"
          title="Delete"
          aria-label="Delete"
        >
          <Trash2 className="size-4" />
        </Button>
      </ResponsiveDialogTrigger>
      <ResponsiveDialogContent>
        <ResponsiveDialogHeader>
          <ResponsiveDialogTitle>{title}</ResponsiveDialogTitle>
          <ResponsiveDialogDescription>
            {description}
          </ResponsiveDialogDescription>
        </ResponsiveDialogHeader>
        <ResponsiveDialogFooter>
          <ResponsiveDialogClose asChild>
            <Button variant="outline" disabled={deleting}>
              Cancel
            </Button>
          </ResponsiveDialogClose>
          <Button
            variant="destructive"
            disabled={deleting}
            onClick={handleConfirm}
          >
            {deleting ? "Deleting..." : "Delete"}
          </Button>
        </ResponsiveDialogFooter>
      </ResponsiveDialogContent>
    </ResponsiveDialog>
  );
}
