"use client";

import { useCallback, useEffect, useState } from "react";
import { Trash2 } from "lucide-react";

import { useAuth } from "@/lib/auth-context";
import { useCurrentUser } from "@/hooks/use-current-user";
import {
  getRateLimits,
  upsertRateLimit,
  setRateLimitEnabled,
  addAllowlistEntry,
  removeAllowlistEntry,
} from "@/lib/api";
import type { AllowlistEntry } from "@/types/rate-limits";
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
  const [capacity, setCapacity] = useState("");
  const [refillRate, setRefillRate] = useState("");
  const [defaultQueryCost, setDefaultQueryCost] = useState("");
  const [defaultProcedureCost, setDefaultProcedureCost] = useState("");
  const [defaultProxyCost, setDefaultProxyCost] = useState("");
  const [allowlist, setAllowlist] = useState<AllowlistEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [toggling, setToggling] = useState(false);
  const [saving, setSaving] = useState(false);

  // Track original values for dirty detection
  const [origCapacity, setOrigCapacity] = useState("");
  const [origRefillRate, setOrigRefillRate] = useState("");
  const [origQueryCost, setOrigQueryCost] = useState("");
  const [origProcedureCost, setOrigProcedureCost] = useState("");
  const [origProxyCost, setOrigProxyCost] = useState("");

  const load = useCallback(() => {
    getRateLimits(getToken)
      .then((data) => {
        setEnabled(data.enabled);
        setCapacity(String(data.capacity));
        setRefillRate(String(data.refill_rate));
        setDefaultQueryCost(String(data.default_query_cost));
        setDefaultProcedureCost(String(data.default_procedure_cost));
        setDefaultProxyCost(String(data.default_proxy_cost));
        setOrigCapacity(String(data.capacity));
        setOrigRefillRate(String(data.refill_rate));
        setOrigQueryCost(String(data.default_query_cost));
        setOrigProcedureCost(String(data.default_procedure_cost));
        setOrigProxyCost(String(data.default_proxy_cost));
        setAllowlist(data.allowlist);
      })
      .catch((e) => setError(e.message));
  }, [getToken]);

  useEffect(() => {
    load();
  }, [load]);

  const isDirty =
    capacity !== origCapacity ||
    refillRate !== origRefillRate ||
    defaultQueryCost !== origQueryCost ||
    defaultProcedureCost !== origProcedureCost ||
    defaultProxyCost !== origProxyCost;

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

  async function handleSave() {
    setError(null);
    const cap = Number(capacity);
    const rate = Number(refillRate);
    const qc = Number(defaultQueryCost);
    const pc = Number(defaultProcedureCost);
    const xc = Number(defaultProxyCost);
    if (!cap || cap <= 0 || !rate || rate <= 0) {
      setError("Capacity and refill rate must be positive numbers.");
      return;
    }
    if (qc < 0 || pc < 0 || xc < 0) {
      setError("Default costs must be non-negative.");
      return;
    }
    setSaving(true);
    try {
      await upsertRateLimit(getToken, {
        capacity: cap,
        refill_rate: rate,
        default_query_cost: qc || 1,
        default_procedure_cost: pc || 1,
        default_proxy_cost: xc || 1,
      });
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
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

  const canEdit = hasPermission("rate-limits:create");

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
            disabled={toggling || !canEdit}
            onCheckedChange={handleToggleEnabled}
          />
          <Label htmlFor="rate-limit-enabled" className="cursor-pointer">
            Rate limiting enabled
          </Label>
        </div>

        {/* Global bucket + Default costs */}
        <div className="flex flex-col gap-4">
          <div>
            <h2 className="text-lg font-semibold">Global Bucket & Default Costs</h2>
            <p className="text-muted-foreground text-sm">
              Configure the shared token bucket and default costs by request type.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
            <div className="flex flex-col gap-2">
              <Label htmlFor="capacity">Capacity</Label>
              <Input
                id="capacity"
                type="number"
                min={1}
                value={capacity}
                onChange={(e) => setCapacity(e.target.value)}
                disabled={!canEdit}
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="refill-rate">Refill Rate (tokens/sec)</Label>
              <Input
                id="refill-rate"
                type="number"
                min={0.01}
                step="any"
                value={refillRate}
                onChange={(e) => setRefillRate(e.target.value)}
                disabled={!canEdit}
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="query-cost">Default Query Cost</Label>
              <Input
                id="query-cost"
                type="number"
                min={0}
                value={defaultQueryCost}
                onChange={(e) => setDefaultQueryCost(e.target.value)}
                disabled={!canEdit}
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="procedure-cost">Default Procedure Cost</Label>
              <Input
                id="procedure-cost"
                type="number"
                min={0}
                value={defaultProcedureCost}
                onChange={(e) => setDefaultProcedureCost(e.target.value)}
                disabled={!canEdit}
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="proxy-cost">Default Proxy Cost</Label>
              <Input
                id="proxy-cost"
                type="number"
                min={0}
                value={defaultProxyCost}
                onChange={(e) => setDefaultProxyCost(e.target.value)}
                disabled={!canEdit}
              />
            </div>
          </div>

          {canEdit && (
            <div>
              <Button onClick={handleSave} disabled={!isDirty || saving}>
                {saving ? "Saving..." : "Save"}
              </Button>
            </div>
          )}
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
            {canEdit && (
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
                      {entry.note ?? "\u2014"}
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
