"use client";

import { useCallback, useEffect, useState } from "react";

import { useAuth } from "@/lib/auth-context";
import { addAdmin, deleteAdmin, getAdmins } from "@/lib/api";
import type { AdminSummary } from "@/types/admins";
import { SiteHeader } from "@/components/site-header";
import { Button } from "@/components/ui/button";
import { Trash2 } from "lucide-react";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export default function AdminsPage() {
  const { getToken } = useAuth();
  const [admins, setAdmins] = useState<AdminSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    getAdmins(getToken)
      .then(setAdmins)
      .catch((e) => setError(e.message));
  }, [getToken]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleDelete(id: string) {
    try {
      await deleteAdmin(getToken, id);
      load();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <>
      <SiteHeader title="Admins" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:p-6">
        {error && <p className="text-destructive text-sm">{error}</p>}

        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Admin Users</h2>
          <AddAdminDialog getToken={getToken} onSuccess={load} />
        </div>

        <div className="overflow-clip rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>DID</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Last Used</TableHead>
                <TableHead className="w-10 sticky right-0 bg-inherit z-[1]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {admins.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={4}
                    className="text-muted-foreground text-center"
                  >
                    No admins yet.
                  </TableCell>
                </TableRow>
              )}
              {admins.map((admin) => (
                <TableRow key={admin.id}>
                  <TableCell className="font-mono text-sm">
                    {admin.did}
                  </TableCell>
                  <TableCell>
                    {new Date(admin.created_at).toLocaleString()}
                  </TableCell>
                  <TableCell>
                    {admin.last_used_at
                      ? new Date(admin.last_used_at).toLocaleString()
                      : "Never"}
                  </TableCell>
                  <TableCell className="w-10 sticky right-0 bg-inherit z-[1]">
                    <Button
                      variant="destructive"
                      size="icon"
                      className="size-8 text-muted-foreground hover:text-destructive"
                      title="Delete admin"
                      aria-label="Delete admin"
                      onClick={() => handleDelete(admin.id)}
                    >
                      <Trash2 className="size-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>
    </>
  );
}

function AddAdminDialog({
  getToken,
  onSuccess,
}: {
  getToken: () => Promise<string | null>;
  onSuccess: () => void;
}) {
  const [did, setDid] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  async function handleAdd() {
    setError(null);
    try {
      await addAdmin(getToken, { did });
      setDid("");
      setOpen(false);
      onSuccess();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <ResponsiveDialog open={open} onOpenChange={setOpen}>
      <ResponsiveDialogTrigger asChild>
        <Button>Add Admin</Button>
      </ResponsiveDialogTrigger>
      <ResponsiveDialogContent>
        <ResponsiveDialogHeader>
          <ResponsiveDialogTitle>Add Admin</ResponsiveDialogTitle>
          <ResponsiveDialogDescription>Add a new admin by their DID.</ResponsiveDialogDescription>
        </ResponsiveDialogHeader>
        <div className="flex flex-col gap-4">
          {error && <p className="text-destructive text-sm">{error}</p>}
          <div className="flex flex-col gap-2">
            <Label htmlFor="admin-did">DID</Label>
            <Input
              id="admin-did"
              value={did}
              onChange={(e) => setDid(e.target.value)}
              placeholder="did:plc:..."
            />
          </div>
        </div>
        <ResponsiveDialogFooter>
          <ResponsiveDialogClose asChild>
            <Button variant="outline">Cancel</Button>
          </ResponsiveDialogClose>
          <Button onClick={handleAdd}>Add</Button>
        </ResponsiveDialogFooter>
      </ResponsiveDialogContent>
    </ResponsiveDialog>
  );
}
