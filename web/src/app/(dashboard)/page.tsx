"use client"

import { useEffect, useState } from "react"

import { useAuth } from "@/lib/auth-context"
import { getStats, type StatsResponse } from "@/lib/api"
import { SiteHeader } from "@/components/site-header"
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

export default function DashboardPage() {
  const { token } = useAuth()
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!token) return
    getStats(token).then(setStats).catch((e) => setError(e.message))
  }, [token])

  return (
    <>
      <SiteHeader title="Dashboard" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:gap-6 md:p-6">
        {error && (
          <p className="text-destructive text-sm">{error}</p>
        )}
        <div className="grid grid-cols-1 gap-4 @xl:grid-cols-2 @3xl:grid-cols-3">
          <Card>
            <CardHeader>
              <CardDescription>Total Records</CardDescription>
              <CardTitle className="text-2xl font-semibold tabular-nums">
                {stats ? stats.total_records.toLocaleString() : "--"}
              </CardTitle>
            </CardHeader>
          </Card>
          <Card>
            <CardHeader>
              <CardDescription>Collections</CardDescription>
              <CardTitle className="text-2xl font-semibold tabular-nums">
                {stats ? stats.collections.length : "--"}
              </CardTitle>
            </CardHeader>
          </Card>
        </div>

        {stats && stats.collections.length > 0 && (
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Collection</TableHead>
                  <TableHead className="text-right">Records</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {stats.collections.map((col) => (
                  <TableRow key={col.collection}>
                    <TableCell className="font-mono text-sm">
                      {col.collection}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {col.count.toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </>
  )
}
