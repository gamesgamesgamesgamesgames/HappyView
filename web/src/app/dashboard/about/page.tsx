"use client"

import { useEffect, useState } from "react"

import { SiteHeader } from "@/components/site-header"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"

interface ConfigInfo {
  version: string
  public_url: string
  database_backend: string
  jetstream_url: string
  relay_url: string
  plc_url: string
}

export default function AboutPage() {
  const [config, setConfig] = useState<ConfigInfo | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch("/config", { credentials: "same-origin" })
      .then((r) => {
        if (!r.ok) throw new Error("Failed to load config")
        return r.json()
      })
      .then(setConfig)
      .catch((e) => setError(e.message))
  }, [])

  const rows: { label: string; value: string | undefined }[] = config
    ? [
        { label: "Version", value: config.version },
        { label: "Public URL", value: config.public_url },
        { label: "Database", value: config.database_backend },
        { label: "Jetstream", value: config.jetstream_url },
        { label: "Relay", value: config.relay_url },
        { label: "PLC Directory", value: config.plc_url },
      ]
    : []

  return (
    <>
      <SiteHeader title="About" />
      <div className="flex flex-1 flex-col gap-4 p-4 md:p-6 max-w-3xl">
        {error && <p className="text-destructive text-sm">{error}</p>}

        <Card>
          <CardHeader>
            <CardTitle>HappyView</CardTitle>
            <CardDescription>
              ATProto AppView instance information
            </CardDescription>
          </CardHeader>
          <CardContent>
            {config ? (
              <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-3 text-sm">
                {rows.map((row) => (
                  <div key={row.label} className="contents">
                    <dt className="text-muted-foreground font-medium">
                      {row.label}
                    </dt>
                    <dd className="font-mono">{row.value ?? "—"}</dd>
                  </div>
                ))}
              </dl>
            ) : (
              !error && (
                <p className="text-muted-foreground text-sm">Loading...</p>
              )
            )}
          </CardContent>
        </Card>
      </div>
    </>
  )
}
