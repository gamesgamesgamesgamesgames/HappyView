"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { Upload, Trash2 } from "lucide-react"

import { useCurrentUser } from "@/hooks/use-current-user"
import {
  getSettings,
  upsertSetting,
  deleteSetting,
  uploadLogo,
  deleteLogo,
  type SettingEntry,
} from "@/lib/api"
import { SiteHeader } from "@/components/site-header"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

const SETTING_KEYS = [
  "app_name",
  "client_uri",
  "logo_uri",
  "tos_uri",
  "policy_uri",
] as const

type FieldKey = (typeof SETTING_KEYS)[number]

type FieldConfig = {
  key: FieldKey
  label: string
  placeholder: string
  description: string
}

const FIELDS: FieldConfig[] = [
  {
    key: "app_name",
    label: "Instance Name",
    placeholder: "My HappyView Instance",
    description:
      "Display name for this instance. Shown in the sidebar and on the OAuth consent screen.",
  },
  {
    key: "client_uri",
    label: "Instance URI",
    placeholder: "https://example.com",
    description:
      "The public URL for this instance, linked from the OAuth consent screen.",
  },
  {
    key: "logo_uri",
    label: "Logo URI",
    placeholder: "https://example.com/logo.png",
    description:
      "External URL to a logo image. Overridden by an uploaded logo below.",
  },
  {
    key: "tos_uri",
    label: "Terms of Service URI",
    placeholder: "https://example.com/terms",
    description: "Link to your terms of service. Optional.",
  },
  {
    key: "policy_uri",
    label: "Privacy Policy URI",
    placeholder: "https://example.com/privacy",
    description: "Link to your privacy policy. Optional.",
  },
]

export default function GeneralSettingsPage() {
  const { hasPermission } = useCurrentUser()
  const canManage = hasPermission("settings:manage")

  const [values, setValues] = useState<Record<FieldKey, string>>({
    app_name: "",
    client_uri: "",
    logo_uri: "",
    tos_uri: "",
    policy_uri: "",
  })
  const [sources, setSources] = useState<Record<FieldKey, "database" | "env" | "unset">>({
    app_name: "unset",
    client_uri: "unset",
    logo_uri: "unset",
    tos_uri: "unset",
    policy_uri: "unset",
  })
  const [logoUploaded, setLogoUploaded] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const load = useCallback(async () => {
    try {
      const entries = await getSettings()
      const byKey = new Map<string, SettingEntry>(entries.map((e) => [e.key, e]))
      setValues({
        app_name: byKey.get("app_name")?.value ?? "",
        client_uri: byKey.get("client_uri")?.value ?? "",
        logo_uri: byKey.get("logo_uri")?.value ?? "",
        tos_uri: byKey.get("tos_uri")?.value ?? "",
        policy_uri: byKey.get("policy_uri")?.value ?? "",
      })
      setSources({
        app_name: (byKey.get("app_name")?.source as "database" | "env" | undefined) ?? "unset",
        client_uri: (byKey.get("client_uri")?.source as "database" | "env" | undefined) ?? "unset",
        logo_uri: (byKey.get("logo_uri")?.source as "database" | "env" | undefined) ?? "unset",
        tos_uri: (byKey.get("tos_uri")?.source as "database" | "env" | undefined) ?? "unset",
        policy_uri: (byKey.get("policy_uri")?.source as "database" | "env" | undefined) ?? "unset",
      })
      setLogoUploaded(byKey.has("logo_data"))
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  async function handleSave() {
    setError(null)
    setNotice(null)
    setSaving(true)
    try {
      for (const field of FIELDS) {
        const value = values[field.key]
        if (value === "") {
          if (sources[field.key] === "database") {
            await deleteSetting(field.key)
          }
        } else {
          await upsertSetting(field.key, value)
        }
      }
      setNotice("Settings saved.")
      await load()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setSaving(false)
    }
  }

  async function handleLogoUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    setError(null)
    try {
      await uploadLogo(file)
      setNotice("Logo uploaded.")
      await load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      if (fileInputRef.current) fileInputRef.current.value = ""
    }
  }

  async function handleLogoDelete() {
    setError(null)
    try {
      await deleteLogo()
      setNotice("Logo removed.")
      await load()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  return (
    <>
      <SiteHeader title="General Settings" />
      <div className="flex flex-1 flex-col gap-6 p-4 md:p-6 max-w-3xl">
        {error && <p className="text-destructive text-sm">{error}</p>}
        {notice && <p className="text-sm text-green-600 dark:text-green-400">{notice}</p>}

        <div>
          <h2 className="text-lg font-semibold">Instance Identity</h2>
          <p className="text-muted-foreground text-sm">
            Configure your HappyView instance. These values are used in the
            dashboard sidebar and on the OAuth consent screen.
          </p>
        </div>

        {FIELDS.map((field) => (
          <div key={field.key} className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <Label htmlFor={field.key}>{field.label}</Label>
              {sources[field.key] === "env" && (
                <span className="text-xs text-muted-foreground">
                  from env var
                </span>
              )}
            </div>
            <Input
              id={field.key}
              value={values[field.key]}
              onChange={(e) =>
                setValues((v) => ({ ...v, [field.key]: e.target.value }))
              }
              placeholder={field.placeholder}
              disabled={!canManage}
            />
            <p className="text-muted-foreground text-xs">{field.description}</p>
          </div>
        ))}

        <div className="flex flex-col gap-2">
          <Label>Logo Upload</Label>
          <p className="text-muted-foreground text-xs">
            Upload a logo (max 5MB). Overrides the Logo URI above when set.
          </p>
          <div className="flex items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              className="hidden"
              onChange={handleLogoUpload}
              disabled={!canManage}
            />
            <Button
              type="button"
              variant="outline"
              onClick={() => fileInputRef.current?.click()}
              disabled={!canManage}
            >
              <Upload className="size-4 mr-2" />
              {logoUploaded ? "Replace logo" : "Upload logo"}
            </Button>
            {logoUploaded && (
              <Button
                type="button"
                variant="ghost"
                onClick={handleLogoDelete}
                disabled={!canManage}
              >
                <Trash2 className="size-4 mr-2" />
                Remove
              </Button>
            )}
            {logoUploaded && (
              <span className="text-xs text-muted-foreground">
                Current logo served at /settings/logo
              </span>
            )}
          </div>
        </div>

        <div className="flex justify-end pt-2">
          <Button
            onClick={handleSave}
            disabled={!canManage || saving}
          >
            {saving ? "Saving..." : "Save changes"}
          </Button>
        </div>
      </div>
    </>
  )
}
