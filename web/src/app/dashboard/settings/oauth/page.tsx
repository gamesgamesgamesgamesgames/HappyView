"use client"

import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { Upload, Trash2 } from "lucide-react"

import { useCurrentUser } from "@/hooks/use-current-user"
import {
  getSettings,
  upsertSetting,
  deleteSetting,
  uploadLogo,
  deleteLogo,
  OAUTH_SETTING_KEYS,
  type SettingEntry,
} from "@/lib/api"
import { SiteHeader } from "@/components/site-header"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"

type FieldKey = (typeof OAUTH_SETTING_KEYS)[number]

type FieldConfig = {
  key: FieldKey
  label: string
  placeholder: string
  description: string
  multiline?: boolean
}

const FIELDS: FieldConfig[] = [
  {
    key: "app_name",
    label: "Client Name",
    placeholder: "My HappyView Instance",
    description:
      "Shown to users on the OAuth consent screen.",
  },
  {
    key: "client_uri",
    label: "Client URI",
    placeholder: "https://example.com",
    description:
      "The homepage for this application, linked from the consent screen.",
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
    description: "Link to your terms of service.",
  },
  {
    key: "policy_uri",
    label: "Privacy Policy URI",
    placeholder: "https://example.com/privacy",
    description: "Link to your privacy policy.",
  },
  {
    key: "oauth_scopes",
    label: "OAuth Scopes",
    placeholder: "atproto\ninclude:com.example.authBasic",
    description:
      "One scope per line (or space-separated). Must include `atproto`. Use `include:<permission-set-nsid>` to reference lexicon permission sets.",
    multiline: true,
  },
]

export default function OAuthSettingsPage() {
  const { hasPermission } = useCurrentUser()
  const canManage = hasPermission("settings:manage")

  const [values, setValues] = useState<Record<FieldKey, string>>({
    app_name: "",
    client_uri: "",
    logo_uri: "",
    tos_uri: "",
    policy_uri: "",
    oauth_scopes: "",
  })
  const [sources, setSources] = useState<Record<FieldKey, "database" | "env" | "unset">>({
    app_name: "unset",
    client_uri: "unset",
    logo_uri: "unset",
    tos_uri: "unset",
    policy_uri: "unset",
    oauth_scopes: "unset",
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
        oauth_scopes: byKey.get("oauth_scopes")?.value ?? "",
      })
      setSources({
        app_name: (byKey.get("app_name")?.source as "database" | "env" | undefined) ?? "unset",
        client_uri: (byKey.get("client_uri")?.source as "database" | "env" | undefined) ?? "unset",
        logo_uri: (byKey.get("logo_uri")?.source as "database" | "env" | undefined) ?? "unset",
        tos_uri: (byKey.get("tos_uri")?.source as "database" | "env" | undefined) ?? "unset",
        policy_uri: (byKey.get("policy_uri")?.source as "database" | "env" | undefined) ?? "unset",
        oauth_scopes:
          (byKey.get("oauth_scopes")?.source as "database" | "env" | undefined) ?? "unset",
      })
      setLogoUploaded(byKey.has("logo_data"))
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const scopesMissingAtproto = useMemo(() => {
    const tokens = values.oauth_scopes.split(/\s+/).filter(Boolean)
    return tokens.length > 0 && !tokens.includes("atproto")
  }, [values.oauth_scopes])

  async function handleSave() {
    setError(null)
    setNotice(null)
    setSaving(true)
    try {
      // Normalize scopes to space-separated
      const normalizedScopes = values.oauth_scopes
        .split(/\s+/)
        .filter(Boolean)
        .join(" ")

      for (const field of FIELDS) {
        const value = field.key === "oauth_scopes" ? normalizedScopes : values[field.key]
        if (value === "") {
          if (sources[field.key] === "database") {
            await deleteSetting(field.key)
          }
          // If source is env or unset and value is empty, nothing to persist
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
      <SiteHeader title="OAuth Settings" />
      <div className="flex flex-1 flex-col gap-6 p-4 md:p-6 max-w-3xl">
        {error && <p className="text-destructive text-sm">{error}</p>}
        {notice && <p className="text-sm text-green-600 dark:text-green-400">{notice}</p>}

        <div>
          <h2 className="text-lg font-semibold">Client Metadata</h2>
          <p className="text-muted-foreground text-sm">
            These values are served from{" "}
            <code className="text-xs">/oauth-client-metadata.json</code> and shown
            on the OAuth consent screen.
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
            {field.multiline ? (
              <Textarea
                id={field.key}
                value={values[field.key]}
                onChange={(e) =>
                  setValues((v) => ({ ...v, [field.key]: e.target.value }))
                }
                placeholder={field.placeholder}
                rows={6}
                className="font-mono text-sm"
                disabled={!canManage}
              />
            ) : (
              <Input
                id={field.key}
                value={values[field.key]}
                onChange={(e) =>
                  setValues((v) => ({ ...v, [field.key]: e.target.value }))
                }
                placeholder={field.placeholder}
                disabled={!canManage}
              />
            )}
            <p className="text-muted-foreground text-xs">{field.description}</p>
            {field.key === "oauth_scopes" && scopesMissingAtproto && (
              <p className="text-destructive text-xs">
                The scope list must include <code>atproto</code>.
              </p>
            )}
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
            disabled={!canManage || saving || scopesMissingAtproto}
          >
            {saving ? "Saving..." : "Save changes"}
          </Button>
        </div>
      </div>
    </>
  )
}
