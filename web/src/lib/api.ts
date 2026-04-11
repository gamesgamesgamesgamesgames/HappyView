import type { ApiKeySummary, CreateApiKeyResponse } from "@/types/api-keys"
import type { StatsResponse } from "@/types/stats"
import type { LexiconSummary, LexiconDetail } from "@/types/lexicons"
import type { NetworkLexiconSummary } from "@/types/network-lexicons"
import type { TapStatsResponse } from "@/types/tap"
import type { BackfillJob } from "@/types/backfill"
import type { UserSummary } from "@/types/users"
import type { AdminListRecordsResponse } from "@/types/records"
import type { EventsListResponse } from "@/types/events"
import type { ScriptVariableSummary } from "@/types/script-variables"
import type { LabelerSummary } from "@/types/labelers"
import type { RateLimitsResponse } from "@/types/rate-limits"
import type { SettingEntry } from "@/types/settings"
import type {
  ExternalProvider,
  LinkedAccount,
  AuthorizeResponse,
  SyncResponse,
  UnlinkResponse,
  ConnectResponse,
} from "@/types/external-accounts"

export type { ApiKeySummary, CreateApiKeyResponse } from "@/types/api-keys"
export type { CollectionStat, StatsResponse } from "@/types/stats"
export type { LexiconSummary, LexiconDetail } from "@/types/lexicons"
export type { NetworkLexiconSummary } from "@/types/network-lexicons"
export type { TapStatsResponse } from "@/types/tap"
export type { BackfillJob } from "@/types/backfill"
export type { UserSummary } from "@/types/users"
export type { AdminRecord, AdminListRecordsResponse } from "@/types/records"
export type { EventLogEntry, EventsListResponse } from "@/types/events"
export type { ScriptVariableSummary } from "@/types/script-variables"
export type { LabelerSummary } from "@/types/labelers"
export type { RecordLabel } from "@/types/records"
export type { AllowlistEntry, RateLimitsResponse } from "@/types/rate-limits"
export type { SettingEntry, OAuthSettings } from "@/types/settings"
export { OAUTH_SETTING_KEYS } from "@/types/settings"
export type {
  ExternalProvider,
  LinkedAccount,
  AuthorizeResponse,
  SyncResponse,
  UnlinkResponse,
  ConnectResponse,
  ConfigSchema,
  ConfigProperty,
} from "@/types/external-accounts"

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function apiFetch<T = unknown>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  const headers: Record<string, string> = {}
  if (
    options?.method === "POST" ||
    options?.method === "PUT" ||
    options?.method === "PATCH"
  ) {
    headers["Content-Type"] = "application/json"
  }

  const res = await fetch(path, {
    ...options,
    headers: { ...headers, ...options?.headers },
    credentials: "same-origin",
  })

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new ApiError(res.status, text)
  }
  if (res.status === 204) return null as T
  const text = await res.text()
  if (!text) return null as T
  return JSON.parse(text)
}

// Stats
export function getStats() {
  return apiFetch<StatsResponse>("/admin/stats")
}

// Lexicons
export function getLexicons() {
  return apiFetch<LexiconSummary[]>("/admin/lexicons")
}

export function getLexicon(id: string) {
  return apiFetch<LexiconDetail>(
    `/admin/lexicons/${encodeURIComponent(id)}`,
  )
}

export function uploadLexicon(
  body: {
    lexicon_json: unknown
    backfill?: boolean
    target_collection?: string
    action?: string
    script?: string
    index_hook?: string
    token_cost?: number | null
  }
) {
  return apiFetch<{ id: string; revision: number }>("/admin/lexicons", {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function deleteLexicon(id: string) {
  return apiFetch(`/admin/lexicons/${encodeURIComponent(id)}`, {
    method: "DELETE",
  })
}

// Network Lexicons
export function getNetworkLexicons() {
  return apiFetch<NetworkLexiconSummary[]>("/admin/network-lexicons")
}

export function addNetworkLexicon(
  body: { nsid: string; target_collection?: string }
) {
  return apiFetch<{ nsid: string; authority_did: string; revision: number }>(
    "/admin/network-lexicons",
    { method: "POST", body: JSON.stringify(body) }
  )
}

export function deleteNetworkLexicon(
  nsid: string
) {
  return apiFetch(
    `/admin/network-lexicons/${encodeURIComponent(nsid)}`,
    { method: "DELETE" }
  )
}

// Tap Stats
export function getTapStats() {
  return apiFetch<TapStatsResponse>("/admin/tap/stats")
}

// Backfill
export function getBackfillJobs() {
  return apiFetch<BackfillJob[]>("/admin/backfill/status")
}

export function createBackfillJob(
  body: { collection?: string; did?: string }
) {
  return apiFetch<{ id: string; status: string }>("/admin/backfill", {
    method: "POST",
    body: JSON.stringify(body),
  })
}

// Users
export function getUsers() {
  return apiFetch<UserSummary[]>("/admin/users")
}

export function getUser(id: string) {
  return apiFetch<UserSummary>(`/admin/users/${encodeURIComponent(id)}`)
}

export function addUser(
  body: { did: string; template?: string; permissions?: string[] }
) {
  return apiFetch<{ id: string; did: string }>("/admin/users", {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function deleteUser(id: string) {
  return apiFetch(`/admin/users/${encodeURIComponent(id)}`, {
    method: "DELETE",
  })
}

export function updateUserPermissions(
  id: string,
  body: { grant?: string[]; revoke?: string[] }
) {
  return apiFetch(`/admin/users/${encodeURIComponent(id)}/permissions`, {
    method: "PATCH",
    body: JSON.stringify(body),
  })
}

export function transferSuper(
  body: { target_user_id: string }
) {
  return apiFetch("/admin/users/transfer-super", {
    method: "POST",
    body: JSON.stringify(body),
  })
}

// API Keys
export function getApiKeys() {
  return apiFetch<ApiKeySummary[]>("/admin/api-keys")
}

export function createApiKey(
  body: { name: string; permissions: string[] }
) {
  return apiFetch<CreateApiKeyResponse>("/admin/api-keys", {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function revokeApiKey(id: string) {
  return apiFetch(`/admin/api-keys/${encodeURIComponent(id)}`, {
    method: "DELETE",
  })
}

// XRPC (public, no auth needed)
export async function xrpcQuery<T = unknown>(
  method: string,
  params?: Record<string, string>
): Promise<T> {
  const search = params ? `?${new URLSearchParams(params)}` : ""
  const res = await fetch(`/xrpc/${encodeURIComponent(method)}${search}`)
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new ApiError(res.status, text)
  }
  return res.json()
}

// Admin records browsing
export function getAdminRecords(
  collection: string,
  limit?: number,
  cursor?: string
) {
  const params = new URLSearchParams({ collection })
  if (limit) params.set("limit", String(limit))
  if (cursor) params.set("cursor", cursor)
  return apiFetch<AdminListRecordsResponse>(
    `/admin/records?${params}`,
  )
}

export function deleteRecord(
  uri: string
) {
  return apiFetch(
    `/admin/records?${new URLSearchParams({ uri })}`,
    { method: "DELETE" }
  )
}

export function deleteCollectionRecords(
  collection: string,
) {
  return apiFetch<{ deleted: number }>(
    `/admin/records/collection?${new URLSearchParams({ collection })}`,
    { method: "DELETE" },
  )
}

// Script Variables
export function getScriptVariables() {
  return apiFetch<ScriptVariableSummary[]>("/admin/script-variables")
}

export function upsertScriptVariable(
  body: { key: string; value: string }
) {
  return apiFetch("/admin/script-variables", {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function deleteScriptVariable(
  key: string
) {
  return apiFetch(
    `/admin/script-variables/${encodeURIComponent(key)}`,
    { method: "DELETE" }
  )
}

// Settings
export function getSettings() {
  return apiFetch<SettingEntry[]>("/admin/settings")
}

export function upsertSetting(key: string, value: string) {
  return apiFetch(`/admin/settings/${encodeURIComponent(key)}`, {
    method: "PUT",
    body: JSON.stringify({ value }),
  })
}

export function deleteSetting(key: string) {
  return apiFetch(`/admin/settings/${encodeURIComponent(key)}`, {
    method: "DELETE",
  })
}

export async function uploadLogo(file: File) {
  const formData = new FormData()
  formData.append("file", file)
  const res = await fetch("/admin/settings/logo", {
    method: "PUT",
    body: formData,
    credentials: "same-origin",
  })
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new ApiError(res.status, text)
  }
}

export function deleteLogo() {
  return apiFetch("/admin/settings/logo", { method: "DELETE" })
}

// Labelers
export function getLabelers() {
  return apiFetch<LabelerSummary[]>("/admin/labelers")
}

export function addLabeler(
  body: { did: string }
) {
  return apiFetch("/admin/labelers", {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function updateLabeler(
  did: string,
  body: { status: string }
) {
  return apiFetch(`/admin/labelers/${encodeURIComponent(did)}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  })
}

export function deleteLabeler(
  did: string
) {
  return apiFetch(`/admin/labelers/${encodeURIComponent(did)}`, {
    method: "DELETE",
  })
}

// Rate Limits
export function getRateLimits() {
  return apiFetch<RateLimitsResponse>("/admin/rate-limits")
}

export function upsertRateLimit(
  body: {
    capacity: number
    refill_rate: number
    default_query_cost: number
    default_procedure_cost: number
    default_proxy_cost: number
  }
) {
  return apiFetch("/admin/rate-limits", {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function setRateLimitEnabled(
  body: { enabled: boolean }
) {
  return apiFetch("/admin/rate-limits/enabled", {
    method: "PUT",
    body: JSON.stringify(body),
  })
}

export function addAllowlistEntry(
  body: { cidr: string; note?: string }
) {
  return apiFetch("/admin/rate-limits/allowlist", {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function removeAllowlistEntry(
  id: number
) {
  return apiFetch(`/admin/rate-limits/allowlist/${encodeURIComponent(id)}`, {
    method: "DELETE",
  })
}

// Event Logs
export function getEvents(
  params?: {
    category?: string
    severity?: string
    subject?: string
    cursor?: string
    limit?: number
  }
) {
  const searchParams = new URLSearchParams()
  if (params?.category) searchParams.set("category", params.category)
  if (params?.severity) searchParams.set("severity", params.severity)
  if (params?.subject) searchParams.set("subject", params.subject)
  if (params?.cursor) searchParams.set("cursor", params.cursor)
  if (params?.limit) searchParams.set("limit", String(params.limit))
  const qs = searchParams.toString()
  return apiFetch<EventsListResponse>(
    `/admin/events${qs ? `?${qs}` : ""}`,
  )
}

// External Accounts
export function getExternalProviders() {
  return apiFetch<ExternalProvider[]>("/external-auth/providers")
}

export function getLinkedAccounts() {
  return apiFetch<LinkedAccount[]>("/external-auth/accounts")
}

export function authorizeExternal(pluginId: string, redirectUri: string) {
  const params = new URLSearchParams({ redirect_uri: redirectUri })
  return apiFetch<AuthorizeResponse>(
    `/external-auth/${encodeURIComponent(pluginId)}/authorize?${params}`,
  )
}

export function syncExternal(pluginId: string) {
  return apiFetch<SyncResponse>(
    `/external-auth/${encodeURIComponent(pluginId)}/sync`,
    { method: "POST" },
  )
}

export function unlinkExternal(pluginId: string) {
  return apiFetch<UnlinkResponse>(
    `/external-auth/${encodeURIComponent(pluginId)}/unlink`,
    { method: "POST" },
  )
}

export function connectWithConfig(pluginId: string, config: Record<string, unknown>) {
  return apiFetch<ConnectResponse>(
    `/external-auth/${encodeURIComponent(pluginId)}/connect`,
    { method: "POST", body: JSON.stringify({ config }) },
  )
}

// Plugins
import type { PluginSummary, PluginsListResponse } from "@/types/plugins"
export type { PluginSummary, PluginsListResponse } from "@/types/plugins"

export function getPlugins() {
  return apiFetch<PluginsListResponse>("/admin/plugins")
}

export function addPlugin(body: { url: string; sha256?: string }) {
  return apiFetch<PluginSummary>("/admin/plugins", {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function removePlugin(id: string) {
  return apiFetch(`/admin/plugins/${encodeURIComponent(id)}`, {
    method: "DELETE",
  })
}

export function reloadPlugin(id: string) {
  return apiFetch<PluginSummary>(
    `/admin/plugins/${encodeURIComponent(id)}/reload`,
    { method: "POST" },
  )
}

export interface PluginSecretsResponse {
  plugin_id: string
  secrets: Record<string, string>
}

export function getPluginSecrets(id: string) {
  return apiFetch<PluginSecretsResponse>(
    `/admin/plugins/${encodeURIComponent(id)}/secrets`,
  )
}

export function updatePluginSecrets(id: string, secrets: Record<string, string>) {
  return apiFetch<void>(
    `/admin/plugins/${encodeURIComponent(id)}/secrets`,
    { method: "PUT", body: JSON.stringify({ secrets }) },
  )
}

export interface SecretDefinition {
  key: string
  name: string
  description: string | null
}

export interface PluginPreview {
  id: string
  name: string
  version: string
  description: string | null
  icon_url: string | null
  auth_type: string
  required_secrets: SecretDefinition[]
  manifest_url: string
  wasm_url: string
}

export function previewPlugin(url: string) {
  return apiFetch<PluginPreview>("/admin/plugins/preview", {
    method: "POST",
    body: JSON.stringify({ url }),
  })
}
