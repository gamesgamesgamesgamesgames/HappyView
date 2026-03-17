import { createDpopProof, setDpopNonce } from "./dpop"

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
export type { RateLimitSummary, AllowlistEntry, RateLimitsResponse } from "@/types/rate-limits"

// The DPoP proof for admin API calls must target AIP's userinfo URL,
// because the backend forwards the proof to AIP for token validation.
// Set at runtime via ConfigProvider.
let aipUrl = ""
export function setAipUrl(url: string) { aipUrl = url }

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function apiFetch<T = unknown>(
  path: string,
  getToken: () => Promise<string | null>,
  options?: RequestInit,
  dpopNonce?: string
): Promise<T> {
  const token = await getToken()
  if (!token) throw new ApiError(401, "Not authenticated")

  // Proof targets AIP's userinfo endpoint (GET) since the backend
  // forwards it there for token validation.
  const dpopProof = await createDpopProof("GET", `${aipUrl}/oauth/userinfo`, token, dpopNonce)

  const headers: Record<string, string> = {
    Authorization: `DPoP ${token}`,
    DPoP: dpopProof,
  }
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
  })

  // If AIP requires a DPoP nonce, the backend relays it via both
  // the dpop-nonce response header and the JSON body. Retry once.
  if (res.status === 401 && !dpopNonce) {
    const text = await res.text().catch(() => "")
    let nonce = res.headers.get("dpop-nonce")
    if (!nonce) {
      try { nonce = JSON.parse(text).dpop_nonce } catch { /* not JSON */ }
    }
    if (nonce) {
      setDpopNonce(nonce)
      return apiFetch<T>(path, getToken, options, nonce)
    }
    throw new ApiError(res.status, text)
  }

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
export function getStats(getToken: () => Promise<string | null>) {
  return apiFetch<StatsResponse>("/admin/stats", getToken)
}

// Lexicons
export function getLexicons(getToken: () => Promise<string | null>) {
  return apiFetch<LexiconSummary[]>("/admin/lexicons", getToken)
}

export function getLexicon(getToken: () => Promise<string | null>, id: string) {
  return apiFetch<LexiconDetail>(
    `/admin/lexicons/${encodeURIComponent(id)}`,
    getToken
  )
}

export function uploadLexicon(
  getToken: () => Promise<string | null>,
  body: {
    lexicon_json: unknown
    backfill?: boolean
    target_collection?: string
    action?: string
    script?: string
    index_hook?: string
  }
) {
  return apiFetch<{ id: string; revision: number }>("/admin/lexicons", getToken, {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function deleteLexicon(getToken: () => Promise<string | null>, id: string) {
  return apiFetch(`/admin/lexicons/${encodeURIComponent(id)}`, getToken, {
    method: "DELETE",
  })
}

// Network Lexicons
export function getNetworkLexicons(getToken: () => Promise<string | null>) {
  return apiFetch<NetworkLexiconSummary[]>("/admin/network-lexicons", getToken)
}

export function addNetworkLexicon(
  getToken: () => Promise<string | null>,
  body: { nsid: string; target_collection?: string }
) {
  return apiFetch<{ nsid: string; authority_did: string; revision: number }>(
    "/admin/network-lexicons",
    getToken,
    { method: "POST", body: JSON.stringify(body) }
  )
}

export function deleteNetworkLexicon(
  getToken: () => Promise<string | null>,
  nsid: string
) {
  return apiFetch(
    `/admin/network-lexicons/${encodeURIComponent(nsid)}`,
    getToken,
    { method: "DELETE" }
  )
}

// Tap Stats
export function getTapStats(getToken: () => Promise<string | null>) {
  return apiFetch<TapStatsResponse>("/admin/tap/stats", getToken)
}

// Backfill
export function getBackfillJobs(getToken: () => Promise<string | null>) {
  return apiFetch<BackfillJob[]>("/admin/backfill/status", getToken)
}

export function createBackfillJob(
  getToken: () => Promise<string | null>,
  body: { collection?: string; did?: string }
) {
  return apiFetch<{ id: string; status: string }>("/admin/backfill", getToken, {
    method: "POST",
    body: JSON.stringify(body),
  })
}

// Users
export function getUsers(getToken: () => Promise<string | null>) {
  return apiFetch<UserSummary[]>("/admin/users", getToken)
}

export function getUser(getToken: () => Promise<string | null>, id: string) {
  return apiFetch<UserSummary>(`/admin/users/${encodeURIComponent(id)}`, getToken)
}

export function addUser(
  getToken: () => Promise<string | null>,
  body: { did: string; template?: string; permissions?: string[] }
) {
  return apiFetch<{ id: string; did: string }>("/admin/users", getToken, {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function deleteUser(getToken: () => Promise<string | null>, id: string) {
  return apiFetch(`/admin/users/${encodeURIComponent(id)}`, getToken, {
    method: "DELETE",
  })
}

export function updateUserPermissions(
  getToken: () => Promise<string | null>,
  id: string,
  body: { grant?: string[]; revoke?: string[] }
) {
  return apiFetch(`/admin/users/${encodeURIComponent(id)}/permissions`, getToken, {
    method: "PATCH",
    body: JSON.stringify(body),
  })
}

export function transferSuper(
  getToken: () => Promise<string | null>,
  body: { target_user_id: string }
) {
  return apiFetch("/admin/users/transfer-super", getToken, {
    method: "POST",
    body: JSON.stringify(body),
  })
}

// API Keys
export function getApiKeys(getToken: () => Promise<string | null>) {
  return apiFetch<ApiKeySummary[]>("/admin/api-keys", getToken)
}

export function createApiKey(
  getToken: () => Promise<string | null>,
  body: { name: string; permissions: string[] }
) {
  return apiFetch<CreateApiKeyResponse>("/admin/api-keys", getToken, {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function revokeApiKey(getToken: () => Promise<string | null>, id: string) {
  return apiFetch(`/admin/api-keys/${encodeURIComponent(id)}`, getToken, {
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
  getToken: () => Promise<string | null>,
  collection: string,
  limit?: number,
  cursor?: string
) {
  const params = new URLSearchParams({ collection })
  if (limit) params.set("limit", String(limit))
  if (cursor) params.set("cursor", cursor)
  return apiFetch<AdminListRecordsResponse>(
    `/admin/records?${params}`,
    getToken
  )
}

export function deleteRecord(
  getToken: () => Promise<string | null>,
  uri: string
) {
  return apiFetch(
    `/admin/records?${new URLSearchParams({ uri })}`,
    getToken,
    { method: "DELETE" }
  )
}

export function deleteCollectionRecords(
  getToken: () => Promise<string | null>,
  collection: string,
) {
  return apiFetch<{ deleted: number }>(
    `/admin/records/collection?${new URLSearchParams({ collection })}`,
    getToken,
    { method: "DELETE" },
  )
}

// Script Variables
export function getScriptVariables(getToken: () => Promise<string | null>) {
  return apiFetch<ScriptVariableSummary[]>("/admin/script-variables", getToken)
}

export function upsertScriptVariable(
  getToken: () => Promise<string | null>,
  body: { key: string; value: string }
) {
  return apiFetch("/admin/script-variables", getToken, {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function deleteScriptVariable(
  getToken: () => Promise<string | null>,
  key: string
) {
  return apiFetch(
    `/admin/script-variables/${encodeURIComponent(key)}`,
    getToken,
    { method: "DELETE" }
  )
}

// Labelers
export function getLabelers(getToken: () => Promise<string | null>) {
  return apiFetch<LabelerSummary[]>("/admin/labelers", getToken)
}

export function addLabeler(
  getToken: () => Promise<string | null>,
  body: { did: string }
) {
  return apiFetch("/admin/labelers", getToken, {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function updateLabeler(
  getToken: () => Promise<string | null>,
  did: string,
  body: { status: string }
) {
  return apiFetch(`/admin/labelers/${encodeURIComponent(did)}`, getToken, {
    method: "PATCH",
    body: JSON.stringify(body),
  })
}

export function deleteLabeler(
  getToken: () => Promise<string | null>,
  did: string
) {
  return apiFetch(`/admin/labelers/${encodeURIComponent(did)}`, getToken, {
    method: "DELETE",
  })
}

// Rate Limits
export function getRateLimits(getToken: () => Promise<string | null>) {
  return apiFetch<RateLimitsResponse>("/admin/rate-limits", getToken)
}

export function upsertRateLimit(
  getToken: () => Promise<string | null>,
  body: { method?: string; capacity: number; refill_rate: number }
) {
  return apiFetch("/admin/rate-limits", getToken, {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function deleteRateLimit(
  getToken: () => Promise<string | null>,
  id: number
) {
  return apiFetch(`/admin/rate-limits/${encodeURIComponent(id)}`, getToken, {
    method: "DELETE",
  })
}

export function setRateLimitEnabled(
  getToken: () => Promise<string | null>,
  body: { enabled: boolean }
) {
  return apiFetch("/admin/rate-limits/enabled", getToken, {
    method: "PUT",
    body: JSON.stringify(body),
  })
}

export function addAllowlistEntry(
  getToken: () => Promise<string | null>,
  body: { cidr: string; note?: string }
) {
  return apiFetch("/admin/rate-limits/allowlist", getToken, {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function removeAllowlistEntry(
  getToken: () => Promise<string | null>,
  id: number
) {
  return apiFetch(`/admin/rate-limits/allowlist/${encodeURIComponent(id)}`, getToken, {
    method: "DELETE",
  })
}

// Event Logs
export function getEvents(
  getToken: () => Promise<string | null>,
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
    getToken
  )
}
