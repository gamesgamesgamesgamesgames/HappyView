import { createDpopProof, setDpopNonce } from "./dpop"

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
  return res.json()
}

// Stats
export interface CollectionStat {
  collection: string
  count: number
}

export interface StatsResponse {
  total_records: number
  collections: CollectionStat[]
}

export function getStats(getToken: () => Promise<string | null>) {
  return apiFetch<StatsResponse>("/admin/stats", getToken)
}

// Lexicons
export interface LexiconSummary {
  id: string
  revision: number
  lexicon_type: string
  backfill: boolean
  action: string | null
  target_collection: string | null
  has_script: boolean
  source: string
  authority_did: string | null
  last_fetched_at: string | null
  created_at: string
  updated_at: string
}

export interface LexiconDetail extends LexiconSummary {
  lexicon_json: Record<string, unknown>
  script: string | null
}

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
export interface NetworkLexiconSummary {
  nsid: string
  authority_did: string
  target_collection: string | null
  last_fetched_at: string | null
  created_at: string
}

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
export interface TapStatsResponse {
  repo_count: number
  record_count: number
  outbox_buffer: number
}

export function getTapStats(getToken: () => Promise<string | null>) {
  return apiFetch<TapStatsResponse>("/admin/tap/stats", getToken)
}

// Backfill
export interface BackfillJob {
  id: string
  collection: string | null
  did: string | null
  status: string
  total_repos: number | null
  processed_repos: number | null
  total_records: number | null
  error: string | null
  started_at: string | null
  completed_at: string | null
  created_at: string
}

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

// Admins
export interface AdminSummary {
  id: string
  did: string
  created_at: string
  last_used_at: string | null
}

export function getAdmins(getToken: () => Promise<string | null>) {
  return apiFetch<AdminSummary[]>("/admin/admins", getToken)
}

export function addAdmin(
  getToken: () => Promise<string | null>,
  body: { did: string }
) {
  return apiFetch<{ id: string; did: string }>("/admin/admins", getToken, {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function deleteAdmin(getToken: () => Promise<string | null>, id: string) {
  return apiFetch(`/admin/admins/${encodeURIComponent(id)}`, getToken, {
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
export interface AdminRecord {
  uri: string
  did: string
  record: Record<string, unknown>
}

export interface AdminListRecordsResponse {
  records: AdminRecord[]
  cursor?: string
}

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
