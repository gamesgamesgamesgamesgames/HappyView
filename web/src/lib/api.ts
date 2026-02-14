export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function apiFetch<T = unknown>(
  path: string,
  token: string,
  options?: RequestInit
): Promise<T> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
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

export function getStats(token: string) {
  return apiFetch<StatsResponse>("/admin/stats", token)
}

// Lexicons
export interface LexiconSummary {
  id: string
  revision: number
  lexicon_type: string
  backfill: boolean
  action: string | null
  created_at: string
  updated_at: string
}

export interface LexiconDetail extends LexiconSummary {
  lexicon_json: Record<string, unknown>
}

export function getLexicons(token: string) {
  return apiFetch<LexiconSummary[]>("/admin/lexicons", token)
}

export function getLexicon(token: string, id: string) {
  return apiFetch<LexiconDetail>(`/admin/lexicons/${encodeURIComponent(id)}`, token)
}

export function uploadLexicon(
  token: string,
  body: {
    lexicon_json: unknown
    backfill?: boolean
    target_collection?: string
    action?: string
  }
) {
  return apiFetch<{ id: string; revision: number }>("/admin/lexicons", token, {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function deleteLexicon(token: string, id: string) {
  return apiFetch(`/admin/lexicons/${encodeURIComponent(id)}`, token, {
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

export function getNetworkLexicons(token: string) {
  return apiFetch<NetworkLexiconSummary[]>("/admin/network-lexicons", token)
}

export function addNetworkLexicon(
  token: string,
  body: { nsid: string; target_collection?: string }
) {
  return apiFetch<{ nsid: string; authority_did: string; revision: number }>(
    "/admin/network-lexicons",
    token,
    { method: "POST", body: JSON.stringify(body) }
  )
}

export function deleteNetworkLexicon(token: string, nsid: string) {
  return apiFetch(
    `/admin/network-lexicons/${encodeURIComponent(nsid)}`,
    token,
    { method: "DELETE" }
  )
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

export function getBackfillJobs(token: string) {
  return apiFetch<BackfillJob[]>("/admin/backfill/status", token)
}

export function createBackfillJob(
  token: string,
  body: { collection?: string; did?: string }
) {
  return apiFetch<{ id: string; status: string }>("/admin/backfill", token, {
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

export function getAdmins(token: string) {
  return apiFetch<AdminSummary[]>("/admin/admins", token)
}

export function addAdmin(token: string, body: { did: string }) {
  return apiFetch<{ id: string; did: string }>("/admin/admins", token, {
    method: "POST",
    body: JSON.stringify(body),
  })
}

export function deleteAdmin(token: string, id: string) {
  return apiFetch(`/admin/admins/${encodeURIComponent(id)}`, token, {
    method: "DELETE",
  })
}
