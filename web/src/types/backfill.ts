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
