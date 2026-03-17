export interface RateLimitSummary {
  id: number
  method: string | null
  capacity: number
  refill_rate: number
  created_at: string
  updated_at: string
}

export interface AllowlistEntry {
  id: number
  cidr: string
  note: string | null
  created_at: string
}

export interface RateLimitsResponse {
  enabled: boolean
  limits: RateLimitSummary[]
  allowlist: AllowlistEntry[]
}
