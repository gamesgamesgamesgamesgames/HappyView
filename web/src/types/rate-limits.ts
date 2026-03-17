export interface AllowlistEntry {
  id: number
  cidr: string
  note: string | null
  created_at: string
}

export interface RateLimitsResponse {
  enabled: boolean
  capacity: number
  refill_rate: number
  default_query_cost: number
  default_procedure_cost: number
  default_proxy_cost: number
  allowlist: AllowlistEntry[]
}
