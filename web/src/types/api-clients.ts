export interface ApiClientSummary {
  id: string
  client_key: string
  name: string
  client_id_url: string
  client_uri: string
  redirect_uris: string[]
  scopes: string
  rate_limit_capacity: number | null
  rate_limit_refill_rate: number | null
  is_active: boolean
  created_by: string
  created_at: string
  updated_at: string
}

export interface CreateApiClientResponse {
  id: string
  client_key: string
  client_secret: string
  name: string
  client_id_url: string
}