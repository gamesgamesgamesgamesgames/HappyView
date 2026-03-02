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
