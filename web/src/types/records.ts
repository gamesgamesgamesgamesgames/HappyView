export interface AdminRecord {
  uri: string
  did: string
  record: Record<string, unknown>
}

export interface AdminListRecordsResponse {
  records: AdminRecord[]
  cursor?: string
}
