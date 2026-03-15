export interface RecordLabel {
  src: string
  val: string
  cts: string
}

export interface AdminRecord {
  uri: string
  did: string
  record: Record<string, unknown>
  labels: RecordLabel[]
}

export interface AdminListRecordsResponse {
  records: AdminRecord[]
  cursor?: string
}
