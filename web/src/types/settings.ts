export type SettingEntry = {
  key: string
  value: string
  source: "database" | "env"
}

export type InstanceSettings = {
  app_name: string
  client_uri: string
  logo_uri: string
  tos_uri: string
  policy_uri: string
}

export const INSTANCE_SETTING_KEYS = [
  "app_name",
  "client_uri",
  "logo_uri",
  "tos_uri",
  "policy_uri",
] as const satisfies readonly (keyof InstanceSettings)[]
