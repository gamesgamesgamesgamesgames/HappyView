export type SettingEntry = {
  key: string
  value: string
  source: "database" | "env"
}

export type OAuthSettings = {
  app_name: string
  client_uri: string
  logo_uri: string
  tos_uri: string
  policy_uri: string
  oauth_scopes: string
}

export const OAUTH_SETTING_KEYS = [
  "app_name",
  "client_uri",
  "logo_uri",
  "tos_uri",
  "policy_uri",
  "oauth_scopes",
] as const satisfies readonly (keyof OAuthSettings)[]
