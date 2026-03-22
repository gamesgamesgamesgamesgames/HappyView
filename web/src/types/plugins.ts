export interface SecretDefinition {
  key: string;
  name: string;
  description: string | null;
}

export interface PluginSummary {
  id: string;
  name: string;
  version: string;
  source: "file" | "url";
  url: string | null;
  sha256: string | null;
  enabled: boolean;
  auth_type: string;
  required_secrets: SecretDefinition[];
  secrets_configured: boolean;
  loaded_at: string | null;
}

export interface PluginsListResponse {
  plugins: PluginSummary[];
  encryption_configured: boolean;
}
