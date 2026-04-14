export interface SecretDefinition {
  key: string;
  name: string;
  description: string | null;
}

export interface ReleaseEntry {
  version: string;
  name: string;
  published_at: string;
  body: string;
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
  update_available: boolean;
  latest_version: string | null;
  pending_releases: ReleaseEntry[];
}

export interface PluginsListResponse {
  plugins: PluginSummary[];
  encryption_configured: boolean;
}

export interface OfficialPluginSummary {
  id: string;
  name: string;
  description: string | null;
  icon_url: string | null;
  latest_version: string;
  manifest_url: string;
}

export interface OfficialPluginsListResponse {
  plugins: OfficialPluginSummary[];
  last_refreshed_at: string | null;
}
