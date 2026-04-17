import { ApiError } from "./errors";
import { HappyViewSession } from "./session";
import { MemoryStorage } from "./storage";
import type {
  CryptoAdapter,
  HappyViewOAuthClientOptions,
  ProvisionKeyResponse,
  RegisterSessionParams,
  RegisterSessionResponse,
  StorageAdapter,
  StoredSession,
} from "./types";

const STORAGE_PREFIX = "happyview:session:";
const LAST_ACTIVE_KEY = "happyview:last-active-did";

export class HappyViewOAuthClient {
  protected readonly instanceUrl: string;
  protected readonly clientKey: string;
  protected readonly crypto: CryptoAdapter;
  protected readonly storage: StorageAdapter;
  private readonly clientSecret: string | undefined;
  private readonly _fetch: typeof globalThis.fetch;

  constructor(
    options: HappyViewOAuthClientOptions & {
      fetch?: typeof globalThis.fetch;
    },
  ) {
    this.instanceUrl = options.instanceUrl.replace(/\/+$/, "");
    this.clientKey = options.clientKey;
    this.clientSecret = options.clientSecret;
    this.crypto = options.crypto;
    this.storage = options.storage ?? new MemoryStorage();
    this._fetch = options.fetch ?? globalThis.fetch;
  }

  get isConfidential(): boolean {
    return this.clientSecret !== undefined;
  }

  async provisionDpopKey(): Promise<{
    provisionId: string;
    dpopKey: JsonWebKey;
    pkceVerifier?: string;
  }> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "x-client-key": this.clientKey,
    };
    if (this.clientSecret) {
      headers["x-client-secret"] = this.clientSecret;
    }

    const body: Record<string, unknown> = {};
    let pkceVerifier: string | undefined;

    if (!this.isConfidential) {
      pkceVerifier = await this.crypto.generatePkceVerifier();
      const challenge = await this.crypto.computePkceChallenge(pkceVerifier);
      body.pkce_challenge = challenge;
    }

    const resp = await this._fetch(`${this.instanceUrl}/oauth/dpop-keys`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new ApiError(
        `Failed to provision DPoP key: ${resp.status} ${(body as any).message ?? resp.statusText}`,
        resp.status,
        body,
      );
    }

    const data: ProvisionKeyResponse = await resp.json();
    return {
      provisionId: data.provision_id,
      dpopKey: data.dpop_key,
      pkceVerifier,
    };
  }

  async registerSession(
    params: RegisterSessionParams,
  ): Promise<HappyViewSession> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "x-client-key": this.clientKey,
    };
    if (this.clientSecret) {
      headers["x-client-secret"] = this.clientSecret;
    }

    const body: Record<string, unknown> = {
      provision_id: params.provisionId,
      did: params.did,
      access_token: params.accessToken,
      refresh_token: params.refreshToken,
      scopes: params.scopes,
      pds_url: params.pdsUrl,
      issuer: params.issuer,
    };

    if (!this.isConfidential && params.pkceVerifier) {
      body.pkce_verifier = params.pkceVerifier;
    }

    const resp = await this._fetch(`${this.instanceUrl}/oauth/sessions`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new ApiError(
        `Failed to register session: ${resp.status} ${(body as any).message ?? resp.statusText}`,
        resp.status,
        body,
      );
    }

    const data: RegisterSessionResponse = await resp.json();

    const storedSession: StoredSession = {
      did: data.did,
      dpopKey: params.dpopKey,
      accessToken: params.accessToken,
      clientKey: this.clientKey,
      instanceUrl: this.instanceUrl,
    };
    await this.storage.set(
      `${STORAGE_PREFIX}${data.did}`,
      JSON.stringify(storedSession),
    );
    await this.storage.set(LAST_ACTIVE_KEY, data.did);

    return new HappyViewSession({
      did: data.did,
      dpopKey: params.dpopKey,
      accessToken: params.accessToken,
      clientKey: this.clientKey,
      instanceUrl: this.instanceUrl,
      crypto: this.crypto,
    });
  }

  async deleteSession(did: string): Promise<void> {
    const headers: Record<string, string> = {
      "x-client-key": this.clientKey,
    };
    if (this.clientSecret) {
      headers["x-client-secret"] = this.clientSecret;
    }

    const resp = await this._fetch(
      `${this.instanceUrl}/oauth/sessions/${did}`,
      {
        method: "DELETE",
        headers,
      },
    );

    if (!resp.ok && resp.status !== 404) {
      const body = await resp.json().catch(() => ({}));
      throw new ApiError(
        `Failed to delete session: ${resp.status} ${(body as any).message ?? resp.statusText}`,
        resp.status,
        body,
      );
    }

    await this.storage.delete(`${STORAGE_PREFIX}${did}`);

    const lastActive = await this.storage.get(LAST_ACTIVE_KEY);
    if (lastActive === did) {
      await this.storage.delete(LAST_ACTIVE_KEY);
    }
  }

  async restoreSession(did: string): Promise<HappyViewSession | null> {
    const stored = await this.storage.get(`${STORAGE_PREFIX}${did}`);
    if (!stored) return null;

    const data: StoredSession = JSON.parse(stored);
    return new HappyViewSession({
      did: data.did,
      dpopKey: data.dpopKey,
      accessToken: data.accessToken,
      clientKey: data.clientKey,
      instanceUrl: data.instanceUrl,
      crypto: this.crypto,
    });
  }

  async restore(): Promise<HappyViewSession | null> {
    const did = await this.storage.get(LAST_ACTIVE_KEY);
    if (!did) return null;
    return this.restoreSession(did);
  }
}
