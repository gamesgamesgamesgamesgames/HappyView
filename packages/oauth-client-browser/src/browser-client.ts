import {
  generateDpopProof,
  HappyViewOAuthClient,
  HappyViewSession,
  InvalidStateError,
  TokenExchangeError,
  type CryptoAdapter,
  type StorageAdapter,
} from "@happyview/oauth-client";
import { LocalStorageAdapter } from "./local-storage-adapter";
import {
  resolveAuthServerMetadata,
  resolveDidDocument,
  resolveHandleToDid,
  resolvePdsUrl,
} from "./resolve";
import { WebCryptoAdapter } from "./web-crypto-adapter";

export interface HappyViewBrowserClientOptions {
  instanceUrl: string;
  clientKey: string;
  crypto?: CryptoAdapter;
  storage?: StorageAdapter;
  fetch?: typeof globalThis.fetch;
}

interface PendingAuthState {
  did: string;
  provisionId: string;
  dpopKey: JsonWebKey;
  provisionPkceVerifier: string;
  authPkceVerifier: string;
  pdsUrl: string;
  tokenEndpoint: string;
  state: string;
  issuer: string;
}

export interface PrepareLoginResult {
  authorizationUrl: string;
  did: string;
  state: string;
}

export class HappyViewBrowserClient extends HappyViewOAuthClient {
  private readonly _fetchFn: typeof globalThis.fetch;

  constructor(options: HappyViewBrowserClientOptions) {
    const fetchFn = options.fetch ?? globalThis.fetch;
    const cryptoAdapter = options.crypto ?? new WebCryptoAdapter();
    const storageAdapter = options.storage ?? new LocalStorageAdapter();
    super({
      instanceUrl: options.instanceUrl,
      clientKey: options.clientKey,
      crypto: cryptoAdapter,
      storage: storageAdapter,
      fetch: fetchFn,
    });
    this._fetchFn = fetchFn;
  }

  async prepareLogin(handle: string): Promise<PrepareLoginResult> {
    const did = await resolveHandleToDid(handle, this._fetchFn);
    const doc = await resolveDidDocument(did, this._fetchFn);
    const pdsUrl = resolvePdsUrl(doc);
    const authMeta = await resolveAuthServerMetadata(pdsUrl, this._fetchFn);

    const { provisionId, dpopKey, pkceVerifier: provisionPkceVerifier } =
      await this.provisionDpopKey();

    // Separate PKCE for the PDS authorization server
    const authPkceVerifier = await this.crypto.generatePkceVerifier();
    const authPkceChallenge =
      await this.crypto.computePkceChallenge(authPkceVerifier);

    const stateBytes = this.crypto.getRandomValues(16);
    const state = Array.from(stateBytes, (b) =>
      b.toString(16).padStart(2, "0"),
    ).join("");

    const pendingState: PendingAuthState = {
      did,
      provisionId,
      dpopKey,
      provisionPkceVerifier: provisionPkceVerifier!,
      authPkceVerifier,
      pdsUrl,
      tokenEndpoint: authMeta.token_endpoint,
      state,
      issuer: authMeta.issuer,
    };
    await this.storage.set(
      `pending-auth:${state}`,
      JSON.stringify(pendingState),
    );

    const redirectUri = window.location.origin + "/oauth/callback";
    const params = new URLSearchParams({
      response_type: "code",
      client_id: `${this.instanceUrl}/oauth-client-metadata.json`,
      redirect_uri: redirectUri,
      state,
      scope: "atproto",
      code_challenge: authPkceChallenge,
      code_challenge_method: "S256",
    });

    const authorizationUrl = `${authMeta.authorization_endpoint}?${params}`;

    return { authorizationUrl, did, state };
  }

  async login(handle: string): Promise<void> {
    const { authorizationUrl } = await this.prepareLogin(handle);
    window.location.href = authorizationUrl;
  }

  async callback(search?: string): Promise<HappyViewSession> {
    const params = new URLSearchParams(search ?? window.location.search);
    const code = params.get("code");
    const state = params.get("state");

    if (!code || !state) {
      throw new InvalidStateError("Missing code or state in callback URL");
    }

    const pendingJson = await this.storage.get(`pending-auth:${state}`);
    if (!pendingJson) {
      throw new InvalidStateError("No pending auth state found for this callback");
    }
    const pending: PendingAuthState = JSON.parse(pendingJson);

    // Generate DPoP proof for the token endpoint (no ath — no access token yet)
    const dpopProof = await generateDpopProof(this.crypto, {
      privateKey: pending.dpopKey,
      method: "POST",
      url: pending.tokenEndpoint,
    });

    const redirectUri = window.location.origin + "/oauth/callback";
    const tokenResp = await this._fetchFn(pending.tokenEndpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: dpopProof,
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: `${this.instanceUrl}/oauth-client-metadata.json`,
        code_verifier: pending.authPkceVerifier,
      }),
    });

    if (!tokenResp.ok) {
      const err = await tokenResp.text();
      throw new TokenExchangeError(
        `Token exchange failed: ${tokenResp.status} ${err}`,
        tokenResp.status,
        err,
      );
    }

    const tokens = (await tokenResp.json()) as {
      access_token: string;
      refresh_token?: string;
      scope?: string;
      sub?: string;
      iss?: string;
    };

    const session = await this.registerSession({
      provisionId: pending.provisionId,
      pkceVerifier: pending.provisionPkceVerifier,
      did: pending.did,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      scopes: tokens.scope ?? "atproto",
      pdsUrl: pending.pdsUrl,
      issuer: tokens.iss ?? pending.issuer,
      dpopKey: pending.dpopKey,
    });

    await this.storage.delete(`pending-auth:${state}`);

    return session;
  }

  async logout(did: string): Promise<void> {
    await this.deleteSession(did);
  }
}
