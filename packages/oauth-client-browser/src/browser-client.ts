import { AtprotoDohHandleResolver } from "@atproto-labs/handle-resolver";
import { DidResolverCommon } from "@atproto-labs/did-resolver";
import type { DidDocument } from "@atproto/did";
import {
  HappyViewOAuthClient,
  HappyViewSession,
  LAST_ACTIVE_KEY,
  importJwk,
  InvalidStateError,
  ResolutionError,
  TokenExchangeError,
  type StorageAdapter,
} from "@happyview/oauth-client";
import { LocalStorageAdapter } from "./local-storage-adapter";

const NAMESPACE = "@happyview/oauth-client-browser";
const POPUP_CHANNEL_NAME = `${NAMESPACE}(popup-channel)`;
const POPUP_STATE_PREFIX = `${NAMESPACE}(popup-state):`;

export class LoginContinuedInParentWindowError extends Error {
  constructor() {
    super("Login continued in parent window");
    this.name = "LoginContinuedInParentWindowError";
  }
}

export interface HappyViewBrowserClientOptions {
  instanceUrl: string;
  clientId: string;
  clientKey: string;
  redirectUri?: string;
  scopes?: string;
  storage?: StorageAdapter;
  fetch?: typeof globalThis.fetch;
}

interface PendingAuthState {
  did: string;
  provisionId: string;
  rawJwk: JsonWebKey;
  provisionPkceVerifier: string;
  authPkceVerifier: string;
  pdsUrl: string;
  tokenEndpoint: string;
  state: string;
  issuer: string;
}

export interface LoginOptions {
  scopes?: string;
  state?: string;
}

export interface PopupLoginOptions extends LoginOptions {
  popupName?: string;
  popupFeatures?: string;
}

export interface SignInOptions extends LoginOptions {
  display?: "popup" | "page";
  popupName?: string;
  popupFeatures?: string;
}

export interface PrepareLoginResult {
  authorizationUrl: string;
  did: string;
  state: string;
}

interface AuthServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  pushed_authorization_request_endpoint?: string;
  dpop_signing_alg_values_supported?: string[];
}

export class HappyViewBrowserClient extends HappyViewOAuthClient {
  private readonly handleResolver: AtprotoDohHandleResolver;
  private readonly didResolver: DidResolverCommon;
  private readonly clientId: string;
  private readonly redirectUri: string | undefined;
  private readonly scopes: string;
  constructor(options: HappyViewBrowserClientOptions) {
    const fetchFn = options.fetch ?? (((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init)) as typeof globalThis.fetch);
    const storageAdapter = options.storage ?? new LocalStorageAdapter();
    super({
      instanceUrl: options.instanceUrl,
      clientKey: options.clientKey,
      storage: storageAdapter,
      fetch: fetchFn,
    });

    this.clientId = options.clientId;
    this.redirectUri = options.redirectUri;
    this.scopes = options.scopes ?? "atproto";
    this.handleResolver = new AtprotoDohHandleResolver({
      dohEndpoint: "https://dns.google/resolve",
      fetch: fetchFn,
    });
    this.didResolver = new DidResolverCommon({ fetch: fetchFn });
  }

  async prepareLogin(handle: string, options?: LoginOptions): Promise<PrepareLoginResult> {
    // Resolve handle → DID → DID document → PDS URL → auth server metadata
    const resolvedDid = await this.handleResolver.resolve(handle);
    if (!resolvedDid) {
      throw new ResolutionError(`Failed to resolve handle: ${handle}`);
    }
    const did = resolvedDid as string;

    const didDoc = await this.didResolver.resolve(resolvedDid);
    const pdsUrl = extractPdsUrl(didDoc);
    const authMeta = await this.fetchAuthServerMetadata(pdsUrl);

    const scopes = options?.scopes ?? this.scopes;

    // Provision DPoP key from HappyView
    const { provisionId, rawJwk, pkceVerifier: provisionPkceVerifier } =
      await this.provisionDpopKey();

    // Separate PKCE for the PDS authorization server
    const authPkceVerifier = generatePkceVerifier();
    const authPkceChallenge = await computePkceChallenge(authPkceVerifier);

    const state = options?.state ?? randomHex(16);

    const pendingState: PendingAuthState = {
      did,
      provisionId,
      rawJwk,
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

    const { clientId, redirectUri } = this.resolveOAuthEndpoints();

    const authParams = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      state,
      scope: scopes,
      code_challenge: authPkceChallenge,
      code_challenge_method: "S256",
      login_hint: handle,
    });

    // ATProto requires Pushed Authorization Requests (PAR)
    const parEndpoint = authMeta.pushed_authorization_request_endpoint;
    if (parEndpoint) {
      const parResp = await this._fetch(parEndpoint, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body: authParams,
      });

      if (!parResp.ok) {
        const err = await parResp.text();
        throw new ResolutionError(
          `PAR request failed: ${parResp.status} ${err}`,
        );
      }

      const parData = (await parResp.json()) as { request_uri: string };
      const authorizationUrl =
        `${authMeta.authorization_endpoint}?` +
        new URLSearchParams({
          client_id: clientId,
          request_uri: parData.request_uri,
        });

      return { authorizationUrl, did, state };
    }

    // Fallback: direct authorization URL (for servers that don't require PAR)
    const authorizationUrl = `${authMeta.authorization_endpoint}?${authParams}`;

    return { authorizationUrl, did, state };
  }

  async login(handle: string, options?: LoginOptions): Promise<void> {
    const { authorizationUrl } = await this.prepareLogin(handle, options);
    window.location.href = authorizationUrl;
  }

  async callback(search?: string): Promise<HappyViewSession> {
    const params = new URLSearchParams(search ?? window.location.search);
    const code = params.get("code");
    const state = params.get("state");

    if (!code || !state) {
      const error = params.get("error");
      const errorDesc = params.get("error_description");
      const raw = search ?? window.location.search;
      throw new InvalidStateError(
        `Missing code or state in callback URL. ` +
        `error=${error}, error_description=${errorDesc}, ` +
        `search=${raw}`
      );
    }

    const pendingJson = await this.storage.get(`pending-auth:${state}`);
    if (!pendingJson) {
      throw new InvalidStateError(
        "No pending auth state found for this callback",
      );
    }
    const pending: PendingAuthState = JSON.parse(pendingJson);

    // Import the stored JWK into a Key for DPoP proof generation
    const dpopKey = await importJwk(pending.rawJwk);
    // Build a plain public JWK object from the raw key (strip private "d" component)
    const { d: _, ...publicJwk } = pending.rawJwk;

    const { clientId, redirectUri } = this.resolveOAuthEndpoints();

    // Token exchange with DPoP nonce handling — the PDS may require a nonce
    // by responding with 400 + use_dpop_nonce error and a DPoP-Nonce header.
    let dpopNonce: string | undefined;
    let tokenResp!: Response;

    for (let attempt = 0; attempt < 2; attempt++) {
      const proof = await dpopKey.createJwt(
        {
          alg: "ES256",
          typ: "dpop+jwt",
          jwk: publicJwk as any,
        },
        {
          htm: "POST",
          htu: pending.tokenEndpoint,
          iat: Math.floor(Date.now() / 1000),
          jti: randomHex(16),
          ...(dpopNonce ? { nonce: dpopNonce } : {}),
        },
      );

      tokenResp = await this._fetch(pending.tokenEndpoint, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          dpop: proof,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: redirectUri,
          client_id: clientId,
          code_verifier: pending.authPkceVerifier,
        }),
      });

      // If the server requires a DPoP nonce, retry with it
      if (!tokenResp.ok && attempt === 0) {
        const nonceHeader = tokenResp.headers.get("dpop-nonce");
        if (nonceHeader) {
          const errorBody = await tokenResp.text();
          if (errorBody.includes("use_dpop_nonce")) {
            dpopNonce = nonceHeader;
            continue;
          }
          // Not a nonce error — throw
          throw new TokenExchangeError(
            `Token exchange failed: ${tokenResp.status} ${errorBody}`,
            tokenResp.status,
            errorBody,
          );
        }
      }

      break;
    }

    if (!tokenResp!.ok) {
      const err = await tokenResp!.text();
      throw new TokenExchangeError(
        `Token exchange failed: ${tokenResp!.status} ${err}`,
        tokenResp!.status,
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
      scopes: tokens.scope ?? this.scopes,
      pdsUrl: pending.pdsUrl,
      issuer: tokens.iss ?? pending.issuer,
      dpopKey: pending.rawJwk,
    });

    await this.storage.delete(`pending-auth:${state}`);

    return session;
  }

  async logout(did: string): Promise<void> {
    await this.deleteSession(did);
  }

  async revoke(did: string): Promise<void> {
    return this.logout(did);
  }

  override async restore(did?: string): Promise<HappyViewSession | null> {
    if (did) {
      const session = await this.restoreSession(did);
      if (session) {
        await this.storage.set(LAST_ACTIVE_KEY, did);
      }
      return session;
    }
    return super.restore();
  }

  async init(): Promise<
    | { session: HappyViewSession; state?: string | null }
    | undefined
  > {
    const params = this.readCallbackParams();
    if (params) {
      return this.initCallback(`?${params.toString()}`);
    }
    return this.initRestore();
  }

  async initRestore(): Promise<{ session: HappyViewSession } | undefined> {
    const session = await this.restore();
    if (session) return { session };
    return undefined;
  }

  async initCallback(
    search?: string,
  ): Promise<{ session: HappyViewSession; state: string | null }> {
    const searchStr = search ?? window.location.search;
    const params = new URLSearchParams(searchStr);
    const state = params.get("state");

    history.replaceState(null, "", window.location.pathname);

    const session = await this.callback(searchStr);

    if (state?.startsWith(POPUP_STATE_PREFIX)) {
      const stateKey = state.slice(POPUP_STATE_PREFIX.length);
      const received = await sendPopupResult(stateKey, {
        status: "fulfilled",
        value: session.did,
      });
      if (!received) {
        await this.logout(session.did);
      }
      window.close();
      throw new LoginContinuedInParentWindowError();
    }

    return { session, state };
  }

  async signIn(
    handle: string,
    options?: SignInOptions,
  ): Promise<HappyViewSession | void> {
    if (options?.display === "popup") {
      return this.signInPopup(handle, options);
    }
    return this.signInRedirect(handle, options);
  }

  async signInRedirect(
    handle: string,
    options?: LoginOptions,
  ): Promise<void> {
    return this.login(handle, options);
  }

  async signInPopup(
    handle: string,
    options?: PopupLoginOptions,
  ): Promise<HappyViewSession> {
    const popupTarget = options?.popupName ?? "_blank";
    const popupFeatures =
      options?.popupFeatures ??
      "width=600,height=600,menubar=no,toolbar=no";

    let popup = window.open("about:blank", popupTarget, popupFeatures);

    const stateKey = Math.random().toString(36).slice(2);
    const result = await this.prepareLogin(handle, {
      ...options,
      state: `${POPUP_STATE_PREFIX}${stateKey}`,
    });

    if (popup) {
      popup.location.href = result.authorizationUrl;
    } else {
      popup = window.open(
        result.authorizationUrl,
        popupTarget,
        popupFeatures,
      );
    }
    popup?.focus();

    return new Promise<HappyViewSession>((resolve, reject) => {
      const channel = new BroadcastChannel(POPUP_CHANNEL_NAME);
      const cleanup = () => {
        clearTimeout(timeout);
        channel.removeEventListener("message", onMessage);
        channel.close();
        popup?.close();
      };

      const timeout = setTimeout(() => {
        reject(new Error("Popup login timed out"));
        cleanup();
      }, 5 * 60e3);

      const onMessage = async ({ data }: MessageEvent) => {
        if (data.key !== stateKey) return;
        if (!("result" in data)) return;

        channel.postMessage({ key: stateKey, ack: true });
        cleanup();

        if (data.result.status === "fulfilled") {
          const did = data.result.value as string;
          try {
            const session = await this.restoreSession(did);
            if (session) {
              resolve(session);
            } else {
              reject(
                new Error(
                  "Failed to restore session after popup login",
                ),
              );
            }
          } catch (err) {
            reject(err);
            await this.logout(did);
          }
        } else {
          reject(
            new Error(
              data.result.reason?.message ?? "Popup login failed",
            ),
          );
        }
      };

      channel.addEventListener("message", onMessage);
    });
  }

  readCallbackParams(): URLSearchParams | null {
    const params = new URLSearchParams(window.location.search);
    if (
      !params.has("state") ||
      !(params.has("code") || params.has("error"))
    ) {
      return null;
    }
    return params;
  }

  findRedirectUrl(): string {
    return (
      this.redirectUri ?? `${window.location.origin}/oauth/callback`
    );
  }

  dispose(): void {
    // No persistent resources to clean up
  }

  private resolveOAuthEndpoints(): { clientId: string; redirectUri: string } {
    return {
      clientId: this.clientId,
      redirectUri: this.redirectUri ?? `${window.location.origin}/oauth/callback`,
    };
  }

  private async fetchAuthServerMetadata(
    pdsUrl: string,
  ): Promise<AuthServerMetadata> {
    const base = pdsUrl.replace(/\/+$/, "");

    const resourceResp = await this._fetch(
      `${base}/.well-known/oauth-protected-resource`,
    );
    if (!resourceResp.ok) {
      throw new ResolutionError(
        `Failed to fetch protected resource metadata from ${pdsUrl}: ${resourceResp.status}`,
      );
    }
    const resource = (await resourceResp.json()) as {
      authorization_servers?: string[];
    };
    const authServer = resource.authorization_servers?.[0];
    if (!authServer) {
      throw new ResolutionError(
        `No authorization server found in protected resource metadata from ${pdsUrl}`,
      );
    }

    const metaResp = await this._fetch(
      `${authServer.replace(/\/+$/, "")}/.well-known/oauth-authorization-server`,
    );
    if (!metaResp.ok) {
      throw new ResolutionError(
        `Failed to fetch auth server metadata from ${authServer}: ${metaResp.status}`,
      );
    }
    return metaResp.json();
  }
}

function extractPdsUrl(doc: DidDocument): string {
  const services = doc.service ?? [];
  for (const service of services) {
    if (
      service.id === "#atproto_pds" ||
      (typeof service.id === "string" && service.id.endsWith("#atproto_pds"))
    ) {
      if (typeof service.serviceEndpoint === "string") {
        return service.serviceEndpoint;
      }
      throw new ResolutionError(
        `#atproto_pds service endpoint is not a string URL in DID document for ${doc.id}`,
      );
    }
  }
  throw new ResolutionError(
    `No #atproto_pds service found in DID document for ${doc.id}`,
  );
}

function randomHex(byteLength: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function generatePkceVerifier(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function sendPopupResult(
  key: string,
  result: {
    status: "fulfilled" | "rejected";
    value?: string;
    reason?: { message: string };
  },
): Promise<boolean> {
  const channel = new BroadcastChannel(POPUP_CHANNEL_NAME);
  return new Promise((resolve) => {
    const cleanup = (received: boolean) => {
      clearTimeout(timer);
      channel.removeEventListener("message", onMessage);
      channel.close();
      resolve(received);
    };
    const onMessage = ({ data }: MessageEvent) => {
      if ("ack" in data && data.key === key) cleanup(true);
    };
    channel.addEventListener("message", onMessage);
    channel.postMessage({ key, result });
    const timer = setTimeout(() => cleanup(false), 500);
  });
}

async function computePkceChallenge(verifier: string): Promise<string> {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  const bytes = new Uint8Array(hash);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
