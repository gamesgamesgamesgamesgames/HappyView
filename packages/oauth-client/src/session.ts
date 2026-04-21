import type { Key } from "@atproto/jwk";

export interface HappyViewSessionOptions {
  did: string;
  dpopKey: Key;
  accessToken: string;
  clientKey: string;
  instanceUrl: string;
  fetch?: typeof globalThis.fetch;
}

function randomHex(byteLength: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function base64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export class HappyViewSession {
  readonly did: string;

  private readonly dpopKey: Key;
  private readonly accessToken: string;
  private readonly clientKey: string;
  private readonly instanceUrl: string;
  private readonly _fetch: typeof globalThis.fetch;
  private dpopNonce: string | undefined;

  constructor(options: HappyViewSessionOptions) {
    this.did = options.did;
    this.dpopKey = options.dpopKey;
    this.accessToken = options.accessToken;
    this.clientKey = options.clientKey;
    this.instanceUrl = options.instanceUrl.replace(/\/+$/, "");
    this._fetch = options.fetch ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init)) as typeof globalThis.fetch;
  }

  async fetchHandler(url: string, init: RequestInit): Promise<Response> {
    const fullUrl = /^https?:\/\//i.test(url)
      ? url
      : `${this.instanceUrl}${url}`;
    const method = (init.method ?? "GET").toUpperCase();
    const htu = fullUrl.split("?")[0];

    const sendWithProof = async (): Promise<Response> => {
      const tokenHash = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(this.accessToken),
      );
      const ath = base64url(tokenHash);

      const proof = await this.dpopKey.createJwt(
        {
          alg: "ES256",
          typ: "dpop+jwt",
          jwk: this.dpopKey.publicJwk!,
        },
        {
          htm: method,
          htu,
          iat: Math.floor(Date.now() / 1000),
          jti: randomHex(16),
          ath,
          nonce: this.dpopNonce,
        },
      );

      const headers = new Headers(init.headers);
      headers.set("authorization", `DPoP ${this.accessToken}`);
      headers.set("dpop", proof);
      headers.set("x-client-key", this.clientKey);

      return this._fetch(fullUrl, { ...init, headers });
    };

    let response: Response;
    try {
      response = await sendWithProof();
    } catch (e) {
      const info = `_fetch type: ${typeof this._fetch}, toString: ${String(this._fetch).slice(0, 120)}, url: ${fullUrl}`;
      throw new Error(`fetchHandler failed: ${(e as Error).message}\n\nDEBUG: ${info}`);
    }

    // Retry once if the server requires a DPoP nonce we didn't have
    const nonce = response.headers.get("dpop-nonce");
    if (nonce && nonce !== this.dpopNonce && (response.status === 401 || response.status === 400)) {
      this.dpopNonce = nonce;
      try {
        response = await sendWithProof();
      } catch (e) {
        throw new Error(`fetchHandler retry failed: ${(e as Error).message}`);
      }
      const retryNonce = response.headers.get("dpop-nonce");
      if (retryNonce) {
        this.dpopNonce = retryNonce;
      }
    } else if (nonce) {
      this.dpopNonce = nonce;
    }

    return response;
  }
}
