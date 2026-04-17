import { generateDpopProof } from "./dpop-proof";
import type { CryptoAdapter } from "./types";

export interface HappyViewSessionOptions {
  did: string;
  dpopKey: JsonWebKey;
  accessToken: string;
  clientKey: string;
  instanceUrl: string;
  crypto: CryptoAdapter;
  fetch?: typeof globalThis.fetch;
}

export class HappyViewSession {
  readonly did: string;

  private readonly dpopKey: JsonWebKey;
  private readonly accessToken: string;
  private readonly clientKey: string;
  private readonly instanceUrl: string;
  private readonly crypto: CryptoAdapter;
  private readonly _fetch: typeof globalThis.fetch;
  private dpopNonce: string | undefined;

  constructor(options: HappyViewSessionOptions) {
    this.did = options.did;
    this.dpopKey = options.dpopKey;
    this.accessToken = options.accessToken;
    this.clientKey = options.clientKey;
    this.instanceUrl = options.instanceUrl.replace(/\/+$/, "");
    this.crypto = options.crypto;
    this._fetch = options.fetch ?? globalThis.fetch;
  }

  async fetchHandler(url: string, init: RequestInit): Promise<Response> {
    const fullUrl = /^https?:\/\//i.test(url) ? url : `${this.instanceUrl}${url}`;
    const method = (init.method ?? "GET").toUpperCase();

    const proof = await generateDpopProof(this.crypto, {
      privateKey: this.dpopKey,
      method,
      url: fullUrl,
      accessToken: this.accessToken,
      nonce: this.dpopNonce,
    });

    const headers = new Headers(init.headers);
    headers.set("authorization", `DPoP ${this.accessToken}`);
    headers.set("dpop", proof);
    headers.set("x-client-key", this.clientKey);

    const response = await this._fetch(fullUrl, {
      ...init,
      headers,
    });

    const nonce = response.headers.get("dpop-nonce");
    if (nonce) {
      this.dpopNonce = nonce;
    }

    return response;
  }
}
