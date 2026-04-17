import { base64urlEncode, type CryptoAdapter } from "@happyview/oauth-client";

export class WebCryptoAdapter implements CryptoAdapter {
  async generatePkceVerifier(): Promise<string> {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return base64urlEncode(bytes);
  }

  async computePkceChallenge(verifier: string): Promise<string> {
    const data = new TextEncoder().encode(verifier);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return base64urlEncode(new Uint8Array(hash));
  }

  async signEs256(
    privateKey: JsonWebKey,
    payload: Uint8Array,
  ): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey(
      "jwk",
      privateKey,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      payload as unknown as ArrayBuffer,
    );
    return new Uint8Array(sig);
  }

  async sha256(data: Uint8Array): Promise<Uint8Array> {
    const hash = await crypto.subtle.digest("SHA-256", data as unknown as ArrayBuffer);
    return new Uint8Array(hash);
  }

  getRandomValues(length: number): Uint8Array {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }
}
