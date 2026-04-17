import type { CryptoAdapter } from "./types";

export function base64urlEncode(data: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export interface DpopProofParams {
  privateKey: JsonWebKey;
  method: string;
  url: string;
  accessToken?: string;
  nonce?: string;
}

export async function generateDpopProof(
  crypto: CryptoAdapter,
  params: DpopProofParams,
): Promise<string> {
  const { privateKey, method, url, accessToken, nonce } = params;

  const publicJwk = {
    kty: privateKey.kty,
    crv: privateKey.crv,
    x: privateKey.x,
    y: privateKey.y,
  };

  const header = {
    alg: "ES256",
    typ: "dpop+jwt",
    jwk: publicJwk,
  };

  // Generate jti
  const jtiBytes = crypto.getRandomValues(16);
  const jti = Array.from(jtiBytes, (b) => b.toString(16).padStart(2, "0")).join("");

  const payload: Record<string, unknown> = {
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    jti,
  };

  // Compute ath: base64url(SHA-256(access_token)) — only when token is present
  if (accessToken) {
    const tokenBytes = new TextEncoder().encode(accessToken);
    const hashBuf = await crypto.sha256(tokenBytes);
    payload.ath = base64urlEncode(hashBuf);
  }

  if (nonce !== undefined) {
    payload.nonce = nonce;
  }

  const headerB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(header)),
  );
  const payloadB64 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(payload)),
  );

  const message = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = await crypto.signEs256(privateKey, message);
  const sigB64 = base64urlEncode(signature);

  return `${headerB64}.${payloadB64}.${sigB64}`;
}
