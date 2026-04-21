import { WebcryptoKey } from "@atproto/jwk-webcrypto";

/**
 * Import a raw ES256 JWK (as returned by HappyView's /oauth/dpop-keys)
 * into a WebcryptoKey that can sign JWTs.
 */
export async function importJwk(jwk: JsonWebKey): Promise<WebcryptoKey> {
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );

  // Derive public key by stripping the private component
  const { d: _, ...publicJwkFields } = jwk;
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    publicJwkFields,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );

  return WebcryptoKey.fromKeypair({ privateKey, publicKey });
}
