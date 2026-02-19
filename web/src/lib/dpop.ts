interface DpopKeyPair {
  privateKey: CryptoKey
  publicJwk: { kty: string; crv: string; x: string; y: string }
}

let cachedKeypair: DpopKeyPair | null = null
let cachedNonce: string | null = null

function base64urlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ""
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

async function importKeypair(jwk: JsonWebKey): Promise<DpopKeyPair> {
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  )
  return {
    privateKey,
    publicJwk: { kty: jwk.kty!, crv: jwk.crv!, x: jwk.x!, y: jwk.y! },
  }
}

export async function ensureDpopKeypair(): Promise<void> {
  if (cachedKeypair) return

  const stored = sessionStorage.getItem("dpop_private_jwk")
  if (stored) {
    cachedKeypair = await importKeypair(JSON.parse(stored))
    return
  }

  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  )
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey)
  sessionStorage.setItem("dpop_private_jwk", JSON.stringify(jwk))

  cachedKeypair = {
    privateKey: keyPair.privateKey,
    publicJwk: { kty: jwk.kty!, crv: jwk.crv!, x: jwk.x!, y: jwk.y! },
  }
}

export function setDpopNonce(nonce: string): void {
  cachedNonce = nonce
}

export async function createDpopProof(
  method: string,
  url: string,
  accessToken?: string,
  nonce?: string
): Promise<string> {
  // Use the cached nonce if no explicit nonce is provided
  const effectiveNonce = nonce ?? cachedNonce
  await ensureDpopKeypair()
  const keypair = cachedKeypair!

  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: keypair.publicJwk,
  }

  const claims: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: method.toUpperCase(),
    htu: url,
    iat: Math.floor(Date.now() / 1000),
  }

  if (accessToken) {
    const hash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(accessToken)
    )
    claims.ath = base64urlEncode(hash)
  }

  if (effectiveNonce) {
    claims.nonce = effectiveNonce
  }

  const enc = new TextEncoder()
  const headerB64 = base64urlEncode(
    enc.encode(JSON.stringify(header)).buffer as ArrayBuffer
  )
  const claimsB64 = base64urlEncode(
    enc.encode(JSON.stringify(claims)).buffer as ArrayBuffer
  )

  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keypair.privateKey,
    enc.encode(`${headerB64}.${claimsB64}`)
  )

  return `${headerB64}.${claimsB64}.${base64urlEncode(signature)}`
}

export function clearDpopKeypair(): void {
  cachedKeypair = null
  sessionStorage.removeItem("dpop_private_jwk")
}
