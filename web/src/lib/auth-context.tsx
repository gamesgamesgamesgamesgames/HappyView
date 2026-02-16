"use client"

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react"

import { clearDpopKeypair, createDpopProof, ensureDpopKeypair, setDpopNonce } from "./dpop"

interface AuthContextType {
  did: string | null
  getToken: () => Promise<string | null>
  login: (handle: string) => Promise<void>
  logout: () => Promise<void>
  loading: boolean
  error: string | null
}

const AuthContext = createContext<AuthContextType>({
  did: null,
  getToken: async () => null,
  login: async () => {},
  logout: async () => {},
  loading: true,
  error: null,
})

// AIP URL for browser redirects (authorization endpoint)
const AIP_URL = process.env.NEXT_PUBLIC_AIP_URL || ""

// PKCE helpers

function base64urlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ""
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function generateRandomString(byteLength: number): string {
  const array = new Uint8Array(byteLength)
  crypto.getRandomValues(array)
  return base64urlEncode(array.buffer as ArrayBuffer)
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(verifier))
  return base64urlEncode(hash)
}

// Dynamic client registration with AIP.
// Caches the client_id in localStorage so we only register once.
async function getOrRegisterClient(redirectUri: string): Promise<string> {
  const cacheKey = `oauth_client_id:${AIP_URL}:${redirectUri}`
  const cached = localStorage.getItem(cacheKey)
  if (cached) return cached

  const resp = await fetch("/aip/oauth/clients/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      redirect_uris: [redirectUri],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      application_type: "native",
      client_name: "HappyView Admin",
    }),
  })

  if (!resp.ok) {
    const text = await resp.text()
    throw new Error(`Client registration failed: ${text}`)
  }

  const data = await resp.json()
  const clientId: string = data.client_id
  localStorage.setItem(cacheKey, clientId)
  return clientId
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [accessToken, setAccessToken] = useState<string | null>(null)
  const [did, setDid] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    // ATProto loopback client IDs require 127.0.0.1, not localhost.
    if (window.location.hostname === "localhost") {
      window.location.hostname = "127.0.0.1"
      return
    }

    let cancelled = false

    async function init() {
      try {
        const params = new URLSearchParams(window.location.search)
        const code = params.get("code")
        const state = params.get("state")

        if (code && state) {
          console.log("[auth] OAuth callback detected, exchanging code")
          await handleOAuthCallback(code, state, cancelled, {
            setAccessToken,
            setDid,
          })
        } else {
          // Restore session from storage
          const savedToken = sessionStorage.getItem("oauth_access_token")
          const savedDid = sessionStorage.getItem("oauth_did")
          const savedDpopKey = sessionStorage.getItem("dpop_private_jwk")

          console.log("[auth] Session restore check:", {
            hasToken: !!savedToken,
            hasDid: !!savedDid,
            hasDpopKey: !!savedDpopKey,
          })

          if (savedToken && !savedDpopKey) {
            console.log("[auth] Clearing pre-DPoP session")
            sessionStorage.removeItem("oauth_access_token")
            sessionStorage.removeItem("oauth_did")
            sessionStorage.removeItem("oauth_client_id")
          } else if (savedToken && savedDid && !cancelled) {
            console.log("[auth] Restoring session from storage")
            setAccessToken(savedToken)
            setDid(savedDid)
          } else {
            console.log("[auth] No session to restore")
          }
        }
      } catch (e) {
        if (!cancelled) {
          console.error("OAuth init error:", e)
          setError(e instanceof Error ? e.message : String(e))
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
    }

    init()
    return () => {
      cancelled = true
    }
  }, [])

  const getToken = useCallback(async (): Promise<string | null> => {
    return accessToken
  }, [accessToken])

  const login = useCallback(async (handle: string) => {
    if (!AIP_URL) {
      throw new Error("AIP URL not configured (set NEXT_PUBLIC_AIP_URL)")
    }

    setError(null)

    await ensureDpopKeypair()

    const redirectUri = `${window.location.origin}/`
    const clientId = await getOrRegisterClient(redirectUri)

    const codeVerifier = generateRandomString(32)
    const codeChallenge = await generateCodeChallenge(codeVerifier)
    const state = generateRandomString(16)

    sessionStorage.setItem("oauth_code_verifier", codeVerifier)
    sessionStorage.setItem("oauth_state", state)
    sessionStorage.setItem("oauth_client_id", clientId)

    const params = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
      scope: "atproto",
      login_hint: handle,
    })

    window.location.href = `${AIP_URL}/oauth/authorize?${params.toString()}`
  }, [])

  const logout = useCallback(async () => {
    const clientId = sessionStorage.getItem("oauth_client_id")
    if (accessToken && clientId) {
      try {
        await fetch("/aip/oauth/revoke", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            token: accessToken,
            client_id: clientId,
          }).toString(),
        })
      } catch {
        // Best-effort revocation
      }
    }
    setAccessToken(null)
    setDid(null)
    clearDpopKeypair()
    sessionStorage.removeItem("oauth_access_token")
    sessionStorage.removeItem("oauth_did")
    sessionStorage.removeItem("oauth_client_id")
  }, [accessToken])

  if (loading) return null

  return (
    <AuthContext.Provider
      value={{
        did,
        getToken,
        login,
        logout,
        loading,
        error,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

async function handleOAuthCallback(
  code: string,
  state: string,
  cancelled: boolean,
  setters: {
    setAccessToken: (t: string) => void
    setDid: (d: string) => void
  }
) {
  const savedState = sessionStorage.getItem("oauth_state")
  if (state !== savedState) {
    throw new Error("OAuth state mismatch")
  }

  const codeVerifier = sessionStorage.getItem("oauth_code_verifier")
  if (!codeVerifier) {
    throw new Error("Missing PKCE code verifier")
  }

  const clientId = sessionStorage.getItem("oauth_client_id")
  if (!clientId) {
    throw new Error("Missing OAuth client ID")
  }

  // Verify issuer if present in callback
  const params = new URLSearchParams(window.location.search)
  const iss = params.get("iss")
  if (iss) {
    const savedIssuer = sessionStorage.getItem("oauth_issuer")
    if (savedIssuer && iss !== savedIssuer) {
      throw new Error("OAuth issuer mismatch")
    }
  }

  const redirectUri = `${window.location.origin}/`

  // Token exchange via proxied path (avoids CORS).
  // AIP may require a DPoP nonce — retry once if we get one back.
  const tokenUrl = `${AIP_URL}/oauth/token`
  const tokenBody = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
    code_verifier: codeVerifier,
  }).toString()

  let tokenDpopProof = await createDpopProof("POST", tokenUrl)
  let resp = await fetch("/aip/oauth/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      DPoP: tokenDpopProof,
    },
    body: tokenBody,
  })

  if (!resp.ok) {
    // AIP returns the nonce via header and/or JSON body
    let nonce = resp.headers.get("dpop-nonce")
    if (!nonce) {
      const errBody = await resp.text().catch(() => "")
      try { nonce = JSON.parse(errBody).dpop_nonce ?? null } catch { /* not JSON */ }
      if (!nonce) throw new Error(`Token exchange failed: ${errBody}`)
    }
    tokenDpopProof = await createDpopProof("POST", tokenUrl, undefined, nonce)
    resp = await fetch("/aip/oauth/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        DPoP: tokenDpopProof,
      },
      body: tokenBody,
    })
  }

  if (!resp.ok) {
    const text = await resp.text()
    throw new Error(`Token exchange failed: ${text}`)
  }

  const tokens = await resp.json()
  // Capture the DPoP nonce from the token response for use in subsequent requests
  const dpopNonce = resp.headers.get("dpop-nonce")
  if (dpopNonce) setDpopNonce(dpopNonce)

  // Clean URL and session storage
  window.history.replaceState({}, "", window.location.pathname)
  sessionStorage.removeItem("oauth_state")
  sessionStorage.removeItem("oauth_code_verifier")
  sessionStorage.removeItem("oauth_issuer")

  if (cancelled) return

  const accessToken: string = tokens.access_token
  setters.setAccessToken(accessToken)

  // Get DID from token response or userinfo
  let userDid: string | undefined = tokens.sub
  if (!userDid) {
    const userinfoUrl = `${AIP_URL}/oauth/userinfo`
    // Use the nonce from the token response if available
    let currentNonce = dpopNonce
    let userinfoDpopProof = await createDpopProof("GET", userinfoUrl, accessToken, currentNonce ?? undefined)

    let userinfoResp = await fetch("/aip/oauth/userinfo", {
      headers: {
        Authorization: `DPoP ${accessToken}`,
        DPoP: userinfoDpopProof,
      },
    })

    // Retry with nonce if AIP requires one
    if (!userinfoResp.ok) {
      let nonce = userinfoResp.headers.get("dpop-nonce")
      if (!nonce) {
        const errBody = await userinfoResp.text().catch(() => "")
        try { nonce = JSON.parse(errBody).dpop_nonce ?? null } catch { /* not JSON */ }
      }
      if (nonce) {
        currentNonce = nonce
        userinfoDpopProof = await createDpopProof("GET", userinfoUrl, accessToken, nonce)
        userinfoResp = await fetch("/aip/oauth/userinfo", {
          headers: {
            Authorization: `DPoP ${accessToken}`,
            DPoP: userinfoDpopProof,
          },
        })
      }
    }

    if (userinfoResp.ok) {
      const info = await userinfoResp.json()
      userDid = info.sub
    }
  }

  if (userDid) {
    setters.setDid(userDid)
    sessionStorage.setItem("oauth_did", userDid)
  }
  sessionStorage.setItem("oauth_access_token", accessToken)
}

export function useAuth() {
  return useContext(AuthContext)
}
