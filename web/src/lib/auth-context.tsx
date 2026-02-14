"use client"

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react"
import type { BrowserOAuthClient, OAuthSession } from "@atproto/oauth-client-browser"

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

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<OAuthSession | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const clientRef = useRef<BrowserOAuthClient | null>(null)

  useEffect(() => {
    let cancelled = false

    async function init() {
      try {
        const {
          BrowserOAuthClient: Client,
          atprotoLoopbackClientMetadata,
          buildAtprotoLoopbackClientId,
        } = await import("@atproto/oauth-client-browser")

        const isLocalhost =
          window.location.hostname === "localhost" ||
          window.location.hostname === "127.0.0.1"

        let client: InstanceType<typeof Client>

        if (isLocalhost) {
          const port = window.location.port
            ? `:${window.location.port}`
            : ""
          const clientId = buildAtprotoLoopbackClientId({
            redirect_uris: [`http://127.0.0.1${port}/`],
          })
          client = new Client({
            handleResolver: "https://bsky.social",
            clientMetadata: atprotoLoopbackClientMetadata(clientId),
          })
        } else {
          client = await Client.load({
            clientId: `${window.location.origin}/oauth/client-metadata.json`,
            handleResolver: "https://bsky.social",
          })
        }

        clientRef.current = client

        const result = await client.init()
        if (!cancelled && result?.session) {
          setSession(result.session)
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
    if (!session) return null
    try {
      // Access the protected getTokenSet method to extract the raw access
      // token. The admin API validates tokens via AIP's userinfo endpoint
      // using plain Bearer auth, so we need the raw JWT.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const tokenSet = await (session as any).getTokenSet("auto")
      return tokenSet.access_token
    } catch {
      return null
    }
  }, [session])

  const login = useCallback(async (handle: string) => {
    const client = clientRef.current
    if (!client) return
    setError(null)
    try {
      await client.signIn(handle, {
        scope: "atproto",
      })
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      throw e
    }
  }, [])

  const logout = useCallback(async () => {
    if (session) {
      try {
        await session.signOut()
      } catch {
        // Ignore sign-out errors
      }
    }
    setSession(null)
  }, [session])

  if (loading) return null

  return (
    <AuthContext.Provider
      value={{
        did: session?.did ?? null,
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

export function useAuth() {
  return useContext(AuthContext)
}
