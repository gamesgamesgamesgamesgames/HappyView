"use client"

import { createContext, useCallback, useContext, useEffect, useState } from "react"

interface AuthContextType {
  token: string | null
  login: (token: string) => void
  logout: () => void
}

const AuthContext = createContext<AuthContextType>({
  token: null,
  login: () => {},
  logout: () => {},
})

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(null)
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    const stored = localStorage.getItem("happyview_token")
    if (stored) setToken(stored)
    setLoaded(true)
  }, [])

  const login = useCallback((t: string) => {
    localStorage.setItem("happyview_token", t)
    setToken(t)
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem("happyview_token")
    setToken(null)
  }, [])

  if (!loaded) return null

  return (
    <AuthContext.Provider value={{ token, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  return useContext(AuthContext)
}
