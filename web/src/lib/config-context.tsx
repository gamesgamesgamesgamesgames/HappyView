"use client"

import { createContext, useContext, useEffect, useState } from "react"

interface ConfigContextType {
  public_url: string
  default_rate_limit_capacity: number
  default_rate_limit_refill_rate: number
  app_name: string | null
  logo_url: string | null
}

const ConfigContext = createContext<ConfigContextType>({
  public_url: "",
  default_rate_limit_capacity: 100,
  default_rate_limit_refill_rate: 2.0,
  app_name: null,
  logo_url: null,
})

export function ConfigProvider({ children }: { children: React.ReactNode }) {
  const [config, setConfig] = useState<ConfigContextType | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch("/config")
      .then((res) => {
        if (!res.ok) throw new Error(`Config fetch failed: ${res.status}`)
        return res.json()
      })
      .then((data) => {
        setConfig({
          public_url: data.public_url,
          default_rate_limit_capacity: data.default_rate_limit_capacity,
          default_rate_limit_refill_rate: data.default_rate_limit_refill_rate,
          app_name: data.app_name ?? null,
          logo_url: data.logo_url ?? null,
        })
      })
      .catch((e) => setError(e.message))
  }, [])

  if (error) {
    return <div style={{ padding: "2rem", color: "red" }}>Failed to load config: {error}</div>
  }

  if (!config) return null

  return (
    <ConfigContext.Provider value={config}>{children}</ConfigContext.Provider>
  )
}

export function useConfig() {
  return useContext(ConfigContext)
}
