"use client"

import { createContext, useContext, useEffect, useState } from "react"
import { setAipUrl } from "./api"

interface ConfigContextType {
  aip_url: string
}

const ConfigContext = createContext<ConfigContextType>({ aip_url: "" })

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
        setAipUrl(data.aip_url)
        setConfig({ aip_url: data.aip_url })
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
