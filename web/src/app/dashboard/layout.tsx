"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"

import { useAuth } from "@/lib/auth-context"
import { useConfig } from "@/lib/config-context"
import { AppSidebar } from "@/components/app-sidebar"
import { PluginUpdateProvider } from "@/components/plugin-update-provider"
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"
import { Toaster } from "@/components/ui/sonner"

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const { did } = useAuth()
  const { app_name } = useConfig()
  const router = useRouter()

  useEffect(() => {
    if (!did) {
      router.replace("/login")
    }
  }, [did, router])

  useEffect(() => {
    document.title = app_name ? `${app_name} Admin` : "HappyView Admin"
  }, [app_name])

  if (!did) return null

  return (
    <PluginUpdateProvider>
      <SidebarProvider
        style={
          {
            "--sidebar-width": "calc(var(--spacing) * 72)",
            "--header-height": "calc(var(--spacing) * 12)",
          } as React.CSSProperties
        }
      >
        <AppSidebar variant="inset" />
        <SidebarInset>{children}</SidebarInset>
      </SidebarProvider>
      <Toaster />
    </PluginUpdateProvider>
  )
}
