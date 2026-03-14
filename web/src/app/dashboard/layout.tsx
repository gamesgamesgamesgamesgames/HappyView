"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"

import { useAuth } from "@/lib/auth-context"
import { AppSidebar } from "@/components/app-sidebar"
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar"

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const { did } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (!did) {
      router.replace("/login")
    }
  }, [did, router])

  if (!did) return null

  return (
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
  )
}
