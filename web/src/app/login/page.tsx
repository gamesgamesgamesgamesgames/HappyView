"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { LoginForm } from "@/components/login-form"
import { useAuth } from "@/lib/auth-context"

export default function LoginPage() {
  const { token } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (token) router.replace("/")
  }, [token, router])

  if (token) return null

  return (
    <div className="bg-background flex min-h-svh flex-col items-center justify-center gap-6 p-6 md:p-10">
      <div className="w-full max-w-sm">
        <LoginForm />
      </div>
    </div>
  )
}
