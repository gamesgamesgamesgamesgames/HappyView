"use client"

import { useState } from "react"

import { cn } from "@/lib/utils"
import { useAuth } from "@/lib/auth-context"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"

export function LoginForm({
  className,
  ...props
}: React.ComponentProps<"div">) {
  const [handle, setHandle] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { login } = useAuth()

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!handle.trim()) return
    setLoading(true)
    setError(null)
    try {
      await login(handle.trim())
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Login failed")
      setLoading(false)
    }
  }

  return (
    <div className={cn("flex flex-col gap-6", className)} {...props}>
      <form onSubmit={handleSubmit}>
        <FieldGroup>
          <div className="flex flex-col items-center gap-2 text-center">
            <h1 className="text-xl font-bold">HappyView Admin</h1>
            <FieldDescription>
              Sign in with your ATProto account to manage your AppView.
            </FieldDescription>
          </div>
          {error && (
            <p className="text-destructive text-center text-sm">{error}</p>
          )}
          <Field>
            <FieldLabel htmlFor="handle">Handle</FieldLabel>
            <Input
              id="handle"
              type="text"
              placeholder="you.bsky.social"
              value={handle}
              onChange={(e) => setHandle(e.target.value)}
              required
              disabled={loading}
            />
          </Field>
          <Field>
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? "Signing in..." : "Sign in"}
            </Button>
          </Field>
        </FieldGroup>
      </form>
    </div>
  )
}
