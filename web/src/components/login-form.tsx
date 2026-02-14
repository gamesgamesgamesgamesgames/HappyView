"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"

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
  const [token, setToken] = useState("")
  const { login } = useAuth()
  const router = useRouter()

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!token.trim()) return
    login(token.trim())
    router.push("/")
  }

  return (
    <div className={cn("flex flex-col gap-6", className)} {...props}>
      <form onSubmit={handleSubmit}>
        <FieldGroup>
          <div className="flex flex-col items-center gap-2 text-center">
            <h1 className="text-xl font-bold">HappyView Admin</h1>
            <FieldDescription>
              Enter your access token to manage your AppView.
            </FieldDescription>
          </div>
          <Field>
            <FieldLabel htmlFor="token">Access Token</FieldLabel>
            <Input
              id="token"
              type="password"
              placeholder="eyJ..."
              value={token}
              onChange={(e) => setToken(e.target.value)}
              required
            />
          </Field>
          <Field>
            <Button type="submit" className="w-full">
              Sign in
            </Button>
          </Field>
        </FieldGroup>
      </form>
    </div>
  )
}
