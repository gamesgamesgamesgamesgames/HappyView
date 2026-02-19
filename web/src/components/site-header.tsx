"use client"

import { IconArrowLeft } from "@tabler/icons-react"
import Link from "next/link"

import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { SidebarTrigger } from "@/components/ui/sidebar"
import { ThemeToggle } from "@/components/theme-toggle"

export function SiteHeader({
  title,
  backHref,
}: {
  title: string
  backHref?: string
}) {
  return (
    <header className="flex h-(--header-height) shrink-0 items-center gap-2 border-b transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-(--header-height)">
      <div className="flex w-full items-center gap-1 px-4 lg:gap-2 lg:px-6">
        <SidebarTrigger className="-ml-1" />
        <Separator
          orientation="vertical"
          className="mx-2 data-[orientation=vertical]:h-4"
        />
        {backHref && (
          <Button variant="ghost" size="icon" className="-ml-1 size-7" asChild>
            <Link href={backHref}>
              <IconArrowLeft className="size-4" />
              <span className="sr-only">Back</span>
            </Link>
          </Button>
        )}
        <h1 className="text-base font-medium">{title}</h1>
        <div className="ml-auto">
          <ThemeToggle />
        </div>
      </div>
    </header>
  )
}
