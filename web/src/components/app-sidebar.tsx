"use client"

import {
  IconDashboard,
  IconFileDescription,
  IconDatabase,
  IconTable,
  IconClipboardList,
  IconUsers,
  IconSettings,
  IconLogout,
  IconKey,
  IconVariable,
  IconTag,
  IconChevronRight,
  IconShield,
  IconLink,
  IconPuzzle,
  IconLockAccess,
} from "@tabler/icons-react"
import Image from "next/image"
import Link from "next/link"
import { usePathname } from "next/navigation"

import { useAuth } from "@/lib/auth-context"
import { useCurrentUser } from "@/hooks/use-current-user"
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
} from "@/components/ui/sidebar"

const navItems = [
  { title: "Dashboard", url: "/dashboard", icon: IconDashboard },
  { title: "Lexicons", url: "/dashboard/lexicons", icon: IconFileDescription },
  { title: "Backfill", url: "/dashboard/backfill", icon: IconDatabase },
  { title: "Records", url: "/dashboard/records", icon: IconTable },
  { title: "Event Logs", url: "/dashboard/events", icon: IconClipboardList, requiredPermissions: ["events:read"] },
] as const

const settingsSubItems = [
  { title: "Users", url: "/dashboard/settings/users", icon: IconUsers, requiredPermissions: ["users:read"] },
  { title: "Linked Accounts", url: "/dashboard/settings/accounts", icon: IconLink, requiredPermissions: [] as string[] },
  { title: "Plugins", url: "/dashboard/settings/plugins", icon: IconPuzzle, requiredPermissions: ["plugins:read"] },
  { title: "ENV Variables", url: "/dashboard/settings/env-variables", icon: IconVariable, requiredPermissions: ["script-variables:read"] },
  { title: "API Keys", url: "/dashboard/settings/api-keys", icon: IconKey, requiredPermissions: ["api-keys:read"] },
  { title: "Labelers", url: "/dashboard/settings/labelers", icon: IconTag, requiredPermissions: ["labelers:read"] },
  { title: "Rate Limits", url: "/dashboard/settings/rate-limits", icon: IconShield, requiredPermissions: ["rate-limits:read"] },
  { title: "OAuth", url: "/dashboard/settings/oauth", icon: IconLockAccess, requiredPermissions: ["settings:manage"] },
] as const

export function AppSidebar({
  ...props
}: React.ComponentProps<typeof Sidebar>) {
  const pathname = usePathname()
  const { logout } = useAuth()
  const { hasPermission } = useCurrentUser()

  const visibleNavItems = navItems.filter((item) => {
    if (!("requiredPermissions" in item)) return true
    return item.requiredPermissions.some((perm) => hasPermission(perm))
  })

  const visibleSettingsItems = settingsSubItems.filter((item) =>
    item.requiredPermissions.length === 0 ||
    item.requiredPermissions.some((perm) => hasPermission(perm))
  )

  const isSettingsActive = pathname.startsWith("/dashboard/settings")

  return (
    <Sidebar collapsible="offcanvas" {...props}>
      <SidebarHeader className="p-4">
        <Image
          src="/logo.light.png"
          alt="HappyView"
          width={140}
          height={48}
          className="block dark:hidden"
        />
        <Image
          src="/logo.dark.png"
          alt="HappyView"
          width={140}
          height={48}
          className="hidden dark:block"
        />
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent className="flex flex-col gap-2">
            <SidebarMenu>
              {visibleNavItems.map((item) => (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton
                    asChild
                    tooltip={item.title}
                    isActive={
                      item.url === "/dashboard"
                        ? pathname === "/dashboard"
                        : pathname.startsWith(item.url)
                    }
                  >
                    <Link href={item.url}>
                      <item.icon />
                      <span>{item.title}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}

              {visibleSettingsItems.length > 0 && (
                <Collapsible defaultOpen={isSettingsActive} className="group/collapsible">
                  <SidebarMenuItem>
                    <CollapsibleTrigger asChild>
                      <SidebarMenuButton tooltip="Settings" isActive={isSettingsActive}>
                        <IconSettings />
                        <span>Settings</span>
                        <IconChevronRight className="ml-auto transition-transform group-data-[state=open]/collapsible:rotate-90" />
                      </SidebarMenuButton>
                    </CollapsibleTrigger>
                    <CollapsibleContent>
                      <SidebarMenuSub>
                        {visibleSettingsItems.map((item) => (
                          <SidebarMenuSubItem key={item.title}>
                            <SidebarMenuSubButton
                              asChild
                              isActive={pathname.startsWith(item.url)}
                            >
                              <Link href={item.url}>
                                <item.icon />
                                <span>{item.title}</span>
                              </Link>
                            </SidebarMenuSubButton>
                          </SidebarMenuSubItem>
                        ))}
                      </SidebarMenuSub>
                    </CollapsibleContent>
                  </SidebarMenuItem>
                </Collapsible>
              )}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton onClick={logout} tooltip="Log out">
              <IconLogout />
              <span>Log out</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  )
}
