import './global.css';
import { RootProvider } from 'fumadocs-ui/provider/next';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { source } from '@/lib/source';
import { fontVariables } from '@/lib/fonts';
import { SidebarFooter } from '@/components/sidebar-footer';
import type { ReactNode } from 'react';

export const metadata = {
  metadataBase: new URL(
    `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL ?? 'localhost:3000'}`,
  ),
  title: {
    template: '%s | HappyView',
    default: 'HappyView',
  },
  description: 'Lexicon-driven ATProto AppView',
  openGraph: {
    images: [{ url: '/img/og.png' }],
  },
  icons: [{ rel: 'icon', url: '/img/favicon.png' }],
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={fontVariables} suppressHydrationWarning>
      <body>
        <RootProvider theme={{ defaultTheme: 'dark' }}>
          <DocsLayout
            tree={source.getPageTree()}
            nav={{
              title: (
                <span className="flex items-center gap-2 text-sm tracking-tight">
                  <img
                    src="/img/logo.dark.png"
                    alt="HappyView"
                    className="h-14 hidden dark:block"
                  />
                  <img
                    src="/img/logo.light.png"
                    alt="HappyView"
                    className="h-14 block dark:hidden"
                  />
                </span>
              ),
            }}
            sidebar={{
              footer: <SidebarFooter key="sidebar-footer" />,
            }}
            themeSwitch={{ enabled: false }}
            links={[
              {
                text: 'Docs',
                url: '/',
                active: 'nested-url',
              },
              {
                text: 'Source',
                url: 'https://tangled.org/gamesgamesgamesgames.games/happyview',
                external: true,
              },
            ]}
          >
            {children}
          </DocsLayout>
        </RootProvider>
      </body>
    </html>
  );
}
