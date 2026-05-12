import './global.css';
import { RootProvider } from 'fumadocs-ui/provider/next';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { source } from '@/lib/source';
import { fontVariables } from '@/lib/fonts';
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
    <html lang="en" className={`${fontVariables} dark`} suppressHydrationWarning>
      <body>
        <RootProvider>
          <DocsLayout
            tree={source.getPageTree()}
            nav={{
              title: (
                <span className="flex items-center gap-2 text-sm tracking-tight">
                  <img src="/img/logo.dark.png" alt="" className="h-5" />
                </span>
              ),
            }}
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
