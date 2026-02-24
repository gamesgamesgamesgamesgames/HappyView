import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";

const config: Config = {
  title: "HappyView",
  tagline: "Lexicon-driven ATProto AppView",
  url: "https://happyview.dev",
  baseUrl: "/",
  favicon: "img/favicon.png",
  onBrokenLinks: "throw",
  markdown: {
    mermaid: true,
  },
  themes: ["@docusaurus/theme-mermaid"],

  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  presets: [
    [
      "classic",
      {
        docs: {
          path: "docs",
          routeBasePath: "/",
          sidebarPath: "./sidebars.ts",
        },
        blog: false,
        theme: {
          customCss: undefined,
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    navbar: {
      title: "HappyView",
      logo: {
        alt: "HappyView Logo",
        src: "img/logo.png",
      },
      items: [
        {
          type: "docSidebar",
          sidebarId: "docs",
          position: "left",
          label: "Docs",
        },
        {
          href: "https://github.com/gamesgamesgamesgamesgames/happyview",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    prism: {
      additionalLanguages: ["lua"],
    },
    footer: {
      copyright: `Copyright \u00a9 ${new Date().getFullYear()} [Birbhouse Games](https://birb.house).`,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
