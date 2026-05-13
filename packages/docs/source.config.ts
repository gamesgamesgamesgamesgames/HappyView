import { defineDocs, defineConfig } from 'fumadocs-mdx/config';
import { remarkMdxMermaid } from 'fumadocs-core/mdx-plugins';

const neonLagoonDark = {
  name: 'neon-lagoon-dark',
  type: 'dark' as const,
  colors: {
    'editor.background': '#06060f',
    'editor.foreground': '#e8f0ff',
  },
  tokenColors: [
    {
      scope: ['comment', 'punctuation'],
      settings: { foreground: '#506080' },
    },
    {
      scope: [
        'keyword',
        'keyword.control',
        'keyword.operator.expression',
        'storage.type',
        'storage.modifier',
      ],
      settings: { foreground: '#ff3390' },
    },
    {
      scope: ['string', 'string.quoted', 'string.template'],
      settings: { foreground: '#00ff9f' },
    },
    {
      scope: [
        'entity.name.type',
        'support.type',
        'entity.name.class',
        'variable.other.constant',
        'support.class',
      ],
      settings: { foreground: '#00d4ff' },
    },
    {
      scope: [
        'entity.name.function',
        'support.function',
        'entity.name.tag',
      ],
      settings: { foreground: '#ffcc00' },
    },
    {
      scope: ['variable', 'variable.other', 'meta.object-literal.key'],
      settings: { foreground: '#e8f0ff' },
    },
  ],
};

const neonLagoonLight = {
  name: 'neon-lagoon-light',
  type: 'light' as const,
  colors: {
    'editor.background': '#f8f0ff',
    'editor.foreground': '#0e1530',
  },
  tokenColors: [
    {
      scope: ['comment', 'punctuation'],
      settings: { foreground: '#8898b0' },
    },
    {
      scope: [
        'keyword',
        'keyword.control',
        'keyword.operator.expression',
        'storage.type',
        'storage.modifier',
      ],
      settings: { foreground: '#d9206e' },
    },
    {
      scope: ['string', 'string.quoted', 'string.template'],
      settings: { foreground: '#00805a' },
    },
    {
      scope: [
        'entity.name.type',
        'support.type',
        'entity.name.class',
        'variable.other.constant',
        'support.class',
      ],
      settings: { foreground: '#0099bb' },
    },
    {
      scope: [
        'entity.name.function',
        'support.function',
        'entity.name.tag',
      ],
      settings: { foreground: '#cc9900' },
    },
    {
      scope: ['variable', 'variable.other', 'meta.object-literal.key'],
      settings: { foreground: '#0e1530' },
    },
  ],
};

export const docs = defineDocs({
  dir: 'content/docs',
});

export default defineConfig({
  mdxOptions: {
    remarkPlugins: [remarkMdxMermaid],
    rehypeCodeOptions: {
      themes: {
        light: neonLagoonLight,
        dark: neonLagoonDark,
      },
    },
  },
});
