import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

const sidebars: SidebarsConfig = {
  docs: [
    {
      type: "doc",
      id: "README",
      label: "Introduction",
    },
    {
      type: "category",
      label: "Getting Started",
      items: [
        {
          type: "doc",
          id: "getting-started/quickstart",
          label: "Quickstart",
        },
        {
          type: "category",
          label: "Deployment",
          items: [
            {
              type: "doc",
              id: "getting-started/deployment/railway",
              label: "Railway",
            },
            {
              type: "doc",
              id: "getting-started/deployment/docker",
              label: "Docker",
            },
            {
              type: "doc",
              id: "getting-started/deployment/other",
              label: "From Source",
            },
            {
              type: "doc",
              id: "reference/production-deployment",
              label: "Production",
            },
          ],
        },
        {
          type: "doc",
          id: "getting-started/configuration",
          label: "Configuration",
        },
        {
          type: "doc",
          id: "getting-started/authentication",
          label: "Authentication",
        },
        {
          type: "doc",
          id: "getting-started/dashboard",
          label: "Dashboard",
        },
      ],
    },
    {
      type: "category",
      label: "Tutorials",
      items: [
        {
          type: "doc",
          id: "tutorials/statusphere",
          label: "Statusphere",
        },
      ],
    },
    {
      type: "category",
      label: "Guides",
      items: [
        {
          type: "category",
          label: "Indexing",
          items: [
            {
              type: "doc",
              id: "guides/lexicons",
              label: "Lexicons",
            },
            {
              type: "doc",
              id: "guides/backfill",
              label: "Backfill",
            },
            {
              type: "doc",
              id: "guides/index-hooks",
              label: "Index Hooks",
            },
          ],
        },
        {
          type: "category",
          label: "Scripting",
          items: [
            {
              type: "doc",
              id: "guides/scripting",
              label: "Lua Scripting",
            },
            {
              type: "category",
              label: "Script Examples",
              items: [
                {
                  type: "doc",
                  id: "reference/scripts/get-record",
                  label: "Get a Record",
                },
                {
                  type: "doc",
                  id: "reference/scripts/create-record",
                  label: "Create Record",
                },
                {
                  type: "doc",
                  id: "reference/scripts/upsert-record",
                  label: "Upsert Record",
                },
                {
                  type: "doc",
                  id: "reference/scripts/paginated-list",
                  label: "Paginated List",
                },
                {
                  type: "doc",
                  id: "reference/scripts/list-or-fetch",
                  label: "List or Fetch",
                },
                {
                  type: "doc",
                  id: "reference/scripts/expanded-query",
                  label: "Expanded Query",
                },
                {
                  type: "doc",
                  id: "reference/scripts/update-or-delete",
                  label: "Update or Delete",
                },
                {
                  type: "doc",
                  id: "reference/scripts/batch-save",
                  label: "Batch Save",
                },
                {
                  type: "doc",
                  id: "reference/scripts/sidecar-records",
                  label: "Sidecar Records",
                },
                {
                  type: "doc",
                  id: "reference/scripts/cascading-delete",
                  label: "Cascading Delete",
                },
                {
                  type: "doc",
                  id: "reference/scripts/complex-mutations",
                  label: "Complex Mutations",
                },
                {
                  type: "doc",
                  id: "reference/scripts/algolia-sync",
                  label: "Algolia Sync",
                },
                {
                  type: "doc",
                  id: "reference/scripts/meilisearch-sync",
                  label: "Meilisearch Sync",
                },
              ],
            },
          ],
        },
        {
          type: "category",
          label: "Features",
          items: [
            {
              type: "doc",
              id: "guides/labelers",
              label: "Labelers",
            },
            {
              type: "doc",
              id: "guides/plugins",
              label: "Plugins",
            },
          ],
        },
        {
          type: "category",
          label: "Administration",
          items: [
            {
              type: "doc",
              id: "guides/api-keys",
              label: "API Keys",
            },
            {
              type: "doc",
              id: "guides/permissions",
              label: "Permissions",
            },
            {
              type: "doc",
              id: "guides/event-logs",
              label: "Event Logs",
            },
          ],
        },
        {
          type: "category",
          label: "Database",
          items: [
            {
              type: "doc",
              id: "guides/database-setup",
              label: "Database Setup",
            },
            {
              type: "doc",
              id: "guides/postgres-to-sqlite-migration",
              label: "Postgres → SQLite Migration",
            },
          ],
        },
      ],
    },
    {
      type: "category",
      label: "JavaScript SDK",
      items: [
        {
          type: "doc",
          id: "sdk/overview",
          label: "Overview",
        },
        {
          type: "doc",
          id: "sdk/lex-agent",
          label: "Lex Agent",
        },
        {
          type: "doc",
          id: "sdk/oauth-client",
          label: "OAuth Client",
        },
        {
          type: "doc",
          id: "sdk/oauth-client-browser",
          label: "Browser Client",
        },
      ],
    },
    {
      type: "category",
      label: "Reference",
      items: [
        {
          type: "doc",
          id: "reference/xrpc-api",
          label: "XRPC API",
        },
        {
          type: "doc",
          id: "reference/admin-api",
          label: "Admin API",
        },
        {
          type: "doc",
          id: "reference/glossary",
          label: "Glossary",
        },
        {
          type: "doc",
          id: "reference/architecture",
          label: "Architecture",
        },
        {
          type: "doc",
          id: "reference/troubleshooting",
          label: "Troubleshooting",
        },
      ],
    },
  ],
};

export default sidebars;
