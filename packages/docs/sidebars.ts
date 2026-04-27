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
          type: "doc",
          id: "getting-started/configuration",
          label: "Configuration",
        },
        {
          type: "doc",
          id: "getting-started/dashboard",
          label: "Dashboard",
        },
        {
          type: "doc",
          id: "getting-started/authentication",
          label: "Authentication",
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
              id: "getting-started/production-deployment",
              label: "Production",
            },
          ],
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
          type: "doc",
          id: "guides/upgrading-to-v2",
          label: "Migrating from v1",
        },
        {
          type: "category",
          label: "Features",
          items: [
            {
              type: "doc",
              id: "guides/features/api-clients",
              label: "API Clients",
            },
            {
              type: "doc",
              id: "guides/features/labelers",
              label: "Labelers",
            },
            {
              type: "doc",
              id: "guides/features/plugins",
              label: "Plugins",
            },
            {
              type: "doc",
              id: "guides/features/developing-plugins",
              label: "Developing Plugins",
            },
          ],
        },
        {
          type: "category",
          label: "Indexing",
          items: [
            {
              type: "doc",
              id: "guides/indexing/lexicons",
              label: "Lexicons",
            },
            {
              type: "doc",
              id: "guides/indexing/backfill",
              label: "Backfill",
            },
            {
              type: "doc",
              id: "guides/indexing/index-hooks",
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
                  id: "guides/scripting/get-record",
                  label: "Get a Record",
                },
                {
                  type: "doc",
                  id: "guides/scripting/create-record",
                  label: "Create Record",
                },
                {
                  type: "doc",
                  id: "guides/scripting/upsert-record",
                  label: "Upsert Record",
                },
                {
                  type: "doc",
                  id: "guides/scripting/paginated-list",
                  label: "Paginated List",
                },
                {
                  type: "doc",
                  id: "guides/scripting/list-or-fetch",
                  label: "List or Fetch",
                },
                {
                  type: "doc",
                  id: "guides/scripting/expanded-query",
                  label: "Expanded Query",
                },
                {
                  type: "doc",
                  id: "guides/scripting/update-or-delete",
                  label: "Update or Delete",
                },
                {
                  type: "doc",
                  id: "guides/scripting/batch-save",
                  label: "Batch Save",
                },
                {
                  type: "doc",
                  id: "guides/scripting/sidecar-records",
                  label: "Sidecar Records",
                },
                {
                  type: "doc",
                  id: "guides/scripting/cascading-delete",
                  label: "Cascading Delete",
                },
                {
                  type: "doc",
                  id: "guides/scripting/complex-mutations",
                  label: "Complex Mutations",
                },
                {
                  type: "doc",
                  id: "guides/scripting/algolia-sync",
                  label: "Algolia Sync",
                },
                {
                  type: "doc",
                  id: "guides/scripting/meilisearch-sync",
                  label: "Meilisearch Sync",
                },
              ],
            },
          ],
        },
        {
          type: "category",
          label: "Administration",
          items: [
            {
              type: "doc",
              id: "guides/admin/api-keys",
              label: "API Keys",
            },
            {
              type: "doc",
              id: "guides/admin/permissions",
              label: "Permissions",
            },
            {
              type: "doc",
              id: "guides/admin/event-logs",
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
              id: "guides/database/database-setup",
              label: "Database Setup",
            },
            {
              type: "doc",
              id: "guides/database/postgres-to-sqlite-migration",
              label: "Postgres → SQLite Migration",
            },
            {
              type: "doc",
              id: "guides/database/sqlite-to-postgres-migration",
              label: "SQLite → Postgres Migration",
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
        {
          type: "category",
          label: "Changelogs",
          items: [
            {
              type: "doc",
              id: "sdk/changelog-oauth-client",
              label: "OAuth Client",
            },
            {
              type: "doc",
              id: "sdk/changelog-oauth-client-browser",
              label: "Browser Client",
            },
            {
              type: "doc",
              id: "sdk/changelog-lex-agent",
              label: "Lex Agent",
            },
          ],
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
          type: "category",
          label: "Admin API",
          items: [
            {
              type: "doc",
              id: "reference/admin/admin-api",
              label: "Overview",
            },
            {
              type: "doc",
              id: "reference/admin/lexicons",
              label: "Lexicons",
            },
            {
              type: "doc",
              id: "reference/admin/stats",
              label: "Stats",
            },
            {
              type: "doc",
              id: "reference/admin/backfill",
              label: "Backfill",
            },
            {
              type: "doc",
              id: "reference/admin/events",
              label: "Event Logs",
            },
            {
              type: "doc",
              id: "reference/admin/api-keys",
              label: "API Keys",
            },
            {
              type: "doc",
              id: "reference/admin/users",
              label: "Users",
            },
            {
              type: "doc",
              id: "reference/admin/labelers",
              label: "Labelers",
            },
            {
              type: "doc",
              id: "reference/admin/settings",
              label: "Instance Settings",
            },
            {
              type: "doc",
              id: "reference/admin/domains",
              label: "Domains",
            },
            {
              type: "doc",
              id: "reference/admin/script-variables",
              label: "Script Variables",
            },
            {
              type: "doc",
              id: "reference/admin/api-clients",
              label: "API Clients",
            },
            {
              type: "doc",
              id: "reference/admin/plugins",
              label: "Plugins",
            },
          ],
        },
        {
          type: "category",
          label: "OAuth API",
          items: [
            {
              type: "doc",
              id: "reference/oauth/api-clients",
              label: "Self-Service API Clients",
            },
          ],
        },
        {
          type: "category",
          label: "Lua API",
          items: [
            {
              type: "doc",
              id: "reference/lua/record-api",
              label: "Record API",
            },
            {
              type: "doc",
              id: "reference/lua/database-api",
              label: "Database API",
            },
            {
              type: "doc",
              id: "reference/lua/http-api",
              label: "HTTP API",
            },
            {
              type: "doc",
              id: "reference/lua/atproto-api",
              label: "atproto API",
            },
            {
              type: "doc",
              id: "reference/lua/json-api",
              label: "JSON API",
            },
            {
              type: "doc",
              id: "reference/lua/utility-globals",
              label: "Utility Globals",
            },
            {
              type: "doc",
              id: "reference/lua/standard-libraries",
              label: "Standard Libraries",
            },
          ],
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
        {
          type: "doc",
          id: "reference/changelog",
          label: "Changelog",
        },
      ],
    },
  ],
};

export default sidebars;
