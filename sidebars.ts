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
              label: "Other",
            },
          ],
        },
        {
          type: "doc",
          id: "getting-started/authentication",
          label: "Authentication",
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
          id: "guides/lexicons",
          label: "Lexicons",
        },
        {
          type: "doc",
          id: "guides/scripting",
          label: "Lua Scripting",
        },
        {
          type: "doc",
          id: "guides/backfill",
          label: "Backfill",
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
          id: "reference/production-deployment",
          label: "Production",
        },
      ],
    },
  ],
};

export default sidebars;
