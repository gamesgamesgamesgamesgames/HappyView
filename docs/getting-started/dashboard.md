# Dashboard

HappyView ships with a web dashboard that provides a visual interface for everything the [admin API](../reference/admin-api.md) offers: managing lexicons, viewing indexed records, and monitoring backfill jobs. It runs as a separate Next.js application alongside the Rust backend.

## Logging in for the first time

The dashboard uses AT Protocol OAuth via AIP. If no admins exist in the database yet, the first authenticated request to any admin endpoint automatically bootstraps that user as an admin.

## Adding a lexicon

Navigate to **Lexicons > Add Lexicon** and choose **Local** or **Network**.

**Local** lexicons are defined by you. The editor shows two side-by-side panels (stacked on mobile):

- **Lexicon JSON** (left): define your lexicon schema
- **Lua Script** (right): write the handler for query/procedure types

The Lua panel only appears when the lexicon's `defs.main.type` is `query` or `procedure`. For record-type lexicons, only the JSON panel is shown.

A default Lua script is auto-generated when you first set the type to query or procedure. The template updates automatically when the type changes, but once you manually edit the script your changes are preserved.

Toggle **Enable backfill** to index historical records when uploading a record-type lexicon.

**Network** lexicons are fetched from the AT Protocol network. Enter an NSID (e.g. `xyz.statusphere.status`) and HappyView resolves the schema automatically. If found, the lexicon JSON is displayed in a read-only editor. Click **Add** to track it. Network lexicons are kept up to date via Tap. See [Lexicons - Network lexicons](../guides/lexicons.md#network-lexicons) for how resolution works.

### JSON editor

The JSON editor provides real-time validation against the AT Protocol Lexicon v1 schema:

- Validation for Lexicon format
- Auto-complete for definition types (`record`, `query`, `procedure`, `subscription`), property types (`string`, `integer`, `boolean`, `ref`, `union`, `blob`, `cid-link`, etc.), and schema structure (`defs`, `main`, `properties`, `required`)
- Enforces the required top-level shape: `lexicon`, `id`, and `defs.main`

### Lua editor

The Lua editor provides context-aware code completions, including suggestions for the `Record`, `db`, `input`, and `params` APIs as well as Lua keywords, builtins, and standard library functions. It also offers snippet templates for common constructs like `if`, `for`, and `function`.

See [Lua Scripting](../guides/scripting.md) for the full runtime reference and examples.
