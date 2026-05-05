/**
 * ATProtocol OAuth scope grammar — pure parse / serialize / describe utilities.
 *
 * The wire format is a space-separated list of scope tokens.  The first token
 * MUST be `atproto`.  See `docs/scope-builder-requirements.md` for the full
 * grammar reference; this module is the canonical encoder / decoder used by
 * the in-app scope builder.
 *
 * No I/O, no React.  Easy to unit-test.
 */

export type RepoAction = "create" | "update" | "delete";
export type AccountAttr = "email" | "repo";
export type AccountAction = "read" | "manage";
export type HandleAttr = "handle" | "*";
export type TransitionValue = "generic" | "chat.bsky" | "email";

export type Permission =
  | { kind: "base" }
  | { kind: "permission-set"; nsid: string; aud?: string }
  | { kind: "repo"; collections: string[]; actions?: RepoAction[] }
  | { kind: "rpc"; lxms: string[]; aud?: string }
  | { kind: "blob"; accept: string }
  | { kind: "account"; attr: AccountAttr; action?: AccountAction }
  | { kind: "handle"; attr: HandleAttr }
  | { kind: "transition"; value: TransitionValue }
  | { kind: "unknown"; raw: string };

const REPO_ACTIONS: ReadonlySet<string> = new Set([
  "create",
  "update",
  "delete",
]);
const ACCOUNT_ATTRS: ReadonlySet<string> = new Set(["email", "repo"]);
const ACCOUNT_ACTIONS: ReadonlySet<string> = new Set(["read", "manage"]);
const HANDLE_ATTRS: ReadonlySet<string> = new Set(["handle", "*"]);
const TRANSITION_VALUES: ReadonlySet<string> = new Set([
  "generic",
  "chat.bsky",
  "email",
]);

/**
 * Validates an NSID-shaped value used inside a scope.
 *
 * - Whole-segment wildcard `*` is allowed.
 * - Partial wildcards (e.g. `app.bsky.*`) are NOT allowed per spec.
 * - We use a relaxed NSID character check; full NSID validity is enforced
 *   server-side and by the lexicon registry.
 */
export function isValidNsid(value: string): boolean {
  if (!value) return false;
  if (value === "*") return true;
  if (value.includes("*")) return false;
  // Relaxed NSID: dotted segments starting with a letter.
  return /^[a-zA-Z][a-zA-Z0-9-]*(\.[a-zA-Z][a-zA-Z0-9-]*)*$/.test(value);
}

/**
 * Parses a space-separated scope string into structured Permission objects.
 *
 * Tolerant of unknown tokens — they are preserved as `{ kind: "unknown" }`
 * so a round-trip through the editor never silently drops data.  The
 * leading `atproto` is always emitted as `{ kind: "base" }` (added if
 * missing from the input).
 */
export function parseScope(input: string): Permission[] {
  const tokens = (input ?? "").split(/\s+/).filter(Boolean);
  const out: Permission[] = [{ kind: "base" }];
  let sawBase = false;

  for (const token of tokens) {
    if (token === "atproto") {
      sawBase = true;
      continue;
    }
    const parsed = parseToken(token);
    out.push(parsed);
  }

  // We always include base.  If the input had it we just used the flag.
  void sawBase;
  return out;
}

function parseToken(token: string): Permission {
  // Split into prefix (everything before the first `?`) and query string.
  const qIdx = token.indexOf("?");
  const prefix = qIdx === -1 ? token : token.slice(0, qIdx);
  const queryStr = qIdx === -1 ? "" : token.slice(qIdx + 1);
  const params = new URLSearchParams(queryStr);

  // The prefix is either `<kind>` or `<kind>:<path>`.
  const colon = prefix.indexOf(":");
  const kind = colon === -1 ? prefix : prefix.slice(0, colon);
  const path = colon === -1 ? "" : prefix.slice(colon + 1);

  switch (kind) {
    case "include": {
      if (!path) return { kind: "unknown", raw: token };
      const aud = params.get("aud") ?? undefined;
      return aud
        ? { kind: "permission-set", nsid: path, aud }
        : { kind: "permission-set", nsid: path };
    }
    case "repo": {
      const collections: string[] = [];
      if (path) collections.push(path);
      for (const c of params.getAll("collection")) collections.push(c);
      const actionVals = params.getAll("action").filter((a) =>
        REPO_ACTIONS.has(a),
      ) as RepoAction[];
      if (collections.length === 0) {
        // No collection — round-trip as unknown rather than fabricate one.
        return { kind: "unknown", raw: token };
      }
      const perm: Permission = { kind: "repo", collections };
      if (actionVals.length) perm.actions = actionVals;
      return perm;
    }
    case "rpc": {
      const lxms: string[] = [];
      if (path) lxms.push(path);
      for (const l of params.getAll("lxm")) lxms.push(l);
      const aud = params.get("aud") ?? undefined;
      if (lxms.length === 0 && !aud) {
        return { kind: "unknown", raw: token };
      }
      return aud ? { kind: "rpc", lxms, aud } : { kind: "rpc", lxms };
    }
    case "blob": {
      if (!path) return { kind: "unknown", raw: token };
      return { kind: "blob", accept: path };
    }
    case "account": {
      if (!ACCOUNT_ATTRS.has(path)) return { kind: "unknown", raw: token };
      const action = params.get("action");
      if (action && !ACCOUNT_ACTIONS.has(action)) {
        return { kind: "unknown", raw: token };
      }
      return action
        ? {
            kind: "account",
            attr: path as AccountAttr,
            action: action as AccountAction,
          }
        : { kind: "account", attr: path as AccountAttr };
    }
    case "identity": {
      if (!HANDLE_ATTRS.has(path)) return { kind: "unknown", raw: token };
      return { kind: "handle", attr: path as HandleAttr };
    }
    case "transition": {
      if (!TRANSITION_VALUES.has(path)) return { kind: "unknown", raw: token };
      return { kind: "transition", value: path as TransitionValue };
    }
    default:
      return { kind: "unknown", raw: token };
  }
}

/**
 * Serializes a list of Permissions back into a space-separated scope string.
 * Always begins with `atproto`.  Preserves order, deduplicates exact matches.
 */
export function serializeScope(perms: Permission[]): string {
  const tokens: string[] = [];
  const seen = new Set<string>();
  let baseEmitted = false;

  for (const p of perms) {
    const tok = serializeOne(p);
    if (tok === null) continue;
    if (tok === "atproto") {
      if (baseEmitted) continue;
      baseEmitted = true;
    }
    if (seen.has(tok)) continue;
    seen.add(tok);
    tokens.push(tok);
  }

  // Always lead with `atproto`.
  if (!baseEmitted) {
    tokens.unshift("atproto");
  } else {
    // Move atproto to front if it isn't already.
    const idx = tokens.indexOf("atproto");
    if (idx > 0) {
      tokens.splice(idx, 1);
      tokens.unshift("atproto");
    }
  }
  return tokens.join(" ");
}

function serializeOne(p: Permission): string | null {
  switch (p.kind) {
    case "base":
      return "atproto";
    case "permission-set": {
      if (!p.nsid) return null;
      const params = new URLSearchParams();
      if (p.aud) params.set("aud", p.aud);
      const tail = params.toString();
      return tail ? `include:${p.nsid}?${decodeParams(tail)}` : `include:${p.nsid}`;
    }
    case "repo": {
      const cols = p.collections.filter(Boolean);
      if (cols.length === 0) return null;
      const actions = p.actions ?? [];
      if (cols.length === 1) {
        const params = new URLSearchParams();
        for (const a of actions) params.append("action", a);
        const tail = params.toString();
        return tail ? `repo:${cols[0]}?${decodeParams(tail)}` : `repo:${cols[0]}`;
      }
      const params = new URLSearchParams();
      for (const c of cols) params.append("collection", c);
      for (const a of actions) params.append("action", a);
      return `repo?${decodeParams(params.toString())}`;
    }
    case "rpc": {
      const lxms = p.lxms.filter(Boolean);
      if (lxms.length === 0 && !p.aud) return null;
      if (lxms.length === 1 && p.aud === undefined) {
        return `rpc:${lxms[0]}`;
      }
      if (lxms.length === 1 && p.aud !== undefined) {
        const params = new URLSearchParams();
        params.set("aud", p.aud);
        return `rpc:${lxms[0]}?${decodeParams(params.toString())}`;
      }
      // 0 lxms with aud, OR 2+ lxms (with or without aud)
      const params = new URLSearchParams();
      for (const l of lxms) params.append("lxm", l);
      if (p.aud !== undefined) params.set("aud", p.aud);
      return `rpc?${decodeParams(params.toString())}`;
    }
    case "blob":
      return p.accept ? `blob:${p.accept}` : null;
    case "account": {
      if (p.action) {
        const params = new URLSearchParams();
        params.set("action", p.action);
        return `account:${p.attr}?${decodeParams(params.toString())}`;
      }
      return `account:${p.attr}`;
    }
    case "handle":
      return `identity:${p.attr}`;
    case "transition":
      return `transition:${p.value}`;
    case "unknown":
      return p.raw || null;
  }
}

/**
 * URLSearchParams.toString() percent-encodes characters like `:`, `*`, and
 * `/` that are perfectly valid in atproto scope tokens and that the spec
 * leaves unencoded.  The reference scope builder emits unencoded values
 * (e.g. `repo:app.bsky.feed.post?action=create`, `blob:image/*`,
 * `aud=did:web:api.bsky.app`), so we walk it back to match.
 */
function decodeParams(params: string): string {
  return params
    .replace(/%3A/gi, ":")
    .replace(/%2A/gi, "*")
    .replace(/%2F/gi, "/")
    .replace(/%23/gi, "#");
}

/**
 * Produces a one-line, human-readable description of a Permission for the
 * "Added Permissions" list.
 */
export function describePermission(p: Permission): string {
  switch (p.kind) {
    case "base":
      return "Base scope (required for all atproto OAuth sessions)";
    case "permission-set":
      return p.aud
        ? `Include permission set ${p.nsid} (audience ${p.aud})`
        : `Include permission set ${p.nsid}`;
    case "repo": {
      const cols =
        p.collections.length === 1
          ? p.collections[0] === "*"
            ? "all collections"
            : p.collections[0]
          : `[${p.collections.join(", ")}]`;
      const verb = p.actions?.length
        ? p.actions.join("/")
        : "any action on";
      return p.actions?.length
        ? `${verb} records in ${cols}`
        : `${verb} records in ${cols}`;
    }
    case "rpc": {
      const methods =
        p.lxms.length === 0
          ? "any method"
          : p.lxms.length === 1
            ? p.lxms[0] === "*"
              ? "any method"
              : p.lxms[0]
            : `[${p.lxms.join(", ")}]`;
      return p.aud
        ? p.aud === "*"
          ? `Call ${methods} on any service`
          : `Call ${methods} on ${p.aud}`
        : `Call ${methods}`;
    }
    case "blob":
      return `Upload blobs of type ${p.accept}`;
    case "account":
      if (p.action === "manage") return `Manage account ${p.attr}`;
      return p.attr === "email"
        ? "Access account email"
        : "Access repository configuration";
    case "handle":
      return p.attr === "*"
        ? "Manage all identity attributes"
        : "Manage handle";
    case "transition":
      switch (p.value) {
        case "generic":
          return "Transitional generic access (legacy app password)";
        case "chat.bsky":
          return "Transitional access to chat.bsky lexicons";
        case "email":
          return "Transitional access to account email";
      }
      return "";
    case "unknown":
      return `Unknown scope token (lexicon may have been removed)`;
  }
}

/**
 * Validation helper used by the form tabs.  Returns `null` if the
 * permission is valid, or a human-readable error message.
 */
export function validatePermission(p: Permission): string | null {
  switch (p.kind) {
    case "base":
      return null;
    case "permission-set":
      if (!p.nsid) return "Permission set NSID is required.";
      if (!isValidNsid(p.nsid)) return `Invalid NSID: ${p.nsid}.`;
      return null;
    case "repo": {
      if (p.collections.length === 0)
        return "Add at least one collection.";
      for (const c of p.collections) {
        if (!isValidNsid(c)) return `Invalid collection NSID: ${c}.`;
      }
      return null;
    }
    case "rpc": {
      if (p.lxms.length === 0 && !p.aud)
        return "Provide at least one LXM or an audience.";
      const allLxmStar = p.lxms.length > 0 && p.lxms.every((l) => l === "*");
      if (allLxmStar && p.aud === "*") {
        return "Both LXM and Audience cannot be * simultaneously.";
      }
      for (const l of p.lxms) {
        if (!isValidNsid(l)) return `Invalid lexicon method NSID: ${l}.`;
      }
      return null;
    }
    case "blob":
      return p.accept ? null : "Accept MIME type is required.";
    case "account":
      return p.attr ? null : "Attribute is required.";
    case "handle":
      return p.attr ? null : "Attribute is required.";
    case "transition":
      return p.value ? null : "Scope is required.";
    case "unknown":
      return null;
  }
}

/**
 * Convenience: `value -> serializeScope(parseScope(value))`.  Useful for
 * normalizing user input.
 */
export function normalizeScope(input: string): string {
  return serializeScope(parseScope(input));
}
