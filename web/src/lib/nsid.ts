export function nsidToDomain(nsid: string): string | null {
  const parts = nsid.split(".");
  if (parts.length < 3) return null;
  const authority = parts.slice(0, -1).reverse();
  return authority.join(".");
}

export interface ResolvedNsid {
  type: string | undefined;
  lexiconJson: Record<string, unknown> | undefined;
}

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";

/** Look up the lexicon-authority DID via the spec-defined DNS TXT record at
 *  `_lexicon.<authority>`. Browsers can't do raw DNS, so we use DNS-over-HTTPS.
 *  Returns `null` on any failure or missing record.
 */
async function lookupLexiconAuthorityDid(
  authority: string,
  signal: AbortSignal,
): Promise<string | null> {
  try {
    const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(`_lexicon.${authority}`)}&type=TXT`;
    const resp = await fetch(url, {
      signal,
      headers: { Accept: "application/dns-json" },
    });
    if (!resp.ok) return null;
    const data = (await resp.json()) as {
      Status?: number;
      Answer?: { type: number; data: string }[];
    };
    if (data.Status !== 0 || !Array.isArray(data.Answer)) return null;
    for (const a of data.Answer) {
      if (a.type !== 16) continue; // 16 = TXT
      // DoH returns TXT data as a JSON string with surrounding quotes.
      const raw = String(a.data || "").replace(/^"|"$/g, "");
      const m = /did=([^\s"]+)/.exec(raw);
      if (m) return m[1];
    }
  } catch (e) {
    if (signal.aborted) return null;
  }
  return null;
}

/** Resolve the PDS endpoint for a DID via plc.directory. */
async function resolvePdsForDid(
  did: string,
  signal: AbortSignal,
): Promise<string | null> {
  try {
    const resp = await fetch(
      `https://plc.directory/${encodeURIComponent(did)}`,
      { signal },
    );
    if (resp.ok) {
      const doc = (await resp.json()) as {
        service?: { id: string; serviceEndpoint: string }[];
      };
      return (
        doc.service?.find((s) => s.id === "#atproto_pds")?.serviceEndpoint ??
        null
      );
    }
  } catch (e) {
    if (signal.aborted) return null;
  }
  return null;
}

/** Fetch the `com.atproto.lexicon.schema` record for an NSID from a PDS. */
async function fetchLexiconRecord(
  did: string,
  pdsEndpoint: string,
  nsid: string,
  signal: AbortSignal,
): Promise<ResolvedNsid> {
  const empty: ResolvedNsid = { type: undefined, lexiconJson: undefined };
  try {
    const resp = await fetch(
      `${pdsEndpoint}/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(did)}&collection=com.atproto.lexicon.schema&rkey=${encodeURIComponent(nsid)}`,
      { signal },
    );
    if (resp.ok) {
      const data = (await resp.json()) as {
        value?: Record<string, unknown>;
      };
      const value = data.value;
      const mainType = (
        value?.defs as Record<string, Record<string, unknown>> | undefined
      )?.main?.type as string | undefined;
      return { type: mainType, lexiconJson: value };
    }
  } catch {
    // Best-effort
  }
  return empty;
}

/** Try a (did → PDS → record) chain. Returns the resolved lexicon, or null
 *  if any step fails or the PDS doesn't have the record. */
async function tryWithDid(
  did: string,
  nsid: string,
  signal: AbortSignal,
): Promise<ResolvedNsid | null> {
  if (signal.aborted) return null;
  const pds = await resolvePdsForDid(did, signal);
  if (!pds) return null;
  const result = await fetchLexiconRecord(did, pds, nsid, signal);
  return result.lexiconJson ? result : null;
}

/**
 * Resolve a lexicon NSID to its published `com.atproto.lexicon.schema`
 * record on the network.
 *
 * Tries two flows in order:
 *
 *  1. **Existing handle-based flow** — `https://<authority>/.well-known/
 *     atproto-did` (with a fallback to `bsky.social` `resolveHandle`) → DID
 *     → PDS → lexicon record. Works when the authority's handle owner also
 *     hosts the lexicon (common for community lexicons).
 *
 *  2. **Spec-defined DoH extension** — DNS-over-HTTPS query for
 *     `_lexicon.<authority>` TXT (per the atproto Lexicon spec) → DID →
 *     PDS → lexicon record. Required for authorities that delegate lexicon
 *     hosting to a separate account (e.g. Bluesky's permission-sets are at
 *     `did:plc:4v4y5r3lwsbtmsxhile2ljac`, NOT the bsky.app handle DID).
 *
 * Returns `{ type, lexiconJson }` from whichever flow finds a record, or
 * `{ undefined, undefined }` if neither does.
 */
export async function resolveNsid(
  nsid: string,
  signal: AbortSignal,
): Promise<ResolvedNsid> {
  const empty: ResolvedNsid = { type: undefined, lexiconJson: undefined };
  const domain = nsidToDomain(nsid);
  if (!domain) return empty;

  // 1. Existing flow: handle-based DID resolution.
  let handleDid: string | undefined;
  try {
    const resp = await fetch(`https://${domain}/.well-known/atproto-did`, {
      signal,
    });
    if (resp.ok) handleDid = (await resp.text()).trim();
  } catch {
    if (signal.aborted) return empty;
  }
  if (!handleDid) {
    try {
      const resp = await fetch(
        `https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(domain)}`,
        { signal },
      );
      if (resp.ok) {
        const data = (await resp.json()) as { did?: string };
        handleDid = data.did;
      }
    } catch {
      if (signal.aborted) return empty;
    }
  }
  if (handleDid) {
    const result = await tryWithDid(handleDid, nsid, signal);
    if (result) return result;
  }
  if (signal.aborted) return empty;

  // 2. Extension: DoH-based DNS TXT lookup at `_lexicon.<authority>`.
  // This is the spec-defined lexicon-authority resolution mechanism, and
  // is required for authorities (like bsky.app) that delegate lexicon
  // hosting to a separate DID from the handle holder.
  const lexAuthorityDid = await lookupLexiconAuthorityDid(domain, signal);
  if (lexAuthorityDid && lexAuthorityDid !== handleDid) {
    const result = await tryWithDid(lexAuthorityDid, nsid, signal);
    if (result) return result;
  }

  return empty;
}
