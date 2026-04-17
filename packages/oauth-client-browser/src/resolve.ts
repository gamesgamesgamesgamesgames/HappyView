import { ResolutionError } from "@happyview/oauth-client";

export interface DidDocument {
  id: string;
  service: Array<{
    id: string;
    type: string;
    serviceEndpoint: string;
  }>;
}

export interface AuthServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  pushed_authorization_request_endpoint?: string;
  dpop_signing_alg_values_supported?: string[];
}

export async function resolveHandleToDid(
  handle: string,
  fetchFn: typeof globalThis.fetch = globalThis.fetch,
): Promise<string> {
  try {
    const dnsUrl = `https://dns.google/dns-query?name=_atproto.${handle}&type=TXT`;
    const resp = await fetchFn(dnsUrl, {
      headers: { accept: "application/dns-json" },
    });
    if (resp.ok) {
      const data = await resp.json();
      const answers = (data as any).Answer ?? [];
      for (const answer of answers) {
        const txt = String(answer.data).replace(/^"|"$/g, "");
        if (txt.startsWith("did=")) {
          return txt.slice(4);
        }
      }
    }
  } catch {
    // DNS resolution failed, try HTTP fallback
  }

  const wellKnownUrl = `https://${handle}/.well-known/atproto-did`;
  const resp = await fetchFn(wellKnownUrl);
  if (!resp.ok) {
    throw new ResolutionError(`Failed to resolve handle ${handle}: ${resp.status}`);
  }
  const did = (await resp.text()).trim();
  if (!did.startsWith("did:")) {
    throw new ResolutionError(`Invalid DID from handle resolution: ${did}`);
  }
  return did;
}

export async function resolveDidDocument(
  did: string,
  fetchFn: typeof globalThis.fetch = globalThis.fetch,
): Promise<DidDocument> {
  let url: string;
  if (did.startsWith("did:plc:")) {
    url = `https://plc.directory/${did}`;
  } else if (did.startsWith("did:web:")) {
    const methodSpecific = did.slice("did:web:".length);
    const parts = methodSpecific.split(":");
    const host = decodeURIComponent(parts[0]);
    const path = parts.length > 1 ? "/" + parts.slice(1).map(decodeURIComponent).join("/") : "";
    url = `https://${host}${path}/.well-known/did.json`;
  } else {
    throw new ResolutionError(`Unsupported DID method: ${did}`);
  }

  const resp = await fetchFn(url);
  if (!resp.ok) {
    throw new ResolutionError(`Failed to resolve DID ${did}: ${resp.status}`);
  }
  return resp.json();
}

export function resolvePdsUrl(doc: DidDocument): string {
  for (const service of doc.service) {
    if (service.id === "#atproto_pds" || service.id.endsWith("#atproto_pds")) {
      return service.serviceEndpoint;
    }
  }
  throw new ResolutionError(`No #atproto_pds service found in DID document for ${doc.id}`);
}

export async function resolveAuthServerMetadata(
  pdsUrl: string,
  fetchFn: typeof globalThis.fetch = globalThis.fetch,
): Promise<AuthServerMetadata> {
  const url = `${pdsUrl.replace(/\/+$/, "")}/.well-known/oauth-authorization-server`;
  const resp = await fetchFn(url);
  if (!resp.ok) {
    throw new ResolutionError(`Failed to fetch auth server metadata from ${pdsUrl}: ${resp.status}`);
  }
  return resp.json();
}
