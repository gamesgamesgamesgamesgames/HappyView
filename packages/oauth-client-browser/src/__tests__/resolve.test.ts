import { describe, expect, mock, test } from "bun:test";
import { ResolutionError } from "@happyview/oauth-client";
import {
  resolveAuthServerMetadata,
  resolveDidDocument,
  resolveHandleToDid,
  resolvePdsUrl,
} from "../resolve";

function mockFetch(responses: Record<string, { status: number; body: unknown }>) {
  return mock(async (input: RequestInfo | URL) => {
    const url = input instanceof URL ? input.toString() : String(input);
    for (const [pattern, resp] of Object.entries(responses)) {
      if (url.includes(pattern)) {
        return new Response(JSON.stringify(resp.body), { status: resp.status });
      }
    }
    return new Response("not found", { status: 404 });
  });
}

describe("resolveHandleToDid", () => {
  test("resolves via DNS-over-HTTPS", async () => {
    const fetchFn = mockFetch({
      "dns-query": {
        status: 200,
        body: {
          Answer: [
            { name: "_atproto.user.bsky.social.", type: 16, data: '"did=did:plc:abc123"' },
          ],
        },
      },
    });
    const did = await resolveHandleToDid("user.bsky.social", fetchFn);
    expect(did).toBe("did:plc:abc123");
  });

  test("falls back to HTTP .well-known", async () => {
    const fn = mock(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("dns-query")) {
        return new Response(JSON.stringify({ Answer: [] }), { status: 200 });
      }
      if (url.includes(".well-known/atproto-did")) {
        return new Response("did:plc:fallback", { status: 200 });
      }
      return new Response("not found", { status: 404 });
    });
    const did = await resolveHandleToDid("user.example.com", fn);
    expect(did).toBe("did:plc:fallback");
  });
});

describe("resolveDidDocument", () => {
  test("resolves did:plc via plc.directory", async () => {
    const fetchFn = mockFetch({
      "plc.directory/did:plc:abc": {
        status: 200,
        body: {
          id: "did:plc:abc",
          service: [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: "https://pds.example.com" }],
        },
      },
    });
    const doc = await resolveDidDocument("did:plc:abc", fetchFn);
    expect(doc.id).toBe("did:plc:abc");
  });

  test("resolves did:web via .well-known", async () => {
    const fetchFn = mockFetch({
      "example.com/.well-known/did.json": {
        status: 200,
        body: { id: "did:web:example.com", service: [] },
      },
    });
    const doc = await resolveDidDocument("did:web:example.com", fetchFn);
    expect(doc.id).toBe("did:web:example.com");
  });

  test("resolves multi-segment did:web with path", async () => {
    const fetchFn = mockFetch({
      "example.com/path/to/resource/.well-known/did.json": {
        status: 200,
        body: { id: "did:web:example.com:path:to:resource", service: [] },
      },
    });
    const doc = await resolveDidDocument("did:web:example.com:path:to:resource", fetchFn);
    expect(doc.id).toBe("did:web:example.com:path:to:resource");
  });
});

describe("resolvePdsUrl", () => {
  test("extracts PDS URL from DID document", () => {
    const doc = {
      id: "did:plc:abc",
      service: [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: "https://pds.example.com" }],
    };
    expect(resolvePdsUrl(doc)).toBe("https://pds.example.com");
  });

  test("throws ResolutionError when no PDS service found", () => {
    const doc = { id: "did:plc:abc", service: [] };
    try {
      resolvePdsUrl(doc);
      expect(true).toBe(false);
    } catch (err) {
      expect(err).toBeInstanceOf(ResolutionError);
    }
  });
});

describe("resolveAuthServerMetadata", () => {
  test("fetches .well-known/oauth-authorization-server from PDS", async () => {
    const fetchFn = mockFetch({
      "pds.example.com/.well-known/oauth-authorization-server": {
        status: 200,
        body: {
          issuer: "https://pds.example.com",
          authorization_endpoint: "https://pds.example.com/oauth/authorize",
          token_endpoint: "https://pds.example.com/oauth/token",
          pushed_authorization_request_endpoint: "https://pds.example.com/oauth/par",
        },
      },
    });
    const meta = await resolveAuthServerMetadata("https://pds.example.com", fetchFn);
    expect(meta.authorization_endpoint).toBe("https://pds.example.com/oauth/authorize");
    expect(meta.token_endpoint).toBe("https://pds.example.com/oauth/token");
  });
});
