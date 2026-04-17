import { describe, expect, mock, test } from "bun:test";
import { HappyViewOAuthClient } from "../client";
import { ApiError } from "../errors";
import { MemoryStorage } from "../storage";
import type { CryptoAdapter } from "../types";

const testCrypto: CryptoAdapter = {
  generatePkceVerifier: async () => "test-verifier-1234567890",
  computePkceChallenge: async (v: string) => `challenge-of-${v}`,
  signEs256: async () => new Uint8Array(64),
  sha256: async (data: Uint8Array) => {
    const hash = await crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(hash);
  },
  getRandomValues: (length: number) => {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  },
};

function createMockFetch(responses: Array<{ status: number; body: unknown }>) {
  let callIndex = 0;
  const calls: Array<{ url: string; init: RequestInit }> = [];

  const fetchFn = mock(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input instanceof URL ? input.toString() : String(input);
    calls.push({ url, init: init ?? {} });
    const resp = responses[callIndex] ?? { status: 500, body: { error: "no more mocked responses" } };
    callIndex++;
    return new Response(JSON.stringify(resp.body), { status: resp.status });
  });

  return { fetchFn, calls };
}

function createClient(overrides?: {
  fetchFn?: typeof globalThis.fetch;
  clientSecret?: string;
  storage?: MemoryStorage;
}) {
  return new HappyViewOAuthClient({
    instanceUrl: "https://happyview.example.com",
    clientKey: "hvc_testkey",
    clientSecret: overrides?.clientSecret,
    crypto: testCrypto,
    storage: overrides?.storage ?? new MemoryStorage(),
    fetch: overrides?.fetchFn,
  });
}

describe("HappyViewOAuthClient", () => {
  describe("provisionDpopKey", () => {
    test("calls POST /oauth/dpop-keys with client credentials in headers", async () => {
      const { fetchFn, calls } = createMockFetch([
        {
          status: 201,
          body: {
            provision_id: "hvp_abc123",
            dpop_key: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
          },
        },
      ]);

      const client = createClient({ fetchFn, clientSecret: "hvs_secret" });
      const result = await client.provisionDpopKey();

      expect(calls[0].url).toBe("https://happyview.example.com/oauth/dpop-keys");
      const headers = new Headers(calls[0].init.headers);
      expect(headers.get("x-client-key")).toBe("hvc_testkey");
      expect(headers.get("x-client-secret")).toBe("hvs_secret");
      expect(result.provisionId).toBe("hvp_abc123");
      expect(result.dpopKey.kty).toBe("EC");
    });

    test("includes PKCE challenge for public clients and returns verifier", async () => {
      const { fetchFn, calls } = createMockFetch([
        {
          status: 201,
          body: {
            provision_id: "hvp_public",
            dpop_key: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
          },
        },
      ]);

      const client = createClient({ fetchFn });
      const result = await client.provisionDpopKey();

      const body = JSON.parse(calls[0].init.body as string);
      expect(body.pkce_challenge).toBe("challenge-of-test-verifier-1234567890");
      expect(result.pkceVerifier).toBe("test-verifier-1234567890");
    });

    test("does not include PKCE for confidential clients", async () => {
      const { fetchFn, calls } = createMockFetch([
        {
          status: 201,
          body: {
            provision_id: "hvp_conf",
            dpop_key: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
          },
        },
      ]);

      const client = createClient({ fetchFn, clientSecret: "hvs_sec" });
      const result = await client.provisionDpopKey();

      const body = JSON.parse(calls[0].init.body as string);
      expect(body.pkce_challenge).toBeUndefined();
      expect(result.pkceVerifier).toBeUndefined();
    });

    test("throws ApiError on non-201 response", async () => {
      const { fetchFn } = createMockFetch([
        { status: 400, body: { message: "bad request" } },
      ]);

      const client = createClient({ fetchFn });
      try {
        await client.provisionDpopKey();
        expect(true).toBe(false); // should not reach
      } catch (err) {
        expect(err).toBeInstanceOf(ApiError);
        expect((err as ApiError).status).toBe(400);
        expect((err as ApiError).body).toEqual({ message: "bad request" });
      }
    });
  });

  describe("registerSession", () => {
    test("calls POST /oauth/sessions and returns a HappyViewSession", async () => {
      const { fetchFn, calls } = createMockFetch([
        {
          status: 201,
          body: { session_id: "sess_123", did: "did:plc:testuser" },
        },
      ]);

      const storage = new MemoryStorage();
      const client = createClient({ fetchFn, clientSecret: "hvs_sec", storage });
      const session = await client.registerSession({
        provisionId: "hvp_abc",
        did: "did:plc:testuser",
        accessToken: "at_token",
        scopes: "atproto",
        dpopKey: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
      });

      expect(calls[0].url).toBe("https://happyview.example.com/oauth/sessions");
      expect(session.did).toBe("did:plc:testuser");
    });

    test("persists session and last active DID to storage", async () => {
      const { fetchFn } = createMockFetch([
        {
          status: 201,
          body: { session_id: "sess_123", did: "did:plc:testuser" },
        },
      ]);

      const storage = new MemoryStorage();
      const client = createClient({ fetchFn, clientSecret: "hvs_sec", storage });
      await client.registerSession({
        provisionId: "hvp_abc",
        did: "did:plc:testuser",
        accessToken: "at_token",
        scopes: "atproto",
        dpopKey: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
      });

      const stored = await storage.get("happyview:session:did:plc:testuser");
      expect(stored).not.toBeNull();
      const parsed = JSON.parse(stored!);
      expect(parsed.did).toBe("did:plc:testuser");
      expect(parsed.accessToken).toBe("at_token");

      const lastActive = await storage.get("happyview:last-active-did");
      expect(lastActive).toBe("did:plc:testuser");
    });
  });

  describe("deleteSession", () => {
    test("calls DELETE /oauth/sessions/:did", async () => {
      const { fetchFn, calls } = createMockFetch([
        { status: 204, body: null },
      ]);

      const storage = new MemoryStorage();
      await storage.set("happyview:session:did:plc:testuser", JSON.stringify({ did: "did:plc:testuser" }));
      await storage.set("happyview:last-active-did", "did:plc:testuser");

      const client = createClient({ fetchFn, clientSecret: "hvs_sec", storage });
      await client.deleteSession("did:plc:testuser");

      expect(calls[0].url).toBe("https://happyview.example.com/oauth/sessions/did:plc:testuser");
      expect(calls[0].init.method).toBe("DELETE");
    });

    test("clears session and last active DID from storage", async () => {
      const { fetchFn } = createMockFetch([{ status: 204, body: null }]);

      const storage = new MemoryStorage();
      await storage.set("happyview:session:did:plc:testuser", JSON.stringify({ did: "did:plc:testuser" }));
      await storage.set("happyview:last-active-did", "did:plc:testuser");

      const client = createClient({ fetchFn, clientSecret: "hvs_sec", storage });
      await client.deleteSession("did:plc:testuser");

      expect(await storage.get("happyview:session:did:plc:testuser")).toBeNull();
      expect(await storage.get("happyview:last-active-did")).toBeNull();
    });

    test("preserves last active DID when deleting a different session", async () => {
      const { fetchFn } = createMockFetch([{ status: 204, body: null }]);

      const storage = new MemoryStorage();
      await storage.set("happyview:session:did:plc:other", JSON.stringify({ did: "did:plc:other" }));
      await storage.set("happyview:last-active-did", "did:plc:testuser");

      const client = createClient({ fetchFn, clientSecret: "hvs_sec", storage });
      await client.deleteSession("did:plc:other");

      expect(await storage.get("happyview:session:did:plc:other")).toBeNull();
      expect(await storage.get("happyview:last-active-did")).toBe("did:plc:testuser");
    });
  });

  describe("restoreSession", () => {
    test("returns null when no session in storage", async () => {
      const client = createClient();
      const session = await client.restoreSession("did:plc:nobody");
      expect(session).toBeNull();
    });

    test("restores session from storage", async () => {
      const storage = new MemoryStorage();
      await storage.set(
        "happyview:session:did:plc:testuser",
        JSON.stringify({
          did: "did:plc:testuser",
          dpopKey: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
          accessToken: "at_stored",
          clientKey: "hvc_testkey",
          instanceUrl: "https://happyview.example.com",
        }),
      );

      const client = createClient({ storage });
      const session = await client.restoreSession("did:plc:testuser");
      expect(session).not.toBeNull();
      expect(session!.did).toBe("did:plc:testuser");
    });
  });

  describe("restore", () => {
    test("returns null when no last active DID", async () => {
      const client = createClient();
      const session = await client.restore();
      expect(session).toBeNull();
    });

    test("restores last active session", async () => {
      const storage = new MemoryStorage();
      await storage.set("happyview:last-active-did", "did:plc:testuser");
      await storage.set(
        "happyview:session:did:plc:testuser",
        JSON.stringify({
          did: "did:plc:testuser",
          dpopKey: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
          accessToken: "at_stored",
          clientKey: "hvc_testkey",
          instanceUrl: "https://happyview.example.com",
        }),
      );

      const client = createClient({ storage });
      const session = await client.restore();
      expect(session).not.toBeNull();
      expect(session!.did).toBe("did:plc:testuser");
    });
  });
});
