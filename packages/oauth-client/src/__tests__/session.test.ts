import { describe, expect, mock, test } from "bun:test";
import { HappyViewSession } from "../session";
import type { CryptoAdapter } from "../types";

const testCrypto: CryptoAdapter = {
  generatePkceVerifier: async () => "not-used",
  computePkceChallenge: async () => "not-used",
  signEs256: async (_key: JsonWebKey, payload: Uint8Array) => {
    return new Uint8Array(64);
  },
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

function createSession(overrides?: {
  instanceUrl?: string;
  fetchMock?: typeof globalThis.fetch;
}) {
  return new HappyViewSession({
    did: "did:plc:testuser",
    dpopKey: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
    accessToken: "test-access-token",
    clientKey: "hvc_testkey",
    instanceUrl: overrides?.instanceUrl ?? "https://happyview.example.com",
    crypto: testCrypto,
    fetch: overrides?.fetchMock,
  });
}

describe("HappyViewSession", () => {
  test("exposes did property", () => {
    const session = createSession();
    expect(session.did).toBe("did:plc:testuser");
  });

  test("fetchHandler prepends instanceUrl to relative paths", async () => {
    let capturedUrl: string | undefined;
    const fetchMock = mock(async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedUrl = input instanceof URL ? input.toString() : String(input);
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    });

    const session = createSession({ fetchMock });
    await session.fetchHandler(
      "/xrpc/com.example.test.getStuff?param=value",
      {},
    );

    expect(capturedUrl).toBe(
      "https://happyview.example.com/xrpc/com.example.test.getStuff?param=value",
    );
  });

  test("fetchHandler passes through absolute URLs without prepending", async () => {
    let capturedUrl: string | undefined;
    const fetchMock = mock(async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedUrl = input instanceof URL ? input.toString() : String(input);
      return new Response("{}", { status: 200 });
    });

    const session = createSession({ fetchMock });
    await session.fetchHandler(
      "https://other-service.example.com/xrpc/test.method",
      {},
    );

    expect(capturedUrl).toBe(
      "https://other-service.example.com/xrpc/test.method",
    );
  });

  test("fetchHandler adds Authorization DPoP header", async () => {
    let capturedInit: RequestInit | undefined;
    const fetchMock = mock(async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedInit = init;
      return new Response("{}", { status: 200 });
    });

    const session = createSession({ fetchMock });
    await session.fetchHandler("/xrpc/test.method", {});

    const headers = new Headers(capturedInit?.headers);
    expect(headers.get("authorization")).toBe("DPoP test-access-token");
  });

  test("fetchHandler adds DPoP proof header", async () => {
    let capturedInit: RequestInit | undefined;
    const fetchMock = mock(async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedInit = init;
      return new Response("{}", { status: 200 });
    });

    const session = createSession({ fetchMock });
    await session.fetchHandler("/xrpc/test.method", {});

    const headers = new Headers(capturedInit?.headers);
    const dpopHeader = headers.get("dpop");
    expect(dpopHeader).not.toBeNull();
    expect(dpopHeader!.split(".")).toHaveLength(3);
  });

  test("fetchHandler adds X-Client-Key header", async () => {
    let capturedInit: RequestInit | undefined;
    const fetchMock = mock(async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedInit = init;
      return new Response("{}", { status: 200 });
    });

    const session = createSession({ fetchMock });
    await session.fetchHandler("/xrpc/test.method", {});

    const headers = new Headers(capturedInit?.headers);
    expect(headers.get("x-client-key")).toBe("hvc_testkey");
  });

  test("fetchHandler preserves existing headers from init", async () => {
    let capturedInit: RequestInit | undefined;
    const fetchMock = mock(async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedInit = init;
      return new Response("{}", { status: 200 });
    });

    const session = createSession({ fetchMock });
    await session.fetchHandler("/xrpc/test.method", {
      headers: { "content-type": "application/json" },
    });

    const headers = new Headers(capturedInit?.headers);
    expect(headers.get("content-type")).toBe("application/json");
    expect(headers.get("authorization")).toBe("DPoP test-access-token");
  });

  test("fetchHandler stores DPoP-Nonce from response", async () => {
    let callCount = 0;
    const fetchMock = mock(async (input: RequestInfo | URL, init?: RequestInit) => {
      callCount++;
      const headers = new Headers();
      if (callCount === 1) {
        headers.set("dpop-nonce", "server-nonce-abc");
      }
      return new Response("{}", { status: 200, headers });
    });

    const session = createSession({ fetchMock });
    await session.fetchHandler("/xrpc/test.method", {});
    expect((session as any).dpopNonce).toBe("server-nonce-abc");
  });

  test("fetchHandler includes stored nonce in subsequent DPoP proofs", async () => {
    const capturedInits: RequestInit[] = [];
    let callCount = 0;
    const fetchMock = mock(async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedInits.push(init ?? {});
      callCount++;
      const headers = new Headers();
      if (callCount === 1) {
        headers.set("dpop-nonce", "server-nonce-xyz");
      }
      return new Response("{}", { status: 200, headers });
    });

    const session = createSession({ fetchMock });

    // First request — no nonce yet
    await session.fetchHandler("/xrpc/test.method", {});

    // Second request — should include nonce from first response
    await session.fetchHandler("/xrpc/test.method2", {});

    const firstDpop = new Headers(capturedInits[0].headers).get("dpop")!;
    const secondDpop = new Headers(capturedInits[1].headers).get("dpop")!;

    function base64urlDecode(str: string): Uint8Array {
      const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
      const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
      return Uint8Array.from(binary, (c) => c.charCodeAt(0));
    }

    const firstPayload = JSON.parse(
      new TextDecoder().decode(base64urlDecode(firstDpop.split(".")[1])),
    );
    const secondPayload = JSON.parse(
      new TextDecoder().decode(base64urlDecode(secondDpop.split(".")[1])),
    );

    expect(firstPayload.nonce).toBeUndefined();
    expect(secondPayload.nonce).toBe("server-nonce-xyz");
  });
});
