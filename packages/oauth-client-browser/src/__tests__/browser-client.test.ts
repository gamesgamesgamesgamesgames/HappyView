import { afterEach, beforeAll, describe, expect, mock, test } from "bun:test";
import {
  InvalidStateError,
  TokenExchangeError,
  type StorageAdapter,
} from "@happyview/oauth-client";
import {
  HappyViewBrowserClient,
  LoginContinuedInParentWindowError,
} from "../browser-client";
import { LocalStorageAdapter } from "../local-storage-adapter";

// Generate a real ES256 JWK once for all tests that need importJwk to succeed
let testJwk: JsonWebKey;
beforeAll(async () => {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  testJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  delete testJwk.key_ops;
});

afterEach(() => {
  localStorage.clear();
});

function createClient(fetchFn?: typeof globalThis.fetch) {
  return new HappyViewBrowserClient({
    instanceUrl: "https://happyview.example.com",
    clientId: "https://example.com/oauth-client-metadata.json",
    clientKey: "hvc_test",
    storage: new LocalStorageAdapter(),
    fetch: fetchFn,
  });
}

function mockFetchForFullFlow() {
  return mock(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);

    if (url.includes("dns.google")) {
      return new Response(
        JSON.stringify({
          Status: 0,
          Answer: [
            {
              name: "_atproto.user.bsky.social.",
              type: 16,
              TTL: 300,
              data: '"did=did:plc:abcdefghijklmnopqrstuvwx"',
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/dns-json" } },
      );
    }

    if (url.includes("plc.directory")) {
      return new Response(
        JSON.stringify({
          id: "did:plc:abcdefghijklmnopqrstuvwx",
          service: [
            {
              id: "#atproto_pds",
              type: "AtprotoPersonalDataServer",
              serviceEndpoint: "https://pds.example.com",
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }

    if (url.includes(".well-known/oauth-protected-resource")) {
      return new Response(
        JSON.stringify({
          authorization_servers: ["https://pds.example.com"],
        }),
        { status: 200 },
      );
    }

    if (url.includes(".well-known/oauth-authorization-server")) {
      return new Response(
        JSON.stringify({
          issuer: "https://pds.example.com",
          authorization_endpoint: "https://pds.example.com/oauth/authorize",
          token_endpoint: "https://pds.example.com/oauth/token",
          pushed_authorization_request_endpoint:
            "https://pds.example.com/oauth/par",
        }),
        { status: 200 },
      );
    }

    if (url.includes("/oauth/dpop-keys")) {
      return new Response(
        JSON.stringify({
          provision_id: "hvp_test123",
          dpop_key: testJwk,
        }),
        { status: 201 },
      );
    }

    if (url.includes("/oauth/par")) {
      return new Response(
        JSON.stringify({
          request_uri: "urn:ietf:params:oauth:request_uri:test",
          expires_in: 60,
        }),
        { status: 201 },
      );
    }

    if (url.includes("/oauth/sessions") && init?.method === "POST") {
      return new Response(
        JSON.stringify({
          session_id: "sess_test",
          did: "did:plc:abcdefghijklmnopqrstuvwx",
        }),
        { status: 201 },
      );
    }

    if (url.includes("/oauth/token")) {
      return new Response(
        JSON.stringify({
          access_token: "at_test_token",
          refresh_token: "rt_test_token",
          token_type: "DPoP",
          scope: "atproto",
          sub: "did:plc:abcdefghijklmnopqrstuvwx",
          iss: "https://pds.example.com",
        }),
        { status: 200 },
      );
    }

    return new Response("not found", { status: 404 });
  });
}

describe("HappyViewBrowserClient", () => {
  test("constructor sets up LocalStorageAdapter by default", () => {
    const client = new HappyViewBrowserClient({
      instanceUrl: "https://happyview.example.com",
      clientId: "https://example.com/oauth-client-metadata.json",
      clientKey: "hvc_test",
    });
    expect(client).toBeDefined();
  });

  test("constructor accepts custom storage adapter", () => {
    const customStorage: StorageAdapter = {
      get: async () => null,
      set: async () => {},
      delete: async () => {},
    };
    const client = new HappyViewBrowserClient({
      instanceUrl: "https://happyview.example.com",
      clientId: "https://example.com/oauth-client-metadata.json",
      clientKey: "hvc_test",
      storage: customStorage,
    });
    expect(client).toBeDefined();
  });

  test("prepareLogin resolves handle and returns auth URL info", async () => {
    const fetchFn = mockFetchForFullFlow();
    const client = createClient(fetchFn);

    const authInfo = await client.prepareLogin("user.bsky.social");

    expect(authInfo.authorizationUrl).toContain("pds.example.com");
    expect(authInfo.did).toBe("did:plc:abcdefghijklmnopqrstuvwx");

    const stateKey = Array.from({ length: localStorage.length }, (_, i) =>
      localStorage.key(i),
    ).find((k) => k?.includes("pending-auth"));
    expect(stateKey).toBeDefined();
  });

  test("callback exchanges code for tokens with DPoP proof and registers session", async () => {
    const fetchFn = mockFetchForFullFlow();
    const client = createClient(fetchFn);

    const pendingState = {
      did: "did:plc:abcdefghijklmnopqrstuvwx",
      provisionId: "hvp_test123",
      rawJwk: testJwk,
      provisionPkceVerifier: "provision-verifier",
      authPkceVerifier: "auth-verifier",
      pdsUrl: "https://pds.example.com",
      tokenEndpoint: "https://pds.example.com/oauth/token",
      state: "state123",
      issuer: "https://pds.example.com",
    };
    localStorage.setItem(
      "@happyview/oauth(pending-auth:state123)",
      JSON.stringify(pendingState),
    );

    const session = await client.callback("?code=auth-code-123&state=state123");
    expect(session.did).toBe("did:plc:abcdefghijklmnopqrstuvwx");

    // Verify token exchange included DPoP proof header
    const tokenCall = fetchFn.mock.calls.find((call: any[]) =>
      String(call[0]).includes("/oauth/token"),
    );
    expect(tokenCall).toBeDefined();
    const tokenInit = tokenCall![1] as RequestInit;
    const tokenHeaders = new Headers(tokenInit.headers);
    expect(tokenHeaders.get("dpop")).not.toBeNull();
    expect(tokenHeaders.get("dpop")!.split(".")).toHaveLength(3);
  });

  test("callback sends provision PKCE verifier to registerSession", async () => {
    const fetchFn = mockFetchForFullFlow();
    const client = createClient(fetchFn);

    const pendingState = {
      did: "did:plc:abcdefghijklmnopqrstuvwx",
      provisionId: "hvp_test123",
      rawJwk: testJwk,
      provisionPkceVerifier: "provision-verifier",
      authPkceVerifier: "auth-verifier",
      pdsUrl: "https://pds.example.com",
      tokenEndpoint: "https://pds.example.com/oauth/token",
      state: "state456",
      issuer: "https://pds.example.com",
    };
    localStorage.setItem(
      "@happyview/oauth(pending-auth:state456)",
      JSON.stringify(pendingState),
    );

    await client.callback("?code=auth-code&state=state456");

    // Find the registerSession call (POST /oauth/sessions)
    const sessionCall = fetchFn.mock.calls.find(
      (call: any[]) =>
        String(call[0]).includes("/oauth/sessions") &&
        (call[1] as RequestInit)?.method === "POST",
    );
    expect(sessionCall).toBeDefined();
    const body = JSON.parse((sessionCall![1] as RequestInit).body as string);
    expect(body.pkce_verifier).toBe("provision-verifier");
  });

  test("callback sends auth PKCE verifier to PDS token endpoint", async () => {
    const fetchFn = mockFetchForFullFlow();
    const client = createClient(fetchFn);

    const pendingState = {
      did: "did:plc:abcdefghijklmnopqrstuvwx",
      provisionId: "hvp_test123",
      rawJwk: testJwk,
      provisionPkceVerifier: "provision-verifier",
      authPkceVerifier: "auth-verifier",
      pdsUrl: "https://pds.example.com",
      tokenEndpoint: "https://pds.example.com/oauth/token",
      state: "state789",
      issuer: "https://pds.example.com",
    };
    localStorage.setItem(
      "@happyview/oauth(pending-auth:state789)",
      JSON.stringify(pendingState),
    );

    await client.callback("?code=auth-code&state=state789");

    const tokenCall = fetchFn.mock.calls.find((call: any[]) =>
      String(call[0]).includes("/oauth/token"),
    );
    expect(tokenCall).toBeDefined();
    const body = new URLSearchParams(
      (tokenCall![1] as RequestInit).body as string,
    );
    expect(body.get("code_verifier")).toBe("auth-verifier");
  });

  test("callback passes issuer to registerSession", async () => {
    const fetchFn = mockFetchForFullFlow();
    const client = createClient(fetchFn);

    const pendingState = {
      did: "did:plc:abcdefghijklmnopqrstuvwx",
      provisionId: "hvp_test123",
      rawJwk: testJwk,
      provisionPkceVerifier: "provision-verifier",
      authPkceVerifier: "auth-verifier",
      pdsUrl: "https://pds.example.com",
      tokenEndpoint: "https://pds.example.com/oauth/token",
      state: "stateiss",
      issuer: "https://pds.example.com",
    };
    localStorage.setItem(
      "@happyview/oauth(pending-auth:stateiss)",
      JSON.stringify(pendingState),
    );

    await client.callback("?code=auth-code&state=stateiss");

    const sessionCall = fetchFn.mock.calls.find(
      (call: any[]) =>
        String(call[0]).includes("/oauth/sessions") &&
        (call[1] as RequestInit)?.method === "POST",
    );
    expect(sessionCall).toBeDefined();
    const body = JSON.parse((sessionCall![1] as RequestInit).body as string);
    expect(body.issuer).toBe("https://pds.example.com");
  });

  test("callback DPoP proof omits ath for token endpoint", async () => {
    const fetchFn = mockFetchForFullFlow();
    const client = createClient(fetchFn);

    const pendingState = {
      did: "did:plc:abcdefghijklmnopqrstuvwx",
      provisionId: "hvp_test123",
      rawJwk: testJwk,
      provisionPkceVerifier: "provision-verifier",
      authPkceVerifier: "auth-verifier",
      pdsUrl: "https://pds.example.com",
      tokenEndpoint: "https://pds.example.com/oauth/token",
      state: "stateathtest",
      issuer: "https://pds.example.com",
    };
    localStorage.setItem(
      "@happyview/oauth(pending-auth:stateathtest)",
      JSON.stringify(pendingState),
    );

    await client.callback("?code=auth-code&state=stateathtest");

    const tokenCall = fetchFn.mock.calls.find((call: any[]) =>
      String(call[0]).includes("/oauth/token"),
    );
    const dpopJwt = new Headers((tokenCall![1] as RequestInit).headers).get(
      "dpop",
    )!;
    const payloadB64 = dpopJwt.split(".")[1];
    const padded = payloadB64 + "=".repeat((4 - (payloadB64.length % 4)) % 4);
    const payload = JSON.parse(
      atob(padded.replace(/-/g, "+").replace(/_/g, "/")),
    );
    expect(payload.ath).toBeUndefined();
    expect(payload.htm).toBe("POST");
    expect(payload.htu).toBe("https://pds.example.com/oauth/token");
  });

  test("prepareLogin uses constructor scopes by default", async () => {
    const fetchFn = mockFetchForFullFlow();
    const client = new HappyViewBrowserClient({
      instanceUrl: "https://happyview.example.com",
      clientId: "https://example.com/oauth-client-metadata.json",
      clientKey: "hvc_test",
      scopes: "atproto transition:generic",
      storage: new LocalStorageAdapter(),
      fetch: fetchFn,
    });

    await client.prepareLogin("user.bsky.social");

    const parCall = fetchFn.mock.calls.find((call: any[]) =>
      String(call[0]).includes("/oauth/par"),
    );
    expect(parCall).toBeDefined();
    const body = new URLSearchParams(
      (parCall![1] as RequestInit).body as string,
    );
    expect(body.get("scope")).toBe("atproto transition:generic");
  });

  test("prepareLogin accepts per-call scope override", async () => {
    const fetchFn = mockFetchForFullFlow();
    const client = new HappyViewBrowserClient({
      instanceUrl: "https://happyview.example.com",
      clientId: "https://example.com/oauth-client-metadata.json",
      clientKey: "hvc_test",
      scopes: "atproto",
      storage: new LocalStorageAdapter(),
      fetch: fetchFn,
    });

    await client.prepareLogin("user.bsky.social", {
      scopes: "atproto transition:generic repo:app.example.post",
    });

    const parCall = fetchFn.mock.calls.find((call: any[]) =>
      String(call[0]).includes("/oauth/par"),
    );
    expect(parCall).toBeDefined();
    const body = new URLSearchParams(
      (parCall![1] as RequestInit).body as string,
    );
    expect(body.get("scope")).toBe(
      "atproto transition:generic repo:app.example.post",
    );
  });

  test("callback throws InvalidStateError when code or state is missing", async () => {
    const client = createClient();
    try {
      await client.callback("?code=auth-code");
      expect(true).toBe(false);
    } catch (err) {
      expect(err).toBeInstanceOf(InvalidStateError);
    }
  });

  test("callback throws InvalidStateError when no pending state found", async () => {
    const client = createClient();
    try {
      await client.callback("?code=auth-code&state=nonexistent");
      expect(true).toBe(false);
    } catch (err) {
      expect(err).toBeInstanceOf(InvalidStateError);
    }
  });

  test("callback throws TokenExchangeError on token endpoint failure", async () => {
    const fetchFn = mock(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.includes("/oauth/token")) {
          return new Response("invalid_grant", { status: 400 });
        }
        return new Response("not found", { status: 404 });
      },
    );

    const client = createClient(fetchFn);

    const pendingState = {
      did: "did:plc:abcdefghijklmnopqrstuvwx",
      provisionId: "hvp_test123",
      rawJwk: testJwk,
      provisionPkceVerifier: "provision-verifier",
      authPkceVerifier: "auth-verifier",
      pdsUrl: "https://pds.example.com",
      tokenEndpoint: "https://pds.example.com/oauth/token",
      state: "statefail",
      issuer: "https://pds.example.com",
    };
    localStorage.setItem(
      "@happyview/oauth(pending-auth:statefail)",
      JSON.stringify(pendingState),
    );

    try {
      await client.callback("?code=auth-code&state=statefail");
      expect(true).toBe(false);
    } catch (err) {
      expect(err).toBeInstanceOf(TokenExchangeError);
      expect((err as TokenExchangeError).status).toBe(400);
      expect((err as TokenExchangeError).body).toBe("invalid_grant");
    }
  });

  test("restore returns null when no session exists", async () => {
    const client = createClient();
    const session = await client.restore();
    expect(session).toBeNull();
  });

  test("restore returns session when last active DID is stored", async () => {
    const fetchFn = mockFetchForFullFlow();
    const client = createClient(fetchFn);

    // Simulate a stored session
    localStorage.setItem(
      "@happyview/oauth(happyview:last-active-did)",
      "did:plc:abcdefghijklmnopqrstuvwx",
    );
    localStorage.setItem(
      "@happyview/oauth(happyview:session:did:plc:abcdefghijklmnopqrstuvwx)",
      JSON.stringify({
        did: "did:plc:abcdefghijklmnopqrstuvwx",
        dpopKey: testJwk,
        accessToken: "at_stored",
        clientKey: "hvc_test",
        instanceUrl: "https://happyview.example.com",
      }),
    );

    const session = await client.restore();
    expect(session).not.toBeNull();
    expect(session!.did).toBe("did:plc:abcdefghijklmnopqrstuvwx");
  });

  test("logout deletes session from server and storage", async () => {
    const fetchFn = mockFetchForFullFlow();
    const client = createClient(fetchFn);

    localStorage.setItem(
      "@happyview/oauth(happyview:session:did:plc:abcdefghijklmnopqrstuvwx)",
      JSON.stringify({
        did: "did:plc:abcdefghijklmnopqrstuvwx",
        dpopKey: testJwk,
        accessToken: "at_stored",
        clientKey: "hvc_test",
        instanceUrl: "https://happyview.example.com",
      }),
    );
    localStorage.setItem(
      "@happyview/oauth(happyview:last-active-did)",
      "did:plc:abcdefghijklmnopqrstuvwx",
    );

    // Mock the DELETE response
    const deleteFn = mock(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        return new Response(null, { status: 204 });
      },
    );
    const logoutClient = createClient(deleteFn);

    await logoutClient.logout("did:plc:abcdefghijklmnopqrstuvwx");

    expect(
      localStorage.getItem(
        "@happyview/oauth(happyview:session:did:plc:abcdefghijklmnopqrstuvwx)",
      ),
    ).toBeNull();
    expect(
      localStorage.getItem("@happyview/oauth(happyview:last-active-did)"),
    ).toBeNull();
  });

  test("revoke is an alias for logout", async () => {
    const deleteFn = mock(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        return new Response(null, { status: 204 });
      },
    );
    const client = createClient(deleteFn);

    localStorage.setItem(
      "@happyview/oauth(happyview:session:did:plc:abcdefghijklmnopqrstuvwx)",
      JSON.stringify({
        did: "did:plc:abcdefghijklmnopqrstuvwx",
        dpopKey: testJwk,
        accessToken: "at_stored",
        clientKey: "hvc_test",
        instanceUrl: "https://happyview.example.com",
      }),
    );
    localStorage.setItem(
      "@happyview/oauth(happyview:last-active-did)",
      "did:plc:abcdefghijklmnopqrstuvwx",
    );

    await client.revoke("did:plc:abcdefghijklmnopqrstuvwx");

    expect(
      localStorage.getItem(
        "@happyview/oauth(happyview:session:did:plc:abcdefghijklmnopqrstuvwx)",
      ),
    ).toBeNull();
  });

  test("restore with no args returns last active session", async () => {
    const client = createClient();

    localStorage.setItem(
      "@happyview/oauth(happyview:last-active-did)",
      "did:plc:abcdefghijklmnopqrstuvwx",
    );
    localStorage.setItem(
      "@happyview/oauth(happyview:session:did:plc:abcdefghijklmnopqrstuvwx)",
      JSON.stringify({
        did: "did:plc:abcdefghijklmnopqrstuvwx",
        dpopKey: testJwk,
        accessToken: "at_stored",
        clientKey: "hvc_test",
        instanceUrl: "https://happyview.example.com",
      }),
    );

    const session = await client.restore();
    expect(session).not.toBeNull();
    expect(session!.did).toBe("did:plc:abcdefghijklmnopqrstuvwx");
  });

  test("restore with DID arg returns that specific session", async () => {
    const client = createClient();

    localStorage.setItem(
      "@happyview/oauth(happyview:session:did:plc:specific)",
      JSON.stringify({
        did: "did:plc:specific",
        dpopKey: testJwk,
        accessToken: "at_stored",
        clientKey: "hvc_test",
        instanceUrl: "https://happyview.example.com",
      }),
    );

    const session = await client.restore("did:plc:specific");
    expect(session).not.toBeNull();
    expect(session!.did).toBe("did:plc:specific");
  });

  test("restore with DID arg updates last active DID", async () => {
    const client = createClient();

    localStorage.setItem(
      "@happyview/oauth(happyview:session:did:plc:specific)",
      JSON.stringify({
        did: "did:plc:specific",
        dpopKey: testJwk,
        accessToken: "at_stored",
        clientKey: "hvc_test",
        instanceUrl: "https://happyview.example.com",
      }),
    );

    await client.restore("did:plc:specific");

    expect(
      localStorage.getItem("@happyview/oauth(happyview:last-active-did)"),
    ).toBe("did:plc:specific");
  });

  test("restore with DID arg does not update last active when session missing", async () => {
    const client = createClient();

    localStorage.setItem(
      "@happyview/oauth(happyview:last-active-did)",
      "did:plc:original",
    );

    await client.restore("did:plc:nonexistent");

    expect(
      localStorage.getItem("@happyview/oauth(happyview:last-active-did)"),
    ).toBe("did:plc:original");
  });

  test("restore with DID arg returns null when session does not exist", async () => {
    const client = createClient();
    const session = await client.restore("did:plc:nonexistent");
    expect(session).toBeNull();
  });

  test("initRestore returns session wrapper when last active exists", async () => {
    const client = createClient();

    localStorage.setItem(
      "@happyview/oauth(happyview:last-active-did)",
      "did:plc:abcdefghijklmnopqrstuvwx",
    );
    localStorage.setItem(
      "@happyview/oauth(happyview:session:did:plc:abcdefghijklmnopqrstuvwx)",
      JSON.stringify({
        did: "did:plc:abcdefghijklmnopqrstuvwx",
        dpopKey: testJwk,
        accessToken: "at_stored",
        clientKey: "hvc_test",
        instanceUrl: "https://happyview.example.com",
      }),
    );

    const result = await client.initRestore();
    expect(result).toBeDefined();
    expect(result!.session.did).toBe("did:plc:abcdefghijklmnopqrstuvwx");
  });

  test("initRestore returns undefined when no session exists", async () => {
    const client = createClient();
    const result = await client.initRestore();
    expect(result).toBeUndefined();
  });

  test("initCallback processes callback and returns session with state", async () => {
    const fetchFn = mockFetchForFullFlow();
    const client = createClient(fetchFn);

    const pendingState = {
      did: "did:plc:abcdefghijklmnopqrstuvwx",
      provisionId: "hvp_test123",
      rawJwk: testJwk,
      provisionPkceVerifier: "provision-verifier",
      authPkceVerifier: "auth-verifier",
      pdsUrl: "https://pds.example.com",
      tokenEndpoint: "https://pds.example.com/oauth/token",
      state: "initcb_state",
      issuer: "https://pds.example.com",
    };
    localStorage.setItem(
      "@happyview/oauth(pending-auth:initcb_state)",
      JSON.stringify(pendingState),
    );

    const result = await client.initCallback(
      "?code=auth-code&state=initcb_state",
    );
    expect(result.session.did).toBe("did:plc:abcdefghijklmnopqrstuvwx");
    expect(result.state).toBe("initcb_state");
  });

  test("readCallbackParams returns null when no OAuth params in URL", () => {
    const client = createClient();
    const params = client.readCallbackParams();
    expect(params).toBeNull();
  });

  test("findRedirectUrl returns configured redirectUri", () => {
    const client = new HappyViewBrowserClient({
      instanceUrl: "https://happyview.example.com",
      clientId: "https://example.com/oauth-client-metadata.json",
      clientKey: "hvc_test",
      redirectUri: "https://myapp.com/callback",
    });
    expect(client.findRedirectUrl()).toBe("https://myapp.com/callback");
  });

  test("findRedirectUrl returns default when no redirectUri configured", () => {
    const client = createClient();
    expect(client.findRedirectUrl()).toBe(
      `${window.location.origin}/oauth/callback`,
    );
  });

  test("signInRedirect delegates to login", async () => {
    const fetchFn = mockFetchForFullFlow();
    const client = createClient(fetchFn);

    // signInRedirect calls login which calls prepareLogin then sets window.location.href
    // We can verify it hits the same fetch endpoints as prepareLogin
    // Since window.location.href assignment doesn't work in tests, we just verify
    // the PAR request was made (proving prepareLogin was called)
    await client.signInRedirect("user.bsky.social");

    const parCall = fetchFn.mock.calls.find((call: any[]) =>
      String(call[0]).includes("/oauth/par"),
    );
    expect(parCall).toBeDefined();
  });

  test("signIn defaults to signInRedirect", async () => {
    const fetchFn = mockFetchForFullFlow();
    const client = createClient(fetchFn);

    await client.signIn("user.bsky.social");

    const parCall = fetchFn.mock.calls.find((call: any[]) =>
      String(call[0]).includes("/oauth/par"),
    );
    expect(parCall).toBeDefined();
  });

  test("prepareLogin accepts custom state", async () => {
    const fetchFn = mockFetchForFullFlow();
    const client = createClient(fetchFn);

    const result = await client.prepareLogin("user.bsky.social", {
      state: "custom-state-123",
    });

    expect(result.state).toBe("custom-state-123");

    const stored = localStorage.getItem(
      "@happyview/oauth(pending-auth:custom-state-123)",
    );
    expect(stored).not.toBeNull();
  });

  test("dispose does not throw", () => {
    const client = createClient();
    expect(() => client.dispose()).not.toThrow();
  });

  test("LoginContinuedInParentWindowError has correct name and message", () => {
    const err = new LoginContinuedInParentWindowError();
    expect(err.name).toBe("LoginContinuedInParentWindowError");
    expect(err.message).toBe("Login continued in parent window");
    expect(err).toBeInstanceOf(Error);
  });
});
