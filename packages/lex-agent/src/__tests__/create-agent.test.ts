import { describe, expect, mock, test } from "bun:test";
import type { Agent, FetchHandler } from "@atproto/lex";
import type { HappyViewSession } from "@happyview/oauth-client";
import { createAgent } from "../index";

function createMockSession(overrides?: {
  did?: string;
  fetchHandler?: HappyViewSession["fetchHandler"];
}): HappyViewSession {
  return {
    did: overrides?.did ?? "did:plc:testuser",
    fetchHandler:
      overrides?.fetchHandler ??
      mock(async () => new Response("{}", { status: 200 })),
  } as unknown as HappyViewSession;
}

describe("createAgent", () => {
  test("returns an object satisfying the Agent interface", () => {
    const session = createMockSession();
    const agent: Agent = createAgent(session);

    expect(agent).toHaveProperty("did");
    expect(agent).toHaveProperty("fetchHandler");
    expect(typeof agent.fetchHandler).toBe("function");
  });

  test("did reflects the session did", () => {
    const session = createMockSession({ did: "did:plc:abc123" });
    const agent = createAgent(session);

    expect(agent.did).toBe("did:plc:abc123");
  });

  test("did stays in sync with session", () => {
    const sessionData = { did: "did:plc:first" };
    const session = {
      get did() {
        return sessionData.did;
      },
      fetchHandler: mock(async () => new Response("{}", { status: 200 })),
    } as unknown as HappyViewSession;

    const agent = createAgent(session);
    expect(agent.did).toBe("did:plc:first");

    sessionData.did = "did:plc:second";
    expect(agent.did).toBe("did:plc:second");
  });

  test("fetchHandler delegates to session.fetchHandler", async () => {
    const mockResponse = new Response(JSON.stringify({ ok: true }), {
      status: 200,
    });
    const fetchMock = mock(async () => mockResponse);
    const session = createMockSession({ fetchHandler: fetchMock });
    const agent = createAgent(session);

    const init: RequestInit = { method: "GET" };
    const result = await agent.fetchHandler("/xrpc/com.example.test", init);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith("/xrpc/com.example.test", init);
    expect(result).toBe(mockResponse);
  });

  test("fetchHandler passes through POST requests with body", async () => {
    const fetchMock = mock(
      async () => new Response("{}", { status: 200 }),
    );
    const session = createMockSession({ fetchHandler: fetchMock });
    const agent = createAgent(session);

    const body = JSON.stringify({ text: "hello" });
    const init: RequestInit = {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    };
    await agent.fetchHandler("/xrpc/com.example.test.create", init);

    expect(fetchMock).toHaveBeenCalledWith(
      "/xrpc/com.example.test.create",
      init,
    );
  });

  test("fetchHandler passes through query parameters in path", async () => {
    const fetchMock = mock(
      async () => new Response("{}", { status: 200 }),
    );
    const session = createMockSession({ fetchHandler: fetchMock });
    const agent = createAgent(session);

    await agent.fetchHandler(
      "/xrpc/com.example.test.get?slug=celeste&limit=10",
      {},
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "/xrpc/com.example.test.get?slug=celeste&limit=10",
      {},
    );
  });
});
