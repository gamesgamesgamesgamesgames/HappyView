import { describe, expect, test } from "bun:test";
import type {
  CryptoAdapter,
  DpopProvision,
  HappyViewOAuthClientOptions,
  RegisterSessionParams,
  StorageAdapter,
} from "../types";

describe("types", () => {
  test("HappyViewOAuthClientOptions accepts confidential client config", () => {
    const opts: HappyViewOAuthClientOptions = {
      instanceUrl: "https://example.com",
      clientKey: "hvc_test",
      clientSecret: "hvs_secret",
      crypto: {
        generatePkceVerifier: async () => "verifier",
        computePkceChallenge: async () => "challenge",
        signEs256: async () => new Uint8Array(64),
        sha256: async () => new Uint8Array(32),
        getRandomValues: (n) => new Uint8Array(n),
      },
    };
    expect(opts.clientKey).toBe("hvc_test");
    expect(opts.clientSecret).toBe("hvs_secret");
  });

  test("HappyViewOAuthClientOptions accepts public client config", () => {
    const opts: HappyViewOAuthClientOptions = {
      instanceUrl: "https://example.com",
      clientKey: "hvc_test",
      crypto: {
        generatePkceVerifier: async () => "verifier",
        computePkceChallenge: async () => "challenge",
        signEs256: async () => new Uint8Array(64),
        sha256: async () => new Uint8Array(32),
        getRandomValues: (n) => new Uint8Array(n),
      },
    };
    expect(opts.clientSecret).toBeUndefined();
  });

  test("DpopProvision has required fields", () => {
    const provision: DpopProvision = {
      provisionId: "hvp_abc123",
      dpopKey: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
    };
    expect(provision.provisionId).toBe("hvp_abc123");
    expect(provision.dpopKey.kty).toBe("EC");
  });

  test("RegisterSessionParams has required and optional fields", () => {
    const params: RegisterSessionParams = {
      provisionId: "hvp_abc123",
      did: "did:plc:test",
      accessToken: "at_token",
      scopes: "atproto",
      dpopKey: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
    };
    expect(params.refreshToken).toBeUndefined();
    expect(params.pdsUrl).toBeUndefined();
  });

  test("StorageAdapter interface shape", () => {
    const storage: StorageAdapter = {
      get: async () => null,
      set: async () => {},
      delete: async () => {},
    };
    expect(storage.get).toBeFunction();
  });

  test("CryptoAdapter interface shape", () => {
    const adapter: CryptoAdapter = {
      generatePkceVerifier: async () => "verifier",
      computePkceChallenge: async () => "challenge",
      signEs256: async () => new Uint8Array(64),
      sha256: async () => new Uint8Array(32),
      getRandomValues: (n) => new Uint8Array(n),
    };
    expect(adapter.signEs256).toBeFunction();
    expect(adapter.sha256).toBeFunction();
    expect(adapter.getRandomValues).toBeFunction();
  });
});
