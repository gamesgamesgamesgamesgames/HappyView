import { describe, expect, test } from "bun:test";
import { generateDpopProof } from "../dpop-proof";
import type { CryptoAdapter } from "../types";

const testCrypto: CryptoAdapter = {
  generatePkceVerifier: async () => "not-used-here",
  computePkceChallenge: async () => "not-used-here",
  signEs256: async (
    privateKey: JsonWebKey,
    payload: Uint8Array,
  ): Promise<Uint8Array> => {
    const key = await crypto.subtle.importKey(
      "jwk",
      privateKey,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      payload,
    );
    return new Uint8Array(sig);
  },
  sha256: async (data: Uint8Array): Promise<Uint8Array> => {
    const hash = await crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(hash);
  },
  getRandomValues: (length: number): Uint8Array => {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  },
};

async function generateTestKeyPair(): Promise<{
  privateKey: JsonWebKey;
  publicKey: JsonWebKey;
}> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const privateKey = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  const publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  return { privateKey, publicKey };
}

function base64urlDecode(str: string): Uint8Array {
  const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
  const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

describe("generateDpopProof", () => {
  test("produces a valid 3-part JWT", async () => {
    const { privateKey } = await generateTestKeyPair();
    const proof = await generateDpopProof(testCrypto, {
      privateKey,
      method: "POST",
      url: "https://pds.example.com/xrpc/com.atproto.repo.createRecord",
      accessToken: "test-access-token",
    });

    const parts = proof.split(".");
    expect(parts).toHaveLength(3);
  });

  test("header has correct alg, typ, and jwk", async () => {
    const { privateKey, publicKey } = await generateTestKeyPair();
    const proof = await generateDpopProof(testCrypto, {
      privateKey,
      method: "GET",
      url: "https://pds.example.com/xrpc/test.method",
      accessToken: "tok",
    });

    const header = JSON.parse(
      new TextDecoder().decode(base64urlDecode(proof.split(".")[0])),
    );
    expect(header.alg).toBe("ES256");
    expect(header.typ).toBe("dpop+jwt");
    expect(header.jwk.kty).toBe("EC");
    expect(header.jwk.crv).toBe("P-256");
    expect(header.jwk.x).toBe(publicKey.x);
    expect(header.jwk.y).toBe(publicKey.y);
    expect(header.jwk.d).toBeUndefined();
  });

  test("payload has htm, htu, iat, ath, jti", async () => {
    const { privateKey } = await generateTestKeyPair();
    const proof = await generateDpopProof(testCrypto, {
      privateKey,
      method: "POST",
      url: "https://pds.example.com/xrpc/test.method",
      accessToken: "my-access-token",
    });

    const payload = JSON.parse(
      new TextDecoder().decode(base64urlDecode(proof.split(".")[1])),
    );
    expect(payload.htm).toBe("POST");
    expect(payload.htu).toBe("https://pds.example.com/xrpc/test.method");
    expect(typeof payload.iat).toBe("number");
    expect(typeof payload.ath).toBe("string");
    expect(typeof payload.jti).toBe("string");
    expect(payload.ath.length).toBeGreaterThan(0);
    expect(payload.jti.length).toBeGreaterThan(0);
  });

  test("ath is base64url(SHA-256(access_token))", async () => {
    const { privateKey } = await generateTestKeyPair();
    const accessToken = "specific-test-token";
    const proof = await generateDpopProof(testCrypto, {
      privateKey,
      method: "GET",
      url: "https://example.com/xrpc/test",
      accessToken,
    });

    const payload = JSON.parse(
      new TextDecoder().decode(base64urlDecode(proof.split(".")[1])),
    );

    const tokenBytes = new TextEncoder().encode(accessToken);
    const hashBuf = await crypto.subtle.digest("SHA-256", tokenBytes);
    const hashArr = new Uint8Array(hashBuf);
    let binary = "";
    for (let i = 0; i < hashArr.length; i++) {
      binary += String.fromCharCode(hashArr[i]);
    }
    const expected = btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    expect(payload.ath).toBe(expected);
  });

  test("includes nonce when provided", async () => {
    const { privateKey } = await generateTestKeyPair();
    const proof = await generateDpopProof(testCrypto, {
      privateKey,
      method: "GET",
      url: "https://example.com/xrpc/test",
      accessToken: "tok",
      nonce: "server-nonce-123",
    });

    const payload = JSON.parse(
      new TextDecoder().decode(base64urlDecode(proof.split(".")[1])),
    );
    expect(payload.nonce).toBe("server-nonce-123");
  });

  test("omits ath when accessToken is not provided", async () => {
    const { privateKey } = await generateTestKeyPair();
    const proof = await generateDpopProof(testCrypto, {
      privateKey,
      method: "POST",
      url: "https://pds.example.com/oauth/token",
    });

    const payload = JSON.parse(
      new TextDecoder().decode(base64urlDecode(proof.split(".")[1])),
    );
    expect(payload.ath).toBeUndefined();
    expect(payload.htm).toBe("POST");
    expect(payload.htu).toBe("https://pds.example.com/oauth/token");
  });

  test("omits nonce when not provided", async () => {
    const { privateKey } = await generateTestKeyPair();
    const proof = await generateDpopProof(testCrypto, {
      privateKey,
      method: "GET",
      url: "https://example.com/xrpc/test",
      accessToken: "tok",
    });

    const payload = JSON.parse(
      new TextDecoder().decode(base64urlDecode(proof.split(".")[1])),
    );
    expect(payload.nonce).toBeUndefined();
  });

  test("signature is verifiable", async () => {
    const { privateKey, publicKey } = await generateTestKeyPair();
    const proof = await generateDpopProof(testCrypto, {
      privateKey,
      method: "POST",
      url: "https://pds.example.com/xrpc/test.method",
      accessToken: "my-token",
    });

    const [headerB64, payloadB64, sigB64] = proof.split(".");
    const message = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const signature = base64urlDecode(sigB64);

    const verifyKey = await crypto.subtle.importKey(
      "jwk",
      publicKey,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      verifyKey,
      signature,
      message,
    );
    expect(valid).toBe(true);
  });
});
