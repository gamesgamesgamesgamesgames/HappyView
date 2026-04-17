import { describe, expect, test } from "bun:test";
import { WebCryptoAdapter } from "../web-crypto-adapter";

const adapter = new WebCryptoAdapter();

describe("WebCryptoAdapter", () => {
  describe("generatePkceVerifier", () => {
    test("returns a string of 43-128 characters", async () => {
      const verifier = await adapter.generatePkceVerifier();
      expect(verifier.length).toBeGreaterThanOrEqual(43);
      expect(verifier.length).toBeLessThanOrEqual(128);
    });

    test("contains only valid characters [A-Za-z0-9-._~]", async () => {
      const verifier = await adapter.generatePkceVerifier();
      expect(verifier).toMatch(/^[A-Za-z0-9\-._~]+$/);
    });

    test("generates unique verifiers", async () => {
      const v1 = await adapter.generatePkceVerifier();
      const v2 = await adapter.generatePkceVerifier();
      expect(v1).not.toBe(v2);
    });
  });

  describe("computePkceChallenge", () => {
    test("returns base64url-encoded SHA-256 hash", async () => {
      const challenge = await adapter.computePkceChallenge("test-verifier");
      expect(challenge).not.toContain("+");
      expect(challenge).not.toContain("/");
      expect(challenge).not.toContain("=");
      expect(challenge.length).toBeGreaterThan(0);
    });

    test("produces consistent output for same input", async () => {
      const c1 = await adapter.computePkceChallenge("same-verifier");
      const c2 = await adapter.computePkceChallenge("same-verifier");
      expect(c1).toBe(c2);
    });

    test("produces different output for different input", async () => {
      const c1 = await adapter.computePkceChallenge("verifier-a");
      const c2 = await adapter.computePkceChallenge("verifier-b");
      expect(c1).not.toBe(c2);
    });
  });

  describe("signEs256", () => {
    test("produces a 64-byte signature", async () => {
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"],
      );
      const privateKey = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
      const payload = new TextEncoder().encode("test payload");

      const sig = await adapter.signEs256(privateKey, payload);
      expect(sig).toBeInstanceOf(Uint8Array);
      expect(sig.length).toBe(64);
    });

    test("produces verifiable signatures", async () => {
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"],
      );
      const privateKey = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
      const payload = new TextEncoder().encode("verify me");

      const sig = await adapter.signEs256(privateKey, payload);

      const valid = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        keyPair.publicKey,
        sig,
        payload,
      );
      expect(valid).toBe(true);
    });
  });

  describe("sha256", () => {
    test("produces a 32-byte hash", async () => {
      const data = new TextEncoder().encode("hello world");
      const hash = await adapter.sha256(data);
      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBe(32);
    });

    test("produces consistent output for same input", async () => {
      const data = new TextEncoder().encode("deterministic");
      const h1 = await adapter.sha256(data);
      const h2 = await adapter.sha256(data);
      expect(Array.from(h1)).toEqual(Array.from(h2));
    });

    test("produces different output for different input", async () => {
      const h1 = await adapter.sha256(new TextEncoder().encode("input-a"));
      const h2 = await adapter.sha256(new TextEncoder().encode("input-b"));
      expect(Array.from(h1)).not.toEqual(Array.from(h2));
    });
  });

  describe("getRandomValues", () => {
    test("returns Uint8Array of requested length", () => {
      const bytes = adapter.getRandomValues(16);
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBe(16);
    });

    test("returns different values on each call", () => {
      const a = adapter.getRandomValues(32);
      const b = adapter.getRandomValues(32);
      expect(Array.from(a)).not.toEqual(Array.from(b));
    });
  });
});
