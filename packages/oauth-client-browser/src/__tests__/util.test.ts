import { describe, expect, test } from "bun:test";
import { buildLoopbackClientId } from "../util";

describe("buildLoopbackClientId", () => {
  test("builds client ID from localhost", () => {
    const result = buildLoopbackClientId({
      hostname: "localhost",
      pathname: "/",
      port: "3000",
    });
    expect(result).toBe(
      "http://localhost?redirect_uri=" +
        encodeURIComponent("http://127.0.0.1:3000/"),
    );
  });

  test("builds client ID from 127.0.0.1", () => {
    const result = buildLoopbackClientId({
      hostname: "127.0.0.1",
      pathname: "/",
      port: "8080",
    });
    expect(result).toBe(
      "http://localhost?redirect_uri=" +
        encodeURIComponent("http://127.0.0.1:8080/"),
    );
  });

  test("preserves non-root pathname in client ID", () => {
    const result = buildLoopbackClientId({
      hostname: "localhost",
      pathname: "/callback",
      port: "3000",
    });
    expect(result).toBe(
      "http://localhost/callback?redirect_uri=" +
        encodeURIComponent("http://127.0.0.1:3000/callback"),
    );
  });

  test("omits port from redirect_uri when empty", () => {
    const result = buildLoopbackClientId({
      hostname: "localhost",
      pathname: "/",
      port: "",
    });
    expect(result).toBe(
      "http://localhost?redirect_uri=" +
        encodeURIComponent("http://127.0.0.1/"),
    );
  });

  test("accepts custom localhost override", () => {
    const result = buildLoopbackClientId(
      { hostname: "localhost", pathname: "/", port: "3000" },
      "::1",
    );
    expect(result).toContain(encodeURIComponent("http://[::1]:3000/"));
  });

  test("does not double-bracket already-bracketed IPv6", () => {
    const result = buildLoopbackClientId(
      { hostname: "[::1]", pathname: "/", port: "3000" },
      "[::1]",
    );
    expect(result).toContain(encodeURIComponent("http://[::1]:3000/"));
  });

  test("accepts [::1] hostname", () => {
    const result = buildLoopbackClientId({
      hostname: "[::1]",
      pathname: "/",
      port: "3000",
    });
    expect(result).toContain("redirect_uri=");
  });

  test("throws on non-loopback hostname", () => {
    expect(() =>
      buildLoopbackClientId({
        hostname: "example.com",
        pathname: "/",
        port: "3000",
      }),
    ).toThrow(TypeError);
  });

  test("throws with descriptive message", () => {
    expect(() =>
      buildLoopbackClientId({
        hostname: "evil.com",
        pathname: "/",
        port: "80",
      }),
    ).toThrow('Expected a loopback hostname, got "evil.com"');
  });
});
