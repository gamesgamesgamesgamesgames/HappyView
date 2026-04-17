import { describe, expect, test } from "bun:test";
import {
  ApiError,
  AuthenticationError,
  HappyViewError,
  InvalidStateError,
  ResolutionError,
  TokenExchangeError,
} from "../errors";

describe("error types", () => {
  test("HappyViewError is an Error", () => {
    const err = new HappyViewError("test");
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(HappyViewError);
    expect(err.name).toBe("HappyViewError");
    expect(err.message).toBe("test");
  });

  test("ApiError has status and body", () => {
    const body = { message: "bad request" };
    const err = new ApiError("fail", 400, body);
    expect(err).toBeInstanceOf(HappyViewError);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.name).toBe("ApiError");
    expect(err.status).toBe(400);
    expect(err.body).toEqual(body);
  });

  test("AuthenticationError defaults to 401", () => {
    const err = new AuthenticationError("unauthorized");
    expect(err).toBeInstanceOf(HappyViewError);
    expect(err.name).toBe("AuthenticationError");
    expect(err.status).toBe(401);
  });

  test("AuthenticationError accepts custom status", () => {
    const err = new AuthenticationError("forbidden", 403);
    expect(err.status).toBe(403);
  });

  test("InvalidStateError has correct name", () => {
    const err = new InvalidStateError("bad state");
    expect(err).toBeInstanceOf(HappyViewError);
    expect(err.name).toBe("InvalidStateError");
  });

  test("TokenExchangeError has status and body", () => {
    const err = new TokenExchangeError("exchange failed", 400, "invalid_grant");
    expect(err).toBeInstanceOf(HappyViewError);
    expect(err.name).toBe("TokenExchangeError");
    expect(err.status).toBe(400);
    expect(err.body).toBe("invalid_grant");
  });

  test("ResolutionError has correct name", () => {
    const err = new ResolutionError("could not resolve");
    expect(err).toBeInstanceOf(HappyViewError);
    expect(err.name).toBe("ResolutionError");
  });

  test("errors can be caught by parent type", () => {
    const errors = [
      new ApiError("a", 500),
      new AuthenticationError("b"),
      new InvalidStateError("c"),
      new TokenExchangeError("d", 400, ""),
      new ResolutionError("e"),
    ];
    for (const err of errors) {
      expect(err).toBeInstanceOf(HappyViewError);
      expect(err).toBeInstanceOf(Error);
    }
  });
});
