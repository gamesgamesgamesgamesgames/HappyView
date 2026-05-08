import { describe, expect, test } from "bun:test";

import {
  describePermission,
  isValidNsid,
  normalizeScope,
  parseScope,
  serializeScope,
  validatePermission,
  type Permission,
} from "./oauth-scope";

describe("isValidNsid", () => {
  test("accepts a normal NSID", () => {
    expect(isValidNsid("app.bsky.feed.post")).toBe(true);
  });
  test("accepts the lone wildcard", () => {
    expect(isValidNsid("*")).toBe(true);
  });
  test("rejects partial wildcards", () => {
    expect(isValidNsid("app.bsky.*")).toBe(false);
    expect(isValidNsid("*.bsky")).toBe(false);
  });
  test("rejects empty / malformed", () => {
    expect(isValidNsid("")).toBe(false);
    expect(isValidNsid(".bsky")).toBe(false);
    expect(isValidNsid("bsky.")).toBe(false);
    expect(isValidNsid("123.foo")).toBe(false);
  });
});

describe("parseScope", () => {
  test("empty input still emits base", () => {
    expect(parseScope("")).toEqual([{ kind: "base" }]);
  });

  test("input missing atproto adds it implicitly", () => {
    const perms = parseScope("repo:app.bsky.feed.post");
    expect(perms[0]).toEqual({ kind: "base" });
    expect(perms.length).toBe(2);
  });

  test("base-only input parses cleanly", () => {
    expect(parseScope("atproto")).toEqual([{ kind: "base" }]);
  });

  test("repo path form with single action", () => {
    const perms = parseScope("atproto repo:app.bsky.feed.post?action=create");
    expect(perms[1]).toEqual({
      kind: "repo",
      collections: ["app.bsky.feed.post"],
      actions: ["create"],
    });
  });

  test("repo path form with multiple actions", () => {
    const perms = parseScope(
      "atproto repo:app.bsky.feed.post?action=create&action=delete",
    );
    expect(perms[1]).toEqual({
      kind: "repo",
      collections: ["app.bsky.feed.post"],
      actions: ["create", "delete"],
    });
  });

  test("repo query form with multiple collections", () => {
    const perms = parseScope(
      "atproto repo?collection=app.bsky.feed.like&collection=app.bsky.feed.repost&action=delete",
    );
    expect(perms[1]).toEqual({
      kind: "repo",
      collections: ["app.bsky.feed.like", "app.bsky.feed.repost"],
      actions: ["delete"],
    });
  });

  test("rpc path form", () => {
    const perms = parseScope(
      "atproto rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app",
    );
    expect(perms[1]).toEqual({
      kind: "rpc",
      lxms: ["app.bsky.feed.getTimeline"],
      aud: "did:web:api.bsky.app",
    });
  });

  test("rpc query form with multiple lxms and aud", () => {
    const perms = parseScope(
      "atproto rpc?lxm=foo.bar&lxm=baz.qux&aud=did:web:example.com",
    );
    expect(perms[1]).toEqual({
      kind: "rpc",
      lxms: ["foo.bar", "baz.qux"],
      aud: "did:web:example.com",
    });
  });

  test("rpc with only aud (no lxm)", () => {
    const perms = parseScope("atproto rpc?aud=did:web:example.com");
    expect(perms[1]).toEqual({
      kind: "rpc",
      lxms: [],
      aud: "did:web:example.com",
    });
  });

  test("blob with mime", () => {
    expect(parseScope("atproto blob:image/*")[1]).toEqual({
      kind: "blob",
      accept: "image/*",
    });
  });

  test("account with action", () => {
    expect(parseScope("atproto account:repo?action=manage")[1]).toEqual({
      kind: "account",
      attr: "repo",
      action: "manage",
    });
  });

  test("account without action", () => {
    expect(parseScope("atproto account:email")[1]).toEqual({
      kind: "account",
      attr: "email",
    });
  });

  test("identity (handle)", () => {
    expect(parseScope("atproto identity:handle")[1]).toEqual({
      kind: "handle",
      attr: "handle",
    });
    expect(parseScope("atproto identity:*")[1]).toEqual({
      kind: "handle",
      attr: "*",
    });
  });

  test("transition", () => {
    expect(parseScope("atproto transition:generic")[1]).toEqual({
      kind: "transition",
      value: "generic",
    });
  });

  test("permission-set with audience", () => {
    expect(
      parseScope(
        "atproto include:app.bsky.permissions.read?aud=did:web:api.bsky.app",
      )[1],
    ).toEqual({
      kind: "permission-set",
      nsid: "app.bsky.permissions.read",
      aud: "did:web:api.bsky.app",
    });
  });

  test("unknown / malformed tokens are preserved", () => {
    const perms = parseScope("atproto something:weird");
    expect(perms[1]).toEqual({ kind: "unknown", raw: "something:weird" });
  });

  test("malformed account attr falls back to unknown", () => {
    expect(parseScope("atproto account:bogus")[1]).toEqual({
      kind: "unknown",
      raw: "account:bogus",
    });
  });

  test("repo with no collection becomes unknown", () => {
    expect(parseScope("atproto repo")[1]).toEqual({
      kind: "unknown",
      raw: "repo",
    });
  });
});

describe("serializeScope", () => {
  test("empty list still emits atproto", () => {
    expect(serializeScope([])).toBe("atproto");
  });

  test("repo path form for single collection", () => {
    const perms: Permission[] = [
      { kind: "base" },
      {
        kind: "repo",
        collections: ["app.bsky.feed.post"],
        actions: ["create"],
      },
    ];
    expect(serializeScope(perms)).toBe(
      "atproto repo:app.bsky.feed.post?action=create",
    );
  });

  test("repo query form for multi collection", () => {
    const perms: Permission[] = [
      { kind: "base" },
      {
        kind: "repo",
        collections: ["app.bsky.feed.like", "app.bsky.feed.repost"],
        actions: ["delete"],
      },
    ];
    expect(serializeScope(perms)).toBe(
      "atproto repo?collection=app.bsky.feed.like&collection=app.bsky.feed.repost&action=delete",
    );
  });

  test("rpc path form keeps colons unencoded in aud", () => {
    const perms: Permission[] = [
      { kind: "base" },
      {
        kind: "rpc",
        lxms: ["app.bsky.feed.getTimeline"],
        aud: "did:web:api.bsky.app",
      },
    ];
    expect(serializeScope(perms)).toBe(
      "atproto rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app",
    );
  });

  test("blob keeps wildcards unencoded", () => {
    const perms: Permission[] = [
      { kind: "base" },
      { kind: "blob", accept: "image/*" },
    ];
    expect(serializeScope(perms)).toBe("atproto blob:image/*");
  });

  test("dedupes identical tokens", () => {
    const perms: Permission[] = [
      { kind: "base" },
      { kind: "blob", accept: "image/*" },
      { kind: "blob", accept: "image/*" },
    ];
    expect(serializeScope(perms)).toBe("atproto blob:image/*");
  });

  test("base is always first", () => {
    const perms: Permission[] = [
      { kind: "blob", accept: "image/*" },
      { kind: "base" },
    ];
    expect(serializeScope(perms)).toBe("atproto blob:image/*");
  });

  test("preserves unknown tokens verbatim", () => {
    const perms: Permission[] = [
      { kind: "base" },
      { kind: "unknown", raw: "made.up:stuff" },
    ];
    expect(serializeScope(perms)).toBe("atproto made.up:stuff");
  });
});

describe("round-trip", () => {
  const cases = [
    "atproto",
    "atproto repo:app.bsky.feed.post?action=create",
    "atproto repo:app.bsky.feed.post?action=create&action=delete",
    "atproto repo?collection=app.bsky.feed.like&collection=app.bsky.feed.repost&action=delete",
    "atproto rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app",
    "atproto rpc?lxm=foo.bar&lxm=baz.qux&aud=did:web:example.com",
    "atproto rpc?aud=did:web:example.com",
    "atproto blob:image/*",
    "atproto blob:*/*",
    "atproto account:email",
    "atproto account:repo?action=manage",
    "atproto identity:handle",
    "atproto identity:*",
    "atproto transition:generic",
    "atproto transition:chat.bsky",
    "atproto include:app.bsky.permissions.read",
    "atproto include:app.bsky.permissions.read?aud=did:web:api.bsky.app",
  ];

  for (const input of cases) {
    test(`round-trips: ${input}`, () => {
      expect(normalizeScope(input)).toBe(input);
    });
  }

  test("complex multi-permission scope round-trips", () => {
    const input =
      "atproto repo:app.bsky.feed.post?action=create rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app blob:image/* account:email identity:handle transition:generic";
    expect(normalizeScope(input)).toBe(input);
  });
});

describe("describePermission", () => {
  test("base", () => {
    expect(describePermission({ kind: "base" })).toMatch(/Base scope/);
  });
  test("repo single", () => {
    expect(
      describePermission({
        kind: "repo",
        collections: ["app.bsky.feed.post"],
        actions: ["create"],
      }),
    ).toBe("create records in app.bsky.feed.post");
  });
  test("repo multi", () => {
    expect(
      describePermission({
        kind: "repo",
        collections: ["a.b", "c.d"],
        actions: ["delete"],
      }),
    ).toBe("delete records in [a.b, c.d]");
  });
  test("repo wildcard collection", () => {
    expect(
      describePermission({ kind: "repo", collections: ["*"] }),
    ).toMatch(/all collections/);
  });
  test("rpc single", () => {
    expect(
      describePermission({
        kind: "rpc",
        lxms: ["app.bsky.feed.getTimeline"],
        aud: "did:web:api.bsky.app",
      }),
    ).toBe("Call app.bsky.feed.getTimeline on did:web:api.bsky.app");
  });
  test("blob", () => {
    expect(describePermission({ kind: "blob", accept: "image/*" })).toBe(
      "Upload blobs of type image/*",
    );
  });
  test("account email", () => {
    expect(describePermission({ kind: "account", attr: "email" })).toBe(
      "Access account email",
    );
  });
  test("handle", () => {
    expect(describePermission({ kind: "handle", attr: "handle" })).toBe(
      "Manage handle",
    );
  });
  test("transition generic", () => {
    expect(
      describePermission({ kind: "transition", value: "generic" }),
    ).toMatch(/legacy app password/);
  });
  test("unknown", () => {
    expect(describePermission({ kind: "unknown", raw: "foo" })).toMatch(
      /Unknown/,
    );
  });
});

describe("validatePermission", () => {
  test("repo with no collections fails", () => {
    expect(validatePermission({ kind: "repo", collections: [] })).toMatch(
      /at least one collection/,
    );
  });
  test("rpc with neither lxm nor aud fails", () => {
    expect(validatePermission({ kind: "rpc", lxms: [] })).toMatch(
      /at least one LXM/i,
    );
  });
  test("rpc with both wildcards fails", () => {
    expect(
      validatePermission({ kind: "rpc", lxms: ["*"], aud: "*" }),
    ).toMatch(/cannot be \*/);
  });
  test("repo with partial wildcard fails", () => {
    expect(
      validatePermission({ kind: "repo", collections: ["app.bsky.*"] }),
    ).toMatch(/Invalid collection/);
  });
  test("valid repo passes", () => {
    expect(
      validatePermission({
        kind: "repo",
        collections: ["app.bsky.feed.post"],
        actions: ["create"],
      }),
    ).toBeNull();
  });
  test("blob requires accept", () => {
    expect(validatePermission({ kind: "blob", accept: "" })).toMatch(
      /MIME/,
    );
  });
});
