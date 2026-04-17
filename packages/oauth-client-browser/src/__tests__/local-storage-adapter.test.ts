import { afterEach, describe, expect, test } from "bun:test";
import { LocalStorageAdapter } from "../local-storage-adapter";

const STORAGE_PREFIX = "@happyview/oauth(";

describe("LocalStorageAdapter", () => {
  afterEach(() => {
    localStorage.clear();
  });

  test("get returns null for missing keys", async () => {
    const adapter = new LocalStorageAdapter();
    expect(await adapter.get("nonexistent")).toBeNull();
  });

  test("set and get round-trips a value", async () => {
    const adapter = new LocalStorageAdapter();
    await adapter.set("key1", "value1");
    expect(await adapter.get("key1")).toBe("value1");
  });

  test("stores values with prefix in localStorage", async () => {
    const adapter = new LocalStorageAdapter();
    await adapter.set("mykey", "myvalue");
    expect(localStorage.getItem(`${STORAGE_PREFIX}mykey)`)).toBe("myvalue");
  });

  test("delete removes a key", async () => {
    const adapter = new LocalStorageAdapter();
    await adapter.set("key1", "value1");
    await adapter.delete("key1");
    expect(await adapter.get("key1")).toBeNull();
    expect(localStorage.getItem(`${STORAGE_PREFIX}key1)`)).toBeNull();
  });

  test("delete is a no-op for missing keys", async () => {
    const adapter = new LocalStorageAdapter();
    await adapter.delete("nonexistent");
  });

  test("set overwrites existing values", async () => {
    const adapter = new LocalStorageAdapter();
    await adapter.set("key1", "first");
    await adapter.set("key1", "second");
    expect(await adapter.get("key1")).toBe("second");
  });
});
