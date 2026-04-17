import { describe, expect, test } from "bun:test";
import { MemoryStorage } from "../storage";

describe("MemoryStorage", () => {
  test("get returns null for missing keys", async () => {
    const storage = new MemoryStorage();
    expect(await storage.get("nonexistent")).toBeNull();
  });

  test("set and get round-trips a value", async () => {
    const storage = new MemoryStorage();
    await storage.set("key1", "value1");
    expect(await storage.get("key1")).toBe("value1");
  });

  test("set overwrites existing values", async () => {
    const storage = new MemoryStorage();
    await storage.set("key1", "first");
    await storage.set("key1", "second");
    expect(await storage.get("key1")).toBe("second");
  });

  test("delete removes a key", async () => {
    const storage = new MemoryStorage();
    await storage.set("key1", "value1");
    await storage.delete("key1");
    expect(await storage.get("key1")).toBeNull();
  });

  test("delete is a no-op for missing keys", async () => {
    const storage = new MemoryStorage();
    await storage.delete("nonexistent");
  });
});
