import type { StorageAdapter } from "@happyview/oauth-client";

const PREFIX = "@happyview/oauth(";

export class LocalStorageAdapter implements StorageAdapter {
  private prefixedKey(key: string): string {
    return `${PREFIX}${key})`;
  }

  async get(key: string): Promise<string | null> {
    return localStorage.getItem(this.prefixedKey(key));
  }

  async set(key: string, value: string): Promise<void> {
    localStorage.setItem(this.prefixedKey(key), value);
  }

  async delete(key: string): Promise<void> {
    localStorage.removeItem(this.prefixedKey(key));
  }
}
