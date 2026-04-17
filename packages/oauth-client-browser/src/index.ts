export {
  ApiError,
  AuthenticationError,
  HappyViewError,
  HappyViewSession,
  InvalidStateError,
  MemoryStorage,
  ResolutionError,
  TokenExchangeError,
  base64urlEncode,
  generateDpopProof,
  type CryptoAdapter,
  type DpopProvision,
  type HappyViewOAuthClientOptions,
  type RegisterSessionParams,
  type StorageAdapter,
  type StoredSession,
} from "@happyview/oauth-client";

export { HappyViewBrowserClient } from "./browser-client";
export type {
  HappyViewBrowserClientOptions,
  PrepareLoginResult,
} from "./browser-client";
export { LocalStorageAdapter } from "./local-storage-adapter";
export {
  resolveAuthServerMetadata,
  resolveDidDocument,
  resolveHandleToDid,
  resolvePdsUrl,
} from "./resolve";
export type { AuthServerMetadata, DidDocument } from "./resolve";
export { WebCryptoAdapter } from "./web-crypto-adapter";
