import type { Agent, DidString } from "@atproto/lex";
import type { HappyViewSession } from "@happyview/oauth-client";

/**
 * Creates an `@atproto/lex` {@link Agent} from a {@link HappyViewSession}.
 *
 * All XRPC requests made through this agent are routed to the HappyView
 * instance with DPoP authentication headers. HappyView handles requests for
 * its own lexicons locally and proxies standard AT Protocol methods (e.g.
 * `com.atproto.repo.createRecord`) to the user's PDS.
 *
 * @example
 * ```typescript
 * import { Client } from "@atproto/lex";
 * import { createAgent } from "@happyview/lex-agent";
 *
 * const agent = createAgent(session);
 * const client = new Client(agent);
 *
 * const game = await client.xrpc(games.gamesgamesgamesgames.getGame, {
 *   params: { slug: "celeste" },
 * });
 * ```
 */
export function createAgent(session: HappyViewSession): Agent {
  return {
    get did() {
      return session.did as DidString;
    },
    fetchHandler(path, init) {
      return session.fetchHandler(path, init);
    },
  };
}
