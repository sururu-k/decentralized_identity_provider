import {
  RefreshRequest,
  RefreshResponse,
  SignOnRequest,
  SignOnResponse,
} from "../protocol/types.js";

/**
 * One identity node, as the proxy sees it.
 *
 * The monolith's `PastaOAuthProxy` held `IdentityNode` objects and called their methods
 * directly. Here a node is a remote HTTP service, so the proxy goes through this
 * interface instead and stays unaware of the transport. `HttpNodeClient` is the real
 * implementation; the tests supply an in-process one over a copied `IdentityNode`.
 *
 * `ownCommitment` is the `{ D, E }` this node returned from `commit(roundId)`. The node
 * needs it back because round 2 signs under the nonce pair it drew in round 1.
 */
export interface NodeClient {
  readonly nodeId: number;
  readonly url: string;

  commit(roundId: string): Promise<{ D: Uint8Array; E: Uint8Array }>;

  signOn(
    roundId: string,
    req: SignOnRequest,
    ownCommitment: { D: Uint8Array; E: Uint8Array }
  ): Promise<SignOnResponse>;

  refresh(
    roundId: string,
    req: RefreshRequest,
    ownCommitment: { D: Uint8Array; E: Uint8Array }
  ): Promise<RefreshResponse>;
}
