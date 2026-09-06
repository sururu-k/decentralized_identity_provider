import { SignOnRequest, SignOnResponse, SignRequest, SignResponse } from "../protocol/types.js";

/**
 * One identity node, as the proxy sees it (`docs/container-split.md` sections 5 and 14).
 *
 * The monolith's `PastaOAuthProxy` held `IdentityNode` objects and called their methods
 * directly. Here a node is a remote HTTP service, so the proxy goes through this
 * interface instead and stays unaware of the transport. `HttpNodeClient` is the real
 * implementation; the tests supply an in-process one over a copied `IdentityNode`.
 *
 * `ownCommitment` is the `{ D, E }` this node returned from `commit(roundId)`. The node
 * needs it back because round 2 signs under the nonce pair it drew in round 1. `/sign`
 * signs two messages, so it consumes two rounds and two of the node's commitments.
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

  sign(
    accessRoundId: string,
    refreshRoundId: string,
    req: SignRequest,
    accessOwnCommitment: { D: Uint8Array; E: Uint8Array },
    refreshOwnCommitment: { D: Uint8Array; E: Uint8Array }
  ): Promise<SignResponse>;
}
