import crypto from "node:crypto";
import { ristretto255 } from "@noble/curves/ed25519";
import { aggregateSignatureShares, computeGroupCommitment } from "../../src/crypto/frost.js";
import { blind, deriveServerKey, finalize, unblind } from "../../src/crypto/toprf.js";
import { aeadDecrypt, deriveAeadNonce } from "../../src/crypto/aead.js";
import { assembleJwt, base64UrlDecode, base64UrlEncode, createSigningInput } from "../../src/jwt/jwt.js";
import { signOnResultFromWire } from "../../src/gateway/wire.js";

/**
 * The browser client's sign-on, run in a test (`docs/container-split.md` section 14).
 *
 * This is the "SDK equivalent" the e2e uses in place of the frozen `client-sdk/client.ts`,
 * which minted an id_token whose payload no longer matches what the node signs. Here the
 * assertion is assembled from the section 14 payload -- `client_id`, `scope`, `nonce=c`,
 * `aud=iss` -- so its group signature verifies and it is spendable at `/token` as the
 * authorization code.
 *
 * It uses only the frozen crypto copies under `src/`, exactly as the browser SDK does: it
 * blinds the password, sends the blinded point, unblinds the TOPRF partials to recover
 * `h`, decrypts each `ct_i` under `h_i`, and aggregates the FROST signature locally. The
 * gateway and the nodes never see the password.
 */

export interface AssembleAssertionOptions {
  gatewayUrl: string;
  issuer: string;
  username: string;
  password: string;
  clientId: string;
  scope: string;
  /** The authorize challenge `c`, signed as the assertion's `nonce`. */
  nonce: string;
  /** The RP front end's DPoP thumbprint the assertion binds to. */
  cnfJkt: string;
  participants?: number[];
  /** Override the assertion lifetime (default 30 s, the node's cap). */
  lifetimeSeconds?: number;
}

export interface AssembledAssertion {
  assertion: string;
  sub: string;
  sessionId: string;
}

export async function assembleAssertion(
  options: AssembleAssertionOptions
): Promise<AssembledAssertion> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (options.lifetimeSeconds ?? 30);

  const { blinding, blinded } = blind(options.password);
  const sessionNonce = crypto.randomBytes(16);

  const res = await fetch(`${options.gatewayUrl}/api/pasta/sign-on`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: options.username,
      blinded: base64UrlEncode(blinded.toRawBytes()),
      sessionNonce: base64UrlEncode(sessionNonce),
      cnfJkt: options.cnfJkt,
      clientId: options.clientId,
      scope: options.scope,
      nonce: options.nonce,
      iat: now,
      exp,
      iss: options.issuer,
      participants: options.participants,
    }),
  });
  if (!res.ok) {
    throw new Error(`sign-on failed with status ${res.status}: ${await res.text()}`);
  }
  const signOn = signOnResultFromWire(await res.json());
  const sub = signOn.nodeResponses[0]?.sub ?? options.username;

  // The byte-identical assertion payload the node signs (node README section 14).
  const header = { alg: "EdDSA", typ: "JWT", kid: "pasta-group-key-1" };
  const payload = {
    iss: options.issuer,
    sub,
    aud: options.issuer,
    client_id: options.clientId,
    scope: options.scope,
    cnf: { jkt: options.cnfJkt },
    nonce: options.nonce,
    iat: now,
    exp,
  };
  const { signingInput, headerB64, payloadB64 } = createSigningInput(header, payload);

  // Recover the master PRF value h by unblinding the TOPRF partials.
  const partials = signOn.nodeResponses.map((r) => ({
    id: r.nodeId,
    point: ristretto255.Point.fromBytes(base64UrlDecode(r.toprfPartial)),
  }));
  const v = unblind(blinding, partials);
  const h = finalize(options.password, v);

  // Decrypt each { z_i } under h_i (AAD = signing input) and aggregate the signature.
  const shares: bigint[] = [];
  for (const nodeResp of signOn.nodeResponses) {
    const h_i = deriveServerKey(h, nodeResp.nodeId);
    const aeadNonce = deriveAeadNonce(sessionNonce, nodeResp.nodeId);
    let decrypted: Uint8Array;
    try {
      decrypted = aeadDecrypt(h_i, aeadNonce, base64UrlDecode(nodeResp.ct_i), signingInput);
    } catch {
      throw new Error(
        `Failed to decrypt share from node ${nodeResp.nodeId}. Invalid password or corrupted share.`
      );
    }
    const parsed = JSON.parse(Buffer.from(decrypted).toString("utf8"));
    shares.push(BigInt(parsed.z_i));
  }

  const R = computeGroupCommitment(signingInput, signOn.commitments);
  const signature = aggregateSignatureShares(R, shares);
  const assertion = assembleJwt(headerB64, payloadB64, signature);

  return { assertion, sub, sessionId: signOn.sessionId };
}
