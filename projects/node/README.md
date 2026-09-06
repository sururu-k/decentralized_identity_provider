# node

The `IdentityNode` HTTP server. One container per node; the demo stack runs three of them
(`node1`, `node2`, `node3`) from the **same image**, told apart only by the config file
they are given.

A node holds one FROST key share of the group signing key and, per user, one TOPRF key
share plus the derived server key `h_i`. It never sees a password, never verifies one, and
never holds a finished token.

It signs two different things, and decides both on its own (`docs/container-split.md`
section 14):

1. **The authentication assertion**, at `/sign-on`, which is also the authorization code.
   The signature share comes back encrypted under `h_i`, so only a client that knows the
   password can decrypt it and assemble the assertion.
2. **The access token and the next refresh token**, at `/sign`, in the clear -- against
   that same assertion presented back to it, together with a DPoP proof from the key the
   assertion is bound to. The refresh token is itself a group-signed JWT
   (`typ: refresh+jwt`), so a later refresh grant presents it in place of the assertion
   and the gateway keeps no state of its own either.

**The node keeps no session state.** The only thing it remembers between two requests is
the FROST nonce pair of an open round. Everything the access token asserts -- `sub`,
`client_id`, `scope`, `cnf.jkt` -- travels inside the assertion, under the group
signature, so the gateway cannot widen a token; `sub` itself is put there from the node's
own user record at sign-on. The gateway supplies only `iat`, `exp` and `jti`, because
every node must sign byte-identical bytes, and the node range-checks those.

See `docs/container-split.md` sections 5 and 14 for the contract this implements.

## Quick start

```bash
npm install
npm test
npm run build

NODE_CONFIG=../dealer/sample-output/node-1.json PORT=4001 ISSUER=http://localhost:3000 node dist/index.js
```

During development `npm run dev` runs the same thing through `tsx` without a build step.

The dealer must have run first: it writes the `node-<id>.json` this server reads. See
`dealer/README.md`.

```bash
curl -s http://localhost:4001/health
```

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `NODE_CONFIG` | `/secrets/node.json` | Path to the dealer's `node-<id>.json`. |
| `PORT` | `4000` | Listen port. In compose, node `N` listens on `400N`. |
| `ISSUER` | `http://localhost:3000` | The URL the browser sees the gateway at. The node signs it as `iss`, requires it as the assertion's `aud`, and expects DPoP proofs bound to `<ISSUER>/token`. |
| `DEMO_LOG` | `1` | Demo trace on stdout. `0` leaves only the operational log lines. |
| `FORCE_COLOR` | set to `1` in the image | Colour even when stdout is not a terminal. `0` disables. |
| `NO_COLOR` | unset | Any non-empty value disables colour, whatever `FORCE_COLOR` says. |

All three of `NODE_CONFIG`, `PORT` and `ISSUER` are read once at startup. A config file that is missing,
unreadable, of the wrong version, or internally inconsistent makes the process print one
explanatory line and exit `1` before it binds the port.

`PORT` must be plain decimal digits naming a port in `1..65535`; unset or empty means the
default. Anything else exits `1` the same way. Values `Number()` would quietly accept are
refused on purpose: `" "` is not port 0, `"1e3"` is not port 1000, and port 0 itself would
make the kernel pick an ephemeral port that neither the `HEALTHCHECK` nor the gateway
could find.

`ISSUER` must be an absolute `http`/`https` URL with no query string and no fragment. A
trailing slash is trimmed rather than refused, so `http://localhost:3000/` and
`http://localhost:3000` name the same issuer; the contract asks for the second form
(`docs/container-split.md` section 2). **It must be the same string the gateway
publishes.** A node whose `ISSUER` differs refuses `/sign-on` outright (see `iss` below),
and would otherwise sign an access token no relying party accepts.

## Config file format

The file is the dealer's `node-<id>.json`, exactly as written (`docs/container-split.md`
sections 3 and 4). Every byte string and every scalar is lowercase hex; a scalar is 64 hex
digits, 32 bytes, **big-endian**, restored with `BigInt("0x" + hex)`.

```json
{
  "version": 1,
  "nodeId": 1,
  "threshold": 2,
  "total": 3,
  "groupPublicKey": "<hex 64>",
  "secretKeyShare": "<hex 64>",
  "users": [
    {
      "username": "alice",
      "sub": "usr_alice_12345",
      "toprfKeyShare": { "id": 1, "value": "<hex 64>" },
      "h_i": "<hex 64>"
    }
  ]
}
```

Checked at startup: `version` is `1`; `nodeId` is at least 1 and at most `total`;
`1 <= threshold <= total`; `groupPublicKey`, `secretKeyShare` and every `h_i` are 32 bytes
of hex; usernames are unique; and every `toprfKeyShare.id` equals `nodeId`, so a node can
never be started with another node's shares.

Users are registered from this file at startup. There is no registration endpoint. The
JWT header `kid` is the dealer's frozen `pasta-group-key-1`; the config file does not
carry it.

## HTTP API

Every request and response is `application/json`. Byte strings on the wire are
**base64url without padding**, never raw `Uint8Array` (`docs/container-split.md` section
3). The scalars on the wire, the two `z_i`, follow the scalar convention of the same
section:
64 lowercase hex digits, big-endian, read back with `BigInt("0x" + hex)`. The gateway is
the only intended caller.

Responses always carry `Content-Type: application/json` and `Cache-Control: no-store`.
Requests are read as JSON whatever their `Content-Type` says, so a caller that forgets the
header still works; send `application/json` anyway, and expect that leniency to go away
rather than be relied on. A body that does not parse as JSON is a 400, including an empty
body and a form-encoded one.

| Method | Path | Request | Response |
|---|---|---|---|
| GET | `/health` | - | `{ "status": "ok", "nodeId": 1, "groupPublicKey": "<b64u>" }` |
| POST | `/commit` | `{ "roundId": string }` | `{ "nodeId": 1, "D": "<b64u>", "E": "<b64u>" }` |
| POST | `/sign-on` | `{ "roundId": string, "request": SignOnRequestWire }` | `SignOnResponseWire` |
| POST | `/sign` | `{ "roundId": string, "refreshRoundId": string, "request": SignRequestWire }` | `SignResponseWire` |

`POST /refresh` and `POST /authenticate` **are both gone** (section 14). There is no
refresh grant on the node -- the gateway calls `/sign` again with the same assertion and a
fresh proof -- and no session to promote, so nothing to authenticate against. `rs_i`,
`rk_i` and the session counter no longer exist, and `src/crypto/kdf.ts` was deleted with
them.

Paths are matched exactly: no trailing slash, no prefix. A `NODE_URLS` entry must
therefore end at the port, so that joining it with `/commit` yields exactly `/commit`.

`/commit` is FROST round 1: the node draws a single-use nonce pair for `roundId` and
returns the commitment. `/sign-on` and `/sign` are round 2. **`/sign` signs two different
messages, so it consumes two rounds**: the gateway calls `/commit` twice per node, sends
both commitment sets, and names both round ids in the envelope. `roundId` is the access
token's round and `refreshRoundId` the refresh token's; a body naming the same id twice is
a 400, because one Schnorr nonce pair over two messages would leak the key share. In each
set the node picks out the entry whose `nodeId` is its own; that entry is the commitment
it signs under. A `roundId` is consumed by the first successful round 2, so a replay is
refused.

A field the node does not ask for is dropped during decoding, so nothing extra in the body
reaches `IdentityNode`: a `sub`, `aud` or `scope` smuggled into a `/sign` request is
ignored, not honoured.

`nonce` on `/sign-on` is the one optional field. **Omit the key entirely rather than
sending `null`**: `"nonce": null` is a 400 (`body.request.nonce must be a string`), because
the node signs `nonce: undefined` and `nonce: null` into different payload bytes. In the
OAuth flow the gateway always sends its authorize challenge `c` as `nonce`, and it should:
an assertion signed without one serializes to `"nonce":undefined`, which is not parseable
JSON, so `/sign` cannot read it back. Every other field is required, and `null` is never a
substitute for a missing one.

### Wire types

```ts
interface CommitmentWire { nodeId: number; D: string; E: string }

interface SignOnRequestWire {
  sessionId: string;
  username: string;
  blinded: string;        // base64url Ristretto255 point A = r * H1(password)
  sessionNonce: string;   // base64url, 16 random bytes
  cnfJkt: string;         // RFC 7638 thumbprint of the rp front-end's DPoP key
  clientId: string;       // OAuth client_id, signed into the assertion as client_id
  scope: string;          // OAuth scope, signed into the assertion; may be ""
  nonce?: string;         // the gateway's authorize challenge c
  iat: number;            // integer seconds, within ±60s of the node's clock
  exp: number;            // integer seconds; exp - iat must be 1..30
  iss: string;            // must equal the node's own ISSUER
  commitments: CommitmentWire[];
  allParticipants: number[];
}

interface SignOnResponseWire {
  nodeId: number;
  commitment: { D: string; E: string };
  toprfPartial: string;   // base64url Ristretto255 point B_i = k_i * A
  ct_i: string;           // base64url ChaCha20-Poly1305 ciphertext of { z_i }
  sessionId: string;
  sub: string;
}

interface AccessTokenClaimsWire {
  iat: number;            // integer seconds, within ±60s of the node's clock
  exp: number;            // integer seconds; exp - iat must be 1..3600
  jti: string;            // non-empty; the access token's own id
}

interface SignRequestWire {
  grant: "authorization_code" | "refresh_token";
  assertion?: string;     // authorization_code: the assembled assertion, i.e. the code
  refreshToken?: string;  // refresh_token: a refresh token this group signed earlier
  dpopProof: string;      // RFC 9449 proof for POST <ISSUER>/token
  claims: AccessTokenClaimsWire;
  refreshExp?: number;    // exp of the new refresh token; default claims.iat + 30 days
  commitments: CommitmentWire[];        // the access token's round
  refreshCommitments: CommitmentWire[]; // the refresh token's round
  allParticipants: number[];
}

interface SignedShareWire {
  commitment: { D: string; E: string };  // this node's commitment in that round
  z_i: string;            // plaintext FROST share, 64 lowercase hex digits, big-endian
}

interface SignResponseWire {
  nodeId: number;
  at: SignedShareWire;    // the access token
  rt: SignedShareWire;    // the refresh token, from the refreshCommitments round
}
```

`SignOnRequestWire` has no `aud`: the assertion is addressed to the issuer, and the client
id it once carried is now `clientId`, which is signed into the assertion for the access
token to use later. `SignRequestWire` carries no identity claims and no session id at all
-- the credential is the identity -- and `SignResponseWire` returns none either. Only the
credential the `grant` names is read: a body carrying both is not a way to choose which
one gets verified.

### JSON examples

```jsonc
// POST /sign-on
{
  "roundId": "5657a04a-2a1e-4f6e-9a2c-1f9d0b3c5e77",
  "request": {
    "sessionId": "548fa582-9a1b-4c3d-8e5f-0a1b2c3d4e5f",
    "username": "alice",
    "blinded": "vIqbtKRE9m1Zr0Xk8Qw3eRt5yUiOpAsDfGhJkLzXcVb",
    "sessionNonce": "IyTsHv2yQw3eRt5yUiOpAg",
    "cnfJkt": "QJkBBMt5oLQ3lJ3JgV8p0k1r7cQnB2xXe1a9mVYt0aM",
    "clientId": "demo_client",
    "scope": "openid profile",
    "nonce": "9f3c1a20",
    "iat": 1757030400,
    "exp": 1757030430,
    "iss": "http://localhost:3000",
    "commitments": [
      { "nodeId": 1, "D": "zVBDfyR0...", "E": "L8mmwSe4..." },
      { "nodeId": 2, "D": "...", "E": "..." },
      { "nodeId": 3, "D": "...", "E": "..." }
    ],
    "allParticipants": [1, 2, 3]
  }
}
// 200
{
  "nodeId": 1,
  "commitment": { "D": "zVBDfyR0...", "E": "L8mmwSe4..." },
  "toprfPartial": "pKrPZ0fW...",
  "ct_i": "n_4T-Hk6...",
  "sessionId": "548fa582-9a1b-4c3d-8e5f-0a1b2c3d4e5f",
  "sub": "usr_alice_12345"
}

// POST /sign  (grant = authorization_code)
{
  "roundId": "b740757e-4b2a-4c1d-9e3f-5a6b7c8d9e0f",
  "refreshRoundId": "660d2a29-1c3b-4d5e-8f70-2a3b4c5d6e7f",
  "request": {
    "grant": "authorization_code",
    "assertion": "eyJhbGciOiJFZERTQSIsImtpZCI6InBhc3RhLWdyb3VwLWtleS0xIiwidHlwIjoiSldUIn0.eyJhdWQ...Q.V0RbbHeU...",
    "dpopProof": "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVkRFNBIiwiandrIjp7Li4ufX0.eyJqdGkiOiI2NzllZDUwYSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvdG9rZW4iLCJpYXQiOjE3NTcwMzA0MDB9.sig",
    "claims": {
      "iat": 1757030400,
      "exp": 1757034000,
      "jti": "a1f0b6d2-6e2c-4f0a-9a3d-6b7c8e9f0a1b"
    },
    "commitments": [
      { "nodeId": 1, "D": "Du7MVsHX...", "E": "4kD8pZhL..." },
      { "nodeId": 2, "D": "...", "E": "..." },
      { "nodeId": 3, "D": "...", "E": "..." }
    ],
    "refreshCommitments": [
      { "nodeId": 1, "D": "4IcexnxI...", "E": "_xL3tUgj..." },
      { "nodeId": 2, "D": "...", "E": "..." },
      { "nodeId": 3, "D": "...", "E": "..." }
    ],
    "allParticipants": [1, 2, 3]
  }
}
// 200
{
  "nodeId": 1,
  "at": {
    "commitment": { "D": "Du7MVsHX...", "E": "4kD8pZhL..." },
    "z_i": "02b02c6440e6c5b8f1d2a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f8"
  },
  "rt": {
    "commitment": { "D": "4IcexnxI...", "E": "_xL3tUgj..." },
    "z_i": "0a40caa30e6c5b8f1d2a3b4c5d6e7f80912a3b4c5d6e7f80912a3b4c5d6e7f80"
  }
}

// POST /sign  (grant = refresh_token) -- same shape, the credential is the refresh token
{
  "roundId": "a3cc3498-...",
  "refreshRoundId": "02ca8e60-...",
  "request": {
    "grant": "refresh_token",
    "refreshToken": "eyJhbGciOiJFZERTQSIsImtpZCI6InBhc3RhLWdyb3VwLWtleS0xIiwidHlwIjoicmVmcmVzaCtqd3QifQ...QnSnfzRi...",
    "dpopProof": "...",
    "claims": { "iat": 1757030400, "exp": 1757034000, "jti": "..." },
    "commitments": [ /* ... */ ],
    "refreshCommitments": [ /* ... */ ],
    "allParticipants": [1, 2, 3]
  }
}
```

## What the node signs

Both payloads go through the copied `createSigningInput` of `src/jwt/jwt.ts`, which
serializes with **`deterministicJsonStringify`: object keys are sorted lexicographically,
at every level**. So the order the keys are written in below does not reach the wire --
the alphabetical order does, and that is what the gateway and the browser must reproduce
byte for byte. Nested `cnf` is sorted too (it has one key). Numbers are plain JSON
integers.

`signingInput = base64url(headerJson) + "." + base64url(payloadJson)`, and the finished
JWT is `signingInput + "." + base64url(signature)` where the signature is
`R ‖ Σ z_i` over the whole participant set.

### Assertion (`/sign-on`)

| Where | Key | Value |
|---|---|---|
| header | `alg` | `EdDSA` |
| header | `typ` | `JWT` |
| header | `kid` | `pasta-group-key-1` |
| payload | `iss` | the node's `ISSUER` |
| payload | `sub` | from the node's user record |
| payload | `aud` | the node's `ISSUER` -- the assertion is addressed to the gateway |
| payload | `client_id` | the request's `clientId` -- becomes the access token's `aud` |
| payload | `scope` | the request's `scope` -- becomes the access token's `scope` |
| payload | `cnf` | `{ "jkt": <cnfJkt from the request> }` |
| payload | `nonce` | the request's `nonce` (the authorize challenge `c`) |
| payload | `iat` | the request's `iat` |
| payload | `exp` | the request's `exp` |

Serialized, sorted:

```
{"alg":"EdDSA","kid":"pasta-group-key-1","typ":"JWT"}
{"aud":"http://localhost:3000","client_id":"demo_client","cnf":{"jkt":"QJkBBMt5oLQ3lJ3JgV8p0k1r7cQnB2xXe1a9mVYt0aM"},"exp":1757030430,"iat":1757030400,"iss":"http://localhost:3000","nonce":"9f3c1a20","scope":"openid profile","sub":"usr_alice_12345"}
```

### Access token (`/sign`, both grants)

| Where | Key | Value |
|---|---|---|
| header | `alg` | `EdDSA` |
| header | `typ` | `at+jwt` |
| header | `kid` | `pasta-group-key-1` |
| payload | `iss` | the node's `ISSUER` |
| payload | `sub` | the assertion's `sub` |
| payload | `aud` | the assertion's `client_id` |
| payload | `scope` | the assertion's `scope` |
| payload | `cnf` | `{ "jkt": <the assertion's cnf.jkt> }` |
| payload | `iat` | the request's `iat` |
| payload | `exp` | the request's `exp` |
| payload | `jti` | the request's `jti` |

Serialized, sorted:

```
{"alg":"EdDSA","kid":"pasta-group-key-1","typ":"at+jwt"}
{"aud":"demo_client","cnf":{"jkt":"QJkBBMt5oLQ3lJ3JgV8p0k1r7cQnB2xXe1a9mVYt0aM"},"exp":1757034000,"iat":1757030400,"iss":"http://localhost:3000","jti":"a1f0b6d2-6e2c-4f0a-9a3d-6b7c8e9f0a1b","scope":"openid profile","sub":"usr_alice_12345"}
```

### Refresh token (`/sign`, both grants)

| Where | Key | Value |
|---|---|---|
| header | `alg` | `EdDSA` |
| header | `typ` | `refresh+jwt` |
| header | `kid` | `pasta-group-key-1` |
| payload | `iss` | the node's `ISSUER` |
| payload | `sub` | the credential's `sub` |
| payload | `cnf` | `{ "jkt": <the credential's cnf.jkt> }` |
| payload | `client_id` | the credential's `client_id` |
| payload | `scope` | the credential's `scope` |
| payload | `iat` | `claims.iat`, the same instant the access token carries |
| payload | `exp` | `refreshExp`, or `claims.iat + 30 days` when the gateway omits it |

There is no `aud` and no `jti`: the refresh token is presented back to the same issuer,
and it is not tracked. Every `/sign` mints a new one, whichever grant was used, so the
gateway can rotate; **the previous refresh token keeps working until it expires**, because
invalidating it would need exactly the state this design gives up (section 14.3).

Serialized, sorted:

```
{"alg":"EdDSA","kid":"pasta-group-key-1","typ":"refresh+jwt"}
{"client_id":"demo_client","cnf":{"jkt":"QJkBBMt5oLQ3lJ3JgV8p0k1r7cQnB2xXe1a9mVYt0aM"},"exp":1759622400,"iat":1757030400,"iss":"http://localhost:3000","scope":"openid profile","sub":"usr_alice_12345"}
```

## What the node verifies

`/sign-on`

- `iss` equals the node's own `ISSUER`, exactly.
- `iat` is within ±60 s of the node's clock, and `exp - iat` is `1..30` seconds. Together
  those cap how long an authorization code can live: a node will not mint a long-lived
  one.
- The commitment set contains this node, and `roundId` still has an unused nonce pair.
- The user exists. **The password is not checked**, here or anywhere.

`/sign` -- all of it against the request itself, since the node holds no session. The two
grants differ only in which credential is verified:

- The credential's Ed25519 signature verifies under the group public key, `alg` is
  `EdDSA`, and `typ` is `JWT` for an `authorization_code` grant or `refresh+jwt` for a
  `refresh_token` grant. That `typ` check is what stops one of the three group-signed JWTs
  from being spent as another: all three carry the same signature.
- The credential has not expired, and its own `exp - iat` is `1..30` for an assertion,
  `1..40 days` for a refresh token.
- The credential's `iss` equals the node's `ISSUER`, an assertion's `aud` does too, and
  `sub`, `client_id` and `cnf.jkt` are present and non-empty.
- The DPoP proof verifies (RFC 9449): `alg` `EdDSA`, `typ` `dpop+jwt`, an OKP/Ed25519
  `jwk` in the header, a valid signature, `htm` `POST`, `htu` exactly
  **`<ISSUER>/token`** -- computed by the node, never taken from the request -- and `iat`
  within ±60 s of the node's clock.
- The proof's `jkt` equals the **credential's** `cnf.jkt`.
- `claims.iat` is within ±60 s of the node's clock, `claims.exp - claims.iat` is
  `1..3600`, and `claims.jti` is non-empty.
- The new refresh token's `exp - claims.iat` is `1..40 days`, whatever `refreshExp` asks
  for.
- `roundId` and `refreshRoundId` are different, and each still has an unused nonce pair.

**The proof's `jti` is deliberately not recorded, and neither is a spent refresh token.** A
replayed `/sign` inside the credential's window returns the same pair of tokens, bound to
the same `cnf.jkt`, which the replayer cannot use without the DPoP private key; a rotated
refresh token's predecessor keeps working until it expires. Not tracking either is what
lets the node stay stateless (section 14.3).

Every rejection is a 400 whose body is `{ "error": "<message>" }`, and the message names
the reason (`htu mismatch`, `thumbprint mismatch`, `Token expired`, `typ at+jwt is not
refresh+jwt`, `Access token lifetime 3601s out of range`, `two different rounds`, and so
on).

`sub` comes from the node's own user record at sign-on, and `client_id`, `scope` and
`cnf.jkt` from the credential the node itself signed. Nothing the caller sends alongside
can change them. The assertion payload is also AAD-bound to that `sub`, so a client that
assumes a different subject cannot even decrypt the share it gets back.

### Status codes

| Code | When |
|---|---|
| 200 | Success. |
| 400 | Malformed JSON, a body that does not match the wire types, a commitment set with no entry for this node, two identical round ids, or any rejection from `IdentityNode` (unknown user, spent round, unverifiable or expired credential, bad DPoP proof, out-of-range claims). The body is `{ "error": message }`. |
| 404 | Unknown path, `/refresh` and `/authenticate` included. |
| 405 | Known path, wrong method. The `Allow` header lists what is accepted. |
| 413 | Request body over 1 MiB. |
| 500 | Anything unexpected. The message is generic; details go to the log. |

Every non-200 answer, 404 and 405 included, has the body `{ "error": "<message>" }` and no
other field. There is no error code and no nested detail object: the string is meant for a
log line, not for branching on. A client that hangs up mid-request gets no answer at all.

## Changes to `src/protocol/node.ts`

The file is a copy of the monolith's `src/protocol/node.ts` (commit `ba20f512`) and was
**frozen until section 14 unfroze it**. The cryptographic steps are unchanged -- TOPRF
evaluation, `computeSignatureShare`, the AEAD with AAD = signing input, all still call the
frozen `src/crypto/*` and `src/jwt/jwt.ts` in the same way. What changed:

- **`NodeSessionRecord` and the session map are gone entirely**, and with them
  `getSession`. The only state left is `activeNonces`, the FROST nonce pair of an open
  round. `rs_i`, `ctr`, the `authenticated` flag and the spent-`jti` set no longer exist.
- The constructor takes `issuer` (and an optional `keyId`, default `pasta-group-key-1`).
  `tokenEndpoint` is `<issuer>/token`.
- `SignOnRequest` gained `clientId` and `scope`, and lost `aud`. The signed payload is the
  assertion above instead of an id_token: it carries `client_id`, `scope` and `cnf.jkt`
  so the later `/sign` can read them back. `iat` freshness and `exp - iat ≤ 30` are
  enforced, and `ct_i` now encrypts `{ z_i }` alone -- **`rs_i` is no longer bundled in**.
- `handleRefresh`, `RefreshRequest` and `RefreshResponse` were deleted, and with them the
  only use of `src/crypto/kdf.ts`, which was deleted too (section 1: files a component
  does not use are not carried).
- `handleSign(rounds, req, commitments)`, `verifyAssertion` and `verifyRefreshToken` were
  added, with the checks listed above. `handleSign` takes two round ids and two of this
  node's commitments, the credential named by `grant`, a proof and the pinned claims, and
  returns `{ nodeId, at: { commitment, z_i }, rt: { commitment, z_i } }` -- two signatures,
  no session id. It refuses two identical round ids outright, since signing two messages
  under one nonce pair would leak the key share.
- `scalarToHex` was added, so `/sign` can return `z_i` in the repository's scalar encoding.

## Demo log

The node prints, in English, what it received and what it computed with its own secrets,
and states once at startup what it structurally cannot hold (`docs/container-split.md`
section 10). Running the services' logs side by side is what shows the audience that no
single component can assemble a token.

One event is one or two lines, prefixed `[nodeN]`; the event name sits in its own column
so the columns line up. This is real output, `FORCE_COLOR=0`:

```
[node1]   ● up      id=1 t=2/3 users=alice,bob   holds: s_1, k_1, h_1(alice,bob)   never: pw, h, other s_i/k_i, sessions, access tokens
[node1]   commit    round=b21f1130  → D_1,E_1 D3U4-Jaw 1ITHa_UE
[node1]   sign-on   sess=448e27a4 round=b21f1130 user=alice  ← A xIjqAcs2  (D,E)×3  nonce_s -fiUOAck  jkt i1vGu7wP
                    → B_1=k_1·A mjbh8XVp  ct_1=AEAD_h1(z_1) x_Kditc3
[node1]   commit    round=251be551  → D_1,E_1 f_BPq9Nt kede3hcz
[node1]   commit    round=d1da8d12  → D_1,E_1 pzf8ZuXZ bbb08_a9
[node1]   sign      round=251be551 grant=authz  ← assertion σ mK6dmuJ2 ✓  DPoP ✓ jti 8934a7e1  (D,E)×3  → at z_1 02c62021 + rt(refresh+jwt) z_1 09f8b8d4
[node1]   commit    round=11624ca1  → D_1,E_1 6DkvrmvF qnJVifNt
[node1]   commit    round=4bdbf4d0  → D_1,E_1 lL91JHKp jV7swT0q
[node1]   sign      round=11624ca1 grant=refresh  ← refresh_token σ ZZN3QJN2 ✓ (typ=refresh+jwt)  DPoP ✓ jti 15906f06  (D,E)×3  → at z_1 0b49a0e5 + rt z_1 0ed11cf1
[node1]   ✖ sign rejected: Node 1 rejected refresh_token: typ at+jwt is not refresh+jwt
```

`←` is what arrived on the wire, `→` what this node produced from it. A rejection is a
single line carrying the reason the caller was given.

Rules the implementation keeps to:

- `never:` is stated once, on the `● up` line, and no later event repeats it. `sessions`
  is on that list because the node keeps none, and `access tokens` because it signs a
  share of one and never sees the assembled token -- the same is true of the refresh token
  it signs. The assertion is not on the list: it arrives at `/sign`, and the node verifies
  it.
- Per-round values (`A`, `B_i`, `ct_i`, `D`, `E`, `sessionNonce`, both `z_i`, a DPoP
  `jti`, a credential signature, ids) are cut to their first 8 characters, with no ellipsis. Nothing
  in the trace is a whole credential: neither the assertion nor the access token appears.
  Long-term secrets -- `secretKeyShare`, the TOPRF key share, `h_i` -- and the password
  never appear, not even as a prefix. A `z_i` is shown only at `/sign`, where it is a
  masked scalar the node put on the wire anyway; at `/sign-on` it is named only inside the
  ciphertext it went into.
- Colour is on when stdout is a terminal or `FORCE_COLOR` is set, and off when `NO_COLOR`
  is set. The node is blue, shaded by node id. `docker compose logs` is not a terminal, so
  the image sets `FORCE_COLOR=1`. For plain text use `FORCE_COLOR=0`; `NO_COLOR=1` also
  works, but the Node runtime then prints its own warning that `NO_COLOR` is ignored
  because `FORCE_COLOR` is set, which is noise in a demo.
- `DEMO_LOG=0` removes the trace. The operational lines (`listening on`, shutdown, errors)
  are unaffected either way.

The trace lives in `src/demolog.ts` and is called from the HTTP handlers in
`src/server.ts`. `src/protocol/node.ts` knows nothing about it.

## Docker

```bash
docker build -t pasta-node ./projects/node

docker run -d --name node1 -p 4001:4001 \
  -e PORT=4001 -e ISSUER=http://localhost:3000 -e NODE_CONFIG=/secrets/node-1.json \
  -v "$PWD/projects/dealer/sample-output:/secrets:ro" \
  pasta-node
```

Multi-stage `node:22-alpine`; the runtime stage carries `dist/` and production
dependencies only and runs as the unprivileged `node` user, uid 1000. It only ever reads
its config, so mount the secrets directory read-only; the dealer writes `0644`, which uid
1000 can read.

`HEALTHCHECK` polls `/health` through the Node runtime, since alpine ships no curl, using
the stack-wide standard from `docs/container-split.md` section 8: `--interval=5s
--timeout=3s --start-period=3s --retries=3`. A fresh container reports healthy about five
seconds in. That matters because compose gates the gateway on `service_healthy`: every
second here is a second the whole stack waits.

`SIGTERM` stops the listener, lets in-flight requests finish, and exits `0`.

## Known limits

One map inside `IdentityNode` can grow: a `/commit` that is never followed by a `/sign-on`
or a `/sign` leaves its nonce pair behind under that `roundId` forever. A successful round
2 deletes its own entry -- a `/sign` deletes both of its rounds -- and a second `/commit`
for the same `roundId` replaces the pair rather than adding one. Nothing else is kept: with the session store gone, a node's memory
no longer grows with the number of users who sign in.

It is not reachable from the browser either: the contract puts the nodes on the compose
network with the gateway as the only caller, and the published ports are for debugging.
Anything that can reach a node directly can grow its heap by a few hundred bytes per
request. A long-lived deployment would want round expiry inside `IdentityNode` itself.

## What is not here

No key generation (that is `dealer`), no user registration API, no OAuth endpoints, no
token assembly and no sessions. A node cannot produce a token on its own: it never learns
the password, so it cannot decrypt its own `ct_i`, and below the threshold the shares do
not aggregate. It does sign refresh tokens, but it does not store, rotate or revoke them:
each `/sign` mints the next one and forgets it.

## Tests

```bash
npm test
```

- `tests/node_protocol.test.ts` drives `IdentityNode` in process: the assertion (single-use
  round nonces, `sub` from the node record, `client_id` and `scope` carried in the
  payload, the complete commitment set, AAD binding across sessions, the 30 s lifetime
  cap, the `iat` freshness and `iss` checks) and `/sign` (both tokens signed from claims
  read out of the credential, plaintext hex shares that aggregate into a verifiable
  `at+jwt` and `refresh+jwt`, the refusal to use one FROST round for both, the
  `refresh_token` grant and its rotation, a tampered or expired credential, each of the
  three JWT types offered in another's place, a proof with the wrong key / URL / method, a
  deliberately accepted proof replay, and every claim range including `refreshExp`).
- `tests/e2e.test.ts` starts all three nodes on ephemeral ports from
  `tests/fixtures/node-*.json` and drives the whole flow over HTTP -- `/commit`,
  `/sign-on`, then two `/commit` calls and `/sign` -- aggregating the assertion, the access
  token and the refresh token in the test and verifying all three with `ed25519.verify`
  against the group public key in `tests/fixtures/group.json`. It covers 3-of-3 and each
  2-of-3 quorum, the wrong password, a spoofed subject, the `refresh_token` grant with a
  foreign key and with a forged or mistyped token, `/refresh` and `/authenticate`
  answering 404, the HTTP error surface, and concurrency: two rounds opened before either
  signs and finished in reverse order, four sign-ons in flight at once, two issuances in
  parallel.
- `tests/wire.test.ts` drives the two directions the node actually uses: it decodes
  literal request bodies of the shape the gateway is expected to send, and checks that an
  encoded response carries base64url, both hex shares, and never a raw `Uint8Array`.
- `tests/config.test.ts` reads the dealer fixtures and pins the hex decoding, including
  the big-endian scalar order, plus `PORT`, `ISSUER` and the rejection paths.
- `tests/demolog.test.ts` pins the demo log: the `DEMO_LOG` and colour switches, the
  8-character truncation, the column widths, that `never:` appears on the startup line and
  nowhere else, and -- over real HTTP, with `console.log` spied on -- that a sign-on and
  sign trace contains neither the password, nor any hex from the node's own config, nor
  the assertion, nor either assembled token.

`tests/fixtures/` is a copy of `projects/dealer/sample-output/`. Nothing in this project
reads outside its own directory.
