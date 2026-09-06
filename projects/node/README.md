# node

The `IdentityNode` HTTP server. One container per node; the demo stack runs three of them
(`node1`, `node2`, `node3`) from the **same image**, told apart only by the config file
they are given.

A node holds one FROST key share of the group signing key and, per user, one TOPRF key
share plus the derived server key `h_i`. It never sees a password, never verifies one, and
never holds a finished token. It signs a byte-identical JWT payload with its share and
hands the share back encrypted under `h_i`, so only a client that knows the password can
decrypt and aggregate it.

See `docs/container-split.md` section 5 for the contract this implements.

## Quick start

```bash
npm install
npm test
npm run build

NODE_CONFIG=../dealer/sample-output/node-1.json PORT=4001 node dist/index.js
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
| `DEMO_LOG` | `1` | Demo trace on stdout. `0` leaves only the operational log lines. |
| `FORCE_COLOR` | set to `1` in the image | Colour even when stdout is not a terminal. `0` disables. |
| `NO_COLOR` | unset | Any non-empty value disables colour, whatever `FORCE_COLOR` says. |

`NODE_CONFIG` and `PORT` are read once at startup. A config file that is missing, unreadable, of the wrong
version, or internally inconsistent makes the process print one explanatory line and exit
`1` before it binds the port.

`PORT` must be plain decimal digits naming a port in `1..65535`; unset or empty means the
default. Anything else exits `1` the same way. Values `Number()` would quietly accept are
refused on purpose: `" "` is not port 0, `"1e3"` is not port 1000, and port 0 itself would
make the kernel pick an ephemeral port that neither the `HEALTHCHECK` nor the gateway
could find.

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

Users are registered from this file at startup. There is no registration endpoint.

## HTTP API

Every request and response is `application/json`. Byte strings on the wire are
**base64url without padding**, never raw `Uint8Array` (`docs/container-split.md` section
3). The gateway is the only intended caller.

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
| POST | `/refresh` | `{ "roundId": string, "request": RefreshRequestWire }` | `RefreshResponseWire` |

Paths are matched exactly: no trailing slash, no prefix. A `NODE_URLS` entry must
therefore end at the port, so that joining it with `/commit` yields exactly `/commit`.

`/commit` is FROST round 1: the node draws a single-use nonce pair for `roundId` and
returns the commitment. `/sign-on` and `/refresh` are round 2. The gateway sends the whole
commitment set, and the node picks out the entry whose `nodeId` is its own; that entry is
the commitment it signs under. A `roundId` is consumed by the first successful round 2, so
a replay is refused.

The wire types are the in-process types of `src/protocol/node.ts` with the two `Uint8Array`
fields base64url encoded. Fields that were already base64url strings (`blinded`,
`sessionNonce`, `toprfPartial`, `ct_i`) are unchanged. A field the node does not ask for
is dropped during decoding, so nothing extra in the body reaches `IdentityNode`.

`nonce` is the one optional field. **Omit the key entirely rather than sending `null`**:
`"nonce": null` is a 400 (`body.request.nonce must be a string`), because the node signs
`nonce: undefined` and `nonce: null` into different payload bytes, and a caller that meant
"no nonce" would otherwise get a token no other node agrees with. Every other field is
required, and `null` is never a substitute for a missing one.

```ts
interface CommitmentWire { nodeId: number; D: string; E: string }

interface SignOnRequestWire {
  sessionId: string;
  username: string;
  blinded: string;        // base64url Ristretto255 point A = r * H1(password)
  sessionNonce: string;   // base64url, 16 random bytes
  cnfJkt: string;
  nonce?: string;
  iat: number;
  exp: number;
  aud: string;
  iss: string;
  commitments: CommitmentWire[];
  allParticipants: number[];
}

interface SignOnResponseWire {
  nodeId: number;
  commitment: { D: string; E: string };
  toprfPartial: string;   // base64url Ristretto255 point B_i = k_i * A
  ct_i: string;           // base64url ChaCha20-Poly1305 ciphertext of { z_i, rs_i }
  sessionId: string;
  sub: string;
}

interface RefreshRequestWire {
  sessionId: string;
  dpopProof: string;
  expectedHtu: string;
  nonce?: string;
  iat: number;
  exp: number;
  aud: string;
  iss: string;
  commitments: CommitmentWire[];
  allParticipants: number[];
}

interface RefreshResponseWire {
  nodeId: number;
  commitment: { D: string; E: string };
  ct_i: string;           // base64url ciphertext of { z_i }, keyed by rk_i = HKDF(rs_i, ctr)
  ctr: number;
  sub: string;
}
```

`sub` always comes from the node's own user record. Nothing the caller sends can change
it, and the payload the node signs is AAD-bound to that `sub`, so a client that assumes a
different subject cannot decrypt the share it gets back.

### Status codes

| Code | When |
|---|---|
| 200 | Success. |
| 400 | Malformed JSON, a body that does not match the wire types, a commitment set with no entry for this node, or any rejection from `IdentityNode` (unknown user, spent round, unknown session, bad DPoP proof). The body is `{ "error": message }`. |
| 404 | Unknown path. |
| 405 | Known path, wrong method. The `Allow` header lists what is accepted. |
| 413 | Request body over 1 MiB. |
| 500 | Anything unexpected. The message is generic; details go to the log. |

Every non-200 answer, 404 and 405 included, has the body `{ "error": "<message>" }` and no
other field. There is no error code and no nested detail object: the string is meant for a
log line, not for branching on. A client that hangs up mid-request gets no answer at all.

## Demo log

The node prints, in English, what it received and what it computed with its own secrets,
and states once at startup what it structurally cannot hold (`docs/container-split.md`
section 10). Running the five services' logs side by side is what shows the audience that
no single component can assemble a token.

One event is one or two lines, prefixed `[nodeN]`; the event name sits in its own column
so the four columns line up:

```
[node1]   ● up      id=1 t=2/3 users=alice,bob   holds: s_1, k_1, h_1(alice,bob)   never: pw, h, other s_i/k_i, id_token
[node1]   commit    round=ef54f65f  → D_1,E_1 -HkVYv-D ZRLY4jT9
[node1]   sign-on   sess=8fa90b5e round=ef54f65f user=alice  ← A mNDkmKAj  (D,E)×3  nonce_s ueP7c3cV  jkt y7VfmjvC
                    → B_1=k_1·A YAU77MtM  ct_1=AEAD_h1(z_1‖rs_1) VchRFz8J
[node1]   commit    round=8837fc27  → D_1,E_1 _LxKOpaZ isQztEBa
[node1]   refresh   sess=8fa90b5e round=8837fc27 ctr=1  ← DPoP ✓  (D,E)×3  → ct_1=AEAD_rk1(z_1) yaMWc3hc
```

`←` is what arrived on the wire, `→` what this node produced from it. A rejection is a
single line carrying the reason the caller was given:

```
[node1]   ✖ sign-on rejected: Round 4f2a expired or not found on node 1
```

Rules the implementation keeps to:

- `never:` is stated once, on the `● up` line, and no later event repeats it: the audience
  reads it once per column instead of on every event.
- Per-session values (`A`, `B_i`, `ct_i`, `D`, `E`, `sessionNonce`, ids) are cut to their
  first 8 characters, with no ellipsis. Long-term secrets -- `secretKeyShare`, the TOPRF
  key share, `h_i` -- and the password never appear, not even as a prefix. `z_i` is named
  only inside the ciphertext it went into: it leaves `IdentityNode` already encrypted
  under `h_i`.
- Colour is on when stdout is a terminal or `FORCE_COLOR` is set, and off when `NO_COLOR`
  is set. The node is blue, shaded by node id. `docker compose logs` is not a terminal, so
  the image sets `FORCE_COLOR=1`. For plain text use `FORCE_COLOR=0`; `NO_COLOR=1` also
  works, but the Node runtime then prints its own warning that `NO_COLOR` is ignored
  because `FORCE_COLOR` is set, which is noise in a demo.
- `DEMO_LOG=0` removes the trace. The operational lines (`listening on`, shutdown, errors)
  are unaffected either way.

The trace lives in `src/demolog.ts` and is called from the HTTP handlers in `src/server.ts`.
`src/protocol/node.ts` is a frozen copy and knows nothing about it.

## Docker

```bash
docker build -t pasta-node ./projects/node

docker run -d --name node1 -p 4001:4001 \
  -e PORT=4001 -e NODE_CONFIG=/secrets/node-1.json \
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

Two maps inside `IdentityNode` only ever grow, because the copied protocol code is not
allowed to change (`docs/container-split.md` section 1) and neither map has an eviction
path the HTTP layer can reach:

- A `/commit` that is never followed by a `/sign-on` or `/refresh` leaves its nonce pair
  behind under that `roundId` forever. A successful round 2 deletes its own entry, and a
  second `/commit` for the same `roundId` replaces the pair rather than adding one.
- A sign-on session record stays until a `/refresh` finds it expired.

Neither is reachable from the browser: the contract puts the nodes on the compose network
with the gateway as the only caller, and the published ports are for debugging. Anything
that can reach a node directly can grow its heap by a few hundred bytes per request. A
long-lived deployment would want round expiry in `IdentityNode` itself.

## What is not here

No key generation (that is `dealer`), no user registration API, no OIDC endpoints and no
token assembly. A node cannot produce a token on its own: it never learns the password, so
it cannot decrypt its own `ct_i`, and below the threshold the shares do not aggregate.

## Tests

```bash
npm test
```

- `tests/demolog.test.ts` pins the demo log: the `DEMO_LOG` and colour switches, the
  8-character truncation, the column widths, that `never:` appears on the startup line and
  nowhere else, and -- over real HTTP, with `console.log` spied on -- that a sign-on trace
  contains neither the password nor any hex from the node's own config.
- `tests/config.test.ts` reads the dealer fixtures and pins the hex decoding, including
  the big-endian scalar order, plus the rejection paths.
- `tests/wire.test.ts` drives the two directions the node actually uses: it decodes
  literal request bodies of the shape the gateway is expected to send, and checks that an
  encoded response carries base64url and never a raw `Uint8Array`.
- `tests/node_protocol.test.ts` covers the node-only properties ported from the monolith's
  `tests/pasta_integration.test.ts` (commit `ba20f512`, since removed from this repository):
  single-use nonces, `sub` taken from the node record,
  the complete commitment set requirement, AAD binding across sessions, and node-side DPoP
  verification.
- `tests/e2e.test.ts` also covers concurrency: two rounds opened before either signs and
  finished in reverse order, four sign-ons in flight at once, and two refreshes in
  parallel. A node that let one round's nonces leak into another would produce a
  signature that does not verify.
- `tests/e2e.test.ts` starts all three nodes on ephemeral ports from
  `tests/fixtures/node-*.json` and drives the whole flow over HTTP, aggregating the token
  in the test and verifying it with `ed25519.verify` against the group public key in
  `tests/fixtures/group.json`. It covers 3-of-3, each 2-of-3 quorum, the wrong password,
  a spoofed subject, refresh, and the HTTP error surface.

`tests/fixtures/` is a copy of `projects/dealer/sample-output/`. Nothing in this project
reads outside its own directory.
