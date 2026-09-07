# dealer

Trusted dealer CLI for the PASTA / FROST identity provider. It runs **once**, before the
nodes start, and writes the key material every other component needs.

It is a one-shot batch job, not a server. In compose it runs to completion and the nodes
wait for it via `service_completed_successfully`.

See `docs/container-split.md` section 4 for the contract this implements.

## What it produces

1. A FROST master secret, split with Shamir secret sharing (t-of-n, default 2-of-3). Node
   `i` receives share `i`; the Ed25519 group public key goes to every file.
2. For each user, an independent TOPRF key, also split t-of-n. The dealer reproduces the
   client-side derivation of the master PRF value `h` and stores `deriveServerKey(h, i)`
   as that node's `h_i`.

**Passwords are never written to disk.** They are used only to derive `h`, which is not
invertible back to the password.

Users are pre-registered by the dealer; there is no registration API. The defaults are
`alice` / `password123` / `usr_alice_12345` and `bob` / `password456` / `usr_bob_67890`.

## Usage

```
node dist/index.js --out <dir> [options]
```

| Option | Default | Meaning |
|---|---|---|
| `--out <dir>` | (required) | Output directory. Created if it does not exist. |
| `--threshold <t>` | `2` | Signing threshold. Must satisfy `1 <= t <= n`. |
| `--total <n>` | `3` | Number of nodes. One `node-<id>.json` per node. |
| `--key-id <id>` | `pasta-group-key-1` | Written to `group.json` as `keyId`, and republished by the gateway as the JWKS `kid`. Must be non-empty. |
| `--users <list>` | `alice:password123:usr_alice_12345,bob:password456:usr_bob_67890` | Comma separated `<username>:<password>:<sub>` entries. |
| `--force` | off | Overwrite existing output files. |
| `--if-missing` | off | Exit `0` without writing when every output file already exists. |
| `-h`, `--help` | | Print usage. |

If any output file already exists and `--force` was not passed, the dealer writes nothing
and exits `1`. Every other error also exits `1`; success exits `0`.

`--if-missing` makes the dealer idempotent, which is what compose needs: if `group.json`
and every `node-<id>.json` for `1..total` is already there, it prints a line, writes
nothing and exits `0`, so restarting the stack does not rotate the keys. The check is
existence only; it does not read or validate the files. A **partial** set is not a usable
key set, so it is not treated as present: the dealer falls back to the normal rules and
exits `1`, or overwrites the whole set if `--force` is also given. The expected file names
follow `--total`, so asking for more nodes than are on disk is also a partial set. With a
complete set present, `--if-missing` wins over `--force` and nothing is rewritten.

In a `--users` entry the first and last colon are the separators, so a password may
contain colons. It may not contain a comma, which separates entries. Username, password
and `sub` must all be non-empty, and usernames and `sub`s must each be unique across the
list. An empty entry, from a doubled or trailing comma, is an error rather than a skipped
user, so a typo in the list fails loudly instead of quietly registering fewer people than
you asked for.

Each run generates fresh random key material. Re-running with `--force` invalidates every
key the nodes already hold.

### Local run

```bash
npm install
npm run build
node dist/index.js --out ../../secrets
```

During development you can skip the build with `npm run dev -- --out ../../secrets`.

## Output format

All byte strings and scalars are **lowercase hex**. A scalar is 64 hex digits: 32 bytes,
big-endian, zero padded. This matches `docs/container-split.md` section 3. Note that HTTP
traffic between the running services uses base64url instead; the hex encoding is specific
to these files.

`<out>/group.json`, read by the gateway (`docs/container-split.md` section 4 also lists
rp, but section 7 has rp take the verification key from the gateway's JWKS instead, so
rp never opens this file):

```json
{
  "version": 1,
  "threshold": 2,
  "total": 3,
  "keyId": "pasta-group-key-1",
  "groupPublicKey": "<hex 64>"
}
```

`<out>/node-<id>.json` for id `1..total`, read by the node with that id:

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

`toprfKeyShare.id` always equals `nodeId`.

## Reading the files

Every hex field is fixed width, and each one decodes to one of exactly two things.

| Field | Decodes to | Length |
|---|---|---|
| `groupPublicKey` | `Uint8Array`, compressed Ed25519 point | 32 bytes (64 hex digits) |
| `secretKeyShare` | `bigint`, Shamir share of the FROST master secret mod the Ed25519 group order | 32 bytes (64 hex digits) |
| `toprfKeyShare.value` | `bigint`, Shamir share of that user's TOPRF key | 32 bytes (64 hex digits) |
| `h_i` | `Uint8Array`, the node's ChaCha20-Poly1305 key for that user | 32 bytes (64 hex digits) |

A scalar is **big-endian**, so decode it with `BigInt("0x" + hex)` and nothing else. In
particular do not route it through `scalarToBytes` from the monolith's `src/crypto/frost.ts`
(commit `ba20f512`, since removed from this repository): that helper is little-endian, and
using it here silently yields a different, wrong scalar.
Bytes decode pairwise:

```ts
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
```

This directory's `src/hex.ts` holds both decoders (`hexToScalar`, `hexToBytes`) if you
would rather copy them than retype them.

### Building an `IdentityNode` from `node-<id>.json`

`nodeId`, `secretKeyShare` and `groupPublicKey` are the three constructor arguments, in
that order. Each entry of `users` is one `registerUser` call, and `toprfKeyShare` maps
straight onto the `Share` type (`{ id, value }`):

```ts
const cfg = JSON.parse(readFileSync(process.env.NODE_CONFIG!, "utf8"));

const node = new IdentityNode(
  cfg.nodeId,
  BigInt("0x" + cfg.secretKeyShare),
  hexToBytes(cfg.groupPublicKey)
);

for (const u of cfg.users) {
  node.registerUser(
    u.username,
    u.sub,
    { id: u.toprfKeyShare.id, value: BigInt("0x" + u.toprfKeyShare.value) },
    hexToBytes(u.h_i)
  );
}
```

`toprfKeyShare.id` is always equal to `nodeId`, so a file whose ids disagree is either
hand-edited or the wrong node's file. Checking that on startup, along with the 32-byte
length of `h_i` and `groupPublicKey`, turns a mismatched mount into a clear startup error
instead of a decryption failure at sign-on time.

Passwords are not in these files and cannot be recovered from them. A node never learns a
password: it only holds `h_i`, and only a client that derived the same `h` through the
TOPRF can decrypt what the node encrypts under it.

## sample-output/

`sample-output/` holds one real run of the CLI with the default arguments. It is the
fixture source for the node and gateway test suites, so it is committed to the repository
on purpose. These are demo keys with no value; never reuse them for anything real.

`tests/sample-output.test.ts` runs the committed files through the same verification a
fresh run gets, so a corrupted or hand-edited fixture fails `npm test` here rather than
somewhere downstream. Regenerate it only when the output format changes:

```bash
npm run dev -- --out sample-output --force
```

## Docker

```bash
docker build -t pasta-dealer ./projects/dealer
mkdir -p ./secrets
docker run --rm -v "$(pwd)/secrets:/secrets" pasta-dealer --out /secrets
```

The image is a `node:22-alpine` multi-stage build. The runtime stage carries only `dist/`
and production dependencies, and runs as the unprivileged `node` user (uid 1000). The
`ENTRYPOINT` is the CLI itself, so arguments after the image name go straight to it. There
is no `HEALTHCHECK`: the container exits as soon as the files are written.

Because the container is not root, the mounted output directory must be writable by uid
1000. Docker Desktop on macOS maps ownership for you, so the command above works as
written. On native Linux, where the mount keeps the host's uid, run the container as
yourself instead:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)/secrets:/secrets" pasta-dealer --out /secrets
```

The output files are written with the default mode (`0644` under a normal umask), so any
container that mounts the directory can read them regardless of its uid. Protect the
directory itself: `secrets/` is gitignored, and it holds the nodes' secret key shares.

## Compose

```yaml
services:
  dealer:
    build: ./projects/dealer
    command: ["--out", "/secrets", "--if-missing"]
    volumes:
      - ./secrets:/secrets
    restart: "no"

  node1:
    depends_on:
      dealer:
        condition: service_completed_successfully
    volumes:
      - ./secrets:/secrets:ro
    environment:
      NODE_CONFIG: /secrets/node-1.json
```

`--if-missing` is what makes a repeated `docker compose up` work. The first run writes the
key material; every later run finds the complete set, writes nothing and exits `0`, so
`service_completed_successfully` is satisfied and the nodes keep the keys they already
hold. Without the flag the second run would exit `1` and block every node from starting.

To rotate keys deliberately, `rm -rf secrets/` and bring the stack up again.

## Tests

```bash
npm test
```

`tests/dealer.test.ts` checks the two completion conditions from the contract: two of the
three `secretKeyShare` values reconstruct a secret whose group public key equals the one
in `group.json`, and two `toprfKeyShare` values plus the password recompute an `h` whose
`deriveServerKey(h, i)` equals every node's `h_i`. It also checks that a single share and
a wrong password both fail, and that no password appears in the output.

Both checks run over every 2-of-3 quorum, and the same checker runs against a 3-of-5
configuration and against `sample-output/`.

`tests/cli.test.ts` runs the CLI as a child process and checks the four generated files,
the exit `1` on pre-existing files, `--force` overwriting, the `--if-missing` cases
(complete set kept byte for byte, partial set rejected, empty directory generated), and
argument handling including the rejected `--users` lists.

`tests/verify.ts` is the shared checker both suites call.

## Layout

```
src/crypto/       verbatim copies of src/crypto/{frost,shamir,toprf}.ts from the monolith
src/hex.ts        hex encoding for the output files
src/dealer.ts     key generation, produces the file contents
src/cli.ts        argument parsing and file writing
src/index.ts      entry point
tests/verify.ts   shared verification of an output set, used by two test suites
```

`src/crypto/` must stay byte-identical to the monolith's `src/crypto/`. The monolith's
`src/` was removed from this repository once all components were split out; its last
state is commit `ba20f512`. Verify with:

```bash
git show ba20f512:src/crypto/frost.ts | diff - src/crypto/frost.ts
git show ba20f512:src/crypto/shamir.ts | diff - src/crypto/shamir.ts
git show ba20f512:src/crypto/toprf.ts | diff - src/crypto/toprf.ts
```
