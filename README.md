# Ear Tag (`@fungi.computer/ear-tag`)

Ear Tag is an independent, modular key server for TypeScript hosts. Its base
entrypoint creates cryptographically random bearer keys and SHA-256 digests, so
a host can issue a secret like an invite code or an API key without inventing
its own random-string and hashing logic. `./grants` builds a typed
capability-grant vocabulary, and `./keys` runs a tenant-scoped key store on top
of it: issuance, verification, compare-and-swap grant edits, revocation,
optional expiry, owner suspension and a per-key rate limit. The owner decides
scope, storage and policy; Ear Tag owns the mechanics.

## Install or set up

```sh
npm install @fungi.computer/ear-tag
```

The package ships ESM only and depends on [Cairn](../cairn/README.md) for
identifiers and random strings, and on `zod` for its schemas. Hashing uses the
global Web Crypto API (`crypto.subtle.digest`), available in Node 19+ and in
Workers runtimes. It has four entrypoints: `@fungi.computer/ear-tag` (the crypto
primitives), `@fungi.computer/ear-tag/grants` (the grant vocabulary),
`@fungi.computer/ear-tag/keys` (the key store, free of any Node-specific type)
and `@fungi.computer/ear-tag/keys/node` (the `node:sqlite` adapter, so a Worker
consumer of `./keys` never needs `@types/node` to typecheck).

## Quick start

This helper creates a prefixed key, stores its digest, then hands the plaintext
to the host's authorized delivery function. The host supplies both operations;
neither the key nor the digest is logged:

```ts
import { generateKeyAndHash } from "@fungi.computer/ear-tag";

export async function issueInvite(
  storeDigest: (digest: string) => Promise<void>,
  deliverKey: (key: string) => Promise<void>,
): Promise<void> {
  const { key, digest } = await generateKeyAndHash({ prefix: "invite" });
  await storeDigest(digest);
  await deliverKey(key);
}
```

The existing tests verify that a generated digest matches the plaintext key in
[`test/crypto.test.ts`](test/crypto.test.ts).

## Core concepts

`generateKey(options)` returns a random bearer string. An optional prefix adds
`<prefix>_` before the random portion. `length` controls the random portion's
length. `hashKey(key)` returns its SHA-256 digest as lowercase hexadecimal.
`generateKeyAndHash(options)` creates both values and returns `{ key, digest }`.

## Grants and the key store

`./grants` declares one host's capability vocabulary and returns the schemas and
operations closed over it:

```ts
import { defineGrants } from "@fungi.computer/ear-tag/grants";

const vocabulary = defineGrants({
  capabilities: ["files.read", "files.write"] as const,
});
```

`./keys` runs a tenant-scoped key store over that vocabulary. `sql` is the
`exec(statement, ...bindings) -> { toArray() }` shape Cloudflare Durable Object
SQLite already provides; `./keys/node`'s `fromNodeSqlite` adapts a `node:sqlite`
database for hosts that run outside a Durable Object:

```ts
import { createKeyStore } from "@fungi.computer/ear-tag/keys";
import { fromNodeSqlite } from "@fungi.computer/ear-tag/keys/node";
import { DatabaseSync } from "node:sqlite";

const store = createKeyStore({
  sql: fromNodeSqlite(new DatabaseSync(":memory:")),
  commit: (body) => Promise.resolve(body()),
  vocabulary,
  prefix: "demo",
  authorizeIssuer: async () => ({ kind: "unrestricted" }),
});

const issued = await store.issue("owner-1", {
  name: "ci bot",
  grants: [{ capability: "files.read", targets: { kind: "all" } }],
});
```

Every operation returns a `KeyOutcome`: `{ kind: "ok", value }` or
`{ kind: "error", error: { code, retryAfterSeconds? } }`, with `code` one of
`invalid` (the caller's own request failed validation), `denied` (well-formed
but refused on its merits), `conflict`, `expired`, `rate_limited` or
`unavailable` (the store's own state could not be read back; always logged). One
store instance is one tenant; namespacing between tenants is the host's own
table or storage boundary.

`authorizeIssuer`'s `"bounded"` only narrows which grants an actor may assign
through `issue` or `updateGrants`. It does not narrow which keys that actor may
`list`, `revoke` or edit: any actor it resolves to a non-null authority for may
manage every key in the tenant, including keys another actor issued. This
matches Hub's own `authorizeManage`. `implies` is one level deep, not
transitive.

## API reference

See the generated API reference for [the crypto primitives](docs/api/index.md),
[`./grants`](docs/api/grants.md), [`./keys`](docs/api/keys.md) and
[`./keys/node`](docs/api/keys-node.md), or start from
[the index](docs/api/README.md).

## Examples and checks

The crypto tests cover hashing, prefixed generation, and the key/digest pair.
The grants and key-store tests cover issuance, verification, compare-and-swap
grant edits and replay, authority-change fencing, a stale captured principal,
revocation, optional expiry, owner suspension, the per-key rate limit, bounded
sub-issuance and bounded grant edits, and `admitUse` on an expired or suspended
key, run through the exact same assertions against two backends: a real
Cloudflare Durable Object (`pnpm run test:cloudflare`, real `state.storage.sql`
and `transactionSync`, not an adapter standing in for them) and the package's
own `node:sqlite` adapter (`pnpm run test:node`). Run everything with:

```sh
pnpm --filter @fungi.computer/ear-tag test
```

## Limits and errors

A bearer key is a secret: anyone who obtains it can present it to the system
that accepts it. Do not log or persist plaintext keys. Retain the digest and
give the plaintext only to its intended recipient.

`hashKey` requires Web Crypto's `crypto.subtle.digest`. Key length follows
Cairn's raw `nanoid` sizing behavior. Callers should supply a bounded
nonnegative integer rather than untrusted sizing input.

The key store's rate limit is counted in memory, not persisted; it resets if the
host recreates the store (for example a Durable Object waking from eviction). A
`KeyPrincipal` returned by `verify` is a plain, unsealed data object: `current`
and `admitUse` accept one back to resume a session cheaply, but they re-read the
live key row and its grant version on every call, so a fabricated or stale
principal is refused rather than trusted.

## Contribute and license

Ear Tag is MIT licensed. See [`LICENSE`](LICENSE).
