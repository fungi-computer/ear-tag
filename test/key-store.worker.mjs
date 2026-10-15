import { DurableObject } from "cloudflare:workers";
import { createKeyStore } from "../src/keys.js";
import { testVocabulary, FIXTURE_CLOCK_START } from "./test-vocabulary.js";

/**
 * A real Durable Object wrapping `createKeyStore` over its own
 * `state.storage.sql` and `state.storage.transactionSync`, so the shared
 * behavior suite (`registerKeyStoreBehaviors`) runs the exact same
 * assertions against genuine DO SQLite, not an adapter standing in for it.
 *
 * Its public methods mirror `KeyStore<TestCapability>` 1:1, so a stub
 * returned by `env.EAR_TAG_KEYS.getByName(...)` is itself usable wherever a
 * `KeyStore` is expected: Workers RPC calls these the same way.
 */
export class KeyStoreDO extends DurableObject {
  #policy = { deny: new Set(), bounded: new Map() };
  // Starts at the same fixed instant the local node:sqlite fixture uses, so
  // hardcoded expiry offsets in the shared behavior suite mean the same
  // thing on both backends; it never falls back to the real wall clock.
  #now = FIXTURE_CLOCK_START;
  #fences = [];
  #store;

  constructor(ctx, env) {
    super(ctx, env);
    this.#store = createKeyStore({
      sql: ctx.storage.sql,
      commit: (body) => Promise.resolve(ctx.storage.transactionSync(body)),
      vocabulary: testVocabulary,
      prefix: "test",
      authorizeIssuer: (actorId) => {
        if (this.#policy.deny.has(actorId)) return Promise.resolve(null);
        const bounded = this.#policy.bounded.get(actorId);
        if (bounded !== undefined)
          return Promise.resolve({ kind: "bounded", grants: bounded });
        return Promise.resolve({ kind: "unrestricted" });
      },
      onAuthorityChange: (fence) => {
        this.#fences.push(fence);
      },
      now: () => this.#now,
    });
  }

  /**
   * Test-only control surface, not part of the `KeyStore` shape. Workers RPC
   * structured-clones `Set`/`Map` directly, so the test's own `FixturePolicy`
   * crosses unchanged.
   */
  setPolicy(policy) {
    this.#policy = {
      deny: policy.deny ?? new Set(),
      bounded: policy.bounded ?? new Map(),
    };
  }

  advanceClock(ms) {
    this.#now += ms;
  }

  fences() {
    return this.#fences;
  }

  issue(actorId, input) {
    return this.#store.issue(actorId, input);
  }

  verify(secret) {
    return this.#store.verify(secret);
  }

  current(principal) {
    return this.#store.current(principal);
  }

  list(actorId, owner) {
    return this.#store.list(actorId, owner);
  }

  read(actorId, keyId) {
    return this.#store.read(actorId, keyId);
  }

  updateGrants(actorId, input) {
    return this.#store.updateGrants(actorId, input);
  }

  revoke(actorId, input) {
    return this.#store.revoke(actorId, input);
  }

  suspendOwner(owner, requestId) {
    return this.#store.suspendOwner(owner, requestId);
  }

  revokeAll(closedAt) {
    return this.#store.revokeAll(closedAt);
  }

  admitUse(principal, input) {
    return this.#store.admitUse(principal, input);
  }

  touch(keyId) {
    return this.#store.touch(keyId);
  }
}

export default {
  fetch() {
    return new globalThis.Response("ear-tag key-store proof worker");
  },
};
