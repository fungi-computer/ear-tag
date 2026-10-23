import { DurableObject } from "cloudflare:workers";
import { createKeyStore } from "../src/keys.js";
import { testVocabulary, FIXTURE_CLOCK_START } from "./test-vocabulary.js";
import { createEpochFixture } from "./key-epoch.fixture.js";

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
  #epochs;

  constructor(ctx, env) {
    super(ctx, env);
    this.#epochs = createEpochFixture((body) =>
      Promise.resolve(ctx.storage.transactionSync(body)),
    );
    this.#store = createKeyStore({
      sql: ctx.storage.sql,
      commit: this.#epochs.commit,
      epoch: this.#epochs.epoch,
      vocabulary: testVocabulary,
      delegation: { manage: "files.manage" },
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

  epochEvents() {
    return this.#epochs.events();
  }

  failNext(at) {
    this.#epochs.failNext(at);
  }

  issue(actorId, input, parent) {
    return this.#store.issue(actorId, input, parent);
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

  live(ref) {
    return this.#store.live(ref);
  }

  updateGrants(actorId, input, parent) {
    return this.#store.updateGrants(actorId, input, parent);
  }

  revoke(actorId, input) {
    return this.#store.revoke(actorId, input);
  }

  suspendOwner(owner, requestId) {
    return this.#store.suspendOwner(owner, requestId);
  }

  close(closedAt) {
    return this.#store.close(closedAt);
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
