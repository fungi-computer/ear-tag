import { DatabaseSync } from "node:sqlite";

import type { Grant } from "../src/grants.js";
import { fromNodeSqlite } from "../src/keys-node.js";
import {
  createKeyStore,
  type AuthorityFence,
  type IssuerAuthority,
  type KeyStore,
} from "../src/keys.js";
import {
  testVocabulary,
  FIXTURE_CLOCK_START,
  type TestCapability,
} from "./test-vocabulary.js";

export function createCommit(
  database: DatabaseSync,
): <Value>(body: () => Value) => Promise<Value> {
  let counter = 0;
  return function commit<Value>(body: () => Value): Promise<Value> {
    return Promise.resolve().then(() => {
      const name = `ear_tag_test_${String(counter++)}`;
      database.exec(`SAVEPOINT ${name}`);
      try {
        const value = body();
        database.exec(`RELEASE ${name}`);
        return value;
      } catch (error) {
        database.exec(`ROLLBACK TO ${name}`);
        database.exec(`RELEASE ${name}`);
        throw error;
      }
    });
  };
}

function mutableClock(start: number) {
  let time = start;
  return {
    now: () => time,
    advance: (ms: number) => {
      time += ms;
    },
  };
}

/** A key-store test double, built the same way against every SQL backend. */
export type TestFixture = Readonly<{
  store: KeyStore<TestCapability>;
  /** Every authority-change fence recorded so far, in order. */
  fences: () => Promise<readonly AuthorityFence[]>;
  /** Move the fixture's virtual clock forward by this many milliseconds. */
  advanceClock: (ms: number) => Promise<void>;
  /** Release any resources the fixture holds. */
  close: () => Promise<void>;
}>;

/** Per-test authorization policy a fixture's `authorizeIssuer` reads. */
export type FixturePolicy = Readonly<{
  bounded?: ReadonlyMap<string, readonly Grant<TestCapability>[]>;
  deny?: ReadonlySet<string>;
}>;

/** Builds one fresh, isolated key-store test double. */
export type CreateFixture = (policy?: FixturePolicy) => Promise<TestFixture>;

function authorizeIssuerFor(
  policy: FixturePolicy,
): (actorId: string) => Promise<IssuerAuthority<TestCapability> | null> {
  return (actorId) => {
    if (policy.deny?.has(actorId)) return Promise.resolve(null);
    const bounded = policy.bounded?.get(actorId);
    if (bounded !== undefined)
      return Promise.resolve({ kind: "bounded", grants: bounded });
    return Promise.resolve({ kind: "unrestricted" });
  };
}

/**
 * A key store over a real, in-memory `node:sqlite` database through the
 * package's own `fromNodeSqlite` adapter.
 */
export function createNodeSqliteFixture(
  policy: FixturePolicy = {},
): Promise<TestFixture> {
  const database = new DatabaseSync(":memory:");
  const clock = mutableClock(FIXTURE_CLOCK_START);
  const fences: AuthorityFence[] = [];
  const store = createKeyStore({
    sql: fromNodeSqlite(database),
    commit: createCommit(database),
    vocabulary: testVocabulary,
    prefix: "test",
    authorizeIssuer: authorizeIssuerFor(policy),
    onAuthorityChange: (fence) => {
      fences.push(fence);
    },
    now: clock.now,
  });
  return Promise.resolve({
    store,
    fences: () => Promise.resolve(fences),
    advanceClock: (ms) => {
      clock.advance(ms);
      return Promise.resolve();
    },
    close: () => {
      database.close();
      return Promise.resolve();
    },
  });
}

export {
  testVocabulary,
  FIXTURE_CLOCK_START,
  type TestCapability,
} from "./test-vocabulary.js";
