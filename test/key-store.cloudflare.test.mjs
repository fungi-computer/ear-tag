import { env } from "cloudflare:workers";
import { describe } from "vitest";

import { registerKeyStoreBehaviors } from "./key-store-behaviors.js";

/**
 * Builds one fresh `KeyStoreDO` instance per test (a random name per call),
 * so tests never share Durable Object storage. The returned stub's public
 * methods mirror `KeyStore` exactly, so it plugs directly into the same
 * shared behavior suite the local `node:sqlite` fixture runs.
 */
async function createDurableObjectFixture(policy = {}) {
  const stub = env.EAR_TAG_KEYS.getByName(globalThis.crypto.randomUUID());
  await stub.setPolicy({ deny: policy.deny, bounded: policy.bounded });
  return {
    store: stub,
    fences: () => stub.fences(),
    advanceClock: (ms) => stub.advanceClock(ms),
    close: () => Promise.resolve(),
  };
}

describe("Ear Tag key store (real Durable Object SQLite)", () => {
  registerKeyStoreBehaviors(createDurableObjectFixture);
});
