import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";

import { fromNodeSqlite } from "../src/keys-node.js";
import { createKeyStore } from "../src/keys.js";
import { createCommit, createNodeSqliteFixture } from "./key-store-fixture.js";
import { registerKeyStoreBehaviors } from "./key-store-behaviors.js";
import { FIXTURE_CLOCK_START, testVocabulary } from "./test-vocabulary.js";

// The package's own `node:sqlite` adapter (@fungi.computer/ear-tag/keys/node),
// for hosts that run outside a Durable Object.
describe("Ear Tag key store (node:sqlite adapter)", () => {
  registerKeyStoreBehaviors(createNodeSqliteFixture);
});

describe("a key whose owner has left the tenant", () => {
  it("refuses every use with issuer_removed, and the owner's own calls with denied", async () => {
    const database = new DatabaseSync(":memory:");
    const removed = new Set<string>();
    const store = createKeyStore({
      sql: fromNodeSqlite(database),
      commit: createCommit(database),
      vocabulary: testVocabulary,
      prefix: "test",
      authorizeIssuer: (actorId) =>
        Promise.resolve(
          removed.has(actorId) ? "removed" : { kind: "unrestricted" },
        ),
      now: () => FIXTURE_CLOCK_START,
    });
    try {
      const issued = await store.issue("owner-a", {
        name: "outlives its owner",
        grants: [{ capability: "files.read", targets: { kind: "all" } }],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const principal = await store.verify(issued.value.key);
      if (principal.kind !== "ok") throw new Error("verify failed");
      removed.add("owner-a");
      const refusal = { kind: "error", error: { code: "issuer_removed" } };
      expect(await store.verify(issued.value.key)).toEqual(refusal);
      expect(await store.live({ keyId: principal.value.keyId })).toEqual(
        refusal,
      );
      expect(
        await store.admitUse(principal.value, {
          capability: "files.read",
          requestId: "after-removal",
        }),
      ).toEqual(refusal);
      expect(await store.list("owner-a")).toEqual({
        kind: "error",
        error: { code: "denied" },
      });
      expect(
        await store.issue("owner-a", {
          name: "after removal",
          grants: [{ capability: "files.read", targets: { kind: "all" } }],
        }),
      ).toEqual({ kind: "error", error: { code: "denied" } });
      await store.suspendOwner("owner-a", "completed-removal");
      const suspended = { kind: "error", error: { code: "key_suspended" } };
      for (const rejoined of [false, true]) {
        if (rejoined) removed.delete("owner-a");
        expect(await store.verify(issued.value.key)).toEqual(suspended);
        expect(await store.live({ keyId: principal.value.keyId })).toEqual(
          suspended,
        );
        expect(
          await store.admitUse(principal.value, {
            capability: "files.read",
            requestId: `durable-removal-${String(rejoined)}`,
          }),
        ).toEqual(suspended);
      }
    } finally {
      database.close();
    }
  });
});
