import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";

import { createKeyStore, type KeySql } from "../src/keys.js";
import { fromNodeSqlite } from "../src/keys-node.js";
import { createCommit } from "./key-store-fixture.js";
import { FIXTURE_CLOCK_START, testVocabulary } from "./test-vocabulary.js";

describe("key contract at the synchronous SQL host boundary", () => {
  it("K3: closure during issuer authorization still refuses the issuing commit", async () => {
    const database = new DatabaseSync(":memory:");
    let authorize: () => Promise<void> = () => Promise.resolve();
    const store = createKeyStore({
      sql: fromNodeSqlite(database),
      vocabulary: testVocabulary,
      prefix: "closure",
      commit: createCommit(database),
      now: () => FIXTURE_CLOCK_START,
      authorizeIssuer: async () => {
        await authorize();
        return { kind: "unrestricted" };
      },
    });
    try {
      authorize = () => {
        expect(store.close(FIXTURE_CLOCK_START).kind).toBe("ok");
        return Promise.resolve();
      };
      expect(
        await store.issue("human", {
          name: "racing closure",
          grants: [{ capability: "files.read", targets: { kind: "all" } }],
        }),
      ).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      database.close();
    }
  });

  it("K7: listing metadata does not select a key digest", async () => {
    const database = new DatabaseSync(":memory:");
    const delegate = fromNodeSqlite(database);
    const statements: string[] = [];
    const sql: KeySql = {
      exec: (statement, ...bindings) => {
        statements.push(statement);
        return delegate.exec(statement, ...bindings);
      },
    };
    const store = createKeyStore({
      sql,
      vocabulary: testVocabulary,
      prefix: "metadata",
      commit: createCommit(database),
      authorizeIssuer: () => Promise.resolve({ kind: "unrestricted" }),
    });
    try {
      const issued = await store.issue("human", {
        name: "metadata key",
        grants: [{ capability: "files.read", targets: { kind: "all" } }],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      statements.length = 0;
      const listed = await store.list("human");
      expect(listed.kind).toBe("ok");
      expect(
        statements.filter((statement) => statement.startsWith("SELECT")),
      ).not.toHaveLength(0);
      for (const statement of statements)
        if (statement.startsWith("SELECT"))
          expect(statement).not.toContain("digest");
      expect(JSON.stringify(listed)).not.toContain("digest");
      expect(JSON.stringify(listed)).not.toContain(issued.value.key);
    } finally {
      database.close();
    }
  });

  it("K6: current is synchronous and does not spend another verification rate slot", async () => {
    const database = new DatabaseSync(":memory:");
    const store = createKeyStore({
      sql: fromNodeSqlite(database),
      vocabulary: testVocabulary,
      prefix: "sync",
      commit: createCommit(database),
      now: () => FIXTURE_CLOCK_START,
      authorizeIssuer: () => Promise.resolve({ kind: "unrestricted" }),
    });
    try {
      const issued = await store.issue("human", {
        name: "one verification",
        grants: [{ capability: "files.read", targets: { kind: "all" } }],
        rateLimit: { limit: 1, windowSeconds: 60 },
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const verified = await store.verify(issued.value.key);
      if (verified.kind !== "ok") throw new Error("verify failed");
      expect(store.current(verified.value)).toEqual(verified);
      expect(store.current(verified.value)).toEqual(verified);
      expect(await store.verify(issued.value.key)).toEqual({
        kind: "error",
        error: { code: "rate_limited", retryAfterSeconds: 60 },
      });
    } finally {
      database.close();
    }
  });
});
