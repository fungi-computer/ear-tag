import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";

import {
  createKeyStore,
  type KeyCommittedEvent,
  type KeySql,
} from "../src/keys.js";
import { fromNodeSqlite } from "../src/keys-node.js";
import { createCommit } from "./key-store-fixture.js";
import {
  FIXTURE_CLOCK_START,
  testVocabulary,
  type TestCapability,
} from "./test-vocabulary.js";

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

  it("names the delegating key on a revocation it made", async () => {
    const database = new DatabaseSync(":memory:");
    const committed: KeyCommittedEvent<TestCapability>[] = [];
    const store = createKeyStore({
      sql: fromNodeSqlite(database),
      vocabulary: testVocabulary,
      prefix: "delegated",
      commit: createCommit(database),
      now: () => FIXTURE_CLOCK_START,
      authorizeIssuer: () => Promise.resolve({ kind: "unrestricted" }),
      onCommitted: (event) => {
        committed.push(event);
      },
    });
    const read = [
      { capability: "files.read", targets: { kind: "all" } },
    ] as const;
    try {
      const bot = await store.issue("human", {
        name: "deploy-bot",
        grants: read,
      });
      const target = await store.issue("human", { name: "ops", grants: read });
      if (bot.kind !== "ok" || target.kind !== "ok")
        throw new Error("issue failed");
      const parent = await store.live({ keyId: bot.value.record.keyId });
      if (parent.kind !== "ok") throw new Error("live failed");
      expect(
        (
          await store.revoke(
            "human",
            { requestId: "revoke", keyId: target.value.record.keyId },
            parent.value,
          )
        ).kind,
      ).toBe("ok");
      expect(
        committed
          .filter((event) => event.kind === "revoked")
          .map(({ parentKeyId, parentKeyName }) => ({
            parentKeyId,
            parentKeyName,
          })),
      ).toEqual([
        { parentKeyId: bot.value.record.keyId, parentKeyName: "deploy-bot" },
      ]);
    } finally {
      database.close();
    }
  });

  it("notifies each committed issue, grant edit and first revocation inside the commit, never a replay", async () => {
    const database = new DatabaseSync(":memory:");
    const committed: KeyCommittedEvent<TestCapability>[] = [];
    let failNotice = false;
    const store = createKeyStore({
      sql: fromNodeSqlite(database),
      vocabulary: testVocabulary,
      prefix: "committed",
      commit: createCommit(database),
      now: () => FIXTURE_CLOCK_START,
      authorizeIssuer: (actorId) =>
        Promise.resolve(
          actorId === "human"
            ? { kind: "unrestricted", attribution: "decided-as-human" }
            : null,
        ),
      onCommitted: (event) => {
        if (failNotice) throw new Error("host audit write failed");
        committed.push(event);
      },
    });
    const read = [
      { capability: "files.read", targets: { kind: "all" } },
    ] as const;
    const write = [
      { capability: "files.write", targets: { kind: "all" } },
    ] as const;
    try {
      const issued = await store.issue("human", { name: "ops", grants: read });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const keyId = issued.value.record.keyId;
      const edit = {
        requestId: "edit",
        keyId,
        expectedGrantVersion: 1,
        grants: write,
      };
      expect((await store.updateGrants("human", edit)).kind).toBe("ok");
      expect((await store.updateGrants("human", edit)).kind).toBe("ok");
      expect(
        await store.issue("stranger", { name: "refused", grants: read }),
      ).toMatchObject({ kind: "error" });
      expect(
        (await store.revoke("human", { requestId: "revoke", keyId })).kind,
      ).toBe("ok");
      expect(
        (await store.revoke("human", { requestId: "revoke", keyId })).kind,
      ).toBe("ok");
      expect(
        (await store.revoke("human", { requestId: "revoke-again", keyId }))
          .kind,
      ).toBe("ok");
      expect(
        committed.map(
          ({ kind, actorId, parentKeyId, attribution, record }) => ({
            kind,
            actorId,
            parentKeyId,
            attribution,
            keyId: record.keyId,
            grantVersion: record.grantVersion,
          }),
        ),
      ).toEqual([
        {
          kind: "issued",
          actorId: "human",
          parentKeyId: null,
          attribution: "decided-as-human",
          keyId,
          grantVersion: 1,
        },
        {
          kind: "grants_changed",
          actorId: "human",
          parentKeyId: null,
          attribution: "decided-as-human",
          keyId,
          grantVersion: 2,
        },
        {
          kind: "revoked",
          actorId: "human",
          parentKeyId: null,
          attribution: "decided-as-human",
          keyId,
          grantVersion: 2,
        },
      ]);
      expect(JSON.stringify(committed)).not.toContain(issued.value.key);
      failNotice = true;
      expect(
        await store.issue("human", { name: "rolled back", grants: read }),
      ).toMatchObject({ kind: "error" });
      failNotice = false;
      const listed = await store.list("human");
      if (listed.kind !== "ok") throw new Error("list failed");
      expect(listed.value.map((record) => record.name)).toEqual(["ops"]);
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
