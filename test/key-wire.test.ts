import { DatabaseSync } from "node:sqlite";
import { expect, it } from "vitest";
import { createKeyStore, keyWire } from "../src/keys.js";
import { fromNodeSqlite } from "../src/keys-node.js";
import { createCommit } from "./key-store-fixture.js";
import { testVocabulary } from "./test-vocabulary.js";

it("decodes the owner's secret-free summary at a JSON consumer boundary", async () => {
  const database = new DatabaseSync(":memory:");
  try {
    const store = createKeyStore({
      sql: fromNodeSqlite(database),
      commit: createCommit(database),
      vocabulary: testVocabulary,
      prefix: "wire",
      authorizeIssuer: () => Promise.resolve({ kind: "unrestricted" }),
    });
    const issued = await store.issue("human", {
      name: "Reader",
      grants: [{ capability: "files.read", targets: { kind: "all" } }],
    });
    if (issued.kind !== "ok") throw new Error("fixture issuance refused");
    const wire = keyWire(testVocabulary);
    const summary = wire.toSummary(issued.value.record);
    expect(wire.summary.parse(JSON.parse(JSON.stringify(summary)))).toEqual(
      summary,
    );
    expect(wire.summary.safeParse({ ...summary, owner: "human" }).success).toBe(
      false,
    );
    expect(
      wire.summary.safeParse({
        ...summary,
        grants: [{ capability: "undeclared", targets: { kind: "all" } }],
      }).success,
    ).toBe(false);
  } finally {
    database.close();
  }
});
