import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import {
  generateKey,
  generateKeyAndHash,
  hashKey,
} from "@fungi.computer/ear-tag";
import { defineGrants } from "@fungi.computer/ear-tag/grants";
import { createKeyStore, keyWire } from "@fungi.computer/ear-tag/keys";
import { fromNodeSqlite } from "@fungi.computer/ear-tag/keys/node";

const key = generateKey({ prefix: "test", length: 32 });
assert.match(key, /^test_.{32}$/);
assert.equal(
  await hashKey("abc"),
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
);
const generated = await generateKeyAndHash({ prefix: "test" });
assert.equal(generated.digest, await hashKey(generated.key));
assert.notEqual(generated.key, key);

const vocabulary = defineGrants({
  capabilities: ["files.read", "files.write"],
});
const grant = { capability: "files.read", targets: { kind: "all" } };

const database = new DatabaseSync(":memory:");
try {
  const store = createKeyStore({
    sql: fromNodeSqlite(database),
    commit: (body) => Promise.resolve(body()),
    vocabulary,
    prefix: "strg",
    authorizeIssuer: async () => ({ kind: "unrestricted" }),
  });
  const issued = await store.issue("owner", {
    name: "stranger",
    grants: [grant],
  });
  assert.equal(issued.kind, "ok");
  const verified = await store.verify(issued.value.key);
  assert.equal(verified.kind, "ok");
  assert.equal(verified.value.owner, "owner");
  assert.deepEqual(store.current(verified.value), verified);
  assert.deepEqual(await store.live({ keyId: verified.value.keyId }), verified);
  const summary = keyWire(vocabulary).toSummary(issued.value.record);
  assert.equal("digest" in summary, false);
  assert.equal("owner" in summary, false);
  assert.deepEqual(summary.grants, [grant]);
  const revoked = await store.revoke("owner", {
    requestId: "stranger-revoke",
    keyId: issued.value.record.keyId,
  });
  assert.equal(revoked.kind, "ok");
  const afterRevoke = await store.verify(issued.value.key);
  assert.equal(afterRevoke.kind, "error");
  assert.equal(afterRevoke.error.code, "denied");
  assert.equal(store.close(Date.now()).kind, "ok");
  assert.deepEqual(
    await store.issue("owner", { name: "closed", grants: [grant] }),
    { kind: "error", error: { code: "denied" } },
  );
} finally {
  database.close();
}
