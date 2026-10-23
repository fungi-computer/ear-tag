import { DatabaseSync } from "node:sqlite";

import {
  generateKey,
  generateKeyAndHash,
  hashKey,
  type GeneratedKey,
  type GenerateKeyOptions,
} from "@fungi.computer/ear-tag";
import {
  defineGrants,
  type Grant,
  type GrantVocabulary,
} from "@fungi.computer/ear-tag/grants";
import {
  createKeyStore,
  keyWire,
  type KeyOutcome,
  type KeyPrincipal,
  type KeyStore,
} from "@fungi.computer/ear-tag/keys";
import { fromNodeSqlite } from "@fungi.computer/ear-tag/keys/node";

const options: GenerateKeyOptions = { prefix: "test", length: 32 };
const key: string = generateKey(options);
const digest: string = await hashKey(key);
const generated: GeneratedKey = await generateKeyAndHash(options);
void [digest, generated];

type Capability = "files.read" | "files.write";
const vocabulary: GrantVocabulary<Capability> = defineGrants({
  capabilities: ["files.read", "files.write"] as const,
});
const grant: Grant<Capability> = {
  capability: "files.read",
  targets: { kind: "all" },
};

const database = new DatabaseSync(":memory:");
const store: KeyStore<Capability> = createKeyStore({
  sql: fromNodeSqlite(database),
  commit: (body) => Promise.resolve(body()),
  vocabulary,
  prefix: "strg",
  authorizeIssuer: () => Promise.resolve({ kind: "unrestricted" }),
});

const issued: KeyOutcome<{ key: string }> = await store.issue("owner", {
  name: "stranger",
  grants: [grant],
});
if (issued.kind === "ok") {
  const verified: KeyOutcome<KeyPrincipal<Capability>> = await store.verify(
    issued.value.key,
  );
  if (verified.kind === "ok") {
    const current: KeyOutcome<KeyPrincipal<Capability>> = store.current(
      verified.value,
    );
    const live: KeyOutcome<KeyPrincipal<Capability>> = await store.live({
      keyId: verified.value.keyId,
      grantVersion: verified.value.grantVersion,
    });
    void [current, live];
  }
}
const wire = keyWire(vocabulary);
const request = wire.revoke.parse({ keyId: "key-id", requestId: "request-id" });
void request;
const closed: KeyOutcome<void> = store.close(Date.now());
void closed;
database.close();
