import { describe } from "vitest";

import { createNodeSqliteFixture } from "./key-store-fixture.js";
import { registerKeyStoreBehaviors } from "./key-store-behaviors.js";

// The package's own `node:sqlite` adapter (@fungi.computer/ear-tag/keys/node),
// for hosts that run outside a Durable Object.
describe("Ear Tag key store (node:sqlite adapter)", () => {
  registerKeyStoreBehaviors(createNodeSqliteFixture);
});
