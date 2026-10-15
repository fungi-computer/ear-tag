import { defineGrants } from "../src/grants.js";

// Shared by every key-store test fixture (local node:sqlite and the real
// Durable Object), so both run the exact same vocabulary and behaviors.
// Carries no `node:sqlite` import, so a Worker-side test can import it too.

export type TestCapability = "files.read" | "files.write" | "files.manage";

export const testVocabulary = defineGrants({
  capabilities: ["files.read", "files.write", "files.manage"] as const,
});

/** Every fixture's virtual clock starts at this same instant. */
export const FIXTURE_CLOCK_START = 1_700_000_000_000;
