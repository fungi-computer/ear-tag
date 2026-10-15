import { describe, expect, it } from "vitest";

import { generateKey, generateKeyAndHash, hashKey } from "../src/index.js";

describe("Ear Tag crypto", () => {
  it("hashes keys with SHA-256", async () => {
    await expect(hashKey("abc")).resolves.toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("generates a bounded key with an explicit family prefix", () => {
    const key = generateKey({ length: 12, prefix: "fungi" });

    expect(key).toMatch(/^fungi_[a-z0-9]{12}$/);
  });

  it("returns plaintext only alongside its matching digest", async () => {
    const generated = await generateKeyAndHash({ prefix: "fungi" });

    expect(generated.digest).toBe(await hashKey(generated.key));
    expect(generated.digest).not.toContain(generated.key);
  });
});
