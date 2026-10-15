import { expect, it } from "vitest";

import type { Grant } from "../src/grants.js";
import {
  FIXTURE_CLOCK_START,
  type CreateFixture,
  type FixturePolicy,
} from "./key-store-fixture.js";
import type { TestCapability } from "./test-vocabulary.js";

const readGrant: Grant<TestCapability> = {
  capability: "files.read",
  targets: { kind: "all" },
};

/** `count` distinct, deterministic resource ids, disjoint across prefixes. */
function idRange(prefix: string, count: number): readonly string[] {
  return Array.from(
    { length: count },
    (_, index) => `${prefix}-${String(index)}`,
  );
}

/**
 * One behavior suite run against both a real, in-memory `node:sqlite`
 * database and a real Cloudflare Durable Object, so both `KeySql` ports are
 * proven against the exact same store logic.
 */
export function registerKeyStoreBehaviors(createFixture: CreateFixture): void {
  const create = (policy?: FixturePolicy) => createFixture(policy);

  it("issues a key and verifies it back to the same principal", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "ci bot",
        grants: [readGrant],
      });
      expect(issued.kind).toBe("ok");
      if (issued.kind !== "ok") return;
      const verified = await store.verify(issued.value.key);
      expect(verified).toEqual({
        kind: "ok",
        value: {
          keyId: issued.value.record.keyId,
          owner: "owner-a",
          name: "ci bot",
          scope: { grants: [readGrant] },
          grantVersion: 1,
          expiresAt: null,
        },
      });
    } finally {
      await close();
    }
  });

  it("refuses an unrecognized secret", async () => {
    const { store, close } = await create();
    try {
      const result = await store.verify("fungi_not-a-real-key");
      expect(result).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });

  it("reports a malformed issue request as invalid, not unavailable", async () => {
    const { store, close } = await create();
    try {
      const result = await store.issue("owner-a", { name: "", grants: [] });
      expect(result).toEqual({ kind: "error", error: { code: "invalid" } });
    } finally {
      await close();
    }
  });

  it("conflicts a grant update on a stale expected version", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "ci bot",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const stale = await store.updateGrants("owner-a", {
        requestId: "req-1",
        keyId: issued.value.record.keyId,
        expectedGrantVersion: 99,
        grants: [readGrant],
      });
      expect(stale).toEqual({ kind: "error", error: { code: "conflict" } });
    } finally {
      await close();
    }
  });

  it("replays an identical grant-update request without incrementing twice", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "ci bot",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const writeGrant: Grant<TestCapability> = {
        capability: "files.write",
        targets: { kind: "all" },
      };
      const input = {
        requestId: "req-replay",
        keyId: issued.value.record.keyId,
        expectedGrantVersion: 1,
        grants: [writeGrant],
      };
      const first = await store.updateGrants("owner-a", input);
      const second = await store.updateGrants("owner-a", input);
      expect(first).toEqual(second);
      expect(first.kind).toBe("ok");
      if (first.kind === "ok") expect(first.value.grantVersion).toBe(2);
    } finally {
      await close();
    }
  });

  it("conflicts a replayed request whose input no longer matches", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "ci bot",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      await store.updateGrants("owner-a", {
        requestId: "req-mismatch",
        keyId: issued.value.record.keyId,
        expectedGrantVersion: 1,
        grants: [readGrant],
      });
      const mismatched = await store.updateGrants("owner-a", {
        requestId: "req-mismatch",
        keyId: issued.value.record.keyId,
        expectedGrantVersion: 1,
        grants: [{ capability: "files.write", targets: { kind: "all" } }],
      });
      expect(mismatched).toEqual({
        kind: "error",
        error: { code: "conflict" },
      });
    } finally {
      await close();
    }
  });

  it("fences every accepted grant edit and revocation, in order", async () => {
    const { store, close, fences } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "fenced",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const keyId = issued.value.record.keyId;
      const updated = await store.updateGrants("owner-a", {
        requestId: "req-fence-grants",
        keyId,
        expectedGrantVersion: 1,
        grants: [{ capability: "files.write", targets: { kind: "all" } }],
      });
      if (updated.kind !== "ok") throw new Error("update failed");
      const revoked = await store.revoke("owner-a", {
        requestId: "req-fence-revoke",
        keyId,
      });
      if (revoked.kind !== "ok") throw new Error("revoke failed");
      expect(await fences()).toEqual([
        {
          requestId: "req-fence-grants",
          keyId,
          grantVersion: 2,
          expiresAt: null,
        },
        {
          requestId: "req-fence-revoke",
          keyId,
          grantVersion: 2,
          expiresAt: null,
        },
      ]);
    } finally {
      await close();
    }
  });

  it("revokes a key so it no longer verifies, and tombstones idempotently", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "ci bot",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const revoked = await store.revoke("owner-a", {
        requestId: "req-revoke",
        keyId: issued.value.record.keyId,
      });
      expect(revoked.kind).toBe("ok");
      if (revoked.kind === "ok") expect(revoked.value.revokedAt).not.toBeNull();
      const verified = await store.verify(issued.value.key);
      expect(verified).toEqual({ kind: "error", error: { code: "denied" } });
      const revokedAgain = await store.revoke("owner-a", {
        requestId: "req-revoke",
        keyId: issued.value.record.keyId,
      });
      expect(revokedAgain).toEqual(revoked);
    } finally {
      await close();
    }
  });

  it("refuses current() for a principal whose grant version has gone stale", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "ci bot",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const verified = await store.verify(issued.value.key);
      if (verified.kind !== "ok") throw new Error("verify failed");
      const updated = await store.updateGrants("owner-a", {
        requestId: "req-stale-current",
        keyId: issued.value.record.keyId,
        expectedGrantVersion: 1,
        grants: [{ capability: "files.write", targets: { kind: "all" } }],
      });
      expect(updated.kind).toBe("ok");
      const stale = await store.current(verified.value);
      expect(stale).toEqual({ kind: "error", error: { code: "denied" } });
      const fresh = await store.current({
        ...verified.value,
        grantVersion: 2,
        scope: {
          grants: [{ capability: "files.write", targets: { kind: "all" } }],
        },
      });
      expect(fresh.kind).toBe("ok");
    } finally {
      await close();
    }
  });

  it("verifies a key with no expiry indefinitely, and expires one with a past expiry", async () => {
    const { store, close, advanceClock } = await create();
    try {
      const unbounded = await store.issue("owner-a", {
        name: "never expires",
        grants: [readGrant],
      });
      if (unbounded.kind !== "ok") throw new Error("issue failed");
      await advanceClock(1_000 * 60 * 60 * 24 * 365);
      expect((await store.verify(unbounded.value.key)).kind).toBe("ok");

      const bounded = await store.issue("owner-a", {
        name: "expires soon",
        grants: [readGrant],
        expiresAt: FIXTURE_CLOCK_START + 1_000 * 60 * 60 * 24 * 365 + 1_000,
      });
      if (bounded.kind !== "ok") throw new Error("issue failed");
      await advanceClock(2_000);
      const expired = await store.verify(bounded.value.key);
      expect(expired).toEqual({ kind: "error", error: { code: "expired" } });
    } finally {
      await close();
    }
  });

  it("refuses to issue a key already expired at issuance", async () => {
    const { store, close } = await create();
    try {
      const result = await store.issue("owner-a", {
        name: "dead on arrival",
        grants: [readGrant],
        expiresAt: FIXTURE_CLOCK_START - 1_000,
      });
      expect(result).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });

  it("refuses admitUse once a key has expired", async () => {
    const { store, close, advanceClock } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "expires under load",
        grants: [readGrant],
        expiresAt: FIXTURE_CLOCK_START + 1_000,
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const verified = await store.verify(issued.value.key);
      if (verified.kind !== "ok") throw new Error("verify failed");
      await advanceClock(2_000);
      const used = await store.admitUse(verified.value, {
        capability: "files.read",
        requestId: "req-use-expired",
      });
      expect(used).toEqual({ kind: "error", error: { code: "expired" } });
    } finally {
      await close();
    }
  });

  it("refuses admitUse once a key's owner is suspended", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "suspended under load",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const verified = await store.verify(issued.value.key);
      if (verified.kind !== "ok") throw new Error("verify failed");
      const suspension = await store.suspendOwner("owner-a", "req-suspend-use");
      expect(suspension.kind).toBe("ok");
      const used = await store.admitUse(verified.value, {
        capability: "files.read",
        requestId: "req-use-suspended",
      });
      expect(used).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });

  it("permanently suspends every key an owner holds", async () => {
    const { store, close } = await create();
    try {
      const first = await store.issue("owner-a", {
        name: "one",
        grants: [readGrant],
      });
      const second = await store.issue("owner-a", {
        name: "two",
        grants: [readGrant],
      });
      if (first.kind !== "ok" || second.kind !== "ok")
        throw new Error("issue failed");
      const suspension = await store.suspendOwner("owner-a", "req-suspend");
      expect(suspension.kind).toBe("ok");
      expect(await store.verify(first.value.key)).toEqual({
        kind: "error",
        error: { code: "denied" },
      });
      expect(await store.verify(second.value.key)).toEqual({
        kind: "error",
        error: { code: "denied" },
      });
    } finally {
      await close();
    }
  });

  it("rate limits verification once a key's own policy is exceeded", async () => {
    const { store, close, advanceClock } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "rate limited",
        grants: [readGrant],
        rateLimit: { limit: 1, windowSeconds: 60 },
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      expect((await store.verify(issued.value.key)).kind).toBe("ok");
      const limited = await store.verify(issued.value.key);
      expect(limited.kind).toBe("error");
      if (limited.kind === "error") {
        expect(limited.error.code).toBe("rate_limited");
        expect(limited.error.retryAfterSeconds).toBeGreaterThan(0);
      }
      await advanceClock(61_000);
      expect((await store.verify(issued.value.key)).kind).toBe("ok");
    } finally {
      await close();
    }
  });

  it("bounds a sub-issuer to a subset of its own live grants", async () => {
    const bounded = new Map<string, readonly Grant<TestCapability>[]>([
      ["sub-issuer", [readGrant]],
    ]);
    const { store, close } = await create({ bounded });
    try {
      const covered = await store.issue("sub-issuer", {
        name: "within bounds",
        grants: [readGrant],
      });
      expect(covered.kind).toBe("ok");

      const uncovered = await store.issue("sub-issuer", {
        name: "outside bounds",
        grants: [{ capability: "files.write", targets: { kind: "all" } }],
      });
      expect(uncovered).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });

  it("bounds a sub-issuer's updateGrants to a subset of its own live grants", async () => {
    const bounded = new Map<string, readonly Grant<TestCapability>[]>([
      ["sub-issuer", [readGrant]],
    ]);
    const { store, close } = await create({ bounded });
    try {
      const issued = await store.issue("owner-a", {
        name: "edited by a bounded issuer",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const keyId = issued.value.record.keyId;

      const covered = await store.updateGrants("sub-issuer", {
        requestId: "req-bounded-update-covered",
        keyId,
        expectedGrantVersion: 1,
        grants: [readGrant],
      });
      expect(covered.kind).toBe("ok");

      const uncovered = await store.updateGrants("sub-issuer", {
        requestId: "req-bounded-update-uncovered",
        keyId,
        expectedGrantVersion: 2,
        grants: [{ capability: "files.write", targets: { kind: "all" } }],
      });
      expect(uncovered).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });

  it("denies an actor authorizeIssuer does not recognize", async () => {
    const { store, close } = await create({ deny: new Set(["stranger"]) });
    try {
      const result = await store.issue("stranger", {
        name: "nope",
        grants: [readGrant],
      });
      expect(result).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });

  it("lists every key for one owner once the actor is authorized", async () => {
    const { store, close } = await create();
    try {
      await store.issue("owner-a", { name: "one", grants: [readGrant] });
      await store.issue("owner-b", { name: "two", grants: [readGrant] });
      const listed = await store.list("owner-a", "owner-a");
      expect(listed.kind).toBe("ok");
      if (listed.kind === "ok") {
        expect(listed.value).toHaveLength(1);
        expect(listed.value[0]?.owner).toBe("owner-a");
      }
    } finally {
      await close();
    }
  });

  it("admits a use once and records an idempotent receipt for a retry", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "spender",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const verified = await store.verify(issued.value.key);
      if (verified.kind !== "ok") throw new Error("verify failed");
      const input = {
        capability: "files.read" as const,
        requestId: "req-use",
      };
      const first = await store.admitUse(verified.value, input);
      const second = await store.admitUse(verified.value, input);
      expect(first).toEqual(second);
      expect(first.kind).toBe("ok");

      const denied = await store.admitUse(verified.value, {
        capability: "files.write",
        requestId: "req-use-denied",
      });
      expect(denied).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });

  it("touch stamps lastUsedAt, and revoking every open key closes the tenant", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "closing",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const touched = await store.touch(issued.value.record.keyId);
      expect(touched.kind).toBe("ok");

      const closedAt = 123;
      const closed = await store.revokeAll(closedAt);
      expect(closed.kind).toBe("ok");
      const verified = await store.verify(issued.value.key);
      expect(verified).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });

  // Two grants sharing a capability merge into one before storage. Each is
  // itself within the 256-id bound, but the merge can still push the
  // combined, canonical grant past it even though no single grant the
  // caller sent ever did.
  it("issues a key whose merged same-capability grants land exactly on the id boundary", async () => {
    const { store, close } = await create();
    try {
      const first: Grant<TestCapability> = {
        capability: "files.read",
        targets: { kind: "selected", ids: idRange("a", 128) },
      };
      const second: Grant<TestCapability> = {
        capability: "files.read",
        targets: { kind: "selected", ids: idRange("b", 128) },
      };
      const expectedIds = [
        ...new Set([...idRange("a", 128), ...idRange("b", 128)]),
      ].sort();
      expect(expectedIds).toHaveLength(256);

      const issued = await store.issue("owner-a", {
        name: "boundary issue",
        grants: [first, second],
      });
      expect(issued.kind).toBe("ok");
      if (issued.kind !== "ok") return;
      expect(issued.value.record.scope).toEqual({
        grants: [
          {
            capability: "files.read",
            targets: { kind: "selected", ids: expectedIds },
          },
        ],
      });

      const verified = await store.verify(issued.value.key);
      expect(verified.kind).toBe("ok");
      if (verified.kind === "ok")
        expect(verified.value.scope).toEqual({
          grants: [
            {
              capability: "files.read",
              targets: { kind: "selected", ids: expectedIds },
            },
          ],
        });
    } finally {
      await close();
    }
  });

  it("refuses to issue a key whose merged same-capability grants exceed the id boundary, leaving the store otherwise unaffected", async () => {
    const { store, close, fences } = await create();
    try {
      const control = await store.issue("owner-a", {
        name: "control",
        grants: [readGrant],
      });
      if (control.kind !== "ok") throw new Error("issue failed");

      const first: Grant<TestCapability> = {
        capability: "files.read",
        targets: { kind: "selected", ids: idRange("a", 128) },
      };
      const second: Grant<TestCapability> = {
        capability: "files.read",
        targets: { kind: "selected", ids: idRange("b", 129) },
      };
      const refused = await store.issue("owner-a", {
        name: "over boundary",
        grants: [first, second],
      });
      expect(refused).toEqual({ kind: "error", error: { code: "invalid" } });

      // The refused attempt created nothing and fenced nothing; the
      // control key issued beforehand still verifies, unaffected.
      expect(await fences()).toEqual([]);
      const verified = await store.verify(control.value.key);
      expect(verified.kind).toBe("ok");
      if (verified.kind === "ok")
        expect(verified.value.scope).toEqual({ grants: [readGrant] });
    } finally {
      await close();
    }
  });

  it("updates a key's grants exactly to the id boundary and verifies the merged scope", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "ci bot",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");

      const first: Grant<TestCapability> = {
        capability: "files.write",
        targets: { kind: "selected", ids: idRange("a", 128) },
      };
      const second: Grant<TestCapability> = {
        capability: "files.write",
        targets: { kind: "selected", ids: idRange("b", 128) },
      };
      const expectedIds = [
        ...new Set([...idRange("a", 128), ...idRange("b", 128)]),
      ].sort();
      expect(expectedIds).toHaveLength(256);

      const updated = await store.updateGrants("owner-a", {
        requestId: "req-boundary-update",
        keyId: issued.value.record.keyId,
        expectedGrantVersion: 1,
        grants: [first, second],
      });
      expect(updated.kind).toBe("ok");
      if (updated.kind === "ok")
        expect(updated.value.scope).toEqual({
          grants: [
            {
              capability: "files.write",
              targets: { kind: "selected", ids: expectedIds },
            },
          ],
        });

      const verified = await store.verify(issued.value.key);
      expect(verified.kind).toBe("ok");
      if (verified.kind === "ok")
        expect(verified.value.scope).toEqual({
          grants: [
            {
              capability: "files.write",
              targets: { kind: "selected", ids: expectedIds },
            },
          ],
        });
    } finally {
      await close();
    }
  });

  it("refuses a grant update whose merged ids exceed the boundary, leaving the key's prior grants verifying unchanged", async () => {
    const { store, close, fences } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "ci bot",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");

      const first: Grant<TestCapability> = {
        capability: "files.write",
        targets: { kind: "selected", ids: idRange("a", 128) },
      };
      const second: Grant<TestCapability> = {
        capability: "files.write",
        targets: { kind: "selected", ids: idRange("b", 129) },
      };
      const refused = await store.updateGrants("owner-a", {
        requestId: "req-over-boundary-update",
        keyId: issued.value.record.keyId,
        expectedGrantVersion: 1,
        grants: [first, second],
      });
      expect(refused).toEqual({ kind: "error", error: { code: "invalid" } });

      // No truncation (the key keeps its prior authority) and no widening
      // (it never gains the attempted grants either): verifying afterward
      // comes back exactly as it was before the refused attempt, on the
      // same grant version, with no authority-change fence recorded.
      expect(await fences()).toEqual([]);
      const verified = await store.verify(issued.value.key);
      expect(verified.kind).toBe("ok");
      if (verified.kind === "ok") {
        expect(verified.value.scope).toEqual({ grants: [readGrant] });
        expect(verified.value.grantVersion).toBe(1);
      }
    } finally {
      await close();
    }
  });

  it("issues a key with a caller-chosen id, and it round-trips through verify and read", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "chosen id",
        grants: [readGrant],
        keyId: "chosen-key-1",
      });
      expect(issued.kind).toBe("ok");
      if (issued.kind !== "ok") return;
      expect(issued.value.record.keyId).toBe("chosen-key-1");

      const verified = await store.verify(issued.value.key);
      expect(verified).toEqual({
        kind: "ok",
        value: {
          keyId: "chosen-key-1",
          owner: "owner-a",
          name: "chosen id",
          scope: { grants: [readGrant] },
          grantVersion: 1,
          expiresAt: null,
        },
      });

      const read = await store.read("owner-a", "chosen-key-1");
      expect(read).toEqual(verified);
    } finally {
      await close();
    }
  });

  it("refuses to reuse a key id, even one a now-revoked key held", async () => {
    const { store, close } = await create();
    try {
      const first = await store.issue("owner-a", {
        name: "first",
        grants: [readGrant],
        keyId: "reused-id",
      });
      if (first.kind !== "ok") throw new Error("issue failed");

      const duplicateWhileLive = await store.issue("owner-a", {
        name: "duplicate",
        grants: [readGrant],
        keyId: "reused-id",
      });
      expect(duplicateWhileLive).toEqual({
        kind: "error",
        error: { code: "conflict" },
      });

      const revoked = await store.revoke("owner-a", {
        requestId: "req-reuse-revoke",
        keyId: "reused-id",
      });
      expect(revoked.kind).toBe("ok");

      const duplicateAfterRevoke = await store.issue("owner-a", {
        name: "duplicate after revoke",
        grants: [readGrant],
        keyId: "reused-id",
      });
      expect(duplicateAfterRevoke).toEqual({
        kind: "error",
        error: { code: "conflict" },
      });
    } finally {
      await close();
    }
  });

  it("refuses to read a revoked key", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "to revoke",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const keyId = issued.value.record.keyId;
      const revoked = await store.revoke("owner-a", {
        requestId: "req-read-revoked",
        keyId,
      });
      expect(revoked.kind).toBe("ok");

      const read = await store.read("owner-a", keyId);
      expect(read).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });

  it("refuses to read an expired key", async () => {
    const { store, close, advanceClock } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "to expire",
        grants: [readGrant],
        expiresAt: FIXTURE_CLOCK_START + 1_000,
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      await advanceClock(2_000);

      const read = await store.read("owner-a", issued.value.record.keyId);
      expect(read).toEqual({ kind: "error", error: { code: "expired" } });
    } finally {
      await close();
    }
  });

  it("refuses to read a key whose owner is suspended", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "to suspend",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const suspension = await store.suspendOwner(
        "owner-a",
        "req-read-suspended",
      );
      expect(suspension.kind).toBe("ok");

      const read = await store.read("owner-a", issued.value.record.keyId);
      expect(read).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });
}
