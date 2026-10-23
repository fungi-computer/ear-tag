import { expect, it } from "vitest";

import type { Grant } from "../src/grants.js";
import {
  FIXTURE_CLOCK_START,
  type CreateFixture,
  type FixturePolicy,
} from "./key-store-fixture.js";
import type { TestCapability } from "./test-vocabulary.js";
import type { EpochFailure } from "./key-epoch.fixture.js";

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

  const epochFailures: readonly EpochFailure[] = [
    "begin",
    "before-commit",
    "after-commit",
  ];
  for (const failure of epochFailures)
    it(`K4: ${failure} failure recovers without reopening an aborted decision`, async () => {
      const { store, epochEvents, fences, failNext, close } = await create();
      try {
        const issued = await store.issue("owner-a", {
          name: "epoch recovery",
          grants: [readGrant],
        });
        if (issued.kind !== "ok") throw new Error("issue failed");
        const input = {
          requestId: "epoch-recovery",
          keyId: issued.value.record.keyId,
          expectedGrantVersion: 1,
          grants: [readGrant],
        };
        const start = (await epochEvents()).length;
        await failNext(failure);
        expect(await store.updateGrants("owner-a", input)).toEqual({
          kind: "error",
          error: { code: "unavailable" },
        });
        const failed = (await epochEvents()).slice(start);
        expect(failed.map((event) => event.kind)).toEqual(
          failure === "begin"
            ? ["begin"]
            : [
                "begin",
                "commit",
                failure === "before-commit" ? "abort" : "finish",
              ],
        );
        const firstDecision = failed[0]?.decisionId;
        expect(firstDecision).toBeTypeOf("string");
        if (failure === "before-commit") {
          const refusedStart = (await epochEvents()).length;
          expect(await store.updateGrants("owner-a", input)).toEqual({
            kind: "error",
            error: { code: "unavailable" },
          });
          expect((await epochEvents()).slice(refusedStart)).toEqual([
            { kind: "begin", decisionId: firstDecision },
          ]);
          expect(await fences()).toHaveLength(0);
        }
        const retryStart = (await epochEvents()).length;
        const repaired = await store.updateGrants("owner-a", {
          ...input,
          // No receipt committed: the aborted decision is terminal, so
          // recovery is a new request, not an exact replay of that decision.
          requestId:
            failure === "before-commit"
              ? `${input.requestId}-after-abort`
              : input.requestId,
        });
        expect(repaired.kind).toBe("ok");
        if (repaired.kind !== "ok") throw new Error("repair failed");
        expect(repaired.value.grantVersion).toBe(2);
        const repairedEvents = (await epochEvents()).slice(retryStart);
        expect(repairedEvents.map((event) => event.kind)).toEqual(
          failure === "after-commit"
            ? ["finish"]
            : ["begin", "commit", "finish"],
        );
        if (failure === "before-commit")
          expect(repairedEvents.at(-1)?.decisionId).not.toBe(firstDecision);
        else expect(repairedEvents.at(-1)?.decisionId).toBe(firstDecision);
        expect(await fences()).toHaveLength(1);
      } finally {
        await close();
      }
    });

  it("K4: a failed finish retains the external fence until committed replay finishes it", async () => {
    const { store, epochEvents, fences, failNext, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "finish recovery",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const input = {
        requestId: "finish-recovery",
        keyId: issued.value.record.keyId,
        expectedGrantVersion: 1,
        grants: [readGrant],
      };
      const start = (await epochEvents()).length;
      await failNext("finish");
      expect(await store.updateGrants("owner-a", input)).toEqual({
        kind: "error",
        error: { code: "unavailable" },
      });
      const failed = (await epochEvents()).slice(start);
      expect(failed.map((event) => event.kind)).toEqual([
        "begin",
        "commit",
        "finish",
      ]);
      const decisionId = failed[0]?.decisionId;
      expect(decisionId).toBeTypeOf("string");
      const committed = await store.list("owner-a");
      expect(committed.kind).toBe("ok");
      if (committed.kind !== "ok") throw new Error("committed key missing");
      const metadata = committed.value[0];
      if (metadata === undefined) throw new Error("committed key missing");
      expect(metadata.grantVersion).toBe(2);
      expect(await fences()).toHaveLength(1);

      // The owner still has a pending decision: a different mutation cannot
      // begin, despite the original mutation having committed locally.
      const next = {
        ...input,
        requestId: "after-finish-recovery",
        expectedGrantVersion: 2,
      };
      const blockedStart = (await epochEvents()).length;
      expect(await store.updateGrants("owner-a", next)).toEqual({
        kind: "error",
        error: { code: "unavailable" },
      });
      const blocked = (await epochEvents()).slice(blockedStart);
      expect(blocked.map((event) => event.kind)).toEqual(["begin"]);
      expect(blocked[0]?.decisionId).not.toBe(decisionId);
      expect(await fences()).toHaveLength(1);

      const replayStart = (await epochEvents()).length;
      expect(await store.updateGrants("owner-a", input)).toEqual({
        kind: "ok",
        value: metadata,
      });
      expect((await epochEvents()).slice(replayStart)).toEqual([
        { kind: "finish", decisionId },
      ]);
      expect(await fences()).toHaveLength(1);

      const nextStart = (await epochEvents()).length;
      const resumed = await store.updateGrants("owner-a", next);
      expect(resumed.kind).toBe("ok");
      if (resumed.kind !== "ok") throw new Error("fence was not released");
      expect(resumed.value.grantVersion).toBe(3);
      const resumedEvents = (await epochEvents()).slice(nextStart);
      expect(resumedEvents.map((event) => event.kind)).toEqual([
        "begin",
        "commit",
        "finish",
      ]);
      expect(resumedEvents[0]?.decisionId).toBe(blocked[0]?.decisionId);
      expect(await fences()).toHaveLength(2);
    } finally {
      await close();
    }
  });

  it("K4: an exact replay only finishes the original epoch decision", async () => {
    const { store, epochEvents, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "epoch replay",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const input = {
        requestId: "epoch-replay",
        keyId: issued.value.record.keyId,
        expectedGrantVersion: 1,
        grants: [readGrant],
      };
      const start = (await epochEvents()).length;
      const first = await store.updateGrants("owner-a", input);
      expect(first.kind).toBe("ok");
      const changed = (await epochEvents()).slice(start);
      expect(changed.map((event) => event.kind)).toEqual([
        "begin",
        "commit",
        "finish",
      ]);
      const retryStart = (await epochEvents()).length;
      expect(await store.updateGrants("owner-a", input)).toEqual(first);
      expect((await epochEvents()).slice(retryStart)).toEqual([
        { kind: "finish", decisionId: changed[0]?.decisionId },
      ]);
    } finally {
      await close();
    }
  });

  it("K6: live and current recheck without using a verification rate slot", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "rate limited",
        grants: [readGrant],
        rateLimit: { limit: 1, windowSeconds: 60 },
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const verified = await store.verify(issued.value.key);
      if (verified.kind !== "ok") throw new Error("verify failed");
      const ref = {
        keyId: verified.value.keyId,
        grantVersion: verified.value.grantVersion,
      };
      expect(await store.live(ref)).toEqual(verified);
      expect(await store.current(verified.value)).toEqual(verified);
      expect(await store.live(ref)).toEqual(verified);
      expect(await store.verify(issued.value.key)).toEqual({
        kind: "error",
        error: { code: "rate_limited", retryAfterSeconds: 60 },
      });
      await store.updateGrants("owner-a", {
        requestId: "narrow-after-list",
        keyId: ref.keyId,
        expectedGrantVersion: 1,
        grants: [
          {
            capability: "files.read",
            targets: { kind: "selected", ids: ["file-a"] },
          },
        ],
      });
      expect(await store.live(ref)).toEqual({
        kind: "error",
        error: { code: "denied" },
      });
      const fresh = await store.live({ keyId: ref.keyId });
      expect(fresh.kind).toBe("ok");
      if (fresh.kind === "ok") expect(fresh.value.grantVersion).toBe(2);
    } finally {
      await close();
    }
  });

  it("K5: a grant edit fences the replaced version, while revoke fences the current version", async () => {
    const { store, fences, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "fenced-key",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const keyId = issued.value.record.keyId;
      expect(
        (
          await store.updateGrants("owner-a", {
            requestId: "edit-fenced-key",
            keyId,
            expectedGrantVersion: 1,
            grants: [readGrant],
          })
        ).kind,
      ).toBe("ok");
      expect(await fences()).toEqual([
        {
          requestId: "edit-fenced-key",
          keyId,
          kind: "grants",
          throughGrantVersion: 1,
          grantVersion: 2,
          expiresAt: null,
        },
      ]);
      await store.revoke("owner-a", {
        requestId: "revoke-fenced-key",
        keyId,
      });
      expect((await fences())[1]).toEqual({
        requestId: "revoke-fenced-key",
        keyId,
        kind: "revoke",
        throughGrantVersion: 2,
        grantVersion: 2,
        expiresAt: null,
      });
    } finally {
      await close();
    }
  });

  it("K3: tenant closure is terminal even for an authorized issuer", async () => {
    const { store, close } = await create();
    try {
      expect((await store.close(FIXTURE_CLOCK_START)).kind).toBe("ok");
      expect(
        await store.issue("owner-a", {
          name: "after-close",
          grants: [readGrant],
        }),
      ).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });

  it("K3: closure refuses both new grant edits and replays of earlier edits", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "closed edits",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      const edit = {
        requestId: "before-close",
        keyId: issued.value.record.keyId,
        expectedGrantVersion: 1,
        grants: [readGrant],
      };
      expect((await store.updateGrants("owner-a", edit)).kind).toBe("ok");
      expect((await store.close(FIXTURE_CLOCK_START)).kind).toBe("ok");
      expect(await store.updateGrants("owner-a", edit)).toEqual({
        kind: "error",
        error: { code: "denied" },
      });
      expect(
        await store.updateGrants("owner-a", {
          ...edit,
          requestId: "after-close",
          expectedGrantVersion: 2,
        }),
      ).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });

  it("K2: a delegated key cannot exceed its live parent's grants or expiry", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "parent",
        grants: [
          { capability: "files.manage", targets: { kind: "all" } },
          {
            capability: "files.read",
            targets: { kind: "selected", ids: ["file-a"] },
          },
        ],
        expiresAt: FIXTURE_CLOCK_START + 10_000,
      });
      if (issued.kind !== "ok") throw new Error("parent issue failed");
      const parent = await store.verify(issued.value.key);
      if (parent.kind !== "ok") throw new Error("parent verification failed");
      const outside = await store.issue(
        "owner-a",
        {
          name: "outside",
          grants: [readGrant],
          expiresAt: FIXTURE_CLOCK_START + 5_000,
        },
        parent.value,
      );
      expect(outside).toEqual({ kind: "error", error: { code: "denied" } });
      const later = await store.issue(
        "owner-a",
        {
          name: "later",
          grants: [
            {
              capability: "files.read",
              targets: { kind: "selected", ids: ["file-a"] },
            },
          ],
          expiresAt: FIXTURE_CLOCK_START + 20_000,
        },
        parent.value,
      );
      expect(later).toEqual({ kind: "error", error: { code: "denied" } });
      const unbounded = await store.issue(
        "owner-a",
        {
          name: "unbounded",
          grants: [
            {
              capability: "files.read",
              targets: { kind: "selected", ids: ["file-a"] },
            },
          ],
        },
        parent.value,
      );
      expect(unbounded).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });

  it("K2: delegated issuance requires manage authority and the same human owner", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "reader",
        grants: [readGrant],
      });
      if (issued.kind !== "ok") throw new Error("parent issue failed");
      const parent = await store.verify(issued.value.key);
      if (parent.kind !== "ok") throw new Error("parent verification failed");
      expect(
        await store.issue(
          "owner-a",
          { name: "no-manage", grants: [readGrant] },
          parent.value,
        ),
      ).toEqual({ kind: "error", error: { code: "denied" } });
      const manager = await store.issue("owner-a", {
        name: "manager",
        grants: [
          { capability: "files.manage", targets: { kind: "all" } },
          readGrant,
        ],
      });
      if (manager.kind !== "ok") throw new Error("manager issue failed");
      const managerPrincipal = await store.verify(manager.value.key);
      if (managerPrincipal.kind !== "ok")
        throw new Error("manager verify failed");
      expect(
        await store.issue(
          "owner-b",
          { name: "different-human", grants: [readGrant] },
          managerPrincipal.value,
        ),
      ).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });

  it("K2: a grant edit delegated by a key cannot widen beyond that parent's live grants", async () => {
    const { store, close } = await create();
    try {
      const manager = await store.issue("owner-a", {
        name: "manager",
        grants: [
          { capability: "files.manage", targets: { kind: "all" } },
          {
            capability: "files.read",
            targets: { kind: "selected", ids: ["file-a"] },
          },
        ],
      });
      const child = await store.issue("owner-a", {
        name: "child",
        grants: [
          {
            capability: "files.read",
            targets: { kind: "selected", ids: ["file-a"] },
          },
        ],
      });
      if (manager.kind !== "ok" || child.kind !== "ok")
        throw new Error("issue failed");
      const parent = await store.verify(manager.value.key);
      if (parent.kind !== "ok") throw new Error("parent verification failed");
      expect(
        await store.updateGrants(
          "owner-a",
          {
            requestId: "widen-child",
            keyId: child.value.record.keyId,
            expectedGrantVersion: 1,
            grants: [readGrant],
          },
          parent.value,
        ),
      ).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });

  it("K2: revoking a parent leaves its issued child live but human suspension does not", async () => {
    const { store, close } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "parent",
        grants: [
          { capability: "files.manage", targets: { kind: "all" } },
          readGrant,
        ],
      });
      if (issued.kind !== "ok") throw new Error("parent issue failed");
      const parent = await store.verify(issued.value.key);
      if (parent.kind !== "ok") throw new Error("parent verification failed");
      const child = await store.issue(
        "owner-a",
        { name: "child", grants: [readGrant] },
        parent.value,
      );
      if (child.kind !== "ok") throw new Error("child issue failed");
      const revoked = await store.revoke("owner-a", {
        requestId: "revoke-parent",
        keyId: parent.value.keyId,
      });
      expect(revoked.kind).toBe("ok");
      expect((await store.verify(child.value.key)).kind).toBe("ok");
      expect(
        await store.issue(
          "owner-a",
          { name: "after-revoke", grants: [readGrant] },
          parent.value,
        ),
      ).toEqual({ kind: "error", error: { code: "denied" } });
      await store.suspendOwner("owner-a", "suspend-human");
      expect(await store.verify(child.value.key)).toEqual({
        kind: "error",
        error: { code: "denied" },
      });
    } finally {
      await close();
    }
  });

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
          kind: "grants",
          throughGrantVersion: 1,
          keyId,
          grantVersion: 2,
          expiresAt: null,
        },
        {
          requestId: "req-fence-revoke",
          kind: "revoke",
          throughGrantVersion: 2,
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
      const closed = await store.close(closedAt);
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

  it("issues a key with a caller-chosen id, and it round-trips through verify and live", async () => {
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

      const read = await store.live({ keyId: "chosen-key-1" });
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

  it("refuses live authority for a revoked key", async () => {
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

      const read = await store.live({ keyId });
      expect(read).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });

  it("refuses live authority for an expired key", async () => {
    const { store, close, advanceClock } = await create();
    try {
      const issued = await store.issue("owner-a", {
        name: "to expire",
        grants: [readGrant],
        expiresAt: FIXTURE_CLOCK_START + 1_000,
      });
      if (issued.kind !== "ok") throw new Error("issue failed");
      await advanceClock(2_000);

      const read = await store.live({ keyId: issued.value.record.keyId });
      expect(read).toEqual({ kind: "error", error: { code: "expired" } });
    } finally {
      await close();
    }
  });

  it("refuses live authority for a key whose owner is suspended", async () => {
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

      const read = await store.live({ keyId: issued.value.record.keyId });
      expect(read).toEqual({ kind: "error", error: { code: "denied" } });
    } finally {
      await close();
    }
  });
}
