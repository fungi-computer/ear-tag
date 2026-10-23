import { describe, expect, it } from "vitest";

import {
  defineGrants,
  GrantsDefinitionError,
  type Grant,
} from "../src/grants.js";

const vocabulary = defineGrants({
  capabilities: ["files.read", "files.write", "files.manage"] as const,
  implies: { "files.manage": ["files.read"] },
});

describe("defineGrants", () => {
  it("K1: implied read authority is listable without widening selected targets", () => {
    const apps = defineGrants({
      capabilities: ["apps.read", "apps.use"],
      implies: { "apps.use": ["apps.read"] },
    });
    const selected: readonly Grant<"apps.read" | "apps.use">[] = [
      {
        capability: "apps.use",
        targets: { kind: "selected", ids: ["installation-x"] },
      },
    ];
    expect(apps.grantsAllow(selected, "apps.read", "installation-x")).toBe(
      true,
    );
    expect(apps.grantsAllow(selected, "apps.read", "installation-y")).toBe(
      false,
    );
    expect(apps.grantsList(selected, "apps.read")).toBe(true);
    expect(
      apps.grantsList(
        [{ capability: "apps.use", targets: { kind: "selected", ids: [] } }],
        "apps.read",
      ),
    ).toBe(false);
    expect(
      apps.grantsList(
        [{ capability: "apps.read", targets: { kind: "all" } }],
        "apps.use",
      ),
    ).toBe(false);
  });

  it("rejects a vocabulary with a repeated capability", () => {
    expect(() =>
      defineGrants({ capabilities: ["files.read", "files.read"] as const }),
    ).toThrow(GrantsDefinitionError);
  });

  it("rejects implies naming a capability outside the vocabulary", () => {
    // SAFETY: simulates untyped config (for example JSON) naming a
    // capability the literal `Capability` union would otherwise reject at
    // compile time; `defineGrants` must still refuse it at runtime.
    const implies = JSON.parse('{"files.read":["files.write"]}') as Readonly<
      Partial<Record<"files.read", readonly "files.read"[]>>
    >;
    expect(() =>
      defineGrants({ capabilities: ["files.read"] as const, implies }),
    ).toThrow(GrantsDefinitionError);
  });

  it("validates capability names against the declared vocabulary", () => {
    expect(
      vocabulary.capabilityNameSchema.safeParse("files.read").success,
    ).toBe(true);
    expect(
      vocabulary.capabilityNameSchema.safeParse("files.delete").success,
    ).toBe(false);
  });

  it("bounds a scope to between 1 and 64 grants", () => {
    expect(vocabulary.scopeSchema.safeParse({ grants: [] }).success).toBe(
      false,
    );
    expect(
      vocabulary.scopeSchema.safeParse({
        grants: [{ capability: "files.read", targets: { kind: "all" } }],
      }).success,
    ).toBe(true);
    const tooMany = Array.from({ length: 65 }, (_, index) => ({
      capability: "files.read",
      targets: { kind: "selected" as const, ids: [`r${String(index)}`] },
    }));
    expect(vocabulary.scopeSchema.safeParse({ grants: tooMany }).success).toBe(
      false,
    );
  });

  it("rejects a selected grant with no explicit target kind", () => {
    const result = vocabulary.grantSchema.safeParse({
      capability: "files.read",
      targets: { ids: ["a"] },
    });
    expect(result.success).toBe(false);
  });

  it("canonicalizes grants: dedupes ids and sorts by capability", () => {
    const grants: readonly Grant<
      "files.read" | "files.write" | "files.manage"
    >[] = [
      {
        capability: "files.write",
        targets: { kind: "selected", ids: ["b", "a", "a"] },
      },
      { capability: "files.read", targets: { kind: "all" } },
    ];
    expect(vocabulary.canonicalGrants(grants)).toEqual([
      { capability: "files.read", targets: { kind: "all" } },
      {
        capability: "files.write",
        targets: { kind: "selected", ids: ["a", "b"] },
      },
    ]);
  });

  it("grantsAllow matches an exact capability against a selected target", () => {
    const grants: readonly Grant<
      "files.read" | "files.write" | "files.manage"
    >[] = [
      { capability: "files.read", targets: { kind: "selected", ids: ["r1"] } },
    ];
    expect(vocabulary.grantsAllow(grants, "files.read", "r1")).toBe(true);
    expect(vocabulary.grantsAllow(grants, "files.read", "r2")).toBe(false);
    expect(vocabulary.grantsAllow(grants, "files.read")).toBe(false);
  });

  it("grantsAllow admits an all-targets grant without naming a resource", () => {
    const grants: readonly Grant<
      "files.read" | "files.write" | "files.manage"
    >[] = [{ capability: "files.read", targets: { kind: "all" } }];
    expect(vocabulary.grantsAllow(grants, "files.read")).toBe(true);
    expect(vocabulary.grantsAllow(grants, "files.read", "anything")).toBe(true);
  });

  it("grantsAllow admits an implied capability", () => {
    const grants: readonly Grant<
      "files.read" | "files.write" | "files.manage"
    >[] = [
      {
        capability: "files.manage",
        targets: { kind: "selected", ids: ["r1"] },
      },
    ];
    expect(vocabulary.grantsAllow(grants, "files.read", "r1")).toBe(true);
    expect(vocabulary.grantsAllow(grants, "files.write", "r1")).toBe(false);
  });

  it("grantsList is true once a capability reaches at least one resource", () => {
    const empty: readonly Grant<
      "files.read" | "files.write" | "files.manage"
    >[] = [
      { capability: "files.read", targets: { kind: "selected", ids: [] } },
    ];
    expect(vocabulary.grantsList(empty, "files.read")).toBe(false);
    const some: readonly Grant<
      "files.read" | "files.write" | "files.manage"
    >[] = [
      { capability: "files.read", targets: { kind: "selected", ids: ["r1"] } },
    ];
    expect(vocabulary.grantsList(some, "files.read")).toBe(true);
    const all: readonly Grant<"files.read" | "files.write" | "files.manage">[] =
      [{ capability: "files.read", targets: { kind: "all" } }];
    expect(vocabulary.grantsList(all, "files.read")).toBe(true);
  });

  it("isSubset accepts a child fully covered by the parent", () => {
    const parent: readonly Grant<
      "files.read" | "files.write" | "files.manage"
    >[] = [
      {
        capability: "files.read",
        targets: { kind: "selected", ids: ["r1", "r2"] },
      },
    ];
    const covered: readonly Grant<
      "files.read" | "files.write" | "files.manage"
    >[] = [
      { capability: "files.read", targets: { kind: "selected", ids: ["r1"] } },
    ];
    expect(vocabulary.isSubset(covered, parent)).toBe(true);
  });

  it("isSubset rejects a child the parent does not fully cover", () => {
    const parent: readonly Grant<
      "files.read" | "files.write" | "files.manage"
    >[] = [
      { capability: "files.read", targets: { kind: "selected", ids: ["r1"] } },
    ];
    const uncovered: readonly Grant<
      "files.read" | "files.write" | "files.manage"
    >[] = [
      { capability: "files.read", targets: { kind: "selected", ids: ["r2"] } },
    ];
    expect(vocabulary.isSubset(uncovered, parent)).toBe(false);
  });

  it("isSubset rejects a child asking for every resource when the parent only selects some", () => {
    const parent: readonly Grant<
      "files.read" | "files.write" | "files.manage"
    >[] = [
      { capability: "files.read", targets: { kind: "selected", ids: ["r1"] } },
    ];
    const unbounded: readonly Grant<
      "files.read" | "files.write" | "files.manage"
    >[] = [{ capability: "files.read", targets: { kind: "all" } }];
    expect(vocabulary.isSubset(unbounded, parent)).toBe(false);
  });
});
