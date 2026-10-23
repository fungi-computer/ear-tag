import { z } from "zod";

/** How a grant's capability reaches resources. */
export type GrantTargets =
  | Readonly<{
      /** The capability reaches every resource, now and later. */
      kind: "all";
    }>
  | Readonly<{
      /** The capability reaches only these resources; a later resource never joins implicitly. */
      kind: "selected";
      /** Bounded, explicitly chosen resource identifiers this grant covers. */
      ids: readonly string[];
    }>;

/** One capability bound to the resources it may act on. */
export type Grant<Capability extends string = string> = Readonly<{
  /** Capability name drawn from the host's declared vocabulary. */
  capability: Capability;
  /** Resources this grant reaches. */
  targets: GrantTargets;
}>;

/** The bounded authority one key carries: 1 to 64 grants. */
export type Scope<Capability extends string = string> = Readonly<{
  /** Every grant the key carries. */
  grants: readonly Grant<Capability>[];
}>;

/** Zod schemas and grant operations closed over one host's capability vocabulary. */
export type GrantVocabulary<Capability extends string> = Readonly<{
  /** Validates one capability name against the declared vocabulary. */
  capabilityNameSchema: z.ZodType<Capability>;
  /** Validates one grant: a vocabulary capability bound to its targets. */
  grantSchema: z.ZodType<Grant<Capability>>;
  /** Validates a bounded, 1-to-64-grant scope. */
  scopeSchema: z.ZodType<Scope<Capability>>;
  /** Dedupes and sorts grants into one canonical, order-independent form. */
  canonicalGrants: (
    grants: readonly Grant<Capability>[],
  ) => readonly Grant<Capability>[];
  /** Whether some grant admits this capability against this optional resource. */
  grantsAllow: (
    grants: readonly Grant<Capability>[],
    capability: Capability,
    resourceId?: string,
  ) => boolean;
  /** Whether some grant admits this capability for at least one resource, without naming one. */
  grantsList: (
    grants: readonly Grant<Capability>[],
    capability: Capability,
  ) => boolean;
  /** Whether every grant in `child` is already admitted by `parent`. */
  isSubset: (
    child: readonly Grant<Capability>[],
    parent: readonly Grant<Capability>[],
  ) => boolean;
}>;

/** A host's capability vocabulary and its optional implied-capability classes. */
export type GrantsDefinition<
  Capability extends readonly [string, ...string[]],
> = Readonly<{
  /** Every capability name a grant may name; at least one. */
  capabilities: Capability;
  /**
   * Extra capabilities a grant's capability also admits, for example a
   * manage capability that also admits a narrower read capability. Every
   * key and value must itself be a declared capability.
   *
   * One level deep, not transitive: if `a` implies `b` and `b` implies `c`,
   * a grant of `a` does not reach `c` unless `a` names `c` directly too.
   */
  implies?: Readonly<
    Partial<Record<Capability[number], readonly Capability[number][]>>
  >;
}>;

/**
 * Rejected when a host's capability vocabulary violates `defineGrants`'
 * invariants.
 *
 * This error retains neither the rejected definition nor a foreign cause.
 */
export class GrantsDefinitionError extends Error {
  /** Stable public error name. */
  override readonly name = "GrantsDefinitionError";

  /** Creates a fresh bounded definition error. */
  constructor() {
    super("Ear Tag grants vocabulary definition is invalid");
  }
}

const capabilitiesSchema = z.lazy(() =>
  z.array(z.string().min(1).max(128)).min(1).max(256),
);

function parseImplies<const Capability extends readonly [string, ...string[]]>(
  definition: GrantsDefinition<Capability>,
): ReadonlyMap<string, readonly string[]> {
  if (!capabilitiesSchema.safeParse(definition.capabilities).success)
    throw new GrantsDefinitionError();
  const capabilitySet = new Set<string>(definition.capabilities);
  if (capabilitySet.size !== definition.capabilities.length)
    throw new GrantsDefinitionError();

  // Object.entries widens the declared literal keys to `string`; every key
  // and value is checked against `capabilitySet` below, and the returned map
  // is itself keyed by `string`, so the vocabulary's literal union is never
  // relied on again here.
  const declaredImplies = definition.implies;
  const impliesEntries: (readonly [
    string,
    readonly Capability[number][] | undefined,
  ])[] = declaredImplies === undefined ? [] : Object.entries(declaredImplies);
  for (const [capability, implied] of impliesEntries) {
    if (!capabilitySet.has(capability)) throw new GrantsDefinitionError();
    for (const impliedCapability of implied ?? [])
      if (!capabilitySet.has(impliedCapability))
        throw new GrantsDefinitionError();
  }

  return new Map(
    impliesEntries.map(([capability, implied]) => [capability, implied ?? []]),
  );
}

/**
 * Declares one host's capability vocabulary and the zod schemas and grant
 * operations closed over it.
 *
 * @throws {@link GrantsDefinitionError} When the vocabulary repeats a
 * capability, or `implies` names a capability outside it.
 */
export function defineGrants<
  const Capability extends readonly [string, ...string[]],
>(
  definition: GrantsDefinition<Capability>,
): GrantVocabulary<Capability[number]> {
  type Name = Capability[number];
  const implies = parseImplies(definition);

  const capabilityNameSchema: z.ZodType<Name> = z.enum(definition.capabilities);
  const grantTargetsSchema: z.ZodType<GrantTargets> = z.discriminatedUnion(
    "kind",
    [
      z.strictObject({ kind: z.literal("all") }),
      z.strictObject({
        kind: z.literal("selected"),
        ids: z.array(z.string().min(1).max(256)).max(256),
      }),
    ],
  );
  const grantSchema: z.ZodType<Grant<Name>> = z.strictObject({
    capability: capabilityNameSchema,
    targets: grantTargetsSchema,
  });
  const scopeSchema: z.ZodType<Scope<Name>> = z.strictObject({
    grants: z.array(grantSchema).min(1).max(64),
  });

  // Merges every grant sharing a capability before canonicalizing, so two
  // scopes naming the same authority in a different order, or split across
  // separate grants for the same capability, always produce one identical
  // result: a reordered retry never lands a spurious replay `conflict`.
  const canonicalGrants = (
    grants: readonly Grant<Name>[],
  ): readonly Grant<Name>[] => {
    const merged = new Map<Name, GrantTargets>();
    for (const grant of grants) {
      const existing = merged.get(grant.capability);
      if (existing === undefined) {
        merged.set(
          grant.capability,
          grant.targets.kind === "all"
            ? grant.targets
            : { kind: "selected", ids: [...grant.targets.ids] },
        );
        continue;
      }
      merged.set(
        grant.capability,
        existing.kind === "all" || grant.targets.kind === "all"
          ? { kind: "all" }
          : {
              kind: "selected",
              ids: [...existing.ids, ...grant.targets.ids],
            },
      );
    }
    // Plain code-unit order: stable and locale-independent, matching how
    // `ids` below are already sorted.
    const byCodeUnit = (left: string, right: string): number =>
      left < right ? -1 : left > right ? 1 : 0;
    return [...merged.entries()]
      .map(([capability, targets]): Grant<Name> => ({
        capability,
        targets:
          targets.kind === "all"
            ? targets
            : { kind: "selected", ids: [...new Set(targets.ids)].sort() },
      }))
      .sort((left, right) => byCodeUnit(left.capability, right.capability));
  };

  const grantsAllow = (
    grants: readonly Grant<Name>[],
    capability: Name,
    resourceId?: string,
  ): boolean =>
    grants.some(
      (grant) =>
        (grant.capability === capability ||
          implies.get(grant.capability)?.includes(capability) === true) &&
        (grant.targets.kind === "all" ||
          (resourceId !== undefined && grant.targets.ids.includes(resourceId))),
    );

  const grantsList = (
    grants: readonly Grant<Name>[],
    capability: Name,
  ): boolean =>
    grants.some(
      (grant) =>
        (grant.capability === capability ||
          implies.get(grant.capability)?.includes(capability) === true) &&
        (grant.targets.kind === "all" || grant.targets.ids.length > 0),
    );

  const isSubset = (
    child: readonly Grant<Name>[],
    parent: readonly Grant<Name>[],
  ): boolean =>
    child.every((grant) =>
      grant.targets.kind === "all"
        ? grantsAllow(parent, grant.capability)
        : grant.targets.ids.every((id) =>
            grantsAllow(parent, grant.capability, id),
          ),
    );

  return {
    capabilityNameSchema,
    grantSchema,
    scopeSchema,
    canonicalGrants,
    grantsAllow,
    grantsList,
    isSubset,
  };
}
