import { defineIdFamily } from "@fungi.computer/cairn/id";
import { z } from "zod";

import { generateKeyAndHash, hashKey } from "./index.js";
import type { Grant, GrantVocabulary, Scope } from "./grants.js";

/** One bound SQL value a key store statement may carry. */
export type KeySqlValue = string | number | null;

/** One materialized SQL row, keyed by column name. */
export type KeySqlRow = Readonly<Record<string, KeySqlValue>>;

/** Materialized result of one executed statement. */
export type KeySqlCursor = Readonly<{
  /** Every row the statement produced. */
  toArray: () => readonly KeySqlRow[];
}>;

/**
 * Synchronous SQL execution the key store runs its statements against. This
 * shape fits Cloudflare Durable Object SQLite (`state.storage.sql`) as is.
 * A `node:sqlite` adapter for hosts outside a Durable Object lives at
 * `@fungi.computer/ear-tag/keys/node`, kept out of this module so a Worker
 * consumer of this type never needs Node's own types to typecheck.
 */
export type KeySql = Readonly<{
  /** Execute one statement with positional bindings and return its rows. */
  exec: (
    statement: string,
    ...bindings: readonly KeySqlValue[]
  ) => KeySqlCursor;
}>;

/** A per-key fixed-window request policy. */
export type RateLimitPolicy = Readonly<{
  /** Requests admitted per window. */
  limit: number;
  /** Window length, in seconds. */
  windowSeconds: number;
}>;

const rateLimitSchema: z.ZodType<RateLimitPolicy> = z.strictObject({
  limit: z.number().int().positive(),
  windowSeconds: z.number().int().positive(),
});

/** A stored key's durable state, without its bearer secret. */
export type KeyRecord<Capability extends string> = Readonly<{
  /** Opaque, canonical key identifier. */
  keyId: string;
  /** Opaque identifier of the accountable owner this key was issued under. */
  owner: string;
  /** Caller-chosen label; not secret, not unique. */
  name: string;
  /** The key's authority, or `null` when its stored grants could not be read back. An unreadable scope carries no authority but remains revocable. */
  scope: Scope<Capability> | null;
  /** Monotonic version, incremented by every accepted grant edit. */
  grantVersion: number;
  /** Unix milliseconds after which the key stops verifying, or `null` when the owner chose no expiry. */
  expiresAt: number | null;
  /** Unix milliseconds the key was revoked, or `null` while still live. */
  revokedAt: number | null;
  /** The key's own rate policy, or `null` when unlimited. */
  rateLimit: RateLimitPolicy | null;
  /** Unix milliseconds of the key's last `touch`, or `null` before one. `verify` does not stamp this on its own; a host calls `touch` when it wants usage tracking. */
  lastUsedAt: number | null;
  /** Unix milliseconds the key was issued. */
  createdAt: number;
  /** Unix milliseconds of the key's last state change. */
  updatedAt: number;
}>;

/** A verified bearer credential: a live key's identity and current authority. */
export type KeyPrincipal<Capability extends string> = Readonly<{
  /** Opaque, canonical key identifier. */
  keyId: string;
  /** Opaque identifier of the accountable owner this key was issued under. */
  owner: string;
  /** Caller-chosen label; not secret, not unique. */
  name: string;
  /** The key's authority at the moment it was read. */
  scope: Scope<Capability>;
  /** The grant version this authority was read at; used to detect a stale credential. */
  grantVersion: number;
  /** Unix milliseconds after which the key stops verifying, or `null` when unbounded. */
  expiresAt: number | null;
}>;

/** Stable, closed reasons a key-store operation refuses to proceed. */
export type KeyRefusalCode =
  | "invalid"
  | "denied"
  | "conflict"
  | "expired"
  | "rate_limited"
  | "unavailable";

/**
 * One closed refusal, carried as data rather than a thrown error type.
 *
 * `invalid` means the caller's own input failed the operation's schema; it
 * is the caller's bug. `denied` means well-formed input was refused on its
 * merits (no authority, revoked, suspended). `unavailable` means the store
 * could not read back its own state (a corrupt row, a corrupt rate limit,
 * or any other failure that is not one of the other closed reasons); that
 * is the store's own fault, never the caller's, and every such failure is
 * also logged before this outcome is returned.
 */
export type KeyRefusal = Readonly<{
  /** The stable, closed refusal reason. */
  code: KeyRefusalCode;
  /** Seconds to wait before retrying; present only for `rate_limited`. */
  retryAfterSeconds?: number;
}>;

/** The outcome of one key-store operation: its value, or a closed refusal. */
export type KeyOutcome<Value> = Readonly<
  | Readonly<{
      /** The operation succeeded. */
      kind: "ok";
      /** The operation's result. */
      value: Value;
    }>
  | Readonly<{
      /** The operation refused to proceed. */
      kind: "error";
      /** The closed refusal. */
      error: KeyRefusal;
    }>
>;

/**
 * What an issuing actor may grant. `"unrestricted"` may grant any capability
 * in the host's vocabulary; `"bounded"` may grant only a subset of its own
 * live grants, checked with the vocabulary's `isSubset`.
 */
export type IssuerAuthority<Capability extends string> =
  | Readonly<{
      /** The actor may grant any capability in the host's vocabulary. */
      kind: "unrestricted";
    }>
  | Readonly<{
      /** The actor may grant only a subset of `grants`. */
      kind: "bounded";
      /** The actor's own live grants; every new grant must be their subset. */
      grants: readonly Grant<Capability>[];
    }>;

/** One durable notice that a key's authority changed, for a host's own downstream fencing. */
export type AuthorityFence = Readonly<{
  /** The request that caused the change; stable across a safe retry. */
  requestId: string;
  /** The affected key. */
  keyId: string;
  /** The key's grant version after the change. */
  grantVersion: number;
  /** The key's expiry after the change, or `null` when unbounded. */
  expiresAt: number | null;
}>;

/** Construction options for {@link createKeyStore}. */
export type CreateKeyStoreOptions<Capability extends string> = Readonly<{
  /** Synchronous SQL execution this store's tables are kept in. */
  sql: KeySql;
  /** Commit a durable write with the host's own transaction and recovery coverage. */
  commit: <Value>(body: () => Value) => Promise<Value>;
  /** The host's capability vocabulary and grant operations. */
  vocabulary: GrantVocabulary<Capability>;
  /** Lowercase, underscore-separated namespace for this store's bearer keys, identifiers and tables. */
  prefix: string;
  /**
   * Resolve one actor's authority to issue or edit keys, or `null` to deny
   * the actor outright. The host owns actor identity, role checks, and
   * re-reading a parent key's live authority.
   *
   * `"bounded"` only narrows which grants the actor may assign (`issue`,
   * `updateGrants`): it does not narrow which keys they may `list`, `revoke`
   * or edit. Any actor this resolves to a non-null authority for may manage
   * every key in the tenant, including keys another actor issued. This
   * matches Hub's own `authorizeManage`.
   */
  authorizeIssuer: (
    actorId: string,
  ) => Promise<IssuerAuthority<Capability> | null>;
  /** Notified, inside the host's commit, whenever a key's authority changes. */
  onAuthorityChange?: (fence: AuthorityFence) => void;
  /** Clock override for tests; defaults to `Date.now`. */
  now?: () => number;
}>;

/** Input to {@link KeyStore}'s `issue`. */
export type IssueKeyInput<Capability extends string> = Readonly<{
  /** Caller-chosen label; not secret, not unique. */
  name: string;
  /** The grants the new key carries; 1 to 64. */
  grants: readonly Grant<Capability>[];
  /**
   * Host-chosen id for the new key; omit to let the store generate one.
   * Once an id has been used, including by a now-revoked key, it is never
   * reused: issuing with a reused id refuses `conflict`.
   */
  keyId?: string;
  /** Unix milliseconds after which the key stops verifying; omit for no expiry. */
  expiresAt?: number;
  /** The key's own rate policy; omit for unlimited. */
  rateLimit?: RateLimitPolicy;
}>;

/** Result of {@link KeyStore}'s `issue`: the bearer secret and its durable record. */
export type IssuedKey<Capability extends string> = Readonly<{
  /** Bearer secret to disclose once to its authorized recipient; never stored. */
  key: string;
  /** The issued key's durable record. */
  record: KeyRecord<Capability>;
}>;

/** Input to {@link KeyStore}'s `updateGrants`: a compare-and-swap grant replacement. */
export type UpdateGrantsInput<Capability extends string> = Readonly<{
  /** The request this edit belongs to; a safe retry replays the same outcome. */
  requestId: string;
  /** The key being edited. */
  keyId: string;
  /** The grant version this edit expects to replace. */
  expectedGrantVersion: number;
  /** The key's replacement grants; 1 to 64. */
  grants: readonly Grant<Capability>[];
}>;

/** Input to {@link KeyStore}'s `revoke`: an exact, replayable revocation. */
export type RevokeInput = Readonly<{
  /** The request this revocation belongs to; a safe retry replays the same outcome. */
  requestId: string;
  /** The key being revoked. */
  keyId: string;
}>;

/** Input to {@link KeyStore}'s `admitUse`: one exact, replayable spend admission. */
export type AdmitUseInput<Capability extends string> = Readonly<{
  /** The capability being spent. */
  capability: Capability;
  /** The resource it is spent against, when the capability is resource-scoped. */
  target?: string;
  /** The request this admission belongs to; a safe retry replays the same outcome. */
  requestId: string;
}>;

/** The operations one key store exposes over its tenant's keys. */
export type KeyStore<Capability extends string> = Readonly<{
  /** Issue a new key under `actorId`'s authority. */
  issue: (
    actorId: string,
    input: IssueKeyInput<Capability>,
  ) => Promise<KeyOutcome<IssuedKey<Capability>>>;
  /** Verify a bearer secret and return its current principal. */
  verify: (secret: string) => Promise<KeyOutcome<KeyPrincipal<Capability>>>;
  /** Re-read a captured principal; refuses once its grant version goes stale. */
  current: (
    principal: KeyPrincipal<Capability>,
  ) => Promise<KeyOutcome<KeyPrincipal<Capability>>>;
  /** List every key, or every key owned by `owner`, once `actorId` is authorized to manage keys. */
  list: (
    actorId: string,
    owner?: string,
  ) => Promise<KeyOutcome<readonly KeyRecord<Capability>[]>>;
  /**
   * Read one key's live principal by id, once `actorId` is authorized to
   * manage keys covering at least this key's own grants. Refuses `denied`
   * for an unknown, revoked or suspended key and `expired` for one past
   * its expiry, the same as `verify`.
   */
  read: (
    actorId: string,
    keyId: string,
  ) => Promise<KeyOutcome<KeyPrincipal<Capability>>>;
  /** Compare-and-swap a key's grants. */
  updateGrants: (
    actorId: string,
    input: UpdateGrantsInput<Capability>,
  ) => Promise<KeyOutcome<KeyRecord<Capability>>>;
  /** Tombstone a key; idempotent on repeat. */
  revoke: (
    actorId: string,
    input: RevokeInput,
  ) => Promise<KeyOutcome<KeyRecord<Capability>>>;
  /** Permanently suspend every key owned by `owner`, for example on its departure. Commits its own write. */
  suspendOwner: (owner: string, requestId: string) => Promise<KeyOutcome<void>>;
  /** Revoke every still-live key as of `closedAt`. Runs inside the caller's own transaction; it does not commit. */
  revokeAll: (closedAt: number) => Promise<KeyOutcome<void>>;
  /** Re-verify a capability against a principal's live authority and record one idempotent use receipt. */
  admitUse: (
    principal: KeyPrincipal<Capability>,
    input: AdmitUseInput<Capability>,
  ) => Promise<KeyOutcome<KeyPrincipal<Capability>>>;
  /**
   * Stamp a key's `lastUsedAt`. The only place that writes it; `verify`
   * never stamps on its own. Refuses `denied` for an unknown key.
   */
  touch: (keyId: string) => Promise<KeyOutcome<void>>;
}>;

class Refusal extends Error {
  constructor(
    readonly code: KeyRefusalCode,
    readonly retryAfterSeconds?: number,
  ) {
    super(`Ear Tag key store refusal: ${code}`);
    this.name = "Refusal";
  }
}

const PREFIX_PATTERN = /^[a-z][a-z0-9]*(?:_[a-z][a-z0-9]*)*$/;
const prefixSchema = z.lazy(() =>
  z.string().min(1).max(24).regex(PREFIX_PATTERN),
);
const requestIdSchema = z.lazy(() => z.string().min(1).max(112));

type MutationKind = "grants" | "revoke";

type MutationReceipt<Capability extends string> = Readonly<{
  kind: MutationKind;
  actorId: string;
  input: string;
  metadata: KeyRecord<Capability>;
}>;

/**
 * Create one tenant-scoped key store: bearer-key issuance, verification and
 * lifecycle over one host's capability vocabulary. One store instance is one
 * tenant; namespacing between tenants is the host's own table or storage
 * boundary, not a column inside this store.
 */
export function createKeyStore<Capability extends string>(
  options: CreateKeyStoreOptions<Capability>,
): KeyStore<Capability> {
  const prefix = prefixSchema.parse(options.prefix);
  const now = options.now ?? Date.now;
  const vocabulary = options.vocabulary;
  const sql = options.sql;

  const ids = defineIdFamily({
    family: "ear-tag",
    version: 1,
    kinds: { key: { prefix } },
  });

  const keysTable = `ear_tag_${prefix}_keys`;
  const receiptsTable = `ear_tag_${prefix}_key_receipts`;
  const suspensionsTable = `ear_tag_${prefix}_key_suspensions`;
  const useReceiptsTable = `ear_tag_${prefix}_key_use_receipts`;

  const ensure = (): void => {
    sql.exec(`CREATE TABLE IF NOT EXISTS ${keysTable} (
      key_id TEXT PRIMARY KEY,
      owner TEXT NOT NULL,
      digest TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      grants TEXT NOT NULL,
      grant_version INTEGER NOT NULL CHECK(grant_version > 0),
      expires_at INTEGER,
      revoked_at INTEGER,
      rate_limit TEXT,
      last_used_at INTEGER,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    ) STRICT`);
    sql.exec(`CREATE TABLE IF NOT EXISTS ${receiptsTable} (
      request_id TEXT PRIMARY KEY,
      kind TEXT NOT NULL CHECK(kind IN ('grants','revoke')),
      actor_id TEXT NOT NULL,
      input TEXT NOT NULL,
      metadata TEXT NOT NULL
    ) STRICT`);
    sql.exec(`CREATE TABLE IF NOT EXISTS ${suspensionsTable} (
      key_id TEXT PRIMARY KEY, suspended_at INTEGER NOT NULL
    ) STRICT`);
    sql.exec(`CREATE TABLE IF NOT EXISTS ${useReceiptsTable} (
      request_id TEXT PRIMARY KEY, key_id TEXT NOT NULL, grant_version INTEGER NOT NULL,
      capability TEXT NOT NULL, target TEXT, at INTEGER NOT NULL
    ) STRICT`);
  };

  const keyRowSchema = z.strictObject({
    key_id: z.string().min(1).max(256),
    owner: z.string().min(1).max(256),
    digest: z.string().length(64),
    name: z.string().min(1).max(128),
    grants: z.string(),
    grant_version: z.number().int().positive(),
    expires_at: z.number().int().positive().nullable(),
    revoked_at: z.number().int().nonnegative().nullable(),
    rate_limit: z.string().nullable(),
    last_used_at: z.number().int().nonnegative().nullable(),
    created_at: z.number().int().nonnegative(),
    updated_at: z.number().int().nonnegative(),
  });

  const grantsArraySchema = z.array(vocabulary.grantSchema).min(1).max(64);
  const issueInputSchema = z.strictObject({
    name: z.string().trim().min(1).max(128),
    grants: grantsArraySchema,
    keyId: z.string().min(1).max(256).optional(),
    expiresAt: z.number().int().positive().optional(),
    rateLimit: rateLimitSchema.optional(),
  });
  const updateGrantsInputSchema = z.strictObject({
    requestId: requestIdSchema,
    keyId: z.string().min(1).max(256),
    expectedGrantVersion: z.number().int().positive(),
    grants: grantsArraySchema,
  });
  const keyRecordSchema = z.strictObject({
    keyId: z.string().min(1).max(256),
    owner: z.string().min(1).max(256),
    name: z.string().min(1).max(128),
    scope: vocabulary.scopeSchema.nullable(),
    grantVersion: z.number().int().positive(),
    expiresAt: z.number().int().positive().nullable(),
    revokedAt: z.number().int().nonnegative().nullable(),
    rateLimit: rateLimitSchema.nullable(),
    lastUsedAt: z.number().int().nonnegative().nullable(),
    createdAt: z.number().int().nonnegative(),
    updatedAt: z.number().int().nonnegative(),
  });
  const revokeInputSchema = z.strictObject({
    requestId: requestIdSchema,
    keyId: z.string().min(1).max(256),
  });
  const admitUseInputSchema = z.strictObject({
    capability: vocabulary.capabilityNameSchema,
    target: z.string().min(1).max(256).optional(),
    requestId: z.string().min(1).max(256),
  });
  const keyPrincipalSchema = z.strictObject({
    keyId: z.string().min(1).max(256),
    owner: z.string().min(1).max(256),
    name: z.string().min(1).max(128),
    scope: vocabulary.scopeSchema,
    grantVersion: z.number().int().positive(),
    expiresAt: z.number().int().positive().nullable(),
  });
  const mutationReceiptRowSchema = z.strictObject({
    request_id: requestIdSchema,
    kind: z.enum(["grants", "revoke"]),
    actor_id: z.string().min(1).max(256),
    input: z.string().min(1),
    metadata: z.string().min(1),
  });

  const columns =
    "key_id,owner,digest,name,grants,grant_version,expires_at,revoked_at,rate_limit,last_used_at,created_at,updated_at";

  const decodeScope = (json: string): Scope<Capability> | null => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch {
      return null;
    }
    const result = vocabulary.scopeSchema.safeParse(parsed);
    if (!result.success) return null;
    return { grants: vocabulary.canonicalGrants(result.data.grants) };
  };

  // Unlike a corrupt scope (which fails closed to no authority), a corrupt
  // rate limit must never fail open to unlimited: a stored, non-null policy
  // that cannot be read back refuses the whole record as unavailable.
  const decodeRateLimit = (json: string | null): RateLimitPolicy | null => {
    if (json === null) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch {
      throw new Refusal("unavailable");
    }
    const result = rateLimitSchema.safeParse(parsed);
    if (!result.success) throw new Refusal("unavailable");
    return result.data;
  };

  const decode = (row: KeySqlRow): KeyRecord<Capability> => {
    const parsed = keyRowSchema.safeParse(row);
    if (!parsed.success) throw new Refusal("unavailable");
    // A key id is either store-generated (`ids.key.generate()`) or
    // host-chosen at issuance (`IssueKeyInput.keyId`); only the former has
    // this id family's own shape, so decode trusts it as the plain, bounded
    // string `keyRowSchema` already validated above, not a family member.
    return {
      keyId: parsed.data.key_id,
      owner: parsed.data.owner,
      name: parsed.data.name,
      scope: decodeScope(parsed.data.grants),
      grantVersion: parsed.data.grant_version,
      expiresAt: parsed.data.expires_at,
      revokedAt: parsed.data.revoked_at,
      rateLimit: decodeRateLimit(parsed.data.rate_limit),
      lastUsedAt: parsed.data.last_used_at,
      createdAt: parsed.data.created_at,
      updatedAt: parsed.data.updated_at,
    };
  };

  const readById = (keyId: string): KeyRecord<Capability> | null => {
    ensure();
    const row = sql
      .exec(`SELECT ${columns} FROM ${keysTable} WHERE key_id=?`, keyId)
      .toArray()[0];
    return row === undefined ? null : decode(row);
  };

  const isSuspended = (keyId: string): boolean =>
    sql
      .exec(`SELECT key_id FROM ${suspensionsTable} WHERE key_id=?`, keyId)
      .toArray().length > 0;

  const requireActive = (
    record: KeyRecord<Capability>,
  ): KeyRecord<Capability> & Readonly<{ scope: Scope<Capability> }> => {
    if (record.scope === null) throw new Refusal("denied");
    if (record.revokedAt !== null) throw new Refusal("denied");
    if (isSuspended(record.keyId)) throw new Refusal("denied");
    if (record.expiresAt !== null && record.expiresAt <= now())
      throw new Refusal("expired");
    return { ...record, scope: record.scope };
  };

  const principalFor = (
    record: KeyRecord<Capability> & Readonly<{ scope: Scope<Capability> }>,
  ): KeyPrincipal<Capability> => ({
    keyId: record.keyId,
    owner: record.owner,
    name: record.name,
    scope: record.scope,
    grantVersion: record.grantVersion,
    expiresAt: record.expiresAt,
  });

  const assertIssuer = async (
    actorId: string,
    grants: readonly Grant<Capability>[],
  ): Promise<void> => {
    const authority = await options.authorizeIssuer(actorId);
    if (authority === null) throw new Refusal("denied");
    if (
      authority.kind === "bounded" &&
      !vocabulary.isSubset(grants, authority.grants)
    )
      throw new Refusal("denied");
  };

  type RateWindow = Readonly<{
    windowStart: number;
    count: number;
    windowMs: number;
  }>;
  const rateWindows = new Map<string, RateWindow>();

  const admitRate = (keyId: string, policy: RateLimitPolicy): number | null => {
    const at = now();
    for (const [id, window] of rateWindows)
      if (at - window.windowStart >= window.windowMs) rateWindows.delete(id);
    const windowMs = policy.windowSeconds * 1_000;
    const window = rateWindows.get(keyId);
    if (window === undefined || at - window.windowStart >= window.windowMs) {
      rateWindows.set(keyId, { windowStart: at, count: 1, windowMs });
      return null;
    }
    if (window.count >= policy.limit)
      return Math.max(
        1,
        Math.ceil((window.windowStart + window.windowMs - at) / 1_000),
      );
    rateWindows.set(keyId, { ...window, count: window.count + 1 });
    return null;
  };

  const currentImpl = (rawPrincipal: unknown): KeyPrincipal<Capability> => {
    const principal = keyPrincipalSchema.parse(rawPrincipal);
    const record = readById(principal.keyId);
    if (record === null) throw new Refusal("denied");
    const active = requireActive(record);
    if (active.grantVersion !== principal.grantVersion)
      throw new Refusal("denied");
    return principalFor(active);
  };

  const currentLiveImpl = async (
    principal: KeyPrincipal<Capability>,
  ): Promise<KeyPrincipal<Capability>> => {
    const record = currentImpl(principal);
    await assertIssuer(record.owner, record.scope.grants);
    return currentImpl(record);
  };

  const verifyImpl = async (
    secret: string,
  ): Promise<KeyPrincipal<Capability>> => {
    const digest = await hashKey(secret);
    ensure();
    const row = sql
      .exec(`SELECT ${columns} FROM ${keysTable} WHERE digest=?`, digest)
      .toArray()[0];
    if (row === undefined) throw new Refusal("denied");
    const record = requireActive(decode(row));
    await assertIssuer(record.owner, record.scope.grants);
    const freshRecord = readById(record.keyId);
    if (freshRecord === null) throw new Refusal("denied");
    const fresh = requireActive(freshRecord);
    if (fresh.rateLimit !== null) {
      const retryAfterSeconds = admitRate(fresh.keyId, fresh.rateLimit);
      if (retryAfterSeconds !== null)
        throw new Refusal("rate_limited", retryAfterSeconds);
    }
    return principalFor(fresh);
  };

  // Merging grants that share a capability can push one grant's `ids` past
  // the bound `grantTargetsSchema` allows even when every grant the caller
  // sent was itself within bounds (two disjoint 129-id grants merge into
  // one 258-id grant). The merged, canonical form is what gets stored and
  // later read back through this same `scopeSchema`, so it must pass that
  // schema here too, before anything is written: an over-bound merge is
  // the caller's own invalid input, never a bound this store relaxes, and
  // refusing it before any write leaves the key exactly as it was.
  const requireValidScope = (grants: readonly Grant<Capability>[]): void => {
    if (!vocabulary.scopeSchema.safeParse({ grants }).success)
      throw new Refusal("invalid");
  };

  const issueImpl = async (
    actorId: string,
    rawInput: unknown,
  ): Promise<IssuedKey<Capability>> => {
    const input = issueInputSchema.parse(rawInput);
    const grants = vocabulary.canonicalGrants(input.grants);
    requireValidScope(grants);
    if (input.expiresAt !== undefined && input.expiresAt <= now())
      throw new Refusal("denied");
    await assertIssuer(actorId, grants);
    const generated = await generateKeyAndHash({ prefix });
    const createdAt = now();
    const record = await options.commit(() => {
      ensure();
      const keyId = input.keyId ?? ids.key.generate();
      // An id is never reused, including one a now-revoked key already
      // held: revoke tombstones the row rather than deleting it, so it
      // still answers here. The check and the insert share this one
      // commit, so no other write can land between them; the PRIMARY KEY
      // on key_id is the storage-level backstop behind this refusal.
      if (readById(keyId) !== null) throw new Refusal("conflict");
      sql.exec(
        `INSERT INTO ${keysTable} (${columns}) VALUES (?,?,?,?,?,1,?,NULL,?,NULL,?,?)`,
        keyId,
        actorId,
        generated.digest,
        input.name,
        JSON.stringify({ grants }),
        input.expiresAt ?? null,
        input.rateLimit ? JSON.stringify(input.rateLimit) : null,
        createdAt,
        createdAt,
      );
      const stored = readById(keyId);
      if (stored === null) throw new Refusal("unavailable");
      return requireActive(stored);
    });
    return { key: generated.key, record };
  };

  const readMutationReceipt = (
    requestId: string,
  ): MutationReceipt<Capability> | null => {
    const raw = sql
      .exec(
        `SELECT request_id,kind,actor_id,input,metadata FROM ${receiptsTable} WHERE request_id=?`,
        requestId,
      )
      .toArray()[0];
    if (raw === undefined) return null;
    const row = mutationReceiptRowSchema.safeParse(raw);
    if (!row.success) throw new Refusal("unavailable");
    let metadata: unknown;
    try {
      metadata = JSON.parse(row.data.metadata);
    } catch {
      throw new Refusal("unavailable");
    }
    const parsedMetadata = keyRecordSchema.safeParse(metadata);
    if (!parsedMetadata.success) throw new Refusal("unavailable");
    return {
      kind: row.data.kind,
      actorId: row.data.actor_id,
      input: row.data.input,
      metadata: parsedMetadata.data,
    };
  };

  const recordMutationReceipt = (
    requestId: string,
    receipt: MutationReceipt<Capability>,
  ): void => {
    sql.exec(
      `INSERT INTO ${receiptsTable} (request_id,kind,actor_id,input,metadata) VALUES (?,?,?,?,?)`,
      requestId,
      receipt.kind,
      receipt.actorId,
      receipt.input,
      JSON.stringify(receipt.metadata),
    );
  };

  const replayMutation = (
    requestId: string,
    actorId: string,
    kind: MutationKind,
    input: string,
  ): KeyRecord<Capability> | null => {
    const prior = readMutationReceipt(requestId);
    if (prior === null) return null;
    if (
      prior.kind !== kind ||
      prior.actorId !== actorId ||
      prior.input !== input
    )
      throw new Refusal("conflict");
    return prior.metadata;
  };

  const fence = (requestId: string, record: KeyRecord<Capability>): void => {
    options.onAuthorityChange?.({
      requestId,
      keyId: record.keyId,
      grantVersion: record.grantVersion,
      expiresAt: record.expiresAt,
    });
  };

  const updateGrantsImpl = async (
    actorId: string,
    rawInput: unknown,
  ): Promise<KeyRecord<Capability>> => {
    const input = updateGrantsInputSchema.parse(rawInput);
    const grants = vocabulary.canonicalGrants(input.grants);
    requireValidScope(grants);
    await assertIssuer(actorId, grants);
    const inputKey = JSON.stringify({
      keyId: input.keyId,
      expectedGrantVersion: input.expectedGrantVersion,
      grants,
    });
    const replay = replayMutation(input.requestId, actorId, "grants", inputKey);
    if (replay !== null) return replay;
    return options.commit(() => {
      const repeated = replayMutation(
        input.requestId,
        actorId,
        "grants",
        inputKey,
      );
      if (repeated !== null) return repeated;
      const current = readById(input.keyId);
      if (current === null) throw new Refusal("denied");
      if (current.revokedAt !== null) throw new Refusal("denied");
      if (current.grantVersion !== input.expectedGrantVersion)
        throw new Refusal("conflict");
      const updatedAt = now();
      sql.exec(
        `UPDATE ${keysTable} SET grants=?,grant_version=grant_version+1,updated_at=? WHERE key_id=? AND grant_version=? AND revoked_at IS NULL`,
        JSON.stringify({ grants }),
        updatedAt,
        input.keyId,
        input.expectedGrantVersion,
      );
      const after = readById(input.keyId);
      if (after === null) throw new Refusal("conflict");
      if (after.grantVersion !== input.expectedGrantVersion + 1)
        throw new Refusal("conflict");
      fence(input.requestId, after);
      recordMutationReceipt(input.requestId, {
        kind: "grants",
        actorId,
        input: inputKey,
        metadata: after,
      });
      return after;
    });
  };

  const revokeImpl = async (
    actorId: string,
    rawInput: unknown,
  ): Promise<KeyRecord<Capability>> => {
    const input = revokeInputSchema.parse(rawInput);
    const authority = await options.authorizeIssuer(actorId);
    if (authority === null) throw new Refusal("denied");
    const inputKey = JSON.stringify({ keyId: input.keyId });
    const replay = replayMutation(input.requestId, actorId, "revoke", inputKey);
    if (replay !== null) return replay;
    return options.commit(() => {
      const repeated = replayMutation(
        input.requestId,
        actorId,
        "revoke",
        inputKey,
      );
      if (repeated !== null) return repeated;
      const current = readById(input.keyId);
      if (current === null) throw new Refusal("denied");
      if (current.revokedAt === null) {
        const revokedAt = now();
        sql.exec(
          `UPDATE ${keysTable} SET revoked_at=?,updated_at=? WHERE key_id=? AND revoked_at IS NULL`,
          revokedAt,
          revokedAt,
          current.keyId,
        );
      }
      const revoked = readById(current.keyId);
      if (revoked === null) throw new Refusal("conflict");
      if (revoked.revokedAt === null) throw new Refusal("conflict");
      fence(input.requestId, revoked);
      recordMutationReceipt(input.requestId, {
        kind: "revoke",
        actorId,
        input: inputKey,
        metadata: revoked,
      });
      return revoked;
    });
  };

  const listImpl = async (
    actorId: string,
    owner?: string,
  ): Promise<readonly KeyRecord<Capability>[]> => {
    const authority = await options.authorizeIssuer(actorId);
    if (authority === null) throw new Refusal("denied");
    ensure();
    const rows =
      owner === undefined
        ? sql
            .exec(
              `SELECT ${columns} FROM ${keysTable} ORDER BY created_at DESC,key_id DESC`,
            )
            .toArray()
        : sql
            .exec(
              `SELECT ${columns} FROM ${keysTable} WHERE owner=? ORDER BY created_at DESC,key_id DESC`,
              owner,
            )
            .toArray();
    return rows.map(decode);
  };

  const readImpl = async (
    actorId: string,
    keyId: string,
  ): Promise<KeyPrincipal<Capability>> => {
    const record = readById(keyId);
    if (record === null) throw new Refusal("denied");
    const active = requireActive(record);
    await assertIssuer(actorId, active.scope.grants);
    return principalFor(active);
  };

  const admitUseImpl = async (
    principal: KeyPrincipal<Capability>,
    rawInput: unknown,
  ): Promise<KeyPrincipal<Capability>> => {
    const input = admitUseInputSchema.parse(rawInput);
    const live = await currentLiveImpl(principal);
    if (
      !vocabulary.grantsAllow(live.scope.grants, input.capability, input.target)
    )
      throw new Refusal("denied");
    const at = now();
    await options.commit(() => {
      currentImpl(live);
      const prior = sql
        .exec(
          `SELECT key_id,grant_version,capability,target FROM ${useReceiptsTable} WHERE request_id=?`,
          input.requestId,
        )
        .toArray()[0];
      if (prior !== undefined) {
        if (
          prior.key_id !== live.keyId ||
          prior.grant_version !== live.grantVersion ||
          prior.capability !== input.capability ||
          prior.target !== (input.target ?? null)
        )
          throw new Refusal("conflict");
        return;
      }
      sql.exec(
        `INSERT INTO ${useReceiptsTable} (request_id,key_id,grant_version,capability,target,at) VALUES (?,?,?,?,?,?)`,
        input.requestId,
        live.keyId,
        live.grantVersion,
        input.capability,
        input.target ?? null,
        at,
      );
    });
    return live;
  };

  const suspendOwnerImpl = async (
    owner: string,
    requestId: string,
  ): Promise<void> => {
    ensure();
    await options.commit(() => {
      const rows = sql
        .exec(`SELECT ${columns} FROM ${keysTable} WHERE owner=?`, owner)
        .toArray()
        .map(decode);
      for (const record of rows) {
        sql.exec(
          `INSERT OR IGNORE INTO ${suspensionsTable} (key_id,suspended_at) VALUES (?,?)`,
          record.keyId,
          now(),
        );
        fence(
          JSON.stringify(["owner-suspension", requestId, record.keyId]),
          record,
        );
      }
    });
  };

  const revokeAllImpl = (closedAt: number): void => {
    ensure();
    const rows = sql
      .exec(`SELECT ${columns} FROM ${keysTable} WHERE revoked_at IS NULL`)
      .toArray()
      .map(decode);
    for (const record of rows) {
      sql.exec(
        `UPDATE ${keysTable} SET revoked_at=?,updated_at=? WHERE key_id=? AND revoked_at IS NULL`,
        closedAt,
        closedAt,
        record.keyId,
      );
      // Fence the post-revoke row, not the pre-revoke `record` read above;
      // grantVersion and expiresAt do not change on revoke, but a fence
      // naming a now-revoked key must never read as still live.
      const revoked = readById(record.keyId);
      if (revoked !== null)
        fence(JSON.stringify(["revoke-all", closedAt, record.keyId]), revoked);
    }
  };

  const touchImpl = async (keyId: string): Promise<void> => {
    const record = readById(keyId);
    if (record === null) throw new Refusal("denied");
    await options.commit(() => {
      ensure();
      sql.exec(
        `UPDATE ${keysTable} SET last_used_at=? WHERE key_id=?`,
        now(),
        keyId,
      );
    });
  };

  const boundary = async <Value>(
    operation: () => Value | Promise<Value>,
  ): Promise<KeyOutcome<Value>> => {
    try {
      return { kind: "ok", value: await operation() };
    } catch (error) {
      if (error instanceof Refusal)
        return {
          kind: "error",
          error:
            error.retryAfterSeconds === undefined
              ? { code: error.code }
              : {
                  code: error.code,
                  retryAfterSeconds: error.retryAfterSeconds,
                },
        };
      // Every `.parse()` call in this store runs only on caller-supplied
      // input (stored data is always read through `.safeParse()` and a
      // `Refusal` above), so a ZodError here is always the caller's own
      // malformed request, never the store's state.
      if (error instanceof z.ZodError)
        return { kind: "error", error: { code: "invalid" } };
      // An unexpected, unclassified failure: never silently relabel it as
      // one of the closed reasons above without a trace of what it was.
      console.error("Ear Tag key store: unexpected failure", error);
      return { kind: "error", error: { code: "unavailable" } };
    }
  };

  return {
    issue: (actorId, input) => boundary(() => issueImpl(actorId, input)),
    verify: (secret) => boundary(() => verifyImpl(secret)),
    current: (principal) => boundary(() => currentImpl(principal)),
    list: (actorId, owner) => boundary(() => listImpl(actorId, owner)),
    read: (actorId, keyId) => boundary(() => readImpl(actorId, keyId)),
    updateGrants: (actorId, input) =>
      boundary(() => updateGrantsImpl(actorId, input)),
    revoke: (actorId, input) => boundary(() => revokeImpl(actorId, input)),
    suspendOwner: (owner, requestId) =>
      boundary(() => suspendOwnerImpl(owner, requestId)),
    revokeAll: (closedAt) =>
      boundary(() => {
        revokeAllImpl(closedAt);
      }),
    admitUse: (principal, input) =>
      boundary(() => admitUseImpl(principal, input)),
    touch: (keyId) => boundary(() => touchImpl(keyId)),
  };
}
