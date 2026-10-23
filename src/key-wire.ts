import { z } from "zod";

import type { GrantVocabulary } from "./grants.js";
import type {
  IssueKeyInput,
  KeyRefusal,
  KeyRecord,
  RevokeInput,
  UpdateGrantsInput,
} from "./keys.js";

export const rateLimitSchema = z.strictObject({
  limit: z.number().int().positive(),
  windowSeconds: z.number().int().positive(),
});

/** The closed refusal vocabulary used by key-owner outcomes and transport decoders. */
export const keyRefusalCodes = [
  "invalid",
  "denied",
  "conflict",
  "expired",
  "rate_limited",
  "unavailable",
] as const;

/** Stable, closed reasons a key-store operation refuses to proceed. */
export type KeyRefusalCode = (typeof keyRefusalCodes)[number];

/** Closed key-owner refusals crossing JSON or RPC transports. */
export const keyRefusalSchema: z.ZodType<KeyRefusal> = z
  .strictObject({
    code: z.enum(keyRefusalCodes),
    retryAfterSeconds: z.number().int().positive().optional(),
  })
  .transform(({ code, retryAfterSeconds }) =>
    retryAfterSeconds === undefined ? { code } : { code, retryAfterSeconds },
  );

/** Owner-facing key metadata; neither the human owner id nor digest is exposed. */
export type KeySummary<Capability extends string> = Readonly<
  Omit<KeyRecord<Capability>, "owner" | "scope"> & {
    /** Canonical grants, empty when stored authority cannot be decoded. */
    grants: NonNullable<KeyRecord<Capability>["scope"]>["grants"];
  }
>;

/** Shared request decoders and secret-free key metadata for host transports. */
export type KeyWire<Capability extends string> = Readonly<{
  /** Decode a key issuance request; hosts retain their own issuance policy. */
  issue: z.ZodType<IssueKeyInput<Capability>>;
  /** Decode an exact, compare-and-swap grant replacement. */
  updateGrants: z.ZodType<UpdateGrantsInput<Capability>>;
  /** Decode an exact revocation request. */
  revoke: z.ZodType<RevokeInput>;
  /** Decode secret-free metadata at a host transport's consumer boundary. */
  summary: z.ZodType<KeySummary<Capability>>;
  /** Project a stored record into owner-facing metadata. */
  toSummary: (record: KeyRecord<Capability>) => KeySummary<Capability>;
}>;

/** One wire grammar for both Hub and standalone Oyster key transports. */
export function keyWire<Capability extends string>(
  vocabulary: GrantVocabulary<Capability>,
): KeyWire<Capability> {
  const keyId = z.string().min(1).max(256);
  const requestId = z.string().min(1).max(112);
  const grants = z.array(vocabulary.grantSchema).min(1).max(64);
  return {
    issue: z.strictObject({
      name: z.string().trim().min(1).max(128),
      grants,
      keyId: keyId.optional(),
      expiresAt: z.number().int().positive().optional(),
      rateLimit: rateLimitSchema.optional(),
    }),
    updateGrants: z.strictObject({
      requestId,
      keyId,
      expectedGrantVersion: z.number().int().positive(),
      grants,
    }),
    revoke: z.strictObject({ requestId, keyId }),
    summary: z.strictObject({
      keyId,
      name: z.string().min(1).max(128),
      grants: z.array(vocabulary.grantSchema).max(64),
      grantVersion: z.number().int().positive(),
      expiresAt: z.number().int().positive().nullable(),
      revokedAt: z.number().int().nonnegative().nullable(),
      rateLimit: rateLimitSchema.nullable(),
      lastUsedAt: z.number().int().nonnegative().nullable(),
      createdAt: z.number().int().nonnegative(),
      updatedAt: z.number().int().nonnegative(),
    }),
    toSummary: (record) => ({
      keyId: record.keyId,
      name: record.name,
      grants: record.scope?.grants ?? [],
      grantVersion: record.grantVersion,
      expiresAt: record.expiresAt,
      revokedAt: record.revokedAt,
      rateLimit: record.rateLimit,
      lastUsedAt: record.lastUsedAt,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    }),
  };
}
