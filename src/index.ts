import { LONG, nanoid } from "@fungi.computer/cairn";

/** Options for generating a bearer key. */
export type GenerateKeyOptions = Readonly<{
  /** Number of random characters after the prefix. */
  length?: number;
  /** Public key-family marker, without the separating underscore. */
  prefix?: string;
}>;

/** A newly generated bearer key and the digest safe to retain in storage. */
export type GeneratedKey = Readonly<{
  /** SHA-256 digest suitable for persistence instead of the bearer secret. */
  digest: string;
  /** Bearer secret to disclose once to its authorized recipient. */
  key: string;
}>;

/** Generate a cryptographically random bearer key. */
export function generateKey(options: GenerateKeyOptions = {}): string {
  const key = nanoid(options.length ?? LONG);
  return options.prefix === undefined ? key : `${options.prefix}_${key}`;
}

/** Hash a bearer key with Worker-compatible Web Crypto. */
export async function hashKey(key: string): Promise<string> {
  const bytes = new TextEncoder().encode(key);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

/** Generate a bearer key and the digest its owner should persist. */
export async function generateKeyAndHash(
  options: GenerateKeyOptions = {},
): Promise<GeneratedKey> {
  const key = generateKey(options);
  return { digest: await hashKey(key), key };
}
