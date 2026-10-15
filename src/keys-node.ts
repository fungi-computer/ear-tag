import type { DatabaseSync } from "node:sqlite";
import { z } from "zod";

import type { KeySql } from "./keys.js";

const nodeSqliteRowSchema = z.record(
  z.string(),
  z.union([z.string(), z.number(), z.null()]),
);

/**
 * Adapt a caller-owned `node:sqlite` database to the `KeySql` port
 * `createKeyStore` expects, for hosts that run outside a Durable Object. The
 * caller retains the database's lifetime.
 */
export function fromNodeSqlite(database: DatabaseSync): KeySql {
  return {
    exec: (statement, ...bindings) => {
      const prepared = database.prepare(statement);
      if (prepared.columns().length === 0) {
        prepared.run(...bindings);
        return { toArray: () => [] };
      }
      const rows = prepared
        .all(...bindings)
        .map((row) => nodeSqliteRowSchema.parse(row));
      return { toArray: () => rows };
    },
  };
}
