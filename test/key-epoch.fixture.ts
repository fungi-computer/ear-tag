import type { AuthorityEpoch, CreateKeyStoreOptions } from "../src/keys.js";
import type { TestCapability } from "./test-vocabulary.js";

export type EpochFailure =
  "begin" | "before-commit" | "after-commit" | "finish";
export type EpochEvent = Readonly<{
  kind: "begin" | "commit" | "finish" | "abort";
  decisionId?: string;
}>;

/** Fault injection at real host commit/epoch ports, shared by both SQL backends. */
export function createEpochFixture(
  commit: CreateKeyStoreOptions<TestCapability>["commit"],
) {
  const events: EpochEvent[] = [];
  // Retained BrokerAuthorityDO at 6590c107: aborted decisions cannot begin
  // again; either terminal outcome can only be resolved idempotently.
  const decisions = new Map<string, "pending" | "applied" | "aborted">();
  let failure: EpochFailure | undefined;
  const fail = (at: EpochFailure) => {
    if (failure !== at) return;
    failure = undefined;
    throw new Error(`fixture host failure: ${at}`);
  };
  const resolve = (decisionId: string, outcome: "applied" | "aborted") => {
    const current = decisions.get(decisionId);
    if (current === undefined) throw new Error("Unknown broker decision");
    if (current === outcome) return;
    if (current !== "pending")
      throw new Error("Broker decision has another outcome");
    decisions.set(decisionId, outcome);
  };
  const epoch: AuthorityEpoch = {
    begin: (decisionId) => {
      events.push({ kind: "begin", decisionId });
      fail("begin");
      const current = decisions.get(decisionId);
      if (current === "aborted") throw new Error("Broker decision was aborted");
      if (current !== undefined) return Promise.resolve();
      if ([...decisions.values()].includes("pending"))
        throw new Error("Broker authority change pending");
      decisions.set(decisionId, "pending");
      return Promise.resolve();
    },
    finish: (decisionId) => {
      events.push({ kind: "finish", decisionId });
      fail("finish");
      resolve(decisionId, "applied");
      return Promise.resolve();
    },
    abort: (decisionId) => {
      events.push({ kind: "abort", decisionId });
      resolve(decisionId, "aborted");
      return Promise.resolve();
    },
  };
  return {
    epoch,
    commit: async <Value>(body: () => Value): Promise<Value> => {
      events.push({ kind: "commit" });
      fail("before-commit");
      const value = await commit(body);
      fail("after-commit");
      return value;
    },
    events: () => [...events],
    decision: (decisionId: string) => decisions.get(decisionId),
    begunDecisions: () => decisions.size,
    pending: () => [...decisions.values()].includes("pending"),
    failNext: (at: EpochFailure) => {
      failure = at;
    },
  };
}
