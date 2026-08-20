// Pure list arithmetic for partial re-probes. No aio, no Deno.
import type { Issue } from "../type/issue.ts";
import { ordered } from "./severity.ts";

/** Fold the result of re-running *some* checks into the current list.
 *
 *  A monitor tick re-probes four checks; the fifteen it did not run must keep
 *  their last verdict rather than vanish for 30 seconds and come back. So the
 *  authority of a pass extends exactly as far as the checks it actually ran:
 *  `ran` is that scope, `found` is what came back, everything else survives. */
export const merge = (
  current: readonly Issue[],
  ran: readonly string[],
  found: readonly Issue[],
): Issue[] => {
  const scope = new Set(ran);
  const kept = current.filter((i) => !scope.has(i.id));
  return ordered([...kept, ...found]);
};

/** The same fold over a bare id list (checks that could not measure). */
export const mergeIds = (
  current: readonly string[],
  ran: readonly string[],
  found: readonly string[],
): string[] => {
  const scope = new Set(ran);
  return [...current.filter((id) => !scope.has(id)), ...found];
};

/** Drop one issue — what a verified fix leaves behind. */
export const without = (current: readonly Issue[], id: string): Issue[] =>
  current.filter((i) => i.id !== id);
