// Pure ordering and tallying over issues. No aio, no Deno — runs identically on
// the server, in the browser and in a unit test.
import type { Issue, Severity } from "../type/issue.ts";

const RANK: Record<Severity, number> = { critical: 0, major: 1, minor: 2 };

export const rank = (s: Severity): number => RANK[s];

/** Significance order: band first, weight inside the band, id last. The id
 *  tie-break is not decoration — without it two equally significant issues can
 *  swap places between renders and the list flickers. */
export const bySignificance = (a: Issue, b: Issue): number =>
  rank(a.severity) - rank(b.severity) ||
  b.weight - a.weight ||
  a.id.localeCompare(b.id);

export const ordered = (issues: readonly Issue[]): Issue[] =>
  [...issues].sort(bySignificance);

export const countBySeverity = (
  issues: readonly Issue[],
): Record<Severity, number> =>
  issues.reduce<Record<Severity, number>>(
    (acc, i) => ({ ...acc, [i.severity]: acc[i.severity] + 1 }),
    { critical: 0, major: 0, minor: 0 },
  );

/** The issues "Fix all" would act on — and nothing else. Optional changes are
 *  excluded by this one line: they are a different remedy kind precisely so
 *  that a sweep cannot pick them up. */
export const fixable = (issues: readonly Issue[]): Issue[] =>
  issues.filter((i) => i.remedy.kind === "fix");

/** The issues "Fix all (sudo required)" would act on. */
export const rootFixable = (issues: readonly Issue[]): Issue[] =>
  issues.filter((i) => i.remedy.kind === "sudo");
