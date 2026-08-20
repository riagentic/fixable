// Pure transforms over the fix log. No aio, no Deno.
import type { FixRecord } from "../type/issue.ts";

/** Newest first, bounded. */
export const remember = (
  log: readonly FixRecord[],
  record: FixRecord,
  limit: number,
): FixRecord[] => [record, ...log].slice(0, limit);

/** Mark the newest still-undoable record for `id` as reversed.
 *
 *  Newest only: two fixes of the same check leave two records, and undoing
 *  once must retire one button, not both. */
export const markUndone = (
  log: readonly FixRecord[],
  id: string,
): FixRecord[] => {
  const at = log.findIndex((r) => r.id === id && r.undoable);
  return at < 0
    ? [...log]
    : log.map((r, i) =>
      i === at ? { ...r, undoable: false, summary: `undone — ${r.summary}` } : r
    );
};

export const hasUndoable = (log: readonly FixRecord[]): boolean =>
  log.some((r) => r.undoable);

/** Retire every Undo button. What a restart leaves behind: the log persists,
 *  the handles that could put a value back do not. */
export const retireUndos = (log: readonly FixRecord[]): FixRecord[] =>
  log.map((r) => r.undoable ? { ...r, undoable: false } : r);
