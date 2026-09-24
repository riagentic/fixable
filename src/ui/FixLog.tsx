// Everything this app changed on the machine, newest first, with Undo where a
// previous value was recorded. Reversibility is only real if the user can see
// it and reach it.
import { useLocal } from "aio/air";
import { issues } from "../cell/issues.ts";
import type { FixRecord } from "../type/issue.ts";
import { clock } from "../lib/format.ts";

/** The log holds up to two thousand changes; the page shows the newest few
 *  until asked for the rest. */
const FIRST = 50;

function Entry({ record }: { record: FixRecord }) {
  return (
    <div className="log-row" t={`log-${record.id}`}>
      <span>{record.title}</span>
      <code>{record.summary}</code>
      <div className="spacer" />
      <span className="none">{clock(record.at)}</span>
      {record.undoable && (
        <button
          type="button"
          t={`undo-${record.id}`}
          aria-label={`Undo: ${record.title}`}
          className="btn small"
          onClick={() => issues.undo(record.id)}
        >
          Undo
        </button>
      )}
    </div>
  );
}

export function FixLog() {
  const [all, setAll] = useLocal(false);
  const log = issues.log;
  if (log.length === 0) return null;
  const shown = all ? log : log.slice(0, FIRST);
  return (
    <section className="log" t="log">
      <h2>Changes made ({log.length})</h2>
      {shown.map((r: FixRecord) => (
        <Entry
          key={`${r.id}-${r.at}`}
          record={r}
        />
      ))}
      {shown.length < log.length && (
        <button
          type="button"
          t="logAll"
          className="btn small"
          onClick={() => setAll(true)}
        >
          Show all {log.length}
        </button>
      )}
    </section>
  );
}
