// Everything this app changed on the machine, newest first, with Undo where a
// previous value was recorded. Reversibility is only real if the user can see
// it and reach it.
import { issues } from "../cell/issues.ts";
import type { FixRecord } from "../type/issue.ts";
import { clock } from "../lib/format.ts";

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
  const log = issues.log;
  if (log.length === 0) return null;
  return (
    <section className="log" t="log">
      <h2>Changes made ({log.length})</h2>
      {log.map((r: FixRecord) => <Entry key={`${r.id}-${r.at}`} record={r} />)}
    </section>
  );
}
