// The issue list, most significant first. The cell stores it already ordered
// (every write goes through `merge`, which sorts) and already filtered by the
// view, so the table renders what it is given rather than deciding twice.
import { issues } from "../cell/issues.ts";
import type { Issue } from "../type/issue.ts";
import { IssueRow } from "./IssueRow.tsx";

const COLUMNS = ["Issue", "Category", "Priority", "Fix", "What Fix does"];

const EMPTY: Record<string, string> = {
  auto: "Nothing left to fix automatically.",
  manual: "Nothing here needs you to step in.",
  all: "All checks passed.",
};

function Empty() {
  if (issues.scanning) {
    return <div className="empty" t="empty">Scanning…</div>;
  }
  const hidden = issues.hidden();
  return (
    <div className="empty" t="empty">
      {issues.lastScan
        ? <strong>Nothing to fix</strong>
        : <strong>Ready</strong>}
      {issues.lastScan
        ? EMPTY[issues.view]
        : "Monitoring is running. Press Scan for the full sweep."}
      {hidden > 0 ? ` ${hidden} more in the other views.` : ""}
    </div>
  );
}

export function IssueTable() {
  const rows = issues.shown();
  return (
    <section className="panel" t="issues">
      {rows.length === 0 ? <Empty /> : (
        <table className="issues">
          <thead>
            <tr>{COLUMNS.map((c) => <th key={c}>{c}</th>)}</tr>
          </thead>
          <tbody>
            {rows.map((i: Issue) => <IssueRow key={i.id} issue={i} />)}
          </tbody>
        </table>
      )}
    </section>
  );
}
