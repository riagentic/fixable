// One issue, as the five columns the app promises: description, category,
// priority, the Fix button, and exactly what pressing it would do.
import { issues } from "../cell/issues.ts";
import type { Issue } from "../type/issue.ts";
import { CATEGORY_MEANING } from "../lib/category.ts";

/** Column 4.
 *
 *  A button appears if and only if the issue carries a remedy that can act.
 *  The row cannot invent one: `remedy.kind` is decided by what the probe
 *  handed back, and the three kinds that act are labelled differently on
 *  purpose. "Fix" happens. "Fix (sudo)" asks the system for a password first.
 *  "Apply" is the optional tier — a different word because it is a choice
 *  rather than a repair, and because it is the one thing on this screen that
 *  "Fix all" will not do for you. */
const LABEL = {
  fix: "Fix",
  sudo: "Fix (sudo)",
  optional: "Apply",
} as const;

function Action({ issue }: { issue: Issue }) {
  const kind = issue.remedy.kind;
  if (kind === "advisory") {
    return <span className="none" t={`no-fix-${issue.id}`}>—</span>;
  }
  const busy = issues.fixing.includes(issue.id);
  return (
    <button
      type="button"
      t={`fix-${issue.id}`}
      className={`btn small act-${kind}`}
      disabled={busy}
      onClick={() => issues.fix(issue.id)}
    >
      {busy ? "Fixing…" : LABEL[kind]}
    </button>
  );
}

export function IssueRow({ issue }: { issue: Issue }) {
  return (
    <tr t={`row-${issue.id}`}>
      <td>
        <div className="desc">{issue.title}</div>
        <div className="detail">{issue.detail}</div>
      </td>
      <td className="col-cat">
        <span
          className={`chip cat cat-${issue.category}`}
          title={CATEGORY_MEANING[issue.category]}
        >
          {issue.category}
        </span>
      </td>
      <td className={`col-pri sev-${issue.severity}`}>
        <span className="chip">
          <i className="dot" />
          {issue.severity}
        </span>
      </td>
      <td className="col-act">
        <Action issue={issue} />
      </td>
      <td className="explain">
        {issue.remedy.explanation}
        {issue.remedy.kind === "sudo" && issue.remedy.commands.length > 0 && (
          <pre className="cmd" t={`cmd-${issue.id}`}>
            {issue.remedy.commands.join("\n")}
          </pre>
        )}
      </td>
    </tr>
  );
}
