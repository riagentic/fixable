// Auto / Sudo / Optional / Manual / All.
//
// One segment per remedy, because the difference between them is the thing
// somebody actually needs to know before pressing anything: whether it happens
// on a click, whether it will ask for a password, and whether it takes
// something away. Auto is the default — the set you can act on from here with
// nothing asked of you. Nothing is ever dropped from the catalogue, only from
// the view, and the counter next to each segment says how much is behind it.
import { issues } from "../cell/issues.ts";
import type { View } from "../type/issue.ts";
import { VIEW_LABEL, VIEW_MEANING, VIEWS, visible } from "../lib/view.ts";

export function ViewSwitch() {
  const current = issues.view;
  const found = issues.issues;
  // Counted through the same filter the table uses, so a segment can never
  // promise a number the list then fails to show.
  const count = (v: View) => visible(v, found).length;
  return (
    <div className="switch" t="view" role="group" aria-label="Show">
      {VIEWS.map((v: View) => (
        <button
          key={v}
          type="button"
          t={`view-${v}`}
          title={VIEW_MEANING[v]}
          aria-pressed={v === current}
          className={`seg${v === current ? " on" : ""}`}
          onClick={() => issues.setView(v)}
        >
          {VIEW_LABEL[v]}
          <em t={`view-count-${v}`}>{count(v)}</em>
        </button>
      ))}
    </div>
  );
}
