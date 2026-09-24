// Header — how many issues, how bad, and the buttons that act on all of them.
// Reads cell state directly; every read here is reactive.
import { issues } from "../cell/issues.ts";
import type { Severity } from "../type/issue.ts";
import { clock } from "../lib/format.ts";
import { CATEGORY_MEANING, countByCategory } from "../lib/category.ts";
import { CATEGORIES } from "../type/issue.ts";
import { ViewSwitch } from "./ViewSwitch.tsx";

const BANDS: Severity[] = ["critical", "major", "minor"];

/** What kind of problem, not just how bad. With a catalogue this size the
 *  severity bands alone do not tell you whether to worry about your data or
 *  your disk, so the categories get their own row. */
function Breakdown() {
  const counts = countByCategory(issues.issues, CATEGORIES);
  return (
    <div className="breakdown" t="breakdown">
      {counts.map(([cat, n]) => (
        <span
          key={cat}
          t={`cat-${cat}`}
          title={CATEGORY_MEANING[cat]}
          className={`chip cat cat-${cat}${n === 0 ? " zero" : ""}`}
        >
          {n} {cat}
        </span>
      ))}
    </div>
  );
}

function Tally() {
  const counts = issues.counts();
  return (
    <div className="tallies">
      {BANDS.map((band) => (
        <span
          key={band}
          t={`tally-${band}`}
          className={`chip sev-${band}${counts[band] === 0 ? " zero" : ""}`}
        >
          <i className="dot" />
          {counts[band]} {band}
        </span>
      ))}
    </div>
  );
}

export function Header() {
  // The header speaks for the whole machine; the switch below says how much of
  // it each view holds, and the table shows one view.
  const found = issues.issues.length;
  const possible = issues.possibleAll();
  const canFix = issues.fixableCount();
  const canRoot = issues.rootCount();
  const busy = issues.busy();
  return (
    <header className="header">
      <div className="brand">
        Fixable
        <small t="status" aria-live="polite">
          {issues.lastMeasure
            ? `monitoring · updated ${clock(issues.lastMeasure)}`
            : "starting monitor…"}
          {issues.lastScan ? ` · full scan ${clock(issues.lastScan)}` : ""}
        </small>
      </div>

      <div className="score" t="score">
        {found} <small>of {possible} checks</small>
      </div>

      <Tally />

      <div className="spacer" />

      <ViewSwitch />

      <div className="actions">
        {issues.scanning
          ? (
            <button
              type="button"
              t="stop"
              className="btn"
              onClick={() => issues.stop()}
            >
              Stop
            </button>
          )
          : (
            <button
              type="button"
              t="scan"
              className="btn"
              disabled={busy}
              onClick={() => issues.scan()}
            >
              Scan
            </button>
          )}
        <button
          type="button"
          t="fixAll"
          className="btn primary"
          title="Runs every fix that needs nothing from you and takes nothing away. Optional changes are never included."
          disabled={canFix === 0 || busy}
          onClick={() => issues.fixAll()}
        >
          Fix all{canFix > 0 ? ` (${canFix})` : ""}
        </button>
        <button
          type="button"
          t="fixAllRoot"
          className="btn"
          title="Shows exactly what would be run as root, then asks for the password once for the whole batch."
          disabled={canRoot === 0 || busy}
          onClick={() => issues.planRootFixes()}
        >
          {issues.rootFixing && !issues.rootPlan
            ? "Working…"
            : "Fix all (sudo required)"}
          {canRoot > 0 ? ` (${canRoot})` : ""}
        </button>
      </div>
      <Breakdown />
    </header>
  );
}
