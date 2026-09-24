// What is about to be run as root, before anybody is asked for a password.
//
// This panel is the consent step, and it is deliberately literal: not a count,
// not a summary, but the script. Every line here is what the privileged shell
// will execute, rendered from the same operations that build it — so there is
// no version of this that shows one thing and runs another.
//
// It is also the place to be plain about two facts a person deciding this
// needs: Fixable never sees the password (the prompt is the system's own), and
// nothing in a root plan stops, restarts or reconfigures anything that is
// running.
import { issues } from "../cell/issues.ts";

export function RootPlan() {
  const plan = issues.rootPlan;
  if (!plan) return null;
  const busy = issues.rootFixing;
  return (
    <section className="plan" t="rootPlan">
      <header className="plan-head">
        <div>
          <h2>{plan.items.length} changes need the root password</h2>
          <p>
            Every line below either takes permission bits away from a file or
            adds a line to a file that belongs to Fixable. Nothing here stops,
            restarts or reconfigures anything that is running. The password is
            asked for once, by your desktop&rsquo;s own prompt — this app never
            sees it.
          </p>
        </div>
        <div className="plan-actions">
          <button
            type="button"
            t="rootCancel"
            className="btn"
            disabled={busy}
            onClick={() => issues.cancelRootFixes()}
          >
            Cancel
          </button>
          <button
            type="button"
            t="rootRun"
            className="btn primary"
            disabled={busy}
            onClick={() => issues.runRootFixes()}
          >
            {busy ? "Waiting for authorisation…" : "Authorise and run"}
          </button>
        </div>
      </header>

      <ol className="plan-items" t="rootItems">
        {plan.items.map((item) => (
          <li key={item.id} t={`plan-${item.id}`}>
            <strong>{item.title}</strong>
            <code>{item.summary}</code>
          </li>
        ))}
      </ol>

      {
        /* Always open: a script behind a disclosure triangle is a script the
          password can be typed without anyone having seen. */
      }
      <div className="plan-script">
        <h3>The exact commands ({plan.lines.length})</h3>
        <pre t="rootScript">{plan.lines.join("\n")}</pre>
      </div>
    </section>
  );
}
