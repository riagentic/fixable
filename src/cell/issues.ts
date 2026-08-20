// The whole application state: what is wrong with this computer, and what has
// been done about it.
//
// Nothing here is browser-specific or server-specific to look at — the UI reads
// this state and calls these methods. The only line that knows a computer
// exists is the dynamic `./checks.server.ts` import, which is also the bundle
// boundary: none of the probing code reaches the client.
import { cell, type MethodDraftMeta, schedule } from "aio";
import type { FixRecord, Issue, Tier, View } from "../type/issue.ts";
import { merge, mergeIds, without } from "../lib/merge.ts";
import { hasUndoable, markUndone, remember, retireUndos } from "../lib/log.ts";
import { countBySeverity, fixable, rootFixable } from "../lib/severity.ts";
import { isView, possibleIn, visible } from "../lib/view.ts";

/** Gap between always-on passes. Cheap enough (two `/proc` reads and one `df`)
 *  that the interval is about UI freshness, not cost. */
export const MONITOR_MS = 30_000;

/** The fix log is the record of every change this app made to someone's
 *  machine, so it outlives the process that made them — and the cap has to be
 *  high enough that "Fix all" over a thousand-check catalogue cannot push the
 *  earliest changes out of it. Fifty did exactly that. */
const LOG_LIMIT = 2000;

/** A root plan as the UI sees it. The operations themselves stay on the
 *  server: what crosses the wire is a description and a token, so a client
 *  cannot hand back an edited list of things to do as root. */
export type RootPlan = {
  token: string;
  /** One entry per check, in the order the plan runs them. */
  items: { id: string; title: string; summary: string }[];
  /** The script itself, as command lines. */
  lines: string[];
};

type IssuesState = {
  issues: Issue[];
  /** Which issues the list shows. A preference, so it persists. */
  view: View;
  /** How many checks of each tier exist — the denominators behind "7 of 61",
   *  one per view. Filled in by the first pass, from the registry. */
  possible: Record<Tier, number>;
  /** The root plan waiting to be authorised. Built from a fresh probe, shown
   *  in full, and thrown away if it is not confirmed — nobody should be asked
   *  for a password by an app that has not first said what it will do. */
  rootPlan: RootPlan | null;
  /** True between authorising a root plan and hearing back. */
  rootFixing: boolean;
  scanning: boolean;
  /** Ids with a fix in flight, so each row can show its own progress. */
  fixing: string[];
  /** When the always-on checks last measured. Visible, because "monitoring"
   *  that silently stopped ticking looks exactly like a healthy machine. */
  lastMeasure: number | null;
  lastScan: number | null;
  /** Checks that could not measure. Not the same as "healthy", so not hidden. */
  failed: string[];
  /** The last operational failure — a fix that threw, not a finding. */
  error: string | null;
  log: FixRecord[];
};

// The type argument is what makes `s.$live` typed state rather than
// `Record<string, unknown>` — every post-await read below goes through it.
type S = IssuesState & Partial<MethodDraftMeta<IssuesState>>;

/** Copy the registry's static totals into state. Written on every pass rather
 *  than once at boot, so the header can never show a denominator from an
 *  earlier version of the catalogue. */
const countChecks = (
  s: IssuesState,
  mod: { POSSIBLE_BY_TIER: Record<Tier, number> },
) => {
  s.possible = { ...mod.POSSIBLE_BY_TIER };
};

export const issues = cell("issues", {
  // Measurements are live: a verdict from the last boot is a claim about a
  // machine that has since changed. The fix log is the exception — it records
  // what this app did to the user's computer and must survive a restart.
  persist: { include: ["log", "view"] },

  // A full scan runs subprocesses and walks the home directory; it can be
  // superseded or stopped mid-flight. Under a transaction, a cancelled call's
  // buffered writes are discarded wholesale, so a scan that loses the race can
  // never land a stale verdict on top of a newer one.
  transaction: true,

  // Re-scanning supersedes the scan still running; "Stop" cancels it.
  cancelOn: { scan: ["self", "issues:stop"] },

  // A full scan shells out to `apt-get -s upgrade` and walks the home
  // directory — minutes on a large machine, well past the framework's default
  // call ceiling. Declared here rather than as a `perfBudget` string in
  // app.ts: this list is checked against the method names at cell() time, so
  // renaming `scan` fails loudly instead of silently orphaning the exemption.
  long: ["scan"],

  state: {
    issues: [] as Issue[],
    // Auto first: the issues you can act on without leaving the app.
    view: "auto" as View,
    possible: { fix: 0, sudo: 0, optional: 0, advisory: 0 } as Record<
      Tier,
      number
    >,
    rootPlan: null as RootPlan | null,
    rootFixing: false,
    scanning: false,
    fixing: [] as string[],
    lastMeasure: null as number | null,
    lastScan: null as number | null,
    failed: [] as string[],
    error: null as string | null,
    log: [] as FixRecord[],
  },

  methods: {
    /** The always-on half: cheap checks, re-armed after every pass.
     *
     *  It re-issues its own schedule rather than relying on a static `every`,
     *  so a wedged tick heals on the next one and the cadence lives next to the
     *  work it paces. */
    async monitor(s: S): Promise<void> {
      const mod = await import("./checks.server.ts");
      countChecks(s, mod);
      const res = await mod.probe("monitor");
      // Fold into state as it is NOW, not as it was when this pass entered: a
      // scan may well have landed while `df` was running, and this pass has
      // authority over four check ids — not over the whole list.
      const live = s.$live!;
      s.issues = merge(live.issues, res.ran, res.issues);
      s.failed = mergeIds(live.failed, res.ran, res.failed);
      s.lastMeasure = Date.now();
      // A self-chained one-shot, not a fixed-clock `every`: the next pass is
      // armed only once this one has finished, so a slow tick can never stack
      // on itself and a wedged one heals the moment it completes.
      s.$do!(
        schedule.after("issues:monitor", MONITOR_MS, issues.monitor.action()),
      );
    },

    /** The on-demand half: every check, including the ones too slow to run on
     *  a timer. */
    async scan(s: S) {
      const mod = await import("./checks.server.ts");
      // Cancelled or superseded while importing? Then this call owns nothing.
      if (s.$signal!.aborted) return;

      countChecks(s, mod);
      s.scanning = true;
      s.error = null;
      s.$commit!(); // publish the spinner now, mid-transaction

      const res = await mod.probe("all", s.$signal!);
      if (s.$signal!.aborted) return;

      // Same rule as the monitor pass, for the same reason — a monitor tick
      // fires every 30 seconds and a full sweep takes longer than that.
      const live = s.$live!;
      s.issues = merge(live.issues, res.ran, res.issues);
      s.failed = mergeIds(live.failed, res.ran, res.failed);
      s.lastScan = s.lastMeasure = Date.now();
      s.scanning = false;
    },

    /** Stop button. `cancelOn` does the aborting; clearing the flag here makes
     *  the UI answer the click instead of the next signal check. */
    stop(s: IssuesState) {
      s.scanning = false;
    },

    /** Apply one issue's fix. The safety work — re-probe, act, verify — lives
     *  in checks.server.ts; what happens here is bookkeeping. */
    async fix(s: S, id: string) {
      if (s.fixing.includes(id)) return;
      const title = s.issues.find((i) => i.id === id)?.title ?? id;
      s.fixing = [...s.fixing, id];
      s.$commit!();
      try {
        const mod = await import("./checks.server.ts");
        // Which of the two the row gets is decided by its remedy, and needing
        // root is a fact the remedy carries in two places: the `sudo` kind,
        // and an `optional` change that happens to be privileged. Reading only
        // the kind would send the second kind down the unprivileged path,
        // where it has no `apply` and would fail on a row with a button.
        const remedy = s.$live!.issues.find((i) => i.id === id)?.remedy;
        const root = remedy?.kind === "sudo" ||
          (remedy?.kind === "optional" && remedy.root);
        const out = root ? await mod.applyRootFix(id) : await mod.applyFix(id);
        const live = s.$live!;
        s.log = remember(live.log, {
          id,
          title,
          at: Date.now(),
          summary: out.summary,
          undoable: out.undoable,
        }, LOG_LIMIT);
        s.issues = out.resolved
          ? without(live.issues, id)
          : merge(live.issues, [id], out.remaining ? [out.remaining] : []);
        // A fix that ran and changed nothing must not read as a success.
        if (!out.resolved) {
          s.error = `${title}: the change was applied but the issue remains`;
        }
      } catch (e) {
        s.error = e instanceof Error ? e.message : String(e);
      }
      s.fixing = s.$live!.fixing.filter((x) => x !== id);
    },

    /** Fix every issue that has a fix — and, by construction, nothing else.
     *
     *  Advisory issues carry no `apply` and so cannot be swept up. Optional
     *  ones carry one and are still not swept up: they are a different remedy
     *  kind, and `fixable` matches only `fix`. That is the whole mechanism
     *  behind "a preference is never changed unless you ask for it". */
    async fixAll(s: S) {
      for (const i of fixable(s.issues)) await issues.fix(i.id);
    },

    /** Work out what the root fixes would do, and show it.
     *
     *  Nothing is run and nothing is authorised here. Every root check is
     *  re-probed against the machine as it is now, the plan is compiled, and
     *  what comes back is the script itself. Asking for a password before
     *  saying what it is for is how an app gets a click instead of consent. */
    async planRootFixes(s: S) {
      if (s.rootFixing) return;
      s.error = null;
      s.rootPlan = null;
      s.rootFixing = true;
      s.$commit!();
      try {
        const { planRoot } = await import("./checks.server.ts");
        const plan = await planRoot();
        s.$live!.rootPlan = plan.items.length === 0 ? null : plan;
        if (plan.items.length === 0) {
          s.$live!.error = "Nothing to do: no root-fixable issue is open.";
        }
      } catch (e) {
        s.$live!.error = e instanceof Error ? e.message : String(e);
      }
      s.$live!.rootFixing = false;
    },

    /** Drop the plan without running it. */
    cancelRootFixes(s: IssuesState) {
      s.rootPlan = null;
    },

    /** Authorise and run the plan on screen.
     *
     *  The token is what ties this to the plan that was shown: the server
     *  keeps the operations and refuses a token that is not the current one,
     *  so what runs is what was displayed and never a list edited in between. */
    async runRootFixes(s: S) {
      const plan = s.rootPlan;
      if (!plan || s.rootFixing) return;
      s.rootFixing = true;
      s.$commit!();
      try {
        const { applyRootPlan } = await import("./checks.server.ts");
        const out = await applyRootPlan(plan.token);
        const live = s.$live!;
        if (out.problem !== null) {
          live.error = out.problem;
        } else {
          const at = Date.now();
          live.log = out.resolved.reduce(
            (log, item) =>
              remember(log, {
                id: item.id,
                title: item.title,
                at,
                summary: item.summary,
                undoable: true,
              }, LOG_LIMIT),
            live.log,
          );
          // The plan's authority is exactly the checks it covered: those are
          // re-probed, so the ones it fixed drop out and the ones still
          // reporting come back with a fresh reading. Nothing else moves.
          live.issues = merge(
            live.issues,
            plan.items.map((i) => i.id),
            out.issues,
          );
          if (out.remaining.length > 0) {
            live.error = `${out.remaining.length} of ${plan.items.length} ` +
              `changes were applied but the check still reports — see the list.`;
          }
        }
        live.rootPlan = null;
      } catch (e) {
        s.$live!.error = e instanceof Error ? e.message : String(e);
        s.$live!.rootPlan = null;
      }
      s.$live!.rootFixing = false;
    },

    /** Put back what a fix replaced. */
    async undo(s: S, id: string) {
      try {
        const { undoFix } = await import("./checks.server.ts");
        const back = await undoFix(id);
        const live = s.$live!;
        // The history stays; it just stops offering a button that would fail.
        s.log = markUndone(live.log, id);
        s.issues = merge(live.issues, [id], back ? [back] : []);
      } catch (e) {
        s.error = e instanceof Error ? e.message : String(e);
      }
    },

    /** Switch the list between Auto, Sudo, Optional, Manual and All. */
    setView(s: IssuesState, view: string) {
      // An unknown view would empty the list with no explanation on screen.
      if (!isView(view)) throw new Error(`unknown view: ${view}`);
      s.view = view;
    },

    dismissError(s: IssuesState) {
      s.error = null;
    },

    /** Retire the Undo buttons the previous run left behind.
     *
     *  The log persists; the handles that can actually put a value back are
     *  closures, and closures do not survive a restart. Left alone, every
     *  entry from the last run would offer an Undo that fails on click — a
     *  promise of reversibility the app cannot keep. The history stays; only
     *  the button goes. */
    expireUndos(s: IssuesState) {
      if (hasUndoable(s.log)) s.log = retireUndos(s.log);
    },
  },

  selectors: {
    /** The rows the table draws — filtered, already ordered by the merge. */
    shown: (s: IssuesState) => visible(s.view, s.issues),
    /** Severity tallies over what is on screen, never over what is hidden. */
    counts: (s: IssuesState) => countBySeverity(visible(s.view, s.issues)),
    /** The denominator that matches the current view. */
    possibleShown: (s: IssuesState) => possibleIn(s.view, s.possible),
    /** What "Fix all" would act on — never limited by the view. */
    fixableCount: (s: IssuesState) => fixable(s.issues).length,
    /** What "Fix all (sudo required)" would act on. */
    rootCount: (s: IssuesState) => rootFixable(s.issues).length,
    /** How many issues the other views are hiding right now. */
    hidden: (s: IssuesState) =>
      s.issues.length - visible(s.view, s.issues).length,
    undoable: (s: IssuesState) => s.log.filter((r) => r.undoable),
  },
});
