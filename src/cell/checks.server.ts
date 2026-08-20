// The check registry, and the only two operations that touch the machine.
//
// This module is where the safety rule is enforced rather than promised:
//
//   1. A fix exists only where a probe returned an `apply` closure, and probes
//      hand one out only for changes that are non-destructive (nothing is
//      deleted), reversible (the old value comes back) and non-disruptive
//      (nothing running is stopped).
//   2. `applyFix` re-probes before acting. A button pressed against a
//      measurement taken a minute ago is a change made against a machine that
//      has since moved; re-probing means a fix only ever acts on what is true
//      right now.
//   3. `applyFix` re-probes again afterwards and reports whether the issue is
//      actually gone, so a fix that silently did nothing cannot look like a
//      success.
import type {
  Check,
  CheckMode,
  Finding,
  RootChange,
  RootOp,
  Undo,
} from "../type/check.ts";
import type { Issue, Remedy, Tier } from "../type/issue.ts";
import { isOptionalTier, isRootTier, TIERS } from "../type/issue.ts";
import { SYSTEM_CHECKS } from "./check-system.server.ts";
import { DESKTOP_CHECKS } from "./check-desktop.server.ts";
import { PERM_CHECKS } from "./check-perms.server.ts";
import { GIT_CHECKS } from "./check-git.server.ts";
import { CONF_CHECKS } from "./check-conf.server.ts";
import { SSH_CHECKS } from "./check-ssh.server.ts";
import { MOZILLA_CHECKS } from "./check-mozilla.server.ts";
import { CHROMIUM_CHECKS } from "./check-chromium.server.ts";
import { SYSCTL_CHECKS } from "./check-sysctl.server.ts";
import { SYSTEM_EXTRA_CHECKS } from "./check-system-extra.server.ts";
import { ETC_CHECKS } from "./check-etc.server.ts";
import { ETC_PERM_CHECKS } from "./check-etc-perms.server.ts";
import { RUNTIME_CHECKS } from "./check-runtime.server.ts";
import { CLUTTER_CHECKS } from "./check-clutter.server.ts";
import { PACKAGE_CHECKS } from "./check-packages.server.ts";
import { NO_BUTTON, OPTIONAL, RETIRED } from "../lib/policy/preferences.ts";
import { commandLines, invertChanges } from "../lib/root.ts";
import { compilePlan, runRootPlan } from "./root.server.ts";
import { beginPass, endPass, sysChecks } from "./check-sys.server.ts";
import { CPU_POLICIES } from "../lib/policy/sys/cpu.ts";
import { PORT_POLICIES } from "../lib/policy/sys/ports.ts";
import { FIREWALL_POLICIES } from "../lib/policy/sys/firewall.ts";
import { VPN_POLICIES } from "../lib/policy/sys/vpn.ts";
import { DATA_POLICIES } from "../lib/policy/sys/data.ts";
import { HARDWARE_POLICIES } from "../lib/policy/sys/hardware.ts";
import { DISK_POLICIES } from "../lib/policy/sys/disk.ts";
import { ACCOUNT_POLICIES } from "../lib/policy/sys/accounts.ts";
import { SERVICE_POLICIES } from "../lib/policy/sys/services.ts";
import { SESSION_POLICIES } from "../lib/policy/sys/session.ts";
import { CONTAINER_POLICIES } from "../lib/policy/sys/containers.ts";
import { LIMIT_POLICIES } from "../lib/policy/sys/limits.ts";
import { NETWORK_POLICIES } from "../lib/policy/sys/network.ts";
import { PRIVACY_SYS_POLICIES } from "../lib/policy/sys/privacy.ts";
import { HARDENING_POLICIES } from "../lib/policy/sys/hardening.ts";
import { KEY_POLICIES } from "../lib/policy/sys/keys.ts";
import { MISC_POLICIES } from "../lib/policy/sys/misc.ts";
import { APP_POLICIES } from "../lib/policy/sys/apps.ts";
import { ETC4_POLICIES } from "../lib/policy/sys/etc4.ts";
import { SAFETY_POLICIES } from "../lib/policy/sys/safety.ts";

/** Everything read from the running system. All report-only: see
 *  check-sys.server.ts for why the whole domain has to be. */
export const SYS_POLICIES = [
  ...CPU_POLICIES,
  ...PORT_POLICIES,
  ...FIREWALL_POLICIES,
  ...VPN_POLICIES,
  ...DATA_POLICIES,
  ...HARDWARE_POLICIES,
  ...DISK_POLICIES,
  ...ACCOUNT_POLICIES,
  ...SERVICE_POLICIES,
  ...SESSION_POLICIES,
  ...CONTAINER_POLICIES,
  ...LIMIT_POLICIES,
  ...NETWORK_POLICIES,
  ...PRIVACY_SYS_POLICIES,
  ...HARDENING_POLICIES,
  ...KEY_POLICIES,
  ...MISC_POLICIES,
  ...APP_POLICIES,
  ...ETC4_POLICIES,
  ...SAFETY_POLICIES,
];

/** The audit, applied in one place.
 *
 *  `lib/policy/preferences.ts` says which checks must not act unattended and
 *  why, and this is the only place that enforces it. A row cannot opt itself
 *  back in, and a rename cannot quietly move one across the line — the tests
 *  check both lists against the catalogue.
 *
 *  Two outcomes, and the difference matters:
 *
 *  `optional` keeps its fix. The probe still hands out `apply`, the row still
 *  gets a button, and the only things that change are that it is filed apart
 *  from the faults and that "Fix all" will not touch it. This is the answer
 *  for a preference: offering is not the same as deciding.
 *
 *  `advisory` loses the fix outright — the closure is dropped here, so no
 *  caller can reach it. Reserved for the accessibility rows, where the worst
 *  case of a wrong press is somebody locked out of their own machine.
 *
 *  A row's own explanation is written for a button that is about to be
 *  pressed: "Sets X to Y … the previous value is recorded and Undo restores
 *  it." That stays true for `optional`, and is prefixed with what the change
 *  costs. For `advisory` it promises an Undo that cannot happen, so the
 *  fix-facing sentences are removed and the opening verb is rewritten into a
 *  statement of fact — the row still says which setting and which value, which
 *  is what somebody changing it by hand needs. */
const asStatement = (explanation: string): string =>
  explanation
    .split(/(?<=\.)\s+/)
    .filter((sentence) =>
      !/\bUndo\b|previous (value|contents?|mode) (is|are) recorded|recorded in full/i
        .test(sentence)
    )
    .join(" ")
    .replace(
      /^Sets `?([^`\s]+)`? to `?([^`\s.]+)`?\./,
      "The setting is `$1`, and `$2` is the value that would help.",
    )
    .replace(/^Runs `([^`]+)`\./, "The command that would do it is `$1`.")
    .replace(/^Adds one line to ([^.]+)\./, "The change is one line in $1.")
    .trim();

/** Keep the fix, change what it is called and when it may run. */
const makeOptional = (c: Check, reason: string): Check => ({
  ...c,
  // A row that already needed root keeps needing it; the audit decides whether
  // a change is a choice, not how it runs.
  tier: isRootTier(c.tier) ? "optional-sudo" : "optional",
  explanation: `${reason} ${c.explanation}`.trim(),
});

/** Take the fix away entirely. */
const withdraw = (c: Check, reason: string): Check => ({
  ...c,
  tier: "advisory",
  explanation: `${reason} ${asStatement(c.explanation)}`.trim(),
  probe: async () => {
    const f = await c.probe();
    if (!f) return null;
    const { apply: _dropped, root: _also, explanation: _row, ...rest } = f;
    return rest;
  },
});

const audited = (checks: Check[]): Check[] =>
  checks
    .filter((c) => !(c.id in RETIRED))
    .map((c) => {
      const optional = OPTIONAL[c.id];
      if (optional !== undefined) return makeOptional(c, optional);
      const none = NO_BUTTON[c.id];
      return none === undefined ? c : withdraw(c, none);
    });

export const CHECKS: readonly Check[] = audited([
  ...SYSTEM_CHECKS,
  ...DESKTOP_CHECKS,
  ...PERM_CHECKS,
  ...GIT_CHECKS,
  ...CONF_CHECKS,
  ...SSH_CHECKS,
  ...MOZILLA_CHECKS,
  ...CHROMIUM_CHECKS,
  ...SYSCTL_CHECKS,
  ...SYSTEM_EXTRA_CHECKS,
  ...ETC_CHECKS,
  ...ETC_PERM_CHECKS,
  ...RUNTIME_CHECKS,
  ...CLUTTER_CHECKS,
  ...PACKAGE_CHECKS,
  ...sysChecks(SYS_POLICIES),
]);

/** How many issues are *possible* — the denominators in the header, one per
 *  view. Static: whether a check can fix what it finds is a property of the
 *  factory that built it, known before anything has been probed. */
export const POSSIBLE = CHECKS.length;

/** How many checks of each tier exist. Static: which remedy a check can offer
 *  is a property of the factory that built it, known before anything has been
 *  probed, so the header has a denominator for every view from the first
 *  frame. */
export const POSSIBLE_BY_TIER: Record<Tier, number> = Object.fromEntries(
  TIERS.map((t) => [t, CHECKS.filter((c) => c.tier === t).length]),
) as Record<Tier, number>;

const byId = new Map(CHECKS.map((c) => [c.id, c]));

/** Revert handles from fixes applied this session. Server-side only: a closure
 *  cannot cross the wire, so the cell keeps the record and this keeps the act. */
const undos = new Map<string, () => Promise<void>>();

/** The same, for root fixes — held as data rather than a closure, because
 *  putting one back means asking for the password again. */
const rootUndos = new Map<string, RootChange[]>();

/** What a finding is shaped like, independent of what its check claims. */
/** What a finding is shaped like, independent of what its check claims. */
const shapeOf = (
  f: NonNullable<Awaited<ReturnType<Check["probe"]>>>,
): "both" | "root" | "apply" | "none" =>
  f.apply && f.root ? "both" : f.root ? "root" : f.apply ? "apply" : "none";

/** What a tier's findings must be shaped like.
 *
 *  Two tiers share each shape, and that is the point of having five: whether a
 *  fix runs unattended is a different question from whether it needs root, and
 *  the finding only answers the second one. */
const shapeFor = (tier: Tier): "root" | "apply" | "none" =>
  isRootTier(tier) ? "root" : tier === "advisory" ? "none" : "apply";

/** The command lines shown on the row itself. Contributions to a drop-in are
 *  left out: what a single row shows should be what that row does, and the
 *  file a hundred of them share is only meaningful once compiled. */
const preview = (plan: NonNullable<Finding["root"]>): string[] =>
  commandLines(
    plan.changes.filter((c): c is Exclude<RootChange, { op: "line" }> =>
      c.op !== "line"
    ),
  );

const remedyFor = (tier: Tier, explanation: string, f: Finding): Remedy => {
  switch (tier) {
    case "fix":
      return { kind: "fix", explanation };
    case "sudo":
      return { kind: "sudo", explanation, commands: preview(f.root!) };
    case "optional":
      return { kind: "optional", explanation, root: false, commands: [] };
    case "optional-sudo":
      return {
        kind: "optional",
        explanation,
        root: true,
        commands: preview(f.root!),
      };
    case "advisory":
      return { kind: "advisory", explanation };
  }
};

const toIssue = (c: Check, f: Finding): Issue => {
  // The tier drives the header's denominators before any probing; what the
  // probe handed back drives the buttons after it. They are set by the same
  // factory, so a disagreement is a bug in the catalogue — and one that would
  // show a count not matching the buttons under it. Fail here rather than
  // mislead there.
  const shape = shapeOf(f);
  if (shape !== shapeFor(c.tier)) {
    throw new Error(
      `${c.id}: declares tier=${c.tier} but produced a ${shape} finding`,
    );
  }
  return {
    id: c.id,
    title: c.title,
    category: c.category,
    severity: f.severity ?? c.severity,
    weight: c.weight,
    detail: f.detail,
    remedy: remedyFor(c.tier, f.explanation ?? c.explanation, f),
  };
};

export type ProbeResult = {
  /** The checks that actually ran — the scope this pass has authority over. */
  ran: string[];
  issues: Issue[];
  /** Checks that could not measure. Reported, never silently dropped. */
  failed: string[];
};

/** How many probes run at once.
 *
 *  Almost every check is a subprocess or a file read waiting on the kernel, so
 *  running them one at a time spends the whole scan idle. A small pool rather
 *  than `Promise.all` over the lot: a catalogue of a thousand checks must not
 *  fork a thousand processes at once on the machine it is meant to be looking
 *  after. Nothing is cached — a fix acts on a fresh reading or on none. */
const CONCURRENCY = 12;

/** Run every check of `mode` ("all" for a full sweep). Cooperative: an aborted
 *  scan stops taking new checks and returns what it has. */
export async function probe(
  mode: CheckMode | "all",
  signal?: AbortSignal,
): Promise<ProbeResult> {
  const due = CHECKS.filter((c) => mode === "all" || c.mode === mode);
  // Slot-indexed so the result order is the catalogue's, not the finish order —
  // a scan must produce the same list every time it finds the same things.
  const found = new Array<Issue | null>(due.length).fill(null);
  const ran = new Array<string | null>(due.length).fill(null);
  const failed = new Array<string | null>(due.length).fill(null);

  let next = 0;
  const worker = async (): Promise<void> => {
    while (true) {
      const i = next++;
      if (i >= due.length || signal?.aborted) return;
      const c = due[i]!;
      try {
        const f = await c.probe();
        ran[i] = c.id;
        if (f) found[i] = toIssue(c, f);
      } catch {
        // "Could not measure" is not "healthy" — say so instead of implying
        // it. The slot stays out of `ran`, so this pass claims no authority
        // over that check and its previous verdict survives.
        failed[i] = c.id;
      }
    }
  };

  // One pass, one reading of each command the catalogue asks about.
  beginPass();
  try {
    await Promise.all(
      Array.from({ length: Math.min(CONCURRENCY, due.length) }, worker),
    );
  } finally {
    endPass();
  }

  return {
    ran: ran.filter((id): id is string => id !== null),
    issues: found.filter((i): i is Issue => i !== null),
    failed: failed.filter((id): id is string => id !== null),
  };
}

export type FixOutcome = {
  summary: string;
  undoable: boolean;
  /** True when the follow-up probe found the issue gone. */
  resolved: boolean;
  /** The issue as it stands now, when it is not gone. */
  remaining: Issue | null;
};

/** Apply one fix: re-probe, act, re-probe. Throws when the check is unknown or
 *  has no safe fix — a caller asking for one is a bug, not a user error. */
export async function applyFix(id: string): Promise<FixOutcome> {
  const check = byId.get(id);
  if (!check) throw new Error(`unknown check: ${id}`);

  const before = await check.probe();
  if (!before) {
    return {
      summary: "already resolved — nothing to change",
      undoable: false,
      resolved: true,
      remaining: null,
    };
  }
  if (!before.apply) {
    throw new Error(`${id} has no safe automatic fix`);
  }

  const undo: Undo = await before.apply();
  if (undo.revert) undos.set(id, undo.revert);

  const after = await check.probe();
  return {
    summary: undo.summary,
    undoable: Boolean(undo.revert),
    resolved: after === null,
    remaining: after ? toIssue(check, after) : null,
  };
}

/** Put back what a fix replaced. Throws when nothing was recorded — silently
 *  doing nothing would let the UI claim an undo that never happened. */
export async function undoFix(id: string): Promise<Issue | null> {
  const back = rootUndos.get(id);
  if (back) {
    // Undoing a root change costs a password, the same as making one did.
    const run = await runRootPlan(await compilePlan(back), "undo");
    if (run.problem !== null) throw new Error(run.problem);
    rootUndos.delete(id);
    const check = byId.get(id);
    const now = await check?.probe();
    return check && now ? toIssue(check, now) : null;
  }
  const revert = undos.get(id);
  if (!revert) throw new Error(`no recorded change to undo for ${id}`);
  await revert();
  undos.delete(id);
  const check = byId.get(id);
  const after = await check?.probe();
  return check && after ? toIssue(check, after) : null;
}

// ---------------------------------------------------------------- root tier

export type RootItem = {
  id: string;
  title: string;
  /** What this check will have done, past tense, for the log. */
  summary: string;
};

export type RootPreview = {
  /** Handed back on confirmation. The ops themselves never cross the wire:
   *  a plan is a list of things root is about to do, and a list of things root
   *  is about to do should not be something a client can hand back edited. */
  token: string;
  items: RootItem[];
  /** The script, as command lines, exactly as it will run. */
  lines: string[];
};

/** The plan awaiting confirmation. One at a time: a second "Fix all" replaces
 *  the first, and a token from a superseded plan is refused rather than run
 *  against a machine that has moved on. */
let pending:
  | { token: string; items: RootItem[]; ops: RootOp[]; changes: RootChange[][] }
  | null = null;

/** What a root plan may contain.
 *
 *  `sudo` only, never `optional-sudo`: needing a password does not make a
 *  choice any less of a choice, and a batch nobody reads line by line is
 *  exactly where an unasked-for change would slip through. Optional root
 *  changes have a button on their own row and nowhere else. */
const rootChecks = (ids?: readonly string[]): Check[] =>
  CHECKS.filter((c) =>
    c.tier === "sudo" && (ids === undefined || ids.includes(c.id))
  );

/** Build a root plan from a fresh reading of the machine.
 *
 *  Everything is re-probed here: a plan built from a scan taken minutes ago
 *  would ask root to change files against measurements that have since moved.
 *  What comes back is what will run, in the order it will run, and it is what
 *  the UI must show before anybody is asked for a password. */
export async function planRoot(ids?: readonly string[]): Promise<RootPreview> {
  const items: RootItem[] = [];
  const changes: RootChange[][] = [];
  const all: RootChange[] = [];

  for (const c of rootChecks(ids)) {
    const f = await c.probe();
    if (!f?.root) continue; // already resolved, or no longer applies
    items.push({ id: c.id, title: c.title, summary: f.root.summary });
    changes.push(f.root.changes);
    all.push(...f.root.changes);
  }

  const ops = await compilePlan(all);
  // Built here rather than trusted from the caller: the gate that refuses a
  // widening or a path this app does not own runs against the compiled plan,
  // and it runs before anybody sees a password prompt, not after.
  const lines = commandLines(ops);
  const token = crypto.randomUUID();
  pending = { token, items, ops, changes };
  return { token, items, lines };
}

export type RootOutcome = {
  /** Checks the follow-up probe found resolved. */
  resolved: RootItem[];
  /** Checks that ran but are still reporting. */
  remaining: RootItem[];
  /** Set when nothing ran: cancelled, or no way to ask for a password. */
  problem: string | null;
  /** The issues as they stand now, for every check that is still reporting.
   *  Folded into the list against the plan's own scope, so the resolved ones
   *  drop out without being listed twice. */
  issues: Issue[];
};

/** Run a confirmed plan. One password prompt for the whole batch. */
export async function applyRootPlan(token: string): Promise<RootOutcome> {
  if (!pending || pending.token !== token) {
    throw new Error(
      "that plan is no longer current — build it again so it is checked " +
        "against the machine as it is now",
    );
  }
  const { items, ops, changes } = pending;
  pending = null;

  const run = await runRootPlan(ops);
  if (run.problem !== null) {
    return { resolved: [], remaining: [], problem: run.problem, issues: [] };
  }

  // The plan is one script, and the ops in it are folded across checks — one
  // file write can carry forty of them — so "did this check's fix land?" is
  // not answerable from the step results. It is answerable by looking at the
  // machine, which is what the check is for.
  const resolved: RootItem[] = [];
  const remaining: RootItem[] = [];
  const issues: Issue[] = [];

  for (const [i, item] of items.entries()) {
    const check = byId.get(item.id)!;
    const after = await check.probe();
    if (after === null) {
      resolved.push(item);
      rootUndos.set(item.id, invertChanges(changes[i]!));
    } else {
      remaining.push(item);
      issues.push(toIssue(check, after));
    }
  }
  return { resolved, remaining, problem: null, issues };
}

/** One row's root fix, without the confirmation step: the polkit dialog names
 *  what it is authorising, and one line of one file is not a batch anybody
 *  needs a summary of. Same shape as {@link applyFix} so the cell can treat
 *  the two the same way. */
export async function applyRootFix(id: string): Promise<FixOutcome> {
  const check = byId.get(id);
  if (!check) throw new Error(`unknown check: ${id}`);
  if (!isRootTier(check.tier)) throw new Error(`${id} is not a root fix`);

  const before = await check.probe();
  if (!before) {
    return {
      summary: "already resolved — nothing to change",
      undoable: false,
      resolved: true,
      remaining: null,
    };
  }
  if (!before.root) throw new Error(`${id} produced no root plan`);

  const ops = await compilePlan(before.root.changes);
  const run = await runRootPlan(ops);
  if (run.problem !== null) throw new Error(run.problem);

  const after = await check.probe();
  if (after === null) rootUndos.set(id, invertChanges(before.root.changes));
  return {
    summary: before.root.summary,
    undoable: after === null,
    resolved: after === null,
    remaining: after ? toIssue(check, after) : null,
  };
}
