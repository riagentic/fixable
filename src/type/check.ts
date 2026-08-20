// The check plugin contract — server-side only (the closures never cross the
// wire), but plain types with zero dependencies. Zero deps.
import type { Category, Severity, Tier } from "./issue.ts";

/** The handle a fix returns. `revert` is what makes the fix reversible; a fix
 *  that cannot offer one may still exist only if it is additive (it took
 *  nothing away), and must say so in its summary. */
export type Undo = {
  /** Exactly what changed, past tense — goes straight into the fix log. */
  summary: string;
  revert?: () => Promise<void>;
};

/** The only three things a Fixable fix is ever allowed to do as root.
 *
 *  This union is the privilege boundary. There is no "run this command"
 *  member, so no catalogue row — present or future — can escalate into
 *  restarting a service, unloading a module, remounting a filesystem or
 *  deleting a file the system owns. Each member is non-disruptive by
 *  construction: none of them changes the behaviour of anything already
 *  running, because none of them touches live state. The effect of a `write`
 *  lands the next time the system reads that drop-in — at boot, at login, at
 *  the next reload — which is precisely why it is safe to make unattended.
 *
 *  `mode` is octal, four digits. `was` and `before` are what the plan will put
 *  back, captured by the probe that built the op. */
export type RootOp =
  /** Narrow permission bits on a file the system owns. Never widens them —
   *  {@link rootOpIsSafe} rejects a mode with bits the current one lacks. */
  | { op: "chmod"; path: string; mode: string; was: string }
  /** Write a drop-in that belongs to Fixable, whole. Never edits a file the
   *  app did not create: the path must be a Fixable drop-in. */
  | {
    op: "write";
    path: string;
    mode: string;
    content: string;
    before: string | null;
  }
  /** Take a Fixable drop-in away again — the undo of a `write` that created
   *  one. Restricted to the same paths, so it can never delete system files. */
  | { op: "remove"; path: string }
  /** Set one kernel parameter, now, so a fix that writes a boot-time drop-in
   *  also takes effect while you are looking at it — and so the check that
   *  re-reads /proc/sys afterwards can confirm it did.
   *
   *  This is the one op that touches live state, and it is bounded twice
   *  over: the shape of `key` and `value` means it can write nowhere but
   *  /proc/sys, and WHICH parameters may be written is a named list in
   *  lib/policy/root-safe.ts, every member of which is either the value the
   *  distribution already ships or a ceiling going up. `was` is the reading
   *  the probe took, and is what Undo writes back. */
  | { op: "sysctl"; key: string; value: string; was: string };

/** What a check actually asks for, before the machine has been consulted.
 *
 *  A hundred kernel-parameter rows all want a line in one drop-in, so a check
 *  contributes a labelled block rather than a file: `text` is the setting,
 *  `id` is the check that owns it, and `null` removes it. The server reads
 *  what is on disk and folds every contribution into a single `write` — which
 *  is why this is a separate type from {@link RootOp}. The script builder can
 *  only be handed the three real operations, so an uncompiled contribution
 *  cannot reach root by any path the type checker allows. */
export type RootLine = {
  op: "line";
  path: string;
  mode: string;
  id: string;
  text: string | null;
};

export type RootChange = RootOp | RootLine;

/** A root-tier fix: what to run, and how to put it back. Built by the probe,
 *  so it describes the machine as it is right now, and re-built immediately
 *  before it runs. */
export type RootPlan = {
  changes: RootChange[];
  /** Past-tense summary for the fix log, in the same voice as {@link Undo}. */
  summary: string;
};

/** A probe's verdict. `null` means healthy, or that the check does not apply to
 *  this machine — never "could not tell": a probe that cannot measure throws,
 *  and the app reports that it could not run. */
export type Finding = {
  /** The measurement. */
  detail: string;
  /** Band override when the measurement decides it (91% vs 96% full). */
  severity?: Severity;
  /** Per-finding override of {@link Check.explanation} — used when the exact
   *  command is only known once the machine has been probed. */
  explanation?: string;
  /** Present ⇔ this finding can be fixed in-process, as this user. Carried by
   *  the `fix` and `optional` tiers; nothing else decides which rows get a
   *  button. */
  apply?: () => Promise<Undo>;
  /** Present ⇔ this finding can be fixed as root. Carried by the `sudo` tier
   *  alone, and mutually exclusive with `apply`: a check is fixable either
   *  here or there, never both, so the button can never be ambiguous. */
  root?: RootPlan;
};

/** `monitor` — cheap and always-on, re-run on every tick.
 *  `scan`    — subprocesses and filesystem walks, run on demand. */
export type CheckMode = "monitor" | "scan";

export type Check = {
  id: string;
  title: string;
  category: Category;
  /** Default band; a finding may override it. */
  severity: Severity;
  weight: number;
  mode: CheckMode;
  /** Which remedy this check can offer, declared by the factory that builds it
   *  alongside the `apply` or `root` it hands out — so the two cannot drift.
   *  It is what lets the header count how many checks of each tier *exist*
   *  before anything has been probed; the registry asserts every finding
   *  agrees with it. */
  tier: Tier;
  /** Shown verbatim in the last column: exactly what Fix does, or why there
   *  cannot be one. Written for someone deciding whether to press the button. */
  explanation: string;
  probe: () => Promise<Finding | null>;
};
