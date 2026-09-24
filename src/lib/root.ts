// The privilege boundary, as pure text.
//
// Everything Fixable will ever run as root is rendered here, from a union with
// three members and no escape hatch. Nothing in this file executes anything —
// it turns a list of {@link RootOp} into a shell script, and refuses to turn
// anything else into one. That split is deliberate: the part that decides what
// root may do has no access to a subprocess, and the part that runs it has no
// say in what it runs.
//
// Two rules do all the work:
//
//   1. A `chmod` may only ever REMOVE permission bits. A fix that widens
//      access is not a fix, and a fix that narrows one cannot stop a running
//      program that already has the file open — and root, which is what reads
//      almost everything under /etc, keeps access regardless.
//   2. A `write` may only ever land on a path this app owns — a `99-fixable`
//      drop-in in a directory whose whole purpose is drop-ins. Fixable never
//      edits a file the distribution shipped, so no upgrade conflicts with it,
//      no syntax of somebody else's is at risk, and undo is "delete our file".
//
// Both effects are deferred by construction: a mode change and a drop-in are
// read the next time something reads them. Nothing live is signalled,
// restarted, unloaded or remounted, so no fix here can interrupt a program,
// a service or a connection that is running right now.
import type { RootChange, RootOp } from "../type/check.ts";

/** The only directories a drop-in may land in, and the only stem it may use.
 *
 *  Every one of these is a directory the system already treats as "files from
 *  elsewhere, merged in order" — that is what makes writing to it additive
 *  rather than an edit. The `99-` prefix puts Fixable last, so a drop-in the
 *  user or the distribution added later still wins. */
export const DROPIN_DIRS: readonly string[] = [
  "/etc/sysctl.d",
  "/etc/modprobe.d",
  "/etc/security/limits.d",
  "/etc/systemd/journald.conf.d",
  "/etc/systemd/coredump.conf.d",
  "/etc/systemd/system.conf.d",
  "/etc/dconf/db/local.d",
  "/etc/ssh/sshd_config.d",
  "/etc/modules-load.d",
];

const DROPIN = new RegExp(
  `^(?:${DROPIN_DIRS.join("|")})/99-fixable(?:-[a-z0-9-]+)?\\.conf$`,
);

/** Is `path` a file this app is allowed to create, replace and delete? */
export const isDropIn = (path: string): boolean => DROPIN.test(path);

const OCTAL = /^0[0-7]{3}$/;

/** A dotted kernel-parameter name. Nothing else can name a path under
 *  /proc/sys, which is the whole reach of the `sysctl` op. */
const SYSCTL_KEY = /^[a-z][a-z0-9_]*(?:\.[a-z0-9_*-]+)+$/;
/** A kernel-parameter value: numbers, a name like `fq_codel`, or a pair like
 *  `1024 65535`. Deliberately narrow — there is no value worth writing that
 *  needs a character with a meaning in a shell. */
const SYSCTL_VALUE = /^[A-Za-z0-9_. \/:,-]{1,64}$/;

/** A path safe to name inside a generated script, and to reason about: rooted,
 *  no traversal, no NUL, no newline, nothing that could end a quoted word. */
const isPlainPath = (p: string): boolean =>
  p.startsWith("/") && !p.includes("\0") && !p.includes("\n") &&
  !p.includes("'") && !p.split("/").includes("..");

/** Does `mode` only take bits away from `was`? The whole safety argument for
 *  running chmod unattended rests on this being true, so it is checked against
 *  the mode the probe actually read, not against a target in the catalogue. */
export const narrows = (mode: string, was: string): boolean => {
  if (!OCTAL.test(mode) || !OCTAL.test(was)) return false;
  const m = parseInt(mode, 8), w = parseInt(was, 8);
  return m !== w && (m & ~w) === 0;
};

/** Why a plan is being run. A fix may only ever narrow a mode; an undo may
 *  only ever put back the exact mode the probe recorded before the fix ran.
 *  Naming the two apart is what lets the gate stay absolute in the direction
 *  that matters without making the sudo tier the one tier you cannot reverse. */
export type RootIntent = "fix" | "undo";

/** The gate. Every op is put through this immediately before the script is
 *  built, so a plan assembled minutes ago against a machine that has since
 *  moved cannot smuggle a stale widening past it. */
export const rootOpIsSafe = (
  op: RootOp,
  intent: RootIntent = "fix",
): boolean => {
  switch (op.op) {
    case "chmod":
      return isPlainPath(op.path) &&
        (intent === "undo"
          ? OCTAL.test(op.mode) && OCTAL.test(op.was)
          : narrows(op.mode, op.was));
    case "write":
      return isDropIn(op.path) && OCTAL.test(op.mode) &&
        !op.content.includes("\0") && op.content.endsWith("\n");
    case "remove":
      return isDropIn(op.path);
    case "sysctl":
      return SYSCTL_KEY.test(op.key) && SYSCTL_VALUE.test(op.value) &&
        SYSCTL_VALUE.test(op.was);
  }
};

/** Why an op was rejected — for the error the user reads, not for a log. */
export const rootOpProblem = (
  op: RootOp,
  intent: RootIntent = "fix",
): string | null => {
  if (rootOpIsSafe(op, intent)) return null;
  switch (op.op) {
    case "chmod":
      return !isPlainPath(op.path)
        ? `${op.path}: not a plain absolute path`
        : `${op.path}: ${op.mode} does not only remove bits from ${op.was}`;
    case "write":
      return !isDropIn(op.path)
        ? `${op.path}: not a Fixable drop-in — this app does not edit files it does not own`
        : `${op.path}: malformed contents`;
    case "remove":
      return `${op.path}: not a Fixable drop-in`;
    case "sysctl":
      return `${op.key}=${op.value}: not a plain kernel parameter`;
  }
};

/** POSIX single-quoting: the only string that cannot be escaped inside single
 *  quotes is the single quote, so it is closed, escaped and reopened. */
export const shq = (s: string): string => `'${s.replaceAll("'", `'\\''`)}'`;

/** What the user is shown before being asked for a password — one line per op,
 *  in the shape of the command it becomes. A `write` shows its payload
 *  indented underneath, because "writes a file" without the contents is not
 *  something anybody can consent to. */
export const commandLines = (ops: readonly RootOp[]): string[] =>
  ops.map((op) => {
    switch (op.op) {
      case "chmod":
        return `chmod ${op.mode.slice(1)} ${op.path}    # was ${
          op.was.slice(1)
        }`;
      case "write":
        return `install -m ${op.mode.slice(1)} ${op.path}\n${
          op.content.trimEnd().split("\n").map((l) => `    ${l}`).join("\n")
        }`;
      case "remove":
        return `rm -f ${op.path}`;
      case "sysctl":
        return `sysctl -w ${op.key}=${op.value}    # now ${op.was}`;
    }
  });

const MARK = "__fixable__";

/** Render one op as a guarded, self-reporting block.
 *
 *  Deliberately boring shell: no pipelines, no command substitution, no
 *  variable that could hold anything but our own literal. Each op is one `&&`
 *  chain inside one `if`, so a write whose `cat` succeeded but whose `mv`
 *  failed is reported as the failure it is — and each block is independent, so
 *  one failure neither aborts the rest nor goes unnoticed. */
const render = (op: RootOp, i: number): string => {
  const guard = (chain: string, heredoc = "") =>
    `if ${chain}\n${heredoc}then echo "${MARK}ok ${i}"\n` +
    `else echo "${MARK}fail ${i}"\nfi`;
  switch (op.op) {
    case "chmod":
      return guard(`chmod ${op.mode} ${shq(op.path)}`);
    case "write": {
      // Replaced atomically through a sibling temp file: a reader of a drop-in
      // never sees a half-written one, and a failure leaves the old file whole.
      const tmp = `${op.path}.fixable-new`;
      const eof = `${MARK}EOF${i}`;
      return guard(
        `cat > ${shq(tmp)} <<'${eof}' && chmod ${op.mode} ${shq(tmp)} && ` +
          `mv -f ${shq(tmp)} ${shq(op.path)}`,
        `${op.content.replace(/\n$/, "")}\n${eof}\n`,
      );
    }
    case "remove":
      return guard(`rm -f ${shq(op.path)}`);
    case "sysctl":
      return guard(`sysctl -q -w ${shq(`${op.key}=${op.value}`)}`);
  }
};

/** The script handed to the privileged shell. Throws if any op fails the
 *  gate — the script is never built from an op that should not run. */
export const buildScript = (
  ops: readonly RootOp[],
  intent: RootIntent = "fix",
): string => {
  const bad = ops
    .map((op) => rootOpProblem(op, intent))
    .filter((p): p is string => p !== null);
  if (bad.length > 0) {
    throw new Error(`refusing to build a root plan: ${bad.join("; ")}`);
  }
  for (const [i, op] of ops.entries()) {
    if (op.op === "write" && op.content.includes(`${MARK}EOF${i}`)) {
      throw new Error(`${op.path}: contents collide with the script delimiter`);
    }
  }
  return [
    "#!/bin/sh",
    "# Written by Fixable, run once as root. Every line of this script is",
    "# shown in the app before it runs.",
    "umask 077",
    ...ops.map(render),
    `echo "${MARK}done"`,
    "",
  ].join("\n");
};

export type RootStep = { index: number; ok: boolean };

/** Read the markers back out. Anything the commands themselves printed is
 *  ignored — only lines the script itself emitted count. */
export const parseResult = (
  stdout: string,
): { steps: RootStep[]; finished: boolean } => {
  const steps: RootStep[] = [];
  let finished = false;
  for (const line of stdout.split("\n")) {
    const m = /^__fixable__(ok|fail) (\d+)$/.exec(line.trim());
    if (m) steps.push({ index: Number(m[2]), ok: m[1] === "ok" });
    else if (line.trim() === `${MARK}done`) finished = true;
  }
  return { steps, finished };
};

/** The changes that put a check's fix back.
 *
 *  Inverted at the level a check speaks in, not at the level root runs in.
 *  That matters because forty kernel parameters compile into ONE write of one
 *  file: inverting that write would undo all forty. Inverting the
 *  contributions instead — remove this check's block, put this check's value
 *  back — undoes exactly one and recompiles the file around what is left.
 *
 *  Reversed, because changes within one plan can touch the same thing. */
export const invertChanges = (changes: readonly RootChange[]): RootChange[] =>
  [...changes].reverse().map((c): RootChange => {
    switch (c.op) {
      case "chmod":
        return { op: "chmod", path: c.path, mode: c.was, was: c.mode };
      case "line":
        // A block belongs to the check that wrote it, so taking it away is
        // the whole of the undo — whatever was there before this app existed
        // was not in a file this app owns.
        return { op: "line", path: c.path, mode: c.mode, id: c.id, text: null };
      case "sysctl":
        return { op: "sysctl", key: c.key, value: c.was, was: c.value };
      case "write":
        return c.before === null
          ? { op: "remove", path: c.path }
          : { ...c, content: c.before, before: c.content };
      case "remove":
        throw new Error(`${c.path}: a removal has no recorded inverse`);
    }
  });
