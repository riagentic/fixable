// Running a root plan. The only privileged code path in the app.
//
// Fixable never handles your password. It writes the script — the same script
// the UI showed you, byte for byte — and hands the file to `pkexec`, which is
// the desktop's own way of asking. The prompt you answer is polkit's, drawn by
// the system, and the password goes from that dialog to the kernel without
// passing through this process, this app's state, its log, or its socket.
//
// That is not squeamishness. This app has a web UI: a password typed into it
// would travel a WebSocket, sit in a form field, land in a cell method's
// arguments, and be one careless log line from disk. Not asking for it is the
// only way to be sure none of that happens.
//
// The script itself is written to a directory only this user can enter, at
// mode 0600, and deleted afterwards — so between writing and running there is
// no window in which anybody but its owner (and root, who is about to run it)
// can read or replace it.
import type { RootChange, RootOp } from "../type/check.ts";
import type { RootIntent } from "../lib/root.ts";
import { buildScript, isDropIn, parseResult } from "../lib/root.ts";
import { parseDropIn, renderDropIn, withBlock } from "../lib/dropin.ts";
import { has, home, readText } from "./sys.server.ts";

/** Fold what the checks asked for into what root will actually do.
 *
 *  Contributions to the same drop-in become ONE write of the whole file, built
 *  from what is on disk right now — so a plan of forty kernel parameters is
 *  one file replaced once, and a plan of one is the same file with one block
 *  more than it had. Reading the current contents here, at the last moment, is
 *  also what makes `before` an accurate undo rather than a guess.
 *
 *  A path whose blocks all went away is removed rather than left empty: an
 *  empty drop-in is a file the system still opens and parses to learn nothing.
 *
 *  Order is preserved for everything else, and every drop-in write is appended
 *  after the pass-through ops, so the compiled plan reads the way the preview
 *  shows it. */
export async function compilePlan(
  changes: readonly RootChange[],
): Promise<RootOp[]> {
  const direct = changes.filter((c): c is RootOp => c.op !== "line");
  const lines = changes.filter((c) => c.op === "line");

  const paths = [...new Set(lines.map((l) => l.path))].sort();
  const writes: RootOp[] = [];
  for (const path of paths) {
    if (!isDropIn(path)) throw new Error(`${path}: not a Fixable drop-in`);
    const before = await readText(path);
    const mine = lines.filter((l) => l.path === path);
    const blocks = mine.reduce(
      (acc, l) => withBlock(acc, l.id, l.text),
      parseDropIn(before),
    );
    const content = renderDropIn(blocks);
    const mode = mine[0]!.mode;
    if (content === "") {
      if (before !== null) writes.push({ op: "remove", path });
    } else if (content !== before) {
      writes.push({ op: "write", path, mode, content, before });
    }
  }
  return [...direct, ...writes];
}

export type RootRun = {
  /** Ops that reported success, by index into the plan. */
  done: number[];
  /** Ops that ran and failed. */
  failed: number[];
  /** Ops that never ran — the shell died, or the user dismissed the prompt. */
  skipped: number[];
  /** Set when nothing ran at all: cancelled, or no way to ask. */
  problem: string | null;
};

const stateDir = (): string => `${home()}/.local/state/fixable`;

/** Where the script lives for the seconds it exists. Under the user's own
 *  state directory, not /tmp: a world-writable directory is exactly where a
 *  file about to be executed by root should never be. */
const scriptPath = (): string => `${stateDir()}/root-plan.sh`;

const writeScript = async (text: string): Promise<string> => {
  const path = scriptPath();
  await Deno.mkdir(stateDir(), { recursive: true, mode: 0o700 });
  // Chmod separately: `mkdir` leaves an existing directory's mode alone, and
  // this one is about to hold a file root will execute.
  await Deno.chmod(stateDir(), 0o700).catch(() => {});
  await Deno.writeTextFile(path, text, { mode: 0o600 });
  await Deno.chmod(path, 0o600);
  return path;
};

/** polkit's exit code for "the user cancelled, or could not authenticate". */
const PKEXEC_DENIED = 126;
/** polkit's exit code for "the program could not be run at all". */
const PKEXEC_MISSING = 127;

const cannotAsk = (path: string) =>
  `No way to ask for the root password on this session: pkexec is not ` +
  `installed, or no polkit agent is running. Nothing was changed. The exact ` +
  `script is at ${path} — you can read it and run it yourself with ` +
  `\`sudo sh ${path}\`.`;

/** Run a plan as root, once, with one prompt for the whole batch.
 *
 *  One `pkexec` for N ops rather than N of them: being asked forty times is
 *  not forty times the consent, it is a habit of clicking through. The plan is
 *  shown whole, authorised once, and every step reports back individually so
 *  the caller knows exactly what landed.
 *
 *  Never throws for anything the user did — a cancelled prompt is a normal
 *  answer, and comes back as `problem` with nothing changed. */
export async function runRootPlan(
  ops: readonly RootOp[],
  intent: RootIntent = "fix",
): Promise<RootRun> {
  const none = (problem: string): RootRun => ({
    done: [],
    failed: [],
    skipped: ops.map((_, i) => i),
    problem,
  });

  if (ops.length === 0) {
    return { done: [], failed: [], skipped: [], problem: null };
  }

  // Throws if any op fails the gate. Deliberately not caught: a plan that
  // should not run is a bug in the catalogue, and the caller must hear it.
  const script = buildScript(ops, intent);
  const path = await writeScript(script);

  // Set when the script has to outlive this call: the only case is "there is
  // no way to ask for a password here", where the plan itself is the useful
  // answer and the message points at it.
  let keep = false;
  try {
    if (!(await has("pkexec"))) {
      keep = true;
      return none(cannotAsk(path));
    }

    // No timeout wrapper: the person is being asked for a password, and how
    // long they take is their business. pkexec exits by itself when its
    // dialog is dismissed.
    const cmd = new Deno.Command("pkexec", {
      args: ["/bin/sh", path],
      stdin: "null",
      stdout: "piped",
      stderr: "piped",
    });
    const out = await cmd.output();
    const stdout = new TextDecoder().decode(out.stdout);
    const stderr = new TextDecoder().decode(out.stderr).trim();

    const { steps } = parseResult(stdout);
    const seen = new Set(steps.map((s) => s.index));

    if (steps.length === 0) {
      if (out.code === PKEXEC_DENIED) {
        return none("Cancelled — no password given, and nothing was changed.");
      }
      if (out.code === PKEXEC_MISSING) {
        keep = true;
        return none(cannotAsk(path));
      }
      return none(
        `Nothing ran${stderr ? `: ${stderr}` : "."} Nothing was changed.`,
      );
    }

    return {
      done: steps.filter((s) => s.ok).map((s) => s.index),
      failed: steps.filter((s) => !s.ok).map((s) => s.index),
      // A step with no marker never reached its `echo`. Reported as skipped
      // rather than failed: it is not known to have changed anything.
      skipped: ops.map((_, i) => i).filter((i) => !seen.has(i)),
      problem: null,
    };
  } finally {
    // The script has served its purpose the moment the shell exits. Leaving a
    // file behind that root will happily execute is not a thing to do — the
    // exception is the one message that tells you to go and run it yourself,
    // which would otherwise name a file that had just been deleted.
    if (!keep) await Deno.remove(path).catch(() => {});
  }
}

/** Read a drop-in Fixable owns, so a plan can record what it is replacing.
 *  `null` when the file is not there — which is the common case, and the thing
 *  that makes the undo a deletion rather than a restore. */
export const readDropIn = (path: string): Promise<string | null> =>
  readText(path);
