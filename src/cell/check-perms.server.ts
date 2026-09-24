// Permission checks — one per catalogue row, all auto-fixable.
//
// Narrowing a mode takes nothing away: the file keeps its contents, its owner
// keeps its access, and `tighten` refuses outright any change that would widen
// it. That guard lives in the writer, not in each caller.
import type { Check, Finding } from "../type/check.ts";
import type { PermPolicy } from "../type/policy.ts";
import { PERM_POLICIES } from "../lib/policy/perms.ts";
import { applyAll, home, octal, restoreMode, tighten } from "./sys.server.ts";
import { join } from "@std/path";

/** Mode and kind in one call — the kind decides whether the owner's execute
 *  bit may be taken away, so both have to be read together.
 *
 *  lstat, and a symlink is skipped: its own mode means nothing, and following
 *  it reports the target — `~/.bash_history -> /dev/null` read as a 0666
 *  history file, with a fix that could never succeed. */
async function statOf(
  path: string,
): Promise<{ mode: number; dir: boolean } | null> {
  try {
    const st = await Deno.lstat(path);
    if (st.isSymlink) return null;
    return st.mode === null ? null : { mode: st.mode, dir: st.isDirectory };
  } catch {
    return null;
  }
}

/** The mode this path should end up with.
 *
 *  A row's `target` is written for a file. Applying a file's target to a
 *  DIRECTORY takes away the owner's execute bit, and a directory without it
 *  cannot be entered at all — the files inside stop opening, which is a far
 *  worse outcome than the exposure the row was closing. So a directory always
 *  keeps owner traversal.
 *
 *  This is not hypothetical: a `chmod 0600` intended for a history file was
 *  applied to `~/.config/GIMP`, `~/.cache/fontconfig` and
 *  `~/.local/share/systemd`, and left all three unreadable by their owner. */
const wanted = (target: number, o: { dir: boolean }): number =>
  o.dir ? target | 0o100 : target;

/** Resolve one catalogue path. `.` is `$HOME`, a leading `/` is absolute, and
 *  a trailing `/*` expands to the directory's direct children. */
async function expand(spec: string): Promise<string[]> {
  const abs = spec.startsWith("/")
    ? spec
    : spec === "."
    ? home()
    : join(home(), spec);
  if (!abs.endsWith("/*")) return [abs];
  const dir = abs.slice(0, -2);
  try {
    const out: string[] = [];
    for await (const e of Deno.readDir(dir)) {
      if (e.isFile) out.push(join(dir, e.name));
    }
    return out.sort();
  } catch {
    return [];
  }
}

/** Private SSH keys: a file with a `<name>.pub` sibling. Contents are never
 *  read — a diagnostics tool has no business opening your keys. */
async function sshPrivateKeys(): Promise<string[]> {
  const dir = join(home(), ".ssh");
  try {
    const names = new Set<string>();
    for await (const e of Deno.readDir(dir)) if (e.isFile) names.add(e.name);
    return [...names]
      .filter((n) => !n.endsWith(".pub") && names.has(`${n}.pub`))
      .map((n) => join(dir, n))
      .sort();
  } catch {
    return [];
  }
}

/** One catalogue row (or one discovery function) becomes one check. */
export function permCheck(
  p: PermPolicy,
  discover: () => Promise<string[]> = async () =>
    (await Promise.all(p.paths.map(expand))).flat(),
): Check {
  const targetOctal = octal(p.target);
  return {
    id: p.id,
    title: p.title,
    category: p.category,
    severity: p.severity,
    weight: p.weight,
    mode: "scan",
    tier: "fix",
    explanation:
      `Runs \`chmod ${targetOctal}\` on ${p.what}. Permissions only get ` +
      `narrower — the change is refused outright if it would widen access — ` +
      `contents and ownership are untouched, and Undo restores the old mode.`,
    probe: async (): Promise<Finding | null> => {
      const offenders: { path: string; bits: number; dir: boolean }[] = [];
      for (const path of await discover()) {
        const st = await statOf(path);
        if (st !== null && (st.mode & p.mask) !== 0) {
          offenders.push({ path, bits: st.mode & 0o7777, dir: st.dir });
        }
      }
      if (offenders.length === 0) return null;
      const names = offenders.map((o) => `${o.path} (${octal(o.bits)})`);
      return {
        detail: names.length === 1
          ? `${names[0]} is open beyond you`
          : `${names.length} paths too open: ${names.join(", ")}`,
        apply: async () => {
          const done: string[] = [];
          const revert = await applyAll(offenders, async (o) => {
            const next = wanted(p.target, o) & o.bits;
            const { previous } = await tighten(o.path, next);
            done.push(`${o.path} ${octal(previous)} -> ${octal(next)}`);
            return restoreMode(o.path, previous);
          });
          return {
            // The previous mode goes into the summary, not just into the undo
            // closure: the log outlives the process, and a change you cannot
            // read back is not a change you can reason about later.
            summary: `chmod: ${done.join(", ")}`,
            revert,
          };
        },
      };
    },
  };
}

const SSH_KEYS = permCheck({
  id: "perm-ssh-keys",
  title: "A private SSH key is readable by other accounts",
  category: "security",
  severity: "critical",
  weight: 95,
  paths: [],
  target: 0o600,
  mask: 0o077,
  what: "your private SSH keys",
}, sshPrivateKeys);

export const PERM_CHECKS: Check[] = [
  SSH_KEYS,
  ...PERM_POLICIES.map((p) => permCheck(p)),
];
