// Readings from the running system: sysfs, procfs, and the tools that answer
// for hardware, firewalls, disks and services.
//
// This family reports and, with one narrow exception, never writes. That is
// not caution for its own sake — it is the whole domain. A firewall rule, a
// mount option, a kernel parameter, a VPN setting and a disk scheduler all
// have one property in common: changing them can take down something that is
// working right now, for a program this app cannot see. So the app reads,
// explains, and hands over the command.
//
// The exception is a row that names a `fix`: a block in a drop-in file that
// belongs to Fixable, in a directory the system already merges, read the next
// time something reads it. Nothing is signalled, restarted or unloaded, so
// nothing running changes behaviour — and because the vocabulary is a line in
// a file and nothing else, a row cannot express a change that would. Whether
// such a change is a repair or a trade is the row's own `optional` flag, and
// a trade is never swept up by "Fix all (sudo required)".
import type { Check, Finding } from "../type/check.ts";
import type { SysPolicy } from "../type/policy.ts";
import { isBad } from "../lib/verdict.ts";
import { has, readText, run } from "./sys.server.ts";

/** Commands repeat across rows — ten NordVPN rows read one `nordvpn settings`,
 *  four Flatpak rows walk the same app list. Within ONE pass the answer cannot
 *  change, so it is read once. The memo exists only for the duration of a pass
 *  and is discarded with it: there is no cache between passes, and a reading
 *  is never carried across one. */
let memo: Map<string, Promise<string | null>> | null = null;

export const beginPass = () => {
  memo = new Map();
};
export const endPass = () => {
  memo = null;
};

/** The reading, or null when this machine has nothing to read.
 *
 *  Empty output is NOT a reading. A tool that is absent, a `grep` that matched
 *  nothing, a sysfs file that does not exist — all produce nothing, and
 *  nothing cannot be judged. A row that needs "absent is the finding" says so
 *  with `missingIsBad`, or emits an explicit token of its own. */
async function value(p: SysPolicy): Promise<string | null> {
  if (p.source.kind === "file") {
    const raw = await readText(p.source.path);
    const t = raw?.trim();
    return t === undefined || t === "" ? null : t;
  }
  const { cmd, args, needs } = p.source;
  if (needs && !(await has(needs))) return null;
  const key = `${cmd}\u0000${args.join("\u0000")}`;
  const hit = memo?.get(key);
  if (hit) return hit;
  // Every command runs under coreutils `timeout`, not just under an
  // AbortSignal. The signal kills the shell it started; it does NOT kill the
  // shell's children, and `output()` keeps waiting on the pipe they inherited
  // — so one slow grandchild (`journalctl --verify`, a `find` on a huge tree)
  // hung the whole scan well past its supposed limit. `timeout` kills the
  // group; `-k` guarantees it even if the program ignores TERM.
  const ask = run("timeout", ["-k", "2", "12", cmd, ...args], 20_000).then((
    r,
  ) => r.out.trim().length > 0 ? r.out.trim() : null);
  memo?.set(key, ask);
  return ask;
}

const pull = (text: string, extract?: string): string | null => {
  if (!extract) return text;
  const m = text.match(new RegExp(extract, "m"));
  return m ? (m[1] ?? m[0]) : null;
};

export function sysCheck(p: SysPolicy): Check {
  return {
    id: p.id,
    title: p.title,
    category: p.category,
    severity: p.severity,
    weight: p.weight,
    mode: "scan",
    tier: p.fix ? (p.fix.optional ? "optional-sudo" : "sudo") : "advisory",
    explanation: p.fix
      ? `Writes \`${p.fix.text.split("\n")[0]}\` into ${p.fix.path} — a file ` +
        `that belongs to this app, so nothing the system ships is edited, and ` +
        `nothing running is restarted or reconfigured. It takes effect the ` +
        `next time that file is read. Needs the root password; Undo takes the ` +
        `line out again.`
      : `No automatic fix: this is hardware, a filesystem, a firewall or a ` +
        `live service, and changing any of them can stop something that is ` +
        `working right now. ${p.how}`,
    probe: async (): Promise<Finding | null> => {
      // Built here rather than at module load so it carries the row's own id:
      // the block is labelled with the check that owns it, which is what makes
      // one check's undo leave every other check's line alone.
      const plan = (): Finding["root"] =>
        p.fix && {
          changes: [{
            op: "line",
            path: p.fix.path,
            mode: p.fix.mode,
            id: p.id,
            text: p.fix.text,
          }],
          summary: p.fix.summary,
        };

      // Presence checks answer before any reading is attempted.
      if (p.source.kind === "file" && (p.presentIsBad || p.missingIsBad)) {
        const there = (await readText(p.source.path)) !== null;
        const wrong = p.presentIsBad ? there : !there;
        return wrong ? { detail: p.detail, root: plan() } : null;
      }

      const raw = await value(p);
      if (raw === null) return null; // nothing here to read
      const v = pull(raw, p.extract);
      if (v === null) return null; // the shape did not match — not a verdict
      if (!p.bad) return null;

      const verdict = isBad(p.bad, v);
      if (verdict === null) {
        throw new Error(
          `${p.id}: cannot judge ${JSON.stringify(v.slice(0, 60))}`,
        );
      }
      return verdict
        ? {
          detail: `${p.detail} (${v.split("\n")[0]!.slice(0, 90)})`,
          root: plan(),
        }
        : null;
    },
  };
}

export const sysChecks = (rows: SysPolicy[]): Check[] => rows.map(sysCheck);
