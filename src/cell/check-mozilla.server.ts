// Firefox and Thunderbird preferences.
//
// The one delicate part: Mozilla applications rewrite `prefs.js` wholesale
// from memory when they shut down. Editing it while the program is running
// would be undone at exit — silently, which is the worst outcome. So a fix
// here refuses while the profile is locked, and says so before you press it.
//
// `user.js` is the other option, and this app deliberately does not use it: it
// re-applies at every start, so a setting you later change in the application's
// own UI would keep reverting. Editing `prefs.js` with the program closed is
// exactly equivalent to changing it in Settings, which is the honest fix.
import type { Check, Finding } from "../type/check.ts";
import type { MozPolicy } from "../type/policy.ts";
import { prefValue, readUserPref, upsertUserPref } from "../lib/conf.ts";
import { isBad } from "../lib/verdict.ts";
import { home, readText } from "./sys.server.ts";
import { restoreConf, writeConf } from "./conf.server.ts";
import { FIREFOX_POLICIES } from "../lib/policy/firefox.ts";
import { FIREFOX2_POLICIES } from "../lib/policy/firefox2.ts";
import { FIREFOX3_POLICIES } from "../lib/policy/firefox3.ts";
import { THUNDERBIRD_POLICIES } from "../lib/policy/thunderbird.ts";
import { THUNDERBIRD2_POLICIES } from "../lib/policy/thunderbird2.ts";
import { join } from "@std/path";

/** Where a product keeps its profiles — packaged, Flatpak, and Snap. */
const ROOTS: Record<MozPolicy["product"], string[]> = {
  firefox: [
    ".mozilla/firefox",
    ".var/app/org.mozilla.firefox/.mozilla/firefox",
    "snap/firefox/common/.mozilla/firefox",
  ],
  thunderbird: [
    ".thunderbird",
    ".var/app/org.mozilla.Thunderbird/.thunderbird",
    "snap/thunderbird/common/.thunderbird",
  ],
};

type Profile = { dir: string; prefs: string; running: boolean };

/** Every profile with a prefs.js, across every install layout. */
async function profiles(product: MozPolicy["product"]): Promise<Profile[]> {
  const out: Profile[] = [];
  for (const root of ROOTS[product]) {
    const base = join(home(), root);
    try {
      for await (const e of Deno.readDir(base)) {
        if (!e.isDirectory) continue;
        const dir = join(base, e.name);
        try {
          await Deno.stat(join(dir, "prefs.js"));
        } catch {
          continue;
        }
        out.push({
          dir,
          prefs: join(dir, "prefs.js"),
          running: await locked(dir),
        });
      }
    } catch { /* this layout is not installed */ }
  }
  return out;
}

/** A running Mozilla profile holds a `lock` symlink. `.parentlock` survives a
 *  crash, so it is not evidence on its own; the symlink is created and removed
 *  by the running process. */
async function locked(dir: string): Promise<boolean> {
  try {
    return (await Deno.lstat(join(dir, "lock"))).isSymlink;
  } catch {
    return false;
  }
}

const label = (p: MozPolicy) =>
  p.product === "firefox" ? "Firefox" : "Thunderbird";

export function mozCheck(p: MozPolicy): Check {
  return {
    id: p.id,
    title: `${label(p)}: ${p.title}`,
    category: p.category,
    severity: p.severity,
    weight: p.weight,
    mode: "scan",
    tier: "fix",
    explanation:
      `Sets \`${p.pref}\` to \`${p.safe}\` in every ${label(p)} profile that ` +
      `has it wrong. ${p.because} ${
        label(p)
      } must be closed — its preferences ` +
      `are rewritten from memory at exit, so a change made while it runs would ` +
      `be silently thrown away. The file's previous contents are recorded in ` +
      `full and Undo restores them exactly.`,
    probe: async (): Promise<Finding | null> => {
      const found = await profiles(p.product);
      if (found.length === 0) return null; // not installed, or never started

      const offenders: Profile[] = [];
      for (const prof of found) {
        const text = await readText(prof.prefs);
        if (text === null) continue;
        // Absent means the application's own default is in force — which is
        // what `fallback` records. Treating absence as "fine" would miss every
        // pref whose default is the problem.
        const literal = readUserPref(text, p.pref) ?? p.fallback;
        if (isBad(p.bad, prefValue(literal))) offenders.push(prof);
      }
      if (offenders.length === 0) return null;

      const running = offenders.filter((o) => o.running);
      const detail = `${p.detail} (${p.pref})` +
        (offenders.length > 1 ? ` in ${offenders.length} profiles` : "") +
        (running.length > 0 ? ` — close ${label(p)} before fixing` : "");

      return {
        detail,
        apply: async () => {
          if (running.length > 0) {
            throw new Error(
              `${label(p)} is running — close it and press Fix again, or the ` +
                `change will be overwritten when it exits`,
            );
          }
          const undone: (() => Promise<void>)[] = [];
          for (const prof of offenders) {
            const text = await readText(prof.prefs) ?? "";
            const was = readUserPref(text, p.pref) ?? p.fallback;
            const write = await writeConf(
              prof.prefs,
              upsertUserPref(text, p.pref, p.safe),
            );
            // Dozens of prefs share one prefs.js, so undo one pref rather
            // than rewriting the file over the other fixes.
            undone.push(restoreConf(
              write,
              (later) => upsertUserPref(later, p.pref, was),
            ));
          }
          return {
            summary: `${p.pref} -> ${p.safe} in ${offenders.length} ${
              label(p)
            } profile${offenders.length === 1 ? "" : "s"}`,
            revert: async () => {
              for (const r of undone) await r();
            },
          };
        },
      };
    },
  };
}

export const MOZILLA_POLICIES: MozPolicy[] = [
  ...FIREFOX_POLICIES,
  ...FIREFOX2_POLICIES,
  ...FIREFOX3_POLICIES,
  ...THUNDERBIRD_POLICIES,
  ...THUNDERBIRD2_POLICIES,
];

export const MOZILLA_CHECKS: Check[] = MOZILLA_POLICIES.map(mozCheck);
