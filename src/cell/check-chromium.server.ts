// Chromium-family browsers: Chromium, Chrome, Brave, Edge, Vivaldi, Opera.
//
// Same constraint as Firefox, for the same reason: the browser rewrites its
// Preferences file from memory when it exits, so a change made while it runs
// is thrown away at close. The fix refuses while the browser is open and the
// row says so before you press it.
import type { Check, Finding } from "../type/check.ts";
import type { ChromiumPolicy } from "../type/policy.ts";
import { readJsonPath, upsertJsonPath } from "../lib/json-conf.ts";
import { isBad } from "../lib/verdict.ts";
import { applyAll, home, readText } from "./sys.server.ts";
import { restoreConf, writeConf } from "./conf.server.ts";
import { CHROMIUM_POLICIES } from "../lib/policy/chromium.ts";
import { CHROMIUM2_POLICIES } from "../lib/policy/chromium2.ts";
import { join } from "@std/path";

/** Every Chromium-family install, packaged and Flatpak. */
const BROWSERS: [name: string, root: string][] = [
  ["Chromium", ".config/chromium"],
  ["Chrome", ".config/google-chrome"],
  ["Chrome Beta", ".config/google-chrome-beta"],
  ["Brave", ".config/BraveSoftware/Brave-Browser"],
  ["Edge", ".config/microsoft-edge"],
  ["Vivaldi", ".config/vivaldi"],
  ["Opera", ".config/opera"],
  ["Chromium (Flatpak)", ".var/app/org.chromium.Chromium/config/chromium"],
  [
    "Brave (Flatpak)",
    ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
  ],
];

type Target = {
  label: string;
  file: string;
  /** The user-data directory, where the browser's lock lives. */
  root: string;
  running: boolean;
};

/** A running Chromium holds `SingletonLock` in its user-data directory. */
async function running(root: string): Promise<boolean> {
  try {
    return (await Deno.lstat(join(root, "SingletonLock"))).isSymlink;
  } catch {
    return false;
  }
}

/** Asked again at the moment of writing, not trusted from the scan: the
 *  browser may have started since. */
async function refuseIfRunning(ts: Target[]): Promise<void> {
  for (const t of ts) {
    if (await running(t.root)) {
      throw new Error(
        `${t.label} is running — close it first, or the change will be ` +
          `overwritten when it exits`,
      );
    }
  }
}

/** Profile directories are `Default`, `Profile 1`, `Profile 2`, … */
async function targets(p: ChromiumPolicy): Promise<Target[]> {
  const out: Target[] = [];
  for (const [name, rel] of BROWSERS) {
    const root = join(home(), rel);
    try {
      await Deno.stat(join(root, "Local State"));
    } catch {
      continue; // this browser is not installed
    }
    const live = await running(root);
    if (p.localState) {
      out.push({
        label: name,
        file: join(root, "Local State"),
        root,
        running: live,
      });
      continue;
    }
    for await (const e of Deno.readDir(root)) {
      if (!e.isDirectory) continue;
      if (e.name !== "Default" && !e.name.startsWith("Profile ")) continue;
      const file = join(root, e.name, "Preferences");
      try {
        await Deno.stat(file);
      } catch {
        continue;
      }
      out.push({ label: `${name}/${e.name}`, file, root, running: live });
    }
  }
  return out;
}

export function chromiumCheck(p: ChromiumPolicy): Check {
  return {
    id: p.id,
    title: `Chromium: ${p.title}`,
    category: p.category,
    severity: p.severity,
    weight: p.weight,
    mode: "scan",
    tier: "fix",
    explanation:
      `Sets \`${p.path}\` to \`${p.safe}\` in every Chromium-family profile ` +
      `that has it wrong. ${p.because} The browser must be closed — it ` +
      `rewrites its preferences from memory at exit, so a change made while ` +
      `it runs would be silently thrown away. The file's previous contents ` +
      `are recorded in full and Undo restores them exactly.`,
    probe: async (): Promise<Finding | null> => {
      const found = await targets(p);
      if (found.length === 0) return null;

      const offenders: Target[] = [];
      for (const t of found) {
        const text = await readText(t.file);
        if (text === null) continue;
        const literal = readJsonPath(text, p.path) ?? p.fallback;
        // A literal string arrives quoted; strip for comparison so a policy
        // row can talk about the value rather than its JSON spelling.
        const value = literal.startsWith('"') ? literal.slice(1, -1) : literal;
        const verdict = isBad(p.bad, value);
        // A value we cannot judge is not a value we call fine.
        if (verdict === null) {
          throw new Error(`${p.path}: cannot judge ${literal.slice(0, 60)}`);
        }
        if (verdict) offenders.push(t);
      }
      if (offenders.length === 0) return null;

      const live = offenders.filter((o) => o.running);
      return {
        detail: `${p.detail} (${p.path} in ${offenders.length} profile${
          offenders.length === 1 ? "" : "s"
        })${live.length > 0 ? " — close the browser before fixing" : ""}`,
        apply: async () => {
          await refuseIfRunning(offenders);
          const revert = await applyAll(offenders, async (t) => {
            const text = await readText(t.file);
            // It was there a moment ago; a Preferences file holding one key
            // is not the edit anyone reviewed.
            if (text === null) throw new Error(`${t.file} has vanished`);
            const was = readJsonPath(text, p.path) ?? p.fallback;
            const write = await writeConf(
              t.file,
              upsertJsonPath(text, p.path, p.safe),
            );
            return restoreConf(
              write,
              (later) => upsertJsonPath(later, p.path, was),
            );
          });
          return {
            summary: `${p.path} -> ${p.safe} in ${
              offenders.map((o) => o.label).join(", ")
            }`,
            // Undo writes the same file, so it is exactly as unsafe while the
            // browser runs: the restore would be overwritten at exit.
            revert: async () => {
              await refuseIfRunning(offenders);
              await revert();
            },
          };
        },
      };
    },
  };
}

export const ALL_CHROMIUM_POLICIES = [
  ...CHROMIUM_POLICIES,
  ...CHROMIUM2_POLICIES,
];

export const CHROMIUM_CHECKS: Check[] = ALL_CHROMIUM_POLICIES.map(
  chromiumCheck,
);
