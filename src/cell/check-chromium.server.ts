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
import { home, readText } from "./sys.server.ts";
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

type Target = { label: string; file: string; running: boolean };

/** A running Chromium holds `SingletonLock` in its user-data directory. */
async function running(root: string): Promise<boolean> {
  try {
    return (await Deno.lstat(join(root, "SingletonLock"))).isSymlink;
  } catch {
    return false;
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
      out.push({ label: name, file: join(root, "Local State"), running: live });
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
      out.push({ label: `${name}/${e.name}`, file, running: live });
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
        if (isBad(p.bad, value)) offenders.push(t);
      }
      if (offenders.length === 0) return null;

      const live = offenders.filter((o) => o.running);
      return {
        detail: `${p.detail} (${p.path} in ${offenders.length} profile${
          offenders.length === 1 ? "" : "s"
        })${live.length > 0 ? " — close the browser before fixing" : ""}`,
        apply: async () => {
          if (live.length > 0) {
            throw new Error(
              `${live[0]!.label} is running — close it and press Fix again, ` +
                `or the change will be overwritten when it exits`,
            );
          }
          const undone: (() => Promise<void>)[] = [];
          for (const t of offenders) {
            const text = await readText(t.file) ?? "{}";
            const was = readJsonPath(text, p.path) ?? p.fallback;
            const write = await writeConf(
              t.file,
              upsertJsonPath(text, p.path, p.safe),
            );
            undone.push(restoreConf(
              write,
              (later) => upsertJsonPath(later, p.path, was),
            ));
          }
          return {
            summary: `${p.path} -> ${p.safe} in ${
              offenders.map((o) => o.label).join(", ")
            }`,
            revert: async () => {
              for (const r of undone) await r();
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
