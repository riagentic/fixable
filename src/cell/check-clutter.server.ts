// Scan checks for accumulation — cache and autostart entries.
//
// Both advisory. The remedy for either is deletion or disabling something the
// user chose to run, and neither is a call this app makes for them.
import type { Check, Finding } from "../type/check.ts";
import { bytes } from "../lib/format.ts";
import { home, run } from "./sys.server.ts";
import { join } from "@std/path";

const CACHE_SIZE: Check = {
  id: "cache-size",
  title: "The user cache directory is very large",
  category: "resource",
  severity: "minor",
  weight: 25,
  mode: "scan",
  tier: "advisory",
  explanation:
    "No automatic fix. Caches are regenerable, but they are still files on " +
    "your disk and some hold offline data — this app will not delete them for " +
    "you. Clear them from the applications that own them.",
  probe: async (): Promise<Finding | null> => {
    const dir = join(home(), ".cache");
    const r = await run("du", ["-sx", "-B1", dir], 20_000);
    const size = Number(r.out.split(/\s+/)[0]);
    if (!r.ok || !Number.isFinite(size) || size < 5 * 1024 ** 3) return null;
    return { detail: `${dir} holds ${bytes(size)}` };
  },
};

const AUTOSTART: Check = {
  id: "autostart-count",
  title: "Many programs start automatically at login",
  category: "performance",
  severity: "minor",
  weight: 20,
  mode: "scan",
  tier: "advisory",
  explanation:
    "No automatic fix. Which of these you actually want is a judgement about " +
    "how you use the machine, and disabling the wrong one breaks a workflow " +
    "silently. Review them in your desktop's Startup Applications.",
  probe: async (): Promise<Finding | null> => {
    const dir = join(home(), ".config", "autostart");
    let n = 0;
    try {
      for await (const e of Deno.readDir(dir)) {
        if (!e.isFile || !e.name.endsWith(".desktop")) continue;
        const text = await Deno.readTextFile(join(dir, e.name));
        if (!/^Hidden=true$/m.test(text)) n++;
      }
    } catch {
      return null;
    }
    return n > 12 ? { detail: `${n} entries in ${dir}` } : null;
  },
};

export const CLUTTER_CHECKS: Check[] = [CACHE_SIZE, AUTOSTART];
