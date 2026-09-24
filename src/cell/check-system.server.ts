// Monitor checks — resource, utilization and performance pressure.
//
// Cheap by construction (`/proc` reads and one `df`), because these run on
// every tick. None of them has an automatic fix: every remedy would mean
// deleting files or stopping programs the user is using.
import type { Check, Finding } from "../type/check.ts";
import { bytes, pct } from "../lib/format.ts";
import { meminfo, readText, run } from "./sys.server.ts";

type Mount = { mount: string; usedPct: number; freeBytes: number };

/** `df -P -k` — POSIX columns, KiB. Real devices only: tmpfs and squashfs
 *  mounts are full by design and reporting them is noise, not diagnosis. */
async function mounts(): Promise<Mount[]> {
  // df exits 1 when ANY mount fails to stat (a stale NFS share) yet still
  // prints every other line — so the output is used whatever the exit code.
  const r = await run("df", ["-P", "-k"], 8_000);
  return r.out.split("\n").slice(1).flatMap((line) => {
    const f = line.split(/\s+/);
    if (f.length < 6 || !f[0]?.startsWith("/dev/")) return [];
    const [used, free, mount] = [Number(f[2]), Number(f[3]), f[5]];
    if (!mount || !Number.isFinite(used) || !Number.isFinite(free)) return [];
    return [{
      mount,
      usedPct: pct(used, used + free),
      freeBytes: free * 1024,
    }];
  });
}

const DISK: Check = {
  id: "disk-space",
  title: "A filesystem is nearly full",
  category: "resource",
  severity: "major",
  weight: 90,
  mode: "monitor",
  tier: "advisory",
  explanation:
    "No automatic fix. Freeing space means deleting files, and this app never " +
    "deletes anything. `du -h --max-depth=1 ~ | sort -h | tail -20` shows " +
    "where it went; `ncdu ~` is easier to read. Empty the trash last, once " +
    "you are sure.",
  probe: async (): Promise<Finding | null> => {
    const worst = (await mounts())
      .filter((m) => m.usedPct >= 90)
      .sort((a, b) => b.usedPct - a.usedPct)[0];
    if (!worst) return null;
    return {
      detail: `${worst.mount} is ${worst.usedPct}% full — ${
        bytes(worst.freeBytes)
      } left`,
      severity: worst.usedPct >= 95 ? "critical" : "major",
    };
  },
};

const MEMORY: Check = {
  id: "memory-pressure",
  title: "Free memory is running out",
  category: "resource",
  severity: "major",
  weight: 80,
  mode: "monitor",
  tier: "advisory",
  explanation:
    "No automatic fix. The only remedy is closing programs, and this app will " +
    "not decide which of yours to stop. `ps aux --sort=-%mem | head` names " +
    "the largest.",
  probe: async (): Promise<Finding | null> => {
    const m = await meminfo();
    const total = m.MemTotal ?? 0, avail = m.MemAvailable ?? 0;
    if (total === 0) return null;
    const free = pct(avail, total);
    if (free >= 10) return null;
    return {
      detail: `${free}% of ${bytes(total)} available (${bytes(avail)})`,
      severity: free < 5 ? "critical" : "major",
    };
  },
};

const SWAP: Check = {
  id: "swap-pressure",
  title: "The machine is swapping heavily",
  category: "performance",
  severity: "major",
  weight: 70,
  mode: "monitor",
  tier: "advisory",
  explanation:
    "No automatic fix. Swapping is a symptom of memory demand; clearing it " +
    "means closing programs or adding RAM, neither of which this app will do " +
    "on your behalf. `ps aux --sort=-rss | head` names what is holding it.",
  probe: async (): Promise<Finding | null> => {
    const m = await meminfo();
    const total = m.SwapTotal ?? 0, free = m.SwapFree ?? 0;
    if (total === 0) return null;
    const used = pct(total - free, total);
    if (used < 50) return null;
    return {
      detail: `${used}% of ${bytes(total)} swap in use`,
      severity: used >= 80 ? "major" : "minor",
    };
  },
};

const LOAD: Check = {
  id: "cpu-load",
  title: "Sustained CPU load is above capacity",
  category: "utilization",
  severity: "minor",
  weight: 60,
  mode: "monitor",
  tier: "advisory",
  explanation:
    "No automatic fix. Lowering load means stopping or renicing a running " +
    "program — a decision only you can make. `ps aux --sort=-%cpu | head` " +
    "names the cause; `renice +10 -p <pid>` calms one without stopping it.",
  probe: async (): Promise<Finding | null> => {
    const raw = await readText("/proc/loadavg");
    const one = Number(raw?.split(" ")[0]);
    if (!Number.isFinite(one)) return null;
    const cpus = navigator.hardwareConcurrency || 1;
    const ratio = one / cpus;
    if (ratio < 1.5) return null;
    return {
      detail: `load ${one.toFixed(2)} across ${cpus} cores (${
        ratio.toFixed(1)
      }x)`,
      severity: ratio >= 3 ? "major" : "minor",
    };
  },
};

export const SYSTEM_CHECKS: Check[] = [DISK, MEMORY, SWAP, LOAD];
