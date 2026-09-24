// Scan checks over system-wide configuration — firewall, updates.
//
// All advisory. Every remedy here needs root and touches something the machine
// depends on: enabling a firewall can sever a live connection, installing
// updates can restart a service you are using. Reporting them is this app's
// job; deciding them is yours.
import type { Check, Finding } from "../type/check.ts";
import { duration } from "../lib/format.ts";
import { readText, run } from "./sys.server.ts";

const FIREWALL: Check = {
  id: "firewall-off",
  title: "The host firewall is installed but not running",
  category: "security",
  severity: "major",
  weight: 82,
  mode: "scan",
  tier: "advisory",
  explanation:
    "No automatic fix. Enabling a firewall needs root and applies a default " +
    "deny policy immediately — that can drop a session you are working in. " +
    "Run `sudo ufw enable` yourself once you have checked the rules.",
  probe: async (): Promise<Finding | null> => {
    // ufw.conf, not systemd: `systemctl is-active` prints "inactive" for a
    // unit that does not exist, and ufw.service is a oneshot that reads
    // "active" even when ufw itself is disabled. `ENABLED` is ufw's own
    // switch — the one `ufw enable` flips — and the file is world-readable.
    const conf = await readText("/etc/ufw/ufw.conf");
    if (conf === null) return null; // ufw is not installed
    // Sourced as shell, so the last assignment wins.
    const enabled = [...conf.matchAll(/^\s*ENABLED\s*=\s*"?(\w*)"?\s*$/gm)]
      .at(-1)?.[1];
    if (enabled?.toLowerCase() === "yes") return null;
    return { detail: `ufw is installed but ENABLED=${enabled || "unset"}` };
  },
};

const UPDATES: Check = {
  id: "pending-updates",
  title: "Package updates are waiting to be installed",
  category: "settings",
  severity: "major",
  weight: 75,
  mode: "scan",
  tier: "advisory",
  explanation:
    "No automatic fix. Installing updates needs root, can restart services " +
    "and occasionally requires a reboot — none of which this app will start " +
    "while you are working. Run your updater when it suits you.",
  probe: async (): Promise<Finding | null> => {
    // A simulated upgrade: reads the package index, changes nothing, needs no
    // root. `Debug::NoLocking` keeps it from blocking behind a running apt.
    const r = await run(
      "apt-get",
      ["-s", "-q", "-o", "Debug::NoLocking=1", "upgrade"],
      25_000,
    );
    if (!r.ok) return null; // not an apt machine, or apt is busy
    const n = r.out.split("\n").filter((l) => l.startsWith("Inst ")).length;
    if (n === 0) return null;
    return {
      detail: `${n} package${n === 1 ? "" : "s"} can be upgraded`,
      severity: n >= 50 ? "major" : "minor",
    };
  },
};

const AUTO_UPDATES: Check = {
  id: "auto-updates-off",
  title: "Unattended security updates are switched off",
  category: "settings",
  severity: "minor",
  weight: 50,
  mode: "scan",
  tier: "advisory",
  explanation:
    "No automatic fix. The switch lives in /etc/apt/apt.conf.d and needs " +
    "root; turning it on also means packages will change while you are not " +
    "watching, which is your call to make.",
  probe: async (): Promise<Finding | null> => {
    const conf = await readText("/etc/apt/apt.conf.d/20auto-upgrades");
    // No apt on this machine — not applicable rather than "off".
    if (conf === null) {
      return (await readText("/etc/debian_version")) === null
        ? null
        : { detail: "20auto-upgrades is absent — nothing installs updates" };
    }
    const on = /Unattended-Upgrade\s+"1"/.test(conf);
    return on ? null : { detail: "Unattended-Upgrade is set to 0" };
  },
};

const INDEX_AGE: Check = {
  id: "package-index-stale",
  title: "The package index has not been refreshed recently",
  category: "settings",
  severity: "minor",
  weight: 28,
  mode: "scan",
  tier: "advisory",
  explanation:
    "No automatic fix. `apt update` needs root and hits the network; both are " +
    "decisions this app leaves to you. Until it runs, the machine cannot see " +
    "that newer packages exist.",
  probe: async (): Promise<Finding | null> => {
    const stamp = "/var/lib/apt/periodic/update-success-stamp";
    let at: number;
    try {
      at = (await Deno.stat(stamp)).mtime?.getTime() ?? 0;
    } catch {
      return null;
    }
    const age = Date.now() - at;
    if (at === 0 || age < 14 * 86_400_000) return null;
    return { detail: `last successful apt update was ${duration(age)} ago` };
  },
};

export const PACKAGE_CHECKS: Check[] = [
  FIREWALL,
  UPDATES,
  AUTO_UPDATES,
  INDEX_AGE,
];
