// Things that are only true while the machine is running: services that are
// enabled, ports that are listening, hardware that is reporting a problem.
//
// Reported only. Stopping a service, closing a port or replacing a disk are
// all decisions with consequences this app cannot see from here.
import type { Check, Finding } from "../type/check.ts";
import type { Category, Severity } from "../type/issue.ts";
import { bytes } from "../lib/format.ts";
import { readText, run } from "./sys.server.ts";

/** [unit, why it matters on a workstation, band, weight] */
const SERVICES: [string, string, Severity, number][] = [
  [
    "sshd",
    "an SSH server accepts logins from the network on this machine",
    "major",
    78,
  ],
  [
    "ssh",
    "an SSH server accepts logins from the network on this machine",
    "major",
    78,
  ],
  ["telnet.socket", "telnet carries passwords in clear text", "critical", 99],
  ["rsh.socket", "rsh is unauthenticated remote execution", "critical", 98],
  [
    "vsftpd",
    "an FTP server is running, and FTP has no transport encryption",
    "critical",
    96,
  ],
  [
    "nfs-server",
    "an NFS server is exporting filesystems from this machine",
    "major",
    77,
  ],
  ["smbd", "a Windows file-sharing server is running", "major", 76],
  [
    "rpcbind",
    "the RPC port mapper is a long-standing amplification and enumeration target",
    "major",
    75,
  ],
  [
    "snmpd",
    "SNMP is running, and its default community strings are public knowledge",
    "major",
    74,
  ],
  ["apache2", "a web server is running on your workstation", "minor", 56],
  ["nginx", "a web server is running on your workstation", "minor", 55],
  ["mysql", "a database server is running and listening", "minor", 54],
  ["postgresql", "a database server is running and listening", "minor", 53],
  [
    "mongod",
    "a database server is running, and MongoDB's default is unauthenticated",
    "major",
    73,
  ],
  [
    "redis-server",
    "Redis is running, and its default is unauthenticated command execution",
    "major",
    72,
  ],
  [
    "memcached",
    "memcached is running, and it is the classic UDP amplification source",
    "major",
    71,
  ],
  [
    "docker",
    "the Docker daemon runs as root and its socket is equivalent to root",
    "minor",
    52,
  ],
  ["cups", "a print server is running whether or not you print", "minor", 40],
  [
    "avahi-daemon",
    "the machine advertises itself continuously on the local network",
    "minor",
    39,
  ],
  [
    "bluetooth",
    "Bluetooth is running, which is radio attack surface when unused",
    "minor",
    38,
  ],
  [
    "ModemManager",
    "the modem service runs on a machine with no modem",
    "minor",
    20,
  ],
  ["whoopsie", "Ubuntu's crash reporter uploads crash data", "minor", 37],
  ["apport", "the crash-report collector is active", "minor", 36],
  ["kerneloops", "kernel oops reports are collected and sent", "minor", 35],
  [
    "xrdp",
    "a remote desktop server accepts connections from the network",
    "critical",
    95,
  ],
  [
    "cockpit.socket",
    "a web administration console is listening, and it authenticates as a system user",
    "critical",
    94,
  ],
  ["tor", "a Tor relay or client is running as a system service", "minor", 34],
  [
    "dnsmasq",
    "a DNS server is running, and an open resolver is an amplification source",
    "major",
    65,
  ],
  ["bind9", "a DNS server is running on a workstation", "major", 64],
  ["slapd", "a directory server is running on a workstation", "major", 63],
  [
    "nfs-kernel-server",
    "an NFS server is exporting filesystems from this machine",
    "major",
    62,
  ],
  [
    "openvpn",
    "a VPN server or client runs unattended as a system service",
    "minor",
    33,
  ],
];

const serviceCheck = (
  [unit, why, severity, weight]: (typeof SERVICES)[number],
): Check => ({
  id: `svc-${unit}`,
  title: `The ${unit} service is enabled`,
  category: "security",
  severity,
  weight,
  mode: "scan",
  tier: "advisory",
  explanation:
    `No automatic fix: stopping a service needs root, and it takes away ` +
    `whatever is using it right now. If this machine does not need it, ` +
    `\`sudo systemctl disable --now ${unit}\` — check what depends on it first.`,
  probe: async (): Promise<Finding | null> => {
    const enabled = await run("systemctl", ["is-enabled", unit], 5_000);
    if (enabled.out === "" || enabled.out === "not-found") return null;
    if (enabled.out !== "enabled" && enabled.out !== "static") return null;
    const active = await run("systemctl", ["is-active", unit], 5_000);
    return { detail: `${why} (${active.out || "inactive"})` };
  },
});

/** Ports that should not be reachable from outside this machine. */
const LISTEN: [
  port: number,
  name: string,
  why: string,
  sev: Severity,
  w: number,
][] = [
  [22, "SSH", "remote login is reachable from the network", "major", 70],
  [
    23,
    "telnet",
    "clear-text remote login is reachable from the network",
    "critical",
    97,
  ],
  [
    21,
    "FTP",
    "clear-text file transfer is reachable from the network",
    "critical",
    95,
  ],
  [25, "SMTP", "a mail server is reachable from the network", "major", 69],
  [
    111,
    "rpcbind",
    "the RPC port mapper is reachable from the network",
    "major",
    68,
  ],
  [
    139,
    "NetBIOS",
    "Windows file sharing is reachable from the network",
    "major",
    67,
  ],
  [
    445,
    "SMB",
    "Windows file sharing is reachable from the network",
    "major",
    66,
  ],
  [631, "CUPS", "the print server is reachable from the network", "minor", 44],
  [3306, "MySQL", "a database is reachable from the network", "critical", 94],
  [
    5432,
    "PostgreSQL",
    "a database is reachable from the network",
    "critical",
    93,
  ],
  [
    6379,
    "Redis",
    "Redis is reachable from the network, and its default has no password",
    "critical",
    92,
  ],
  [27017, "MongoDB", "MongoDB is reachable from the network", "critical", 91],
  [
    11211,
    "memcached",
    "memcached is reachable from the network",
    "critical",
    90,
  ],
  [
    5900,
    "VNC",
    "a remote desktop is reachable from the network",
    "critical",
    89,
  ],
  [
    3389,
    "RDP",
    "a remote desktop is reachable from the network",
    "critical",
    88,
  ],
  [
    8080,
    "HTTP alternate",
    "a development server is reachable from the network",
    "minor",
    43,
  ],
  [
    9090,
    "HTTP alternate",
    "a development server is reachable from the network",
    "minor",
    42,
  ],
];

const listenCheck = (
  [port, name, why, severity, weight]: (typeof LISTEN)[number],
): Check => ({
  id: `port-${port}`,
  title: `Port ${port} (${name}) is listening on all interfaces`,
  category: "security",
  severity,
  weight,
  mode: "scan",
  tier: "advisory",
  explanation:
    `No automatic fix: closing a port means stopping or reconfiguring whatever ` +
    `opened it, and this app cannot tell what depends on it. Bind the service ` +
    `to 127.0.0.1 instead, or block the port at the firewall. ` +
    `\`sudo ss -ltnp 'sport = :${port}'\` names the process.`,
  probe: async (): Promise<Finding | null> => {
    // /proc/net/tcp is the dependency-free reading; 00000000 is 0.0.0.0 and
    // 0A is the LISTEN state.
    const raw = await readText("/proc/net/tcp");
    if (raw === null) return null;
    const hex = port.toString(16).toUpperCase().padStart(4, "0");
    const open = raw.split("\n").slice(1).some((l) => {
      const f = l.trim().split(/\s+/);
      const local = f[1] ?? "";
      return f[3] === "0A" && local.endsWith(`:${hex}`) &&
        !local.startsWith("0100007F"); // not 127.0.0.1
    });
    return open ? { detail: why } : null;
  },
});

/** Hardware and capacity signals that predict a bad day. */
const HEALTH: [
  id: string,
  title: string,
  cat: Category,
  sev: Severity,
  weight: number,
  explain: string,
  probe: () => Promise<Finding | null>,
][] = [
  [
    "swap-missing",
    "The machine has no swap at all",
    "resource",
    "minor",
    30,
    "No automatic fix: adding swap means creating a file or partition, which is a change to how the machine is laid out. `sudo fallocate -l 8G /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile` is the usual route, plus an /etc/fstab line.",
    async () => {
      const m = await readText("/proc/meminfo");
      if (m === null) return null;
      const total = Number(m.match(/^SwapTotal:\s+(\d+)/m)?.[1] ?? "0");
      return total === 0
        ? {
          detail:
            "under memory pressure the kernel has nowhere to go but the OOM killer, which ends whichever program it decides on",
        }
        : null;
    },
  ],
  [
    "zram-absent",
    "Compressed memory (zram) is not in use",
    "performance",
    "minor",
    12,
    "No automatic fix: enabling zram needs root and a service. `sudo apt install zram-config` on Debian-family systems is the whole job.",
    async () => {
      const swaps = await readText("/proc/swaps");
      if (swaps === null) return null;
      if (swaps.includes("zram")) return null;
      const m = await readText("/proc/meminfo");
      const total = Number(m?.match(/^SwapTotal:\s+(\d+)/m)?.[1] ?? "0");
      return total > 0
        ? {
          detail:
            "swap goes to disk rather than to compressed memory, which is orders of magnitude slower under pressure",
        }
        : null;
    },
  ],
  [
    "entropy-low",
    "The kernel entropy pool is depleted",
    "performance",
    "major",
    58,
    "No automatic fix. On modern kernels this is rare; if it persists, install `rng-tools` or check that the CPU's hardware random generator is enabled in firmware.",
    async () => {
      const avail = Number(
        (await readText("/proc/sys/kernel/random/entropy_avail"))?.trim() ??
          "9999",
      );
      return avail < 256
        ? {
          detail:
            `${avail} bits available — anything generating a key or a TLS session will block`,
        }
        : null;
    },
  ],
  [
    "thermal-throttle",
    "The processor is thermally throttled",
    "performance",
    "major",
    57,
    "No automatic fix: this is dust, thermal paste, or a fan. Clean the vents first; it is the cause more often than anything else.",
    async () => {
      const raw = await readText(
        "/sys/devices/system/cpu/cpu0/thermal_throttle/core_throttle_count",
      );
      const n = Number(raw?.trim() ?? "0");
      return n > 0
        ? {
          detail:
            `the processor has been slowed to stay cool ${n} times since boot`,
        }
        : null;
    },
  ],
  [
    "tmp-large",
    "/tmp holds a lot of data",
    "resource",
    "minor",
    19,
    "No automatic fix: this app does not delete files, and something in /tmp may be in use right now. A reboot clears it if /tmp is a tmpfs; otherwise look at what is there first.",
    async () => {
      const r = await run("du", ["-sx", "-B1", "/tmp"], 15_000);
      const size = Number(r.out.split(/\s+/)[0]);
      return r.ok && Number.isFinite(size) && size > 2 * 1024 ** 3
        ? { detail: `/tmp holds ${bytes(size)}` }
        : null;
    },
  ],
];

const healthCheck = (
  [id, title, category, severity, weight, explain, probe]: (typeof HEALTH)[
    number
  ],
): Check => ({
  id: `health-${id}`,
  title,
  category,
  severity,
  weight,
  mode: "scan",
  tier: "advisory",
  explanation: explain,
  probe,
});

export const RUNTIME_CHECKS: Check[] = [
  ...SERVICES.map(serviceCheck),
  ...LISTEN.map(listenCheck),
  ...HEALTH.map(healthCheck),
];
