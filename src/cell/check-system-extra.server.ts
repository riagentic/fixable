// Loaded kernel modules and mount options.
//
// Both families are reported only. Unloading a module or remounting a
// filesystem needs root, and both can take away something that is in use right
// now — a Bluetooth mouse, a running container, /tmp under an open editor.
// What the app can do is name the thing and hand over the exact command.
import type { Check, Finding } from "../type/check.ts";
import type { Severity } from "../type/issue.ts";
import { readText } from "./sys.server.ts";

/** [module, why it matters, band, weight] */
const MODULES: [string, string, Severity, number][] = [
  [
    "firewire-core",
    "FireWire gives any attached device direct memory access — the classic 'plug in and read RAM' attack",
    "major",
    76,
  ],
  [
    "firewire-ohci",
    "the FireWire host controller, same direct-memory-access exposure",
    "major",
    75,
  ],
  [
    "thunderbolt",
    "Thunderbolt devices get direct memory access unless IOMMU protection is on",
    "major",
    74,
  ],
  [
    "dccp",
    "an obscure transport protocol with a long history of kernel bugs and essentially no desktop use",
    "major",
    73,
  ],
  [
    "sctp",
    "a transport protocol almost no desktop uses, with kernel-level attack surface",
    "major",
    72,
  ],
  [
    "rds",
    "the Reliable Datagram Sockets protocol — datacentre-only, repeatedly exploitable",
    "major",
    71,
  ],
  [
    "tipc",
    "a cluster protocol with a recent history of remote kernel exploits",
    "major",
    70,
  ],
  [
    "cramfs",
    "a legacy filesystem parser reachable by plugging in a crafted image",
    "minor",
    48,
  ],
  [
    "freevxfs",
    "a legacy filesystem parser reachable by plugging in a crafted image",
    "minor",
    47,
  ],
  ["jffs2", "a flash filesystem parser almost no desktop needs", "minor", 46],
  [
    "hfs",
    "a legacy Mac filesystem parser reachable from removable media",
    "minor",
    45,
  ],
  [
    "hfsplus",
    "a Mac filesystem parser reachable from removable media",
    "minor",
    44,
  ],
  [
    "udf",
    "an optical-disc filesystem parser, reachable from any image you mount",
    "minor",
    43,
  ],
  [
    "ksmbd",
    "an in-kernel SMB server — remote code execution history, and nothing on a desktop needs it",
    "major",
    69,
  ],
  [
    "nfsd",
    "an in-kernel NFS server, exporting filesystems from a workstation",
    "major",
    68,
  ],
  [
    "squashfs",
    "a compressed filesystem parser reachable from any image you mount",
    "minor",
    42,
  ],
  [
    "vivid",
    "a test video driver that has repeatedly been a local privilege-escalation path",
    "major",
    67,
  ],
  [
    "bluetooth",
    "the Bluetooth stack — radio-reachable kernel code on a machine that may never pair anything",
    "minor",
    41,
  ],
  [
    "appletalk",
    "a protocol from the 1980s, still shipping as loadable kernel code",
    "minor",
    40,
  ],
  ["decnet", "another protocol nothing has used in decades", "minor", 39],
  ["ipx", "a Novell protocol with no modern use", "minor", 38],
  [
    "n-hdlc",
    "a line discipline with a known local privilege-escalation history",
    "minor",
    37,
  ],
  [
    "ax25",
    "amateur radio networking, in the kernel, on a desktop",
    "minor",
    36,
  ],
  [
    "can",
    "the CAN bus stack, unless this machine talks to a vehicle",
    "minor",
    35,
  ],
  ["atm", "ATM networking, which nothing on a desktop uses", "minor", 34],
  [
    "usb-storage",
    "USB mass storage — worth knowing about on a machine that never uses it",
    "minor",
    20,
  ],
];

const moduleCheck = (
  [name, why, severity, weight]: (typeof MODULES)[number],
): Check => ({
  id: `module-${name}`,
  title: `The ${name} kernel module is loaded`,
  category: "security",
  severity,
  weight,
  mode: "scan",
  tier: "advisory",
  explanation:
    `No automatic fix: unloading a module needs root and takes away whatever ` +
    `is using it right now. If nothing on this machine needs ${name}, run ` +
    `\`sudo modprobe -r ${name}\` and keep it out with a line reading ` +
    `\`install ${name} /bin/false\` in /etc/modprobe.d/99-local.conf.`,
  probe: async (): Promise<Finding | null> => {
    const mods = await readText("/proc/modules");
    if (mods === null) return null;
    const loaded = mods.split("\n").some((l) =>
      l.split(" ")[0]?.replaceAll("_", "-") === name.replaceAll("_", "-")
    );
    return loaded ? { detail: why } : null;
  },
});

/** [mount point, required option, why, band, weight] */
const MOUNTS: [string, string, string, Severity, number][] = [
  [
    "/dev/shm",
    "noexec",
    "shared memory is a writable, world-accessible place to drop and run a binary",
    "major",
    69,
  ],
  [
    "/dev/shm",
    "nosuid",
    "a setuid binary placed in shared memory would keep its privileges",
    "major",
    68,
  ],
  [
    "/dev/shm",
    "nodev",
    "device nodes in shared memory are a route around file permissions",
    "minor",
    42,
  ],
  [
    "/tmp",
    "noexec",
    "/tmp is the first place a downloaded payload lands, and it is writable by everyone",
    "major",
    67,
  ],
  [
    "/tmp",
    "nosuid",
    "a setuid binary in /tmp would keep its privileges",
    "major",
    66,
  ],
  [
    "/tmp",
    "nodev",
    "device nodes in /tmp are a route around file permissions",
    "minor",
    41,
  ],
  [
    "/var/tmp",
    "noexec",
    "/var/tmp is /tmp that survives a reboot",
    "minor",
    40,
  ],
  [
    "/var/tmp",
    "nosuid",
    "a setuid binary in /var/tmp would keep its privileges",
    "minor",
    39,
  ],
  [
    "/home",
    "nodev",
    "no user's home directory has any business holding a device node",
    "minor",
    50,
  ],
  [
    "/home",
    "nosuid",
    "a setuid binary under /home is a privilege-escalation waiting to be found",
    "major",
    62,
  ],
  [
    "/",
    "nosuid",
    "the root filesystem accepts setuid binaries anywhere on it",
    "minor",
    24,
  ],
  [
    "/home",
    "noexec",
    "programs can be run from any home directory — reported, since many workflows need it",
    "minor",
    23,
  ],
  [
    "/var",
    "nodev",
    "device nodes under /var have no legitimate use",
    "minor",
    22,
  ],
  [
    "/var/log",
    "nodev",
    "device nodes in the log directory have no legitimate use",
    "minor",
    21,
  ],
  [
    "/var/log",
    "nosuid",
    "a setuid binary in the log directory would keep its privileges",
    "minor",
    20,
  ],
  [
    "/var/log",
    "noexec",
    "the log directory is not a place programs should run from",
    "minor",
    19,
  ],
  [
    "/run",
    "nodev",
    "device nodes in the runtime directory have no legitimate use",
    "minor",
    18,
  ],
  [
    "/run",
    "nosuid",
    "a setuid binary under /run would keep its privileges",
    "minor",
    17,
  ],
  [
    "/boot",
    "nodev",
    "the boot partition should hold kernels, not device nodes",
    "minor",
    25,
  ],
];

const mountCheck = (
  [point, option, why, severity, weight]: (typeof MOUNTS)[number],
): Check => ({
  id: `mount${point.replaceAll("/", "-")}-${option}`,
  title: `${point} is mounted without ${option}`,
  category: "security",
  severity,
  weight,
  mode: "scan",
  tier: "advisory",
  explanation:
    `No automatic fix: remounting needs root, and adding ${option} to ` +
    `${point} can stop something that is running right now — a build in ` +
    `/tmp, a container, an installer. Add \`${option}\` to the ${point} line ` +
    `in /etc/fstab and apply it with \`sudo mount -o remount ${point}\` when ` +
    `the machine is quiet.`,
  probe: async (): Promise<Finding | null> => {
    const mounts = await readText("/proc/mounts");
    if (mounts === null) return null;
    const line = mounts.split("\n").find((l) => l.split(" ")[1] === point);
    if (!line) return null; // not a separate mount here
    const opts = (line.split(" ")[3] ?? "").split(",");
    return opts.includes(option) ? null : { detail: why };
  },
});

export const SYSTEM_EXTRA_CHECKS: Check[] = [
  ...MODULES.map(moduleCheck),
  ...MOUNTS.map(mountCheck),
];
