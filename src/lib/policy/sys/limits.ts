// Resource limits — the ceilings that turn "the machine is busy" into "the
// program failed with an error that names none of this".
//
// This is the family where a root fix is least arguable. Every raised ceiling
// here can only make a program that was failing start working: a process that
// fitted under the old limit fits under the new one, so nothing that runs
// today runs differently tomorrow. They land in one drop-in under
// /etc/security/limits.d, which PAM reads at the next login — nothing is
// signalled and no session changes underneath itself.
//
// Lowering a ceiling is a different thing and is marked `optional`: core dumps
// at zero is a privacy win and the loss of every crash report a developer
// might have wanted.
import type { SysPolicy, SysRootFix } from "../../../type/policy.ts";

const LIMITS = "/etc/security/limits.d/99-fixable.conf";

/** A line in the limits drop-in. `*` is every account: these are ceilings, and
 *  a ceiling that applies to one login and not the next is a bug report
 *  nobody can reproduce. */
const limit = (
  what: string,
  value: string,
  summary: string,
  optional?: boolean,
): SysRootFix => ({
  path: LIMITS,
  mode: "0644",
  text: `* ${what} ${value}`,
  summary,
  optional,
});

const sh = (script: string) => ({
  kind: "cmd" as const,
  cmd: "sh",
  args: ["-c", script] as const,
});

/** [id, ulimit flag, minimum, band, weight, title, detail, how, fix?] */
const ULIMITS: [
  string,
  string,
  number,
  SysPolicy["severity"],
  number,
  string,
  string,
  string,
  SysRootFix?,
][] = [
  // No fix, and the line is 1024, not higher. 1024 soft is deliberate:
  // select() cannot see a descriptor past 1023, so raising the soft limit
  // for everything breaks the programs still built on it, while the ones that
  // need more raise their own soft limit up to the hard ceiling. A soft limit
  // BELOW 1024 is the fault; the remedy is whatever lowered it.
  [
    "nofile-soft",
    "-Sn",
    1024,
    "major",
    72,
    "The open-file limit is below the standard 1024",
    "editors, browsers and language servers each hold hundreds of descriptors; at this ceiling they start failing with 'too many open files'",
    "Something lowered it: look for a `nofile` line in /etc/security/limits.conf and /etc/security/limits.d/, and remove it. Leave the soft limit at 1024 — programs that need more raise their own, up to the hard limit.",
  ],
  [
    "nofile-hard",
    "-Hn",
    65536,
    "minor",
    44,
    "The hard open-file ceiling is low",
    "no process can raise its own limit past this, however it is configured",
    "Set `* hard nofile 524288` in /etc/security/limits.conf.",
    limit("hard nofile", "524288", "open-file hard ceiling raised to 524288"),
  ],
  [
    "nproc-soft",
    "-Su",
    4096,
    "minor",
    42,
    "The process limit is low",
    "a parallel build or a container runtime can exhaust it, and the failure looks like a random fork error",
    "Set `* soft nproc 32768` in /etc/security/limits.conf.",
    limit("soft nproc", "32768", "process limit raised to 32768"),
  ],
  [
    "memlock",
    "-Sl",
    65536,
    "minor",
    40,
    "The locked-memory limit is low",
    "password managers, GPG and databases lock memory so secrets never reach swap; at a low ceiling they silently stop",
    "Set `* soft memlock unlimited` in /etc/security/limits.conf if you run a database, or 65536 for general use.",
    limit("soft memlock", "65536", "locked-memory limit raised to 64 MB"),
  ],
  [
    "stack",
    "-Ss",
    8192,
    "minor",
    24,
    "The stack limit is small",
    "deeply recursive programs crash rather than run",
    "Usually fine at 8 MB. Raise it only for a specific program that needs it.",
  ],
];

const ulimitRow = (
  [id, flag, min, severity, weight, title, detail, how, fix]:
    (typeof ULIMITS)[number],
): SysPolicy => ({
  id: `limit-${id}`,
  title,
  category: "stability",
  severity,
  weight,
  source: sh(
    `v=$(ulimit ${flag} 2>/dev/null); [ "$v" = unlimited ] && echo 999999999 || echo "$v"`,
  ),
  bad: `<${min}`,
  detail,
  how,
  fix,
});

export const LIMIT_POLICIES: SysPolicy[] = [
  ...ULIMITS.map(ulimitRow),
  {
    id: "limit-core-unlimited",
    title: "Core dumps are unlimited in size",
    category: "privacy",
    severity: "minor",
    weight: 46,
    source: sh(
      'v=$(ulimit -Sc 2>/dev/null); [ "$v" = unlimited ] && echo 999999999 || echo "$v"',
    ),
    bad: ">0",
    detail:
      "a crashing program can write its whole memory to disk, and that memory routinely holds keys and passwords",
    how:
      "Set `* soft core 0` in /etc/security/limits.conf, and `Storage=none` in /etc/systemd/coredump.conf.",
    // Optional, not automatic: a core dump holds keys and passwords, and it is
    // also the only evidence left behind when a program you care about
    // crashes. Which of those matters more is not this app's call.
    fix: limit("soft core", "0", "core dumps disabled", true),
  },
  {
    id: "limit-systemd-nofile",
    title: "The system-wide open-file ceiling is low",
    category: "stability",
    severity: "minor",
    weight: 48,
    // The HARD limit, and no fix. systemd ships 1024:524288 — a select()-safe
    // soft limit under a high ceiling services raise themselves to — and the
    // only drop-in that could raise the ceiling has to restate the soft half
    // too, overwriting whatever somebody chose for it.
    source: sh(
      'v=$(systemctl show -p DefaultLimitNOFILE --value 2>/dev/null); [ "$v" = infinity ] && echo 999999999 || echo "$v"',
    ),
    bad: "<524288",
    detail:
      "every service inherits this ceiling and cannot raise its own open-file limit past it",
    how:
      "Set `DefaultLimitNOFILE=1024:524288` (systemd's own default) in /etc/systemd/system.conf, or remove the line that lowered it, and reboot.",
  },
  {
    id: "limit-user-tasks",
    title: "The per-user task limit is low",
    category: "stability",
    severity: "minor",
    weight: 38,
    source: sh(
      "systemctl show user-$(id -u).slice -p TasksMax --value 2>/dev/null | grep -v infinity",
    ),
    bad: "<4096",
    detail:
      "your whole session shares this budget, so a parallel build can starve the desktop of threads",
    how: "Set `UserTasksMax=33%` in /etc/systemd/logind.conf.",
  },
  {
    id: "limit-cgroup-v1",
    title: "The machine is using the old control-group hierarchy",
    category: "stability",
    severity: "minor",
    weight: 36,
    source: sh("stat -fc %T /sys/fs/cgroup 2>/dev/null"),
    bad: "~tmpfs",
    detail:
      "cgroup v1 has no unified memory accounting, so per-application memory limits and the OOM handling built on them do not work properly",
    how:
      "Add `systemd.unified_cgroup_hierarchy=1` to the kernel command line. Check that your container runtime supports v2 first.",
  },
  {
    id: "limit-oom-daemon",
    title: "Nothing manages memory pressure before the kernel does",
    category: "stability",
    severity: "minor",
    weight: 52,
    source: sh(
      "systemctl is-active systemd-oomd earlyoom 2>/dev/null | grep -c active",
    ),
    bad: "=0",
    detail:
      "when memory runs out the kernel picks a program and kills it, with no warning and no preference — usually the largest one, which is usually the one you were using",
    how:
      "`sudo apt install earlyoom && sudo systemctl enable --now earlyoom`, or enable systemd-oomd. Either acts sooner and more predictably than the kernel's own killer.",
  },
  {
    id: "limit-zram-absent",
    title: "Compressed memory is not in use",
    category: "performance",
    severity: "minor",
    weight: 32,
    source: sh("grep -qc zram /proc/swaps 2>/dev/null && echo yes || echo no"),
    bad: "~no",
    detail:
      "swapping goes to disk instead of to compressed RAM, which is orders of magnitude slower exactly when the machine is already struggling",
    how:
      "`sudo apt install zram-config` (or systemd-zram-generator) and reboot.",
  },
  {
    id: "limit-thp-always",
    title: "Transparent huge pages are always on",
    category: "performance",
    severity: "minor",
    weight: 30,
    source: {
      kind: "file",
      path: "/sys/kernel/mm/transparent_hugepage/enabled",
    },
    bad: "~[always]",
    detail:
      "always-on huge pages cause latency spikes in databases and some virtual machines while helping little on a desktop",
    how:
      "`madvise` is the balanced setting: add `transparent_hugepage=madvise` to the kernel command line.",
  },
  {
    id: "limit-watches",
    title: "The file-watch limit is low for development work",
    category: "stability",
    severity: "major",
    weight: 68,
    source: { kind: "file", path: "/proc/sys/fs/inotify/max_user_watches" },
    bad: "<65536",
    detail:
      "editors, bundlers and sync tools each register thousands of watches; past the ceiling they fail with ENOSPC, which almost every tool reports as something else entirely",
    how:
      "`fs.inotify.max_user_watches=524288` in /etc/sysctl.d/99-local.conf, then `sudo sysctl --system`.",
  },
  {
    id: "limit-pid-max",
    title: "The process id space is small",
    category: "stability",
    severity: "minor",
    weight: 22,
    source: { kind: "file", path: "/proc/sys/kernel/pid_max" },
    bad: "<65536",
    detail: "a busy build or a container host can exhaust process ids",
    how: "`kernel.pid_max=4194304` in /etc/sysctl.d/99-local.conf.",
  },
];
