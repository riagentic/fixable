// Reliability: whether the machine's own services are working, whether it is
// running the software it has installed, and whether its packages are intact.
import type { SysPolicy } from "../../../type/policy.ts";

const sh = (script: string) => ({
  kind: "cmd" as const,
  cmd: "sh",
  args: ["-c", script] as const,
});

export const SERVICE_POLICIES: SysPolicy[] = [
  {
    id: "svc-failed-system",
    title: "A system service has failed",
    category: "stability",
    severity: "major",
    weight: 86,
    source: sh("systemctl --failed --no-legend --plain 2>/dev/null | wc -l"),
    bad: ">0",
    detail:
      "something the machine is supposed to be running has stopped and stayed stopped",
    how:
      "`systemctl --failed` names them; `journalctl -u <unit> -b` says why. A failed unit is the most under-read signal on a Linux machine.",
  },
  {
    id: "svc-failed-user",
    title: "One of your own user services has failed",
    category: "stability",
    severity: "minor",
    weight: 56,
    source: sh(
      "systemctl --user --failed --no-legend --plain 2>/dev/null | wc -l",
    ),
    bad: ">0",
    detail:
      "a service belonging to your session is not running — usually the reason an application 'sometimes' does not work",
    how: "`systemctl --user --failed`, then `journalctl --user -u <unit> -b`.",
  },
  {
    id: "svc-restart-loop",
    title: "A service is restarting repeatedly",
    category: "stability",
    severity: "major",
    weight: 80,
    source: sh(
      "journalctl -b --no-pager 2>/dev/null | grep -ci 'Scheduled restart job, restart counter is at'",
    ),
    bad: ">20",
    detail:
      "a unit is crashing and being restarted in a loop, which burns CPU and fills the log while looking like nothing is wrong",
    how:
      "`journalctl -b | grep 'restart counter'` names it, then read that unit's log.",
  },
  {
    id: "svc-reboot-required",
    title: "The machine needs a reboot to finish an update",
    category: "stability",
    severity: "major",
    weight: 84,
    source: { kind: "file", path: "/var/run/reboot-required" },
    presentIsBad: true,
    detail:
      "updated packages are on disk while the running system still uses the old ones — including, often, the kernel with the security fix",
    how:
      "Reboot when convenient. `cat /var/run/reboot-required.pkgs` lists what is waiting.",
  },
  {
    id: "svc-kernel-stale",
    title: "A newer kernel is installed than the one running",
    category: "stability",
    severity: "major",
    weight: 83,
    source: sh(
      'r=$(uname -r); n=$(ls -1 /boot/vmlinuz-* 2>/dev/null | sed \'s#.*/vmlinuz-##\' | sort -V | tail -1); [ "$r" = "$n" ] && echo same || echo differ',
    ),
    bad: "~differ",
    detail:
      "the security fixes in the installed kernel are not in effect until the machine restarts",
    how: "Reboot. `uname -r` then shows the new version.",
  },
  {
    id: "svc-kernel-tainted",
    title: "The kernel is tainted",
    category: "stability",
    severity: "minor",
    weight: 44,
    source: { kind: "file", path: "/proc/sys/kernel/tainted" },
    bad: ">0",
    detail:
      "a proprietary or unsigned module is loaded, or the kernel has already hit an internal error — either way, its behaviour is no longer the one upstream tests",
    how:
      "`cat /proc/sys/kernel/tainted` and decode the bits in the kernel documentation. A graphics driver usually accounts for it; a `D` bit means it has already crashed once.",
  },
  {
    id: "svc-oom-kills",
    title: "The kernel has been killing programs to reclaim memory",
    category: "stability",
    severity: "major",
    weight: 82,
    source: sh(
      "journalctl -k -b --no-pager 2>/dev/null | grep -ci 'Out of memory: Killed process'",
    ),
    bad: ">0",
    detail:
      "the machine ran out of memory and chose a program to end — which is why something 'closed by itself'",
    how:
      "`journalctl -k -b | grep 'Out of memory'` names the victim. Add swap or zram so the machine slows down instead of killing things.",
  },
  {
    id: "svc-segfaults",
    title: "Programs are crashing repeatedly",
    category: "stability",
    severity: "minor",
    weight: 54,
    source: sh(
      "journalctl -b --no-pager 2>/dev/null | grep -ciE 'segfault|general protection fault'",
    ),
    bad: ">5",
    detail:
      "several crashes since boot, which points at a bad library, failing memory, or an overclock",
    how:
      "`journalctl -b | grep segfault` shows which program and which library. If it is spread across unrelated programs, test the memory (`memtest86+`).",
  },
  {
    id: "svc-time-unsync",
    title: "The system clock is not synchronised",
    category: "stability",
    severity: "major",
    weight: 78,
    source: sh("timedatectl show -p NTPSynchronized --value 2>/dev/null"),
    bad: "false",
    detail:
      "a drifting clock breaks TLS certificate validation, two-factor codes and every log correlation, and the errors it produces name none of those things",
    how:
      "`sudo timedatectl set-ntp true`, then check `timedatectl status`. If it stays false, the NTP port may be blocked.",
  },
  {
    id: "svc-dpkg-broken",
    title: "The package database is in a broken state",
    category: "stability",
    severity: "critical",
    weight: 90,
    source: sh("dpkg -C 2>/dev/null | wc -l"),
    bad: ">0",
    detail:
      "a package is half-configured or half-installed, and every future update will stop on it",
    how: "`sudo dpkg --configure -a`, then `sudo apt -f install`.",
  },
  {
    id: "svc-held-packages",
    title: "Packages are held back from updating",
    category: "stability",
    severity: "minor",
    weight: 50,
    source: sh("apt-mark showhold 2>/dev/null | wc -l"),
    bad: ">0",
    detail:
      "a held package never receives a security update, and the hold is usually forgotten long before it stops being needed",
    how:
      "`apt-mark showhold` lists them, `sudo apt-mark unhold <pkg>` releases one.",
  },
  {
    id: "svc-repo-http",
    title: "A software source is fetched over plain HTTP",
    category: "security",
    severity: "major",
    weight: 79,
    source: sh(
      "grep -rhE '^\\s*(deb|URIs:)' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -c 'http://'",
    ),
    bad: ">0",
    detail:
      "packages are downloaded over an unencrypted connection; signatures still protect integrity, but everyone on the path sees exactly what you install",
    how:
      "`grep -r 'http://' /etc/apt/sources.list*` and change to https where the mirror supports it.",
  },
  {
    id: "svc-repo-unsigned",
    title: "A software source is not signature-checked",
    category: "security",
    severity: "critical",
    weight: 94,
    source: sh(
      "grep -rhE '^\\s*deb' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -c 'trusted=yes'",
    ),
    bad: ">0",
    detail:
      "`trusted=yes` disables signature verification for that source, so anything it serves is installed as root without being checked",
    how:
      "Remove `trusted=yes` and import the repository's key properly into /etc/apt/keyrings.",
  },
  {
    id: "svc-release-eol",
    title: "This release is close to or past end of life",
    category: "security",
    severity: "critical",
    weight: 95,
    source: sh(
      "d=$(lsb_release -d 2>/dev/null); s=$(stat -c %Y /etc/os-release 2>/dev/null); echo $(( ( $(date +%s) - ${s:-0} ) / 86400 ))",
    ),
    bad: ">1400",
    detail:
      "an unsupported release stops receiving security updates entirely, and nothing on screen tells you it has happened",
    how:
      "Check your distribution's support dates and plan the upgrade. This is the single change with the largest security effect on an old machine.",
  },
  {
    id: "svc-unattended-health",
    title: "Unattended upgrades are configured but not running",
    category: "stability",
    severity: "major",
    weight: 76,
    source: sh(
      "if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then systemctl is-active unattended-upgrades 2>/dev/null; else echo skip; fi",
    ),
    bad: "~inactive",
    detail:
      "the machine is configured to install security updates by itself and the service that does it is not running",
    how:
      "`sudo systemctl enable --now unattended-upgrades`, then check `/var/log/unattended-upgrades/`.",
  },
];
