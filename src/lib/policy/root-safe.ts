// The audit for the root tier: which kernel parameters Fixable may write, and
// the reason every other one is refused.
//
// The sudo tier exists because "it needs root" was never a good reason to make
// somebody read a command out of a table and retype it. It is not a reason to
// relax anything else. So every row that gets a root fix has to pass the same
// question the auto tier passes, plus one more that only matters here:
//
//     If this lands at the next boot, what stops working?
//
// A parameter is allowed only when the answer is "nothing", and only for one
// of two reasons:
//
//   * it is the value the mainstream distributions already ship, so a machine
//     that has it is the normal machine, not an experiment; or
//   * it raises a ceiling — a buffer, a table, a watch count — which can make
//     something that was failing start working and cannot make anything that
//     works stop.
//
// Everything else is refused BY NAME below, with what it would break. Three
// kinds of refusal turn up again and again, and they are worth naming because
// they are the ones a "hardening guide" will happily tell you to apply:
//
//   1. It breaks containers and sandboxes. Turning off user namespaces, IP
//      forwarding or IPv6 forwarding does not harden a workstation; it stops
//      Docker, podman, libvirt, Flatpak and every Chromium- or Electron-based
//      application from working, mostly without saying why.
//   2. It breaks the network on a machine that moves. Reverse-path filtering
//      and disabling router advertisements are correct on a server with one
//      static route and wrong on a laptop with a VPN, a dock and a phone
//      hotspot — which is the machine this app runs on.
//   3. It breaks development tools. ptrace scoping, perf paranoia and
//      unprivileged BPF are the switches that turn `gdb -p`, `perf top` and
//      `bpftrace` into permission errors.
//
// The list is checked against the catalogue by a test: every kernel-parameter
// row is either allowed here or refused here, so a row added later cannot
// quietly default into either.

const allow = (...ids: string[]): string[] => ids;

/** Distribution defaults. A machine reporting one of these has drifted from
 *  what its own vendor ships; putting it back is the least surprising change
 *  this app can make, and every one of them is a value the software on this
 *  machine was built and tested against. */
const DEFAULTS = allow(
  "sysctl-kptr",
  "sysctl-dmesg",
  "sysctl-randomize-va",
  "sysctl-core-uses-pid",
  "sysctl-printk-console",
  "sysctl-protected-hardlinks",
  "sysctl-protected-symlinks",
  "sysctl-protected-fifos",
  "sysctl-protected-regular",
  "sysctl-suid-dumpable",
  "sysctl-mmap-min-addr",
  "sysctl-userfaultfd",
  "sysctl-overcommit-memory",
  "sysctl-route-localnet",
  "sysctl-proxy-arp",
  "sysctl-accept-local",
  "sysctl-bootp-relay",
  "sysctl-icmp-echo-all",
  "sysctl-tcp-abort-overflow",
  "sysctl-tcp-syncookies",
  "sysctl-icmp-broadcast",
  "sysctl-qdisc",
  "sysctl-tcp-tw-reuse",
);

/** Legacy routing behaviour. ICMP redirects and source routing are how a
 *  machine on the same network as you rewrites your routing table; neither has
 *  a use on a workstation, and no current software asks for them. Turning them
 *  off changes nothing that is running, because nothing running uses them. */
const LEGACY_ROUTING = allow(
  "sysctl-accept-redirects",
  "sysctl-secure-redirects",
  "sysctl-send-redirects",
  "sysctl-source-route",
  "sysctl-ipv6-redirects",
  "sysctl-default-accept-redirects",
  "sysctl-default-send-redirects",
  "sysctl-default-source-route",
  "sysctl-ipv6-default-redirects",
  "sysctl-ipv6-default-source-route",
  "sysctl-icmp-redirect-secure-def",
  "sysctl-bogus-icmp",
  "sysctl-tcp-rfc1337",
);

/** Ceilings. Every one of these is a number going UP, which is the one kind of
 *  change that cannot take a capability away: a program that fits under the
 *  old limit still fits under the new one. These are also the parameters
 *  behind the most common "it just stopped working" on a developer machine —
 *  an editor that runs out of inotify watches, a server that cannot accept,
 *  a runtime that cannot map. */
const CEILINGS = allow(
  "sysctl-inotify-watches",
  "sysctl-inotify-instances",
  "sysctl-file-max",
  "sysctl-aio-max",
  "sysctl-pid-max",
  "sysctl-max-map-count",
  "sysctl-tcp-max-syn",
  "sysctl-somaxconn",
  "sysctl-netdev-backlog",
  "sysctl-rmem-max",
  "sysctl-wmem-max",
  "sysctl-udp-rmem-min",
  "sysctl-netfilter-conntrack-max",
  "sysctl-neigh-gc-thresh",
);

/** Timers and probes that only change how patiently the stack waits. None of
 *  them refuses a connection that would otherwise have been made; they shorten
 *  a wait, free a table entry sooner, or find a path MTU that a silent router
 *  would otherwise have hidden. */
const TIMING = allow(
  "sysctl-tcp-keepalive-time",
  "sysctl-tcp-fin-timeout",
  "sysctl-nf-conntrack-timeout",
  "sysctl-tcp-mtu-probing",
  "sysctl-tcp-slow-start",
);

/** Logging and address selection — visible, reversible, and inert with respect
 *  to whether a connection succeeds. */
const OBSERVABLE = allow(
  "sysctl-log-martians",
  "sysctl-default-log-martians",
  "sysctl-tempaddr",
  "sysctl-tempaddr-default",
  "sysctl-ldisc-autoload",
);

/** Allowed, but a trade rather than a repair.
 *
 *  Each of these is the value the distribution ships AND takes something a
 *  person might be using: reading the kernel log without sudo, resolving
 *  kernel symbols in a profiler, loading a line discipline for an unusual
 *  serial device. They keep their button — being a choice is not a reason to
 *  make somebody retype a command — but they are filed under Optional and are
 *  never part of "Fix all (sudo required)".
 *
 *  This is the same distinction the preferences audit draws, applied to the
 *  tier that has a password behind it. Needing root and being a choice are
 *  different facts, and a row can be both. */
export const SYSCTL_ROOT_OPTIONAL: Record<string, string> = {
  "sysctl-dmesg":
    "Optional — this one costs you something. `dmesg` stops working for an " +
    "ordinary account, so reading the kernel log means `sudo dmesg` from " +
    "then on. On a machine you develop on that is a tool, not an exposure " +
    "you had forgotten about.",
  "sysctl-kptr":
    "Optional — this one costs you something. Kernel symbols stop resolving " +
    "for an unprivileged profiler, so `perf` and the tools built on it show " +
    "addresses instead of names unless they are run as root.",
  "sysctl-ldisc-autoload":
    "Optional — this one costs you something. A serial device that needs an " +
    "unusual line discipline loaded on demand stops working. That is rare, " +
    "and rare is not the same as nobody.",
};

/** Kernel-parameter checks Fixable will write, as a root drop-in. */
export const SYSCTL_ROOT_SAFE: ReadonlySet<string> = new Set([
  ...DEFAULTS,
  ...LEGACY_ROUTING,
  ...CEILINGS,
  ...TIMING,
  ...OBSERVABLE,
]);

const deny = (reason: string, ids: string[]): [string, string][] =>
  ids.map((id) => [id, reason]);

/** Why every other kernel-parameter row stays report-only. Each entry names
 *  what would stop working, not a category — a reason you cannot check is a
 *  reason nobody can argue with later. */
export const SYSCTL_ROOT_DENIED: Record<string, string> = Object.fromEntries([
  ...deny(
    "This would break containers and application sandboxes. Docker, podman, " +
      "libvirt, Flatpak, Chromium and every Electron application depend on " +
      "unprivileged user namespaces and on the kernel forwarding packets " +
      "between their virtual interfaces. Turning either off does not harden " +
      "a workstation — it stops that software from starting, usually without " +
      "saying why.",
    [
      "sysctl-userns",
      "sysctl-max-user-namespaces",
      "sysctl-ip-forward",
      "sysctl-ipv6-forward",
      "sysctl-forwarding-default",
    ],
  ),
  ...deny(
    "This would break the network on a machine that moves between them. " +
      "Reverse-path filtering and ARP hardening are right for a server with " +
      "one route and wrong for a laptop with a VPN, a dock, a bridge and a " +
      "phone hotspot: the return path is legitimately not the one the packet " +
      "arrived on, and the kernel silently drops it.",
    [
      "sysctl-rp-filter",
      "sysctl-default-rp-filter",
      "sysctl-arp-ignore",
      "sysctl-arp-announce",
      "sysctl-shared-media",
    ],
  ),
  ...deny(
    "This would break IPv6 autoconfiguration. Router advertisements are how " +
      "a machine gets an IPv6 address at all on nearly every network; " +
      "refusing them leaves you with no IPv6 connectivity, which shows up as " +
      "sites that hang rather than sites that fail.",
    [
      "sysctl-ipv6-ra",
      "sysctl-ipv6-default-ra",
      "sysctl-ipv6-autoconf",
      "sysctl-ipv6-router-solicit",
    ],
  ),
  ...deny(
    "This would break development tools. It is the switch that turns " +
      "`gdb -p`, `strace -p`, `perf`, `bpftrace` and the profilers built on " +
      "them into permission errors — on the machine you develop on, which is " +
      "not a trade this app will make for you.",
    [
      "sysctl-ptrace",
      "sysctl-perf-event",
      "sysctl-unprivileged-bpf",
      "sysctl-bpf-jit-harden",
      "sysctl-kptr-restrict-strict",
      "sysctl-io-uring",
    ],
  ),
  ...deny(
    "This would change what the machine does when something goes wrong — " +
      "panicking on a fault it would currently survive, or rebooting out from " +
      "under whatever you had not saved. A diagnostics app turning a warning " +
      "into a reboot is the wrong direction.",
    [
      "sysctl-panic-on-oops",
      "sysctl-panic-timeout",
      "sysctl-nmi-watchdog",
    ],
  ),
  ...deny(
    "This cannot be undone. The kernel accepts the value once and refuses to " +
      "take it back until the machine reboots, so the promise every other fix " +
      "here makes — press once to change it, press once to change it back — " +
      "would not hold.",
    ["sysctl-kexec", "sysctl-modules-autoload"],
  ),
  ...deny(
    "This would let ordinary programs take the ports your own services " +
      "listen on. Widening the ephemeral range down to 1024 means an outgoing " +
      "connection can be handed 5432 or 6379 first, and the database that " +
      "wanted it then cannot start — intermittently, and only sometimes.",
    ["sysctl-ip-local-port-range"],
  ),
  ...deny(
    "This is a performance trade, not a fault, and which side of it you want " +
      "depends on this machine's memory and disk. The row says what the value " +
      "is and what changing it buys, and leaves the choice where it belongs.",
    [
      "sysctl-swappiness",
      "sysctl-dirty-ratio",
      "sysctl-dirty-bg-ratio",
      "sysctl-vfs-cache-pressure",
      "sysctl-min-free-kbytes",
      "sysctl-watermark-scale",
      "sysctl-compaction-proactive",
      "sysctl-page-cluster",
      "sysctl-tcp-timestamps",
      "sysctl-tcp-syn-retries",
      "sysctl-tcp-orphan-retries",
      "sysctl-icmp-ratelimit",
    ],
  ),
  ...deny(
    "This is known to fail on networks that mangle or drop what it enables, " +
      "and the failure is a connection that hangs rather than one that " +
      "reports an error — the hardest kind to trace back to a setting.",
    ["sysctl-tcp-fastopen"],
  ),
  ...deny(
    "This asks for the value the kernel already uses, so applying it would " +
      "change nothing and claim to have fixed something.",
    ["sysctl-igmp-max"],
  ),
  ...deny(
    "This would take away a way out of a locked-up machine. The magic SysRq " +
      "keys are what turn a frozen desktop into a clean sync-and-reboot " +
      "instead of a held-down power button, and removing them buys very " +
      "little on a machine whose keyboard you are the one sitting at.",
    ["sysctl-sysrq"],
  ),
]);
