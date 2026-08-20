// Processor state: the published hardware vulnerabilities and their
// mitigations, plus the frequency policy that decides whether the machine is
// fast or quiet.
//
// The vulnerability rows read the kernel's own verdict. "Vulnerable" there is
// not a guess — it is the kernel saying this silicon is exposed and nothing is
// standing in the way.
import type { SysPolicy } from "../../../type/policy.ts";

const VULN = "/sys/devices/system/cpu/vulnerabilities";

/** [file, name, what it costs you, band, weight] */
const VULNS: [string, string, string, SysPolicy["severity"], number][] = [
  [
    "spectre_v1",
    "Spectre v1",
    "bounds-check bypass: one process can read another's memory through speculative execution",
    "critical",
    96,
  ],
  [
    "spectre_v2",
    "Spectre v2",
    "branch-target injection — the variant that reaches across privilege boundaries",
    "critical",
    95,
  ],
  [
    "meltdown",
    "Meltdown",
    "user code can read kernel memory directly",
    "critical",
    97,
  ],
  [
    "l1tf",
    "L1TF",
    "L1 terminal fault: data from another virtual machine or the host is readable",
    "critical",
    94,
  ],
  [
    "mds",
    "MDS",
    "microarchitectural data sampling — leaks from store buffers and fill buffers",
    "critical",
    93,
  ],
  [
    "tsx_async_abort",
    "TAA",
    "the TSX variant of the same sampling leak",
    "major",
    84,
  ],
  [
    "itlb_multihit",
    "iTLB multihit",
    "a guest can hang or crash the host outright",
    "major",
    83,
  ],
  [
    "srbds",
    "SRBDS",
    "special register buffer data sampling — leaks RDRAND output, which is key material",
    "critical",
    92,
  ],
  [
    "mmio_stale_data",
    "MMIO stale data",
    "memory-mapped IO returns another context's leftover data",
    "major",
    82,
  ],
  [
    "retbleed",
    "Retbleed",
    "return instructions are speculatively hijacked across privilege levels",
    "critical",
    91,
  ],
  [
    "spec_store_bypass",
    "Spectre v4",
    "speculative store bypass lets a read see data it should not",
    "major",
    81,
  ],
  [
    "spec_rstack_overflow",
    "Inception",
    "return-stack overflow on AMD, same class of cross-boundary leak",
    "major",
    80,
  ],
  [
    "gather_data_sampling",
    "Downfall",
    "AVX gather leaks data from other processes on the same core",
    "critical",
    90,
  ],
  [
    "reg_file_data_sampling",
    "RFDS",
    "register file data sampling on recent Atom cores",
    "major",
    79,
  ],
  [
    "ghostwrite",
    "GhostWrite",
    "an architectural bug that lets unprivileged code write arbitrary memory",
    "critical",
    98,
  ],
  [
    "indirect_target_selection",
    "ITS",
    "indirect branch targets are selected speculatively across boundaries",
    "major",
    78,
  ],
  [
    "old_microcode",
    "Old microcode",
    "the CPU is running firmware older than the mitigations it needs",
    "major",
    88,
  ],
  [
    "tsa",
    "TSA",
    "transient scheduler attack — timing leaks between sibling threads",
    "major",
    77,
  ],
  [
    "vmscape",
    "VMScape",
    "a guest can observe host state across the virtualisation boundary",
    "major",
    76,
  ],
];

const vulnRow = (
  [file, name, why, severity, weight]: (typeof VULNS)[number],
): SysPolicy => ({
  id: `cpu-vuln-${file.replaceAll("_", "-")}`,
  title: `The processor is exposed to ${name}`,
  category: "security",
  severity,
  weight,
  source: { kind: "file", path: `${VULN}/${file}` },
  bad: "~Vulnerable",
  detail: why,
  how: `Mitigation for this comes from a microcode update and a kernel that " +
      "applies it: keep the machine updated (\`sudo apt full-upgrade\`), " +
      "install \`intel-microcode\` or \`amd64-microcode\`, and reboot. If the " +
      "kernel command line carries \`mitigations=off\` or a per-bug \`=off\`, " +
      "that is what is disabling it — check /proc/cmdline.`,
});

/** Everything else about how the processor is being driven. */
const OTHER: SysPolicy[] = [
  {
    id: "cpu-governor-powersave",
    title: "Every core is pinned to the power-saving governor",
    category: "performance",
    severity: "minor",
    weight: 46,
    source: {
      kind: "file",
      path: "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
    },
    bad: "~powersave",
    detail:
      "the processor holds back clock speed even under full load, which shows up as everything feeling slightly slow",
    how:
      "On a desktop, `sudo cpupower frequency-set -g schedutil` (or `performance`) is the usual choice; on a laptop, powersave is often what you want. Make it permanent with the `cpufrequtils` package or a systemd unit.",
  },
  {
    id: "cpu-mitigations-off",
    title: "Kernel mitigations are disabled on the command line",
    category: "security",
    severity: "critical",
    weight: 99,
    source: { kind: "file", path: "/proc/cmdline" },
    bad: "~mitigations=off",
    detail:
      "every processor vulnerability mitigation above has been switched off wholesale, usually for benchmark numbers",
    how:
      "Remove `mitigations=off` from GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub, run `sudo update-grub`, and reboot. Expect to give back a few percent of performance for it.",
  },
  {
    id: "cpu-nosmt-check",
    title:
      "Simultaneous multithreading is on with a sampling vulnerability present",
    category: "security",
    severity: "minor",
    weight: 44,
    source: { kind: "file", path: `${VULN}/mds` },
    bad: "~SMT vulnerable",
    detail:
      "sibling threads share microarchitectural state, which is the path several of the leaks above take",
    how:
      "Disabling SMT halves your thread count and is rarely worth it on a personal machine. If this is a shared or multi-tenant host, `mitigations=auto,nosmt` on the kernel command line is the switch.",
  },
  {
    id: "cpu-thermal-pressure",
    title: "The processor is spending time above its thermal limit",
    category: "performance",
    severity: "major",
    weight: 58,
    source: {
      kind: "file",
      path:
        "/sys/devices/system/cpu/cpu0/thermal_throttle/package_throttle_count",
    },
    bad: ">0",
    detail:
      "the package has been slowed to stay within its temperature budget, which costs sustained performance",
    how:
      "This is dust, thermal paste or a fan, in that order of likelihood. Clean the vents first. `sensors` shows current temperatures.",
  },
];

export const CPU_POLICIES: SysPolicy[] = [...VULNS.map(vulnRow), ...OTHER];
