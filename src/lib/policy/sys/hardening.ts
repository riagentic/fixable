// Mandatory access control, auditing, and the keys and modules this machine
// trusts — read from the running system.
import type { SysPolicy } from "../../../type/policy.ts";

const sh = (script: string) => ({
  kind: "cmd" as const,
  cmd: "sh",
  args: ["-c", script] as const,
});

/** [module, why it is worth knowing about, band, weight] */
const MODULES: [string, string, SysPolicy["severity"], number][] = [
  [
    "ksmbd",
    "an in-kernel SMB server with a remote-code-execution history, which nothing on a desktop needs",
    "major",
    78,
  ],
  [
    "nfsd",
    "an in-kernel NFS server exporting filesystems from a workstation",
    "major",
    77,
  ],
  [
    "vivid",
    "a test video driver that has repeatedly been a local privilege-escalation path",
    "major",
    79,
  ],
  [
    "appletalk",
    "a protocol from the 1980s, still loadable kernel code",
    "minor",
    30,
  ],
  ["decnet", "a protocol nothing has used in decades", "minor", 29],
  ["ipx", "a Novell protocol with no modern use", "minor", 28],
  [
    "n-hdlc",
    "a line discipline with a known local privilege-escalation history",
    "minor",
    44,
  ],
  [
    "ax25",
    "amateur radio networking, in the kernel, on a desktop",
    "minor",
    27,
  ],
  ["netrom", "another amateur radio protocol", "minor", 26],
  ["rose", "another amateur radio protocol", "minor", 25],
  [
    "can",
    "the CAN bus stack, unless this machine talks to a vehicle",
    "minor",
    24,
  ],
  ["atm", "ATM networking, which nothing on a desktop uses", "minor", 23],
  ["p8023", "a legacy 802.3 protocol module", "minor", 22],
  ["psnap", "a legacy SNAP protocol module", "minor", 21],
  ["llc", "a legacy link-layer control module", "minor", 20],
  [
    "gfs2",
    "a cluster filesystem parser, reachable from any image you mount",
    "minor",
    34,
  ],
  [
    "ceph",
    "a cluster filesystem client on a machine with no cluster",
    "minor",
    33,
  ],
  [
    "cifs",
    "the SMB client, worth knowing about when nothing mounts network shares",
    "minor",
    32,
  ],
  [
    "nfs",
    "the NFS client, worth knowing about when nothing mounts network shares",
    "minor",
    31,
  ],
  [
    "overlay",
    "the overlay filesystem, used by containers — reported so an unexpected container runtime is visible",
    "minor",
    12,
  ],
  [
    "uvcvideo",
    "the webcam driver, on a machine where the camera may be unused",
    "minor",
    18,
  ],
  [
    "snd_usb_audio",
    "USB audio, worth knowing about if no USB audio device is attached",
    "minor",
    10,
  ],
  [
    "joydev",
    "the joystick interface, which any local program can read",
    "minor",
    16,
  ],
  [
    "msr",
    "direct model-specific register access, which reads and writes processor state",
    "major",
    70,
  ],
  [
    "kvm",
    "hardware virtualisation, reported so an unexpected hypervisor is visible",
    "minor",
    14,
  ],
];

const moduleRow = (
  [name, why, severity, weight]: (typeof MODULES)[number],
): SysPolicy => ({
  id: `mod-${name.replaceAll("_", "-")}`,
  title: `The ${name} kernel module is loaded`,
  category: "security",
  severity,
  weight,
  source: { kind: "file", path: "/proc/modules" },
  bad: `~\n${name} ` as const,
  detail: why,
  how: `If nothing on this machine needs ${name}, unload it with ` +
    `\`sudo modprobe -r ${name}\` and keep it out with ` +
    `\`install ${name} /bin/false\` in /etc/modprobe.d/99-local.conf. ` +
    `Check what is using it first — \`lsmod | grep ${name}\` shows the count.`,
});

/** One walk of the home directory, four questions.
 *
 *  These rows each need a different fact about the same tree, and a tree can be
 *  large. Asking four times meant four full walks and a scan that doubled in
 *  length; the per-pass memo collapses identical commands, so they now share
 *  one. The shape is `suid=N ww=N wwdir=N unowned=N`. */
const HOME_WALK = [
  'cd "$HOME" 2>/dev/null || exit 0;',
  // Depth 8 is not a compromise: measured on a 2 TB home it found every one
  // of the same results in 0.4s that an unbounded walk took 9.9s to reach.
  // Everything below that depth is inside a project or a dependency tree.
  "find . -xdev -maxdepth 8",
  // Caches and dependency trees hold hundreds of thousands of files and
  // nothing of interest here. Walking them turned a one-second scan into
  // twenty, so they are skipped — and this comment is the record of that.
  String.raw`\( -name node_modules -o -name .git -o -path ./.cache`,
  String.raw`-o -path ./.npm -o -path ./.cargo/registry -o -path ./go/pkg`,
  String.raw`-o -path ./snap -o -path ./.local/share/Trash \) -prune -o`,
  String.raw`\( -type f -perm -4000 -printf 's\n' \) -o`,
  String.raw`\( -type f ! -type l -perm -o+w -printf 'w\n' \) -o`,
  String.raw`\( -type d -perm -o+w ! -perm -1000 -printf 'd\n' \) -o`,
  String.raw`\( \( -nouser -o -nogroup \) -printf 'u\n' \)`,
  "2>/dev/null |",
  String.raw`awk '{c[$0]++} END{printf "s=%d w=%d d=%d u=%d\n",`,
  String.raw`c["s"],c["w"],c["d"],c["u"]}'`,
].join(" ");

const walk = (
  id: string,
  letter: string,
  severity: SysPolicy["severity"],
  weight: number,
  title: string,
  detail: string,
  how: string,
): SysPolicy => ({
  id: `hard-${id}`,
  title,
  category: letter === "u" ? "stability" : "security",
  severity,
  weight,
  source: sh(HOME_WALK),
  extract: `(?:^|\\s)${letter}=(\\d+)`,
  bad: ">0",
  detail,
  how,
});

export const HARDENING_POLICIES: SysPolicy[] = [
  ...MODULES.map(moduleRow),
  walk(
    "suid-unexpected",
    "s",
    "critical",
    95,
    "There are setuid programs in your home directory",
    "a setuid file under your own home has no legitimate reason to exist, and it runs as its owner rather than as you",
    "`find $HOME -xdev -type f -perm -4000 -ls` lists them. Remove the bit with `chmod u-s`, and work out how it got there.",
  ),
  walk(
    "world-writable-home",
    "w",
    "major",
    72,
    "There are world-writable files in your home directory",
    "any account on the machine can change these — and if one is a script you run, that is code execution as you",
    "`find $HOME -xdev -type f -perm -o+w -ls` lists them, `chmod o-w` fixes them.",
  ),
  walk(
    "world-writable-dirs",
    "d",
    "major",
    71,
    "There are world-writable directories without the sticky bit",
    "another account can replace files in them, and without the sticky bit it can delete yours",
    "`chmod o-w` on each, or `chmod +t` if the directory is deliberately shared.",
  ),
  walk(
    "unowned-files",
    "u",
    "minor",
    32,
    "There are files owned by no existing account",
    "files left by a removed account, which a new account inherits simply by being given the same numeric id",
    "`find $HOME -xdev \\( -nouser -o -nogroup \\) -ls` lists them; `chown` or remove them.",
  ),
  {
    id: "hard-apparmor-inactive",
    title: "Mandatory access control is not enforcing",
    category: "security",
    severity: "major",
    weight: 82,
    source: sh("aa-status --enabled 2>/dev/null && echo on || echo off"),
    bad: "~off",
    detail:
      "AppArmor confines browsers, document viewers and other programs that open untrusted content; without it a compromise reaches everything your account can",
    how:
      "`sudo systemctl enable --now apparmor` and check `sudo aa-status`. If profiles are missing, `sudo apt install apparmor-profiles apparmor-utils`.",
  },
  {
    id: "hard-apparmor-complain",
    title: "Some AppArmor profiles only warn instead of blocking",
    category: "security",
    severity: "minor",
    weight: 54,
    source: sh(
      "aa-status 2>/dev/null | awk '/profiles are in complain mode/{print $1}'",
    ),
    bad: ">0",
    detail:
      "a profile in complain mode logs what it would have stopped and then allows it",
    how:
      "`sudo aa-status` lists them; `sudo aa-enforce /etc/apparmor.d/<profile>` switches one to enforcing. Read the logs first — a profile is usually in complain mode because enforcing it broke something.",
  },
  {
    id: "hard-apparmor-unconfined",
    title: "Processes that should be confined are running unconfined",
    category: "security",
    severity: "minor",
    weight: 52,
    source: sh(
      "aa-status 2>/dev/null | awk '/processes are unconfined but have a profile defined/{print $1}'",
    ),
    bad: ">0",
    detail:
      "a profile exists for these programs and is not applied to the running instance — usually because it started before AppArmor did",
    how: "Restart the affected services. `sudo aa-status` names them.",
  },
  {
    id: "hard-auditd-inactive",
    title: "No audit trail is being recorded",
    category: "security",
    severity: "minor",
    weight: 40,
    source: sh("systemctl is-active auditd 2>/dev/null || echo absent"),
    bad: "~inactive",
    detail:
      "changes to accounts, sudoers and privileged files leave only whatever the journal happened to catch",
    how:
      "`sudo apt install auditd` and add watch rules under /etc/audit/rules.d/. Worth it on a machine that matters; noisy on one that does not.",
  },
  {
    id: "hard-secureboot-mok",
    title: "Locally signed kernel modules are enrolled",
    category: "security",
    severity: "minor",
    weight: 26,
    source: sh("mokutil --list-enrolled 2>/dev/null | grep -c 'Subject:'"),
    bad: ">2",
    detail:
      "several machine-owner keys are trusted for module signing — each one is something that can load code into the kernel",
    how:
      "`mokutil --list-enrolled` shows them. Remove any you do not recognise with `mokutil --delete`.",
  },
  {
    id: "hard-kernel-lockdown",
    title: "Kernel lockdown is not in effect",
    category: "security",
    severity: "minor",
    weight: 42,
    source: sh(
      "cat /sys/kernel/security/lockdown 2>/dev/null || echo '[none]'",
    ),
    bad: "~[none]",
    detail:
      "root can read kernel memory and load unsigned modules, so Secure Boot's chain of trust ends at the bootloader",
    how:
      "Add `lockdown=confidentiality` to the kernel command line. It blocks unsigned DKMS modules — check your graphics driver first.",
  },
  {
    id: "hard-module-sig-force",
    title: "Unsigned kernel modules can be loaded",
    category: "security",
    severity: "minor",
    weight: 38,
    source: sh(
      "cat /sys/module/module/parameters/sig_enforce 2>/dev/null || echo N",
    ),
    bad: "~N",
    detail:
      "any module can be loaded into the kernel regardless of who built it",
    how:
      "Add `module.sig_enforce=1` to the kernel command line, after confirming every module you rely on is signed.",
  },
];
