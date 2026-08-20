// File modes under /etc, and the PAM stack.
//
// These files belong to root, so nothing here can be fixed as your user. The
// modes are fixable with a password: taking a bit away from a file root owns
// cannot stop a program that is running — root reads these regardless, and a
// process that already has one open keeps it open — so a `chmod` that only
// ever narrows meets the same bar as an unattended fix, with a prompt in front
// of it. See lib/root.ts for what enforces "only ever narrows".
//
// The PAM stack and the forbidden files stay report-only, and would even if
// the app ran as root: a wrong line in a PAM file locks every account out of
// the machine at the next login, and deleting a file is not something this app
// does at any privilege level.
import type { Check, Finding } from "../type/check.ts";
import type { Severity } from "../type/issue.ts";
import { mode, octal, readText } from "./sys.server.ts";

/** [path, max mode, why, band, weight] */
const MODES: [string, number, string, Severity, number][] = [
  [
    "/etc/shadow",
    0o640,
    "the password hashes of every account on this machine",
    "critical",
    99,
  ],
  ["/etc/gshadow", 0o640, "group password hashes", "critical", 98],
  [
    "/etc/shadow-",
    0o640,
    "a backup copy of every password hash",
    "critical",
    97,
  ],
  [
    "/etc/gshadow-",
    0o640,
    "a backup copy of the group password hashes",
    "critical",
    96,
  ],
  [
    "/etc/passwd",
    0o644,
    "the account list — writable would mean anyone can add a root user",
    "critical",
    95,
  ],
  [
    "/etc/group",
    0o644,
    "group membership, which decides who is in sudo",
    "critical",
    94,
  ],
  [
    "/etc/sudoers",
    0o440,
    "the file that decides who may become root",
    "critical",
    93,
  ],
  [
    "/etc/sudoers.d",
    0o750,
    "the directory that decides who may become root",
    "critical",
    92,
  ],
  [
    "/etc/ssh/sshd_config",
    0o600,
    "the SSH server's configuration",
    "major",
    88,
  ],
  ["/etc/crontab", 0o600, "the system's scheduled commands", "major", 87],
  [
    "/etc/cron.d",
    0o700,
    "the directory of system scheduled commands",
    "major",
    86,
  ],
  ["/etc/cron.daily", 0o700, "scripts that run as root every day", "major", 85],
  [
    "/etc/cron.hourly",
    0o700,
    "scripts that run as root every hour",
    "major",
    84,
  ],
  [
    "/etc/cron.weekly",
    0o700,
    "scripts that run as root every week",
    "major",
    83,
  ],
  [
    "/etc/cron.monthly",
    0o700,
    "scripts that run as root every month",
    "major",
    82,
  ],
  ["/boot/grub/grub.cfg", 0o600, "the boot configuration", "minor", 55],
  ["/etc/ssh", 0o755, "the SSH server's configuration directory", "major", 81],
  ["/etc/passwd-", 0o644, "a backup copy of the account list", "major", 80],
  ["/etc/group-", 0o644, "a backup copy of group membership", "major", 79],
  [
    // 0775, NOT 0755. On a Debian or Ubuntu machine /var/log is
    // `drwxrwxr-x root syslog` and rsyslogd runs as the `syslog` user: the
    // group-write bit is what lets it create tomorrow's log and what lets
    // logrotate hand it a fresh one. Tightening to 0755 takes that away and
    // breaks logging — silently, and mostly at rotation time, which is the
    // worst possible moment to find out. The bit worth removing here is
    // world-WRITE, and that is the only one this ceiling removes.
    "/var/log",
    0o775,
    "the system logs — a world-writable log directory lets any account plant or truncate the record of what happened",
    "major",
    78,
  ],
];

const modeCheck = (
  [path, max, why, severity, weight]: (typeof MODES)[number],
): Check => ({
  id: `etcmode${path.replaceAll("/", "-")}`,
  title: `${path} is more open than it should be`,
  category: "security",
  severity,
  weight,
  mode: "scan",
  tier: "sudo",
  explanation:
    `Takes away the permission bits beyond \`${
      octal(max)
    }\` — nothing is added, so root keeps every access it has and anything ` +
    `already reading the file keeps reading it. Needs the root password; ` +
    `Undo puts the exact previous mode back.`,
  probe: async (): Promise<Finding | null> => {
    const m = await mode(path);
    if (m === null) return null; // not on this machine
    const bits = m & 0o7777;
    // Extra bits beyond the ceiling are the finding.
    if ((bits & ~max) === 0) return null;
    // Intersection, not the ceiling: a file already tighter than the ceiling
    // in some other bit stays tighter. This is what makes the op a narrowing
    // by arithmetic rather than by hope.
    const target = bits & max;
    return {
      detail: `${why} — mode is ${octal(bits)}, should be ${octal(target)}`,
      root: {
        changes: [
          { op: "chmod", path, mode: octal(target), was: octal(bits) },
        ],
        summary: `${path}: mode ${octal(bits)} → ${octal(target)}`,
      },
    };
  },
});

/** [id, file, module, arg, why, band, weight, how] */
const PAM: [
  string,
  string,
  string,
  string,
  string,
  Severity,
  number,
  string,
][] = [
  [
    "faillock",
    "/etc/pam.d/common-auth",
    "pam_faillock.so",
    "",
    "there is no limit on how many times a password can be guessed at this machine's login prompt",
    "major",
    81,
    "Add `auth required pam_faillock.so preauth silent deny=5 unlock_time=900` (and the matching authfail/account lines) to /etc/pam.d/common-auth.",
  ],
  [
    "pwquality",
    "/etc/pam.d/common-password",
    "pam_pwquality.so",
    "",
    "any password is accepted, including one character",
    "major",
    80,
    "Install libpam-pwquality and add `password requisite pam_pwquality.so retry=3 minlen=12` to /etc/pam.d/common-password.",
  ],
  [
    "pwhistory",
    "/etc/pam.d/common-password",
    "pam_pwhistory.so",
    "",
    "an old password can be set again immediately after being changed",
    "minor",
    52,
    "Add `password required pam_pwhistory.so remember=5` to /etc/pam.d/common-password.",
  ],
  [
    "umask",
    "/etc/pam.d/common-session",
    "pam_umask.so",
    "",
    "the login-time umask is not applied, so new files start world-readable",
    "major",
    79,
    "Add `session optional pam_umask.so` to /etc/pam.d/common-session and set UMASK 077 in /etc/login.defs.",
  ],
  [
    "limits",
    "/etc/pam.d/common-session",
    "pam_limits.so",
    "",
    "resource limits — including the one that stops core dumps — are not applied at login",
    "minor",
    51,
    "Add `session required pam_limits.so` to /etc/pam.d/common-session.",
  ],
  [
    "lastlog",
    "/etc/pam.d/login",
    "pam_lastlog.so",
    "",
    "you are not told about the previous login, which is the cheapest way to notice one you did not make",
    "minor",
    39,
    "Add `session optional pam_lastlog.so showfailed` to /etc/pam.d/login.",
  ],
];

const pamCheck = (
  [id, file, module, _arg, why, severity, weight, how]: (typeof PAM)[number],
): Check => ({
  id: `pam-${id}`,
  title: `PAM: ${
    module.replace(".so", "").replace("pam_", "")
  } is not configured`,
  category: "security",
  severity,
  weight,
  mode: "scan",
  tier: "advisory",
  explanation:
    `No automatic fix: a wrong line in a PAM file locks every account out of ` +
    `the machine, including yours, and the mistake is only visible at the next ` +
    `login. ${how} Keep a root shell open until you have tested it.`,
  probe: async (): Promise<Finding | null> => {
    const text = await readText(file);
    if (text === null) return null; // no PAM, or a different layout
    const present = text.split("\n").some((l) =>
      !l.trimStart().startsWith("#") && l.includes(module)
    );
    return present ? null : { detail: why };
  },
});

/** Files that must not exist at all. */
const FORBIDDEN: [string, string, Severity, number, string][] = [
  [
    "/etc/hosts.equiv",
    "host-based trust: any listed host is believed without a password",
    "critical",
    91,
    "Remove it with `sudo rm /etc/hosts.equiv` — nothing modern uses it.",
  ],
  [
    "/etc/cron.deny",
    "cron access is controlled by a deny list, which is open by default",
    "minor",
    38,
    "Use /etc/cron.allow instead: `sudo rm /etc/cron.deny` and list the accounts that may schedule jobs.",
  ],
  [
    "/etc/at.deny",
    "`at` access is controlled by a deny list, which is open by default",
    "minor",
    37,
    "Use /etc/at.allow instead.",
  ],
  [
    "/etc/securetty",
    "the list of terminals root may log in on is present",
    "minor",
    36,
    "An empty /etc/securetty stops root logging in on any console.",
  ],
];

const forbiddenCheck = (
  [path, why, severity, weight, how]: (typeof FORBIDDEN)[number],
): Check => ({
  id: `etcfile${path.replaceAll("/", "-")}`,
  title: `${path} exists`,
  category: "security",
  severity,
  weight,
  mode: "scan",
  tier: "advisory",
  explanation:
    `No automatic fix: this file belongs to root, and this app does ` +
    `not delete files. ${how}`,
  probe: async (): Promise<Finding | null> =>
    (await mode(path)) === null ? null : { detail: why },
});

export const ETC_PERM_CHECKS: Check[] = [
  ...MODES.map(modeCheck),
  ...PAM.map(pamCheck),
  ...FORBIDDEN.map(forbiddenCheck),
];
