// Policy rows — the catalogue's data shape. Zero dependencies, no closures:
// a row is a fact about how a machine should be configured, and a factory in
// `cell/check-*.server.ts` turns it into a Check. Growing the catalogue is
// adding rows, never adding code.
import type { Category, Severity } from "./issue.ts";

type Head = {
  /** Stable check id — it keys the UI rows and the fix log. */
  id: string;
  title: string;
  category: Category;
  severity: Severity;
  /** Tie-break inside a severity band — higher first. */
  weight: number;
};

/** How a measured value is judged wrong.
 *
 *  A string rather than a predicate so the catalogue stays data: `"true"` and
 *  `"false"` are booleans, `"=N"` / `"<N"` / `">N"` compare integers. */
export type Verdict =
  | "true"
  | "false"
  | `=${string}`
  | `<${string}`
  | `>${string}`
  /** The value CONTAINS this substring — for algorithm lists and option
   *  strings, where the problem is one weak entry among many. */
  | `~${string}`;

/** One desktop setting (gsettings/dconf) that should hold a given value. */
export type SettingPolicy = Head & {
  /** Candidate schemas, best first. The first one installed on the machine is
   *  used; none installed = this desktop, not an issue. */
  schemas: readonly string[];
  key: string;
  /** When the current value counts as the problem. */
  bad: Verdict;
  /** What the fix writes. */
  safe: string;
  /** The consequence, in the user's terms — the row's second line. */
  detail: string;
  /** Why `safe` is safe to write. Goes into the last column. */
  because: string;
  /** Set only when the setting must NOT be written automatically — the string
   *  is the reason, shown verbatim instead of a Fix button. Reserved for
   *  settings whose *effect* is destructive even though the write is not:
   *  switching on automatic deletion of the user's files, for one. */
  advisory?: string;
};

/** One path (or family of paths) that must not be readable or writable by
 *  other accounts. */
export type PermPolicy = Head & {
  /** `$HOME`-relative unless it starts with `/`. A trailing `/*` expands to
   *  the directory's direct children. */
  paths: readonly string[];
  /** The mode the path must not exceed. The fix intersects, never widens. */
  target: number;
  /** Bits that are the problem when present. */
  mask: number;
  /** Human phrase for the last column: "chmod 0600 on <what>". */
  what: string;
};

/** One `git config --global` key. Tool-mediated, so the fix never edits the
 *  file by hand. */
export type GitPolicy = Head & {
  key: string;
  safe: string;
  /** Whether an unset key is itself the problem. */
  missingIsBad: boolean;
  detail: string;
  because: string;
  /** Reported without a button; the string is the reason. Used where the key
   *  being SET is the problem and unsetting it would break what it was added
   *  for. */
  advisory?: string;
  /** Narrows an advisory row to one dangerous value. Without it the row fires
   *  on any value at all — which reports `credential.helper libsecret` as a
   *  problem when only `store` is one. */
  onlyWhen?: string;
};

/** How a configuration file spells `key value`. */
/** `space` — `Keyword value` (ssh_config, gpg.conf).
 *  `equals` — `key=value` (npmrc).
 *  `ini` — `key = value`, optionally under `[section]` (pip.conf, .wgetrc).
 *  `line` — the whole line is the setting (`set nomodeline` in a .vimrc). */
export type ConfFormat = "space" | "equals" | "ini" | "line";

/** One key in one user-owned configuration file.
 *
 *  The fix rewrites a single line and records the file's previous contents
 *  verbatim, so Undo is exact — including "the file did not exist". */
export type ConfPolicy = Head & {
  /** `$HOME`-relative path. */
  file: string;
  format: ConfFormat;
  /** INI section, when the format has them. */
  section?: string;
  key: string;
  /** The value the fix writes. `""` writes the key as a bare flag. */
  safe: string;
  /** An unset key is itself the problem. */
  missingIsBad: boolean;
  /** Invert the whole check: the key being SET is the problem, and the fix
   *  comments it out. For options that are only ever dangerous. */
  presentIsBad?: boolean;
  /** Only look at all if this binary is on PATH — a gpg.conf policy has no
   *  business creating a file on a machine without gpg. */
  needs?: string;
  detail: string;
  because: string;
  /** Reported without a button; the string is the reason. */
  advisory?: string;
};

/** One effective ssh client option, read via `ssh -G` and written into a
 *  trailing `Host *` block. */
export type SshPolicy = Head & {
  /** Canonical keyword spelling, e.g. `HashKnownHosts`. */
  key: string;
  bad: Verdict;
  safe: string;
  detail: string;
  because: string;
  advisory?: string;
};

/** One kernel parameter. Reported only — every remedy needs root. */
export type SysctlPolicy = Head & {
  key: string;
  bad: Verdict;
  safe: string;
  detail: string;
};

/** One Firefox or Thunderbird preference. */
export type MozPolicy = Head & {
  product: "firefox" | "thunderbird";
  /** Dotted pref name, as it appears in prefs.js and about:config. */
  pref: string;
  /** The application's own default, used when prefs.js does not mention the
   *  pref — absence means "the default is in force", not "off". */
  fallback: string;
  bad: Verdict;
  /** Written verbatim, so it must be a JS literal: `true`, `2`, `"text"`. */
  safe: string;
  detail: string;
  because: string;
};

/** One key in a system-wide configuration file under /etc.
 *
 *  Always reported, never written: every one of these needs root, and most of
 *  them change how a running service treats connections that already exist. */
export type EtcPolicy = Head & {
  /** Absolute path. A file that is absent means the service is not installed. */
  file: string;
  format: ConfFormat;
  section?: string;
  key: string;
  /** The value the row expects to find. */
  safe: string;
  /** Absence is itself the problem — the compiled-in default is the unsafe one. */
  missingIsBad: boolean;
  detail: string;
  /** What to do about it, in one sentence with the exact edit. */
  how: string;
};

/** One preference inside a Chromium-family browser profile. */
export type ChromiumPolicy = Head & {
  /** Dotted path inside the profile's `Preferences` JSON, or inside the
   *  browser-wide `Local State` when `localState` is set. */
  path: string;
  localState?: boolean;
  /** The browser's own default, used when the key is absent. */
  fallback: string;
  bad: Verdict;
  /** JSON source: `true`, `2`, `"text"`. */
  safe: string;
  detail: string;
  because: string;
};

/** Where a system reading comes from. */
export type SysSource =
  | { kind: "file"; path: string }
  | { kind: "cmd"; cmd: string; args: readonly string[]; needs?: string };

/** A root fix for a system reading, expressed as data rather than code.
 *
 *  The whole family is report-only by default, because a firewall rule, a
 *  mount option, a live service and a piece of hardware all share one property:
 *  changing them can take down something that is working right now, for a
 *  program this app cannot see.
 *
 *  A row may opt out of that default only by naming a drop-in — a file that
 *  belongs to Fixable, in a directory the system already merges, read the next
 *  time something reads it. That is the whole vocabulary: no command, no
 *  service to restart, no live state to poke. If a change cannot be expressed
 *  as a line in a drop-in, this family does not make it. */
export type SysRootFix = {
  /** Which drop-in carries it. Checked against the allow-list in lib/root.ts. */
  path: string;
  mode: string;
  /** The block written under this check's marker. */
  text: string;
  /** True when the change trades a capability away rather than repairing a
   *  fault — it keeps its button, but is filed under Optional and is never
   *  swept up by "Fix all (sudo required)". */
  optional?: boolean;
  /** What changed, past tense, for the fix log. */
  summary: string;
};

/** One reading taken from the running system — sysfs, procfs, or a tool.
 *
 *  Reported, and written only where `fix` says exactly how. Everything else in
 *  this family needs root, or reconfigures hardware, a filesystem or a live
 *  network path — the three places where a "fix" can take down something that
 *  is working. The app's job there is to notice and hand over the command. */
export type SysPolicy = Head & {
  source: SysSource;
  /** Pull the value out of a larger output. One capture group. */
  extract?: string;
  /** When the reading is the problem. Omit when `presentIsBad` decides. */
  bad?: Verdict;
  /** For a file source: the file EXISTING is the finding. */
  presentIsBad?: boolean;
  /** For a file source: the file being ABSENT is the finding. */
  missingIsBad?: boolean;
  detail: string;
  /** The remedy, with the exact command. */
  how: string;
  /** A drop-in that fixes it as root, when one exists that cannot disturb
   *  anything running. Absent on almost every row, and that is the default. */
  fix?: SysRootFix;
};
