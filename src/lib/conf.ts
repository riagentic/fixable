// Reading and rewriting `key value` configuration files, as pure text
// transforms. No aio, no Deno — which is what makes every one of these
// unit-testable, and it is the piece that must not be wrong: a config writer
// that mangles a file is exactly the kind of harm this app promises never to do.
import type { ConfFormat } from "../type/policy.ts";

const COMMENT = /^\s*[#;]/;

/** The `key value` separator, per format. `equals` is npmrc's tight spelling,
 *  `ini` is the spaced one that pip.conf and .wgetrc use, `space` is the
 *  keyword style of ssh_config and gpg.conf. */
const line = (fmt: ConfFormat, key: string, value: string): string =>
  fmt === "equals"
    ? `${key}=${value}`
    : fmt === "ini"
    ? `${key} = ${value}`
    : fmt === "line" || value === ""
    ? key
    : `${key} ${value}`;

/** Match one key line, capturing its value. Keywords are matched
 *  case-insensitively (ssh_config and gpg.conf both accept any casing) but
 *  written back in the policy's canonical spelling. */
const matcher = (fmt: ConfFormat, key: string): RegExp =>
  // `line` matches the whole setting and captures nothing — "is this line
  // here" is the entire question, which is how a shell rc or a .vimrc works.
  fmt === "line"
    ? new RegExp(`^(\\s*)${esc(key)}\\s*()$`)
    : fmt === "space"
    ? new RegExp(`^(\\s*)${esc(key)}(?:\\s+(.*?))?\\s*$`, "i")
    : new RegExp(`^(\\s*)${esc(key)}\\s*=\\s*(.*?)\\s*$`, "i");

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const sectionHead = (l: string) => l.match(/^\s*\[([^\]]+)\]\s*$/)?.[1];

/** Is this line inside `section`? `undefined` section means "anywhere". */
const inSection = (
  lines: string[],
  i: number,
  section: string | undefined,
): boolean => {
  if (section === undefined) return true;
  let current: string | undefined;
  for (let j = 0; j <= i; j++) {
    const head = sectionHead(lines[j] ?? "");
    if (head !== undefined) current = head;
  }
  return current === section;
};

/** The effective value of `key`, or null when it is not set.
 *
 *  The LAST occurrence wins, which is what gpg.conf and npmrc do. (ssh_config
 *  is first-wins and is never read through here — `ssh -G` answers for it.) */
export function readKey(
  text: string,
  fmt: ConfFormat,
  key: string,
  section?: string,
): string | null {
  const lines = text.split("\n");
  const re = matcher(fmt, key);
  for (let i = lines.length - 1; i >= 0; i--) {
    const l = lines[i]!;
    if (COMMENT.test(l) || !inSection(lines, i, section)) continue;
    const m = l.match(re);
    if (m) return (m[2] ?? "").trim();
  }
  return null;
}

/** Set `key` to `value`, replacing the last occurrence or appending.
 *
 *  Appending, never prepending: a file's existing lines keep their meaning and
 *  their order, and the diff is one line. */
export function upsertKey(
  text: string,
  fmt: ConfFormat,
  key: string,
  value: string,
  section?: string,
): string {
  const lines = text.split("\n");
  const re = matcher(fmt, key);
  for (let i = lines.length - 1; i >= 0; i--) {
    const l = lines[i]!;
    if (COMMENT.test(l) || !inSection(lines, i, section)) continue;
    if (re.test(l)) {
      lines[i] = line(fmt, key, value);
      return lines.join("\n");
    }
  }

  if (section !== undefined) {
    const at = lines.findIndex((l) => sectionHead(l) === section);
    if (at < 0) {
      return `${trimEnd(text)}\n\n[${section}]\n${line(fmt, key, value)}\n`;
    }
    // Append at the end of the section — after its last real line, not after
    // the blank line that separates it from whatever comes next.
    let end = lines.length;
    for (let j = at + 1; j < lines.length; j++) {
      if (sectionHead(lines[j] ?? "") !== undefined) {
        (end = j, j = lines.length);
      }
    }
    while (end > at + 1 && (lines[end - 1] ?? "").trim() === "") end--;
    lines.splice(end, 0, line(fmt, key, value));
    return lines.join("\n");
  }

  return `${trimEnd(text)}\n${line(fmt, key, value)}\n`;
}

/** Comment out every occurrence of `key`.
 *
 *  Commenting rather than deleting: the line that was there stays readable in
 *  the file, so a user who wonders what changed can see it, and the undo is a
 *  whole-file restore anyway. */
export function disableKey(
  text: string,
  fmt: ConfFormat,
  key: string,
  section?: string,
): string {
  const lines = text.split("\n");
  const re = matcher(fmt, key);
  return lines.map((l, i) =>
    !COMMENT.test(l) && inSection(lines, i, section) && re.test(l)
      ? `# disabled by Fixable: ${l.trim()}`
      : l
  ).join("\n");
}

const trimEnd = (s: string) => s.replace(/\s*$/, "");

// ------------------------------------------------------------------- ssh

const SSH_BANNER = "# Added by Fixable — safe to remove.";

/** Set an option for every host in an ssh_config, without overriding any
 *  per-host setting.
 *
 *  ssh_config is FIRST-match-wins. So:
 *
 *   1. If the key is already set globally — above the first block, or inside
 *      a `Host *` / `Match all` block — the first such line is the one ssh
 *      uses, and it is edited in place. Precedence stays exactly as it was.
 *   2. Otherwise it goes into a `Host *` block at the very END, the documented
 *      idiom: it applies only where nothing more specific already answered.
 *      An earlier `Host *` block is NOT reused — anything written there
 *      would beat every per-host block that follows it. */
export function upsertSshOption(
  text: string,
  key: string,
  value: string,
): string {
  const lines = text.split("\n");
  const setting = `    ${key} ${value}`;
  const isBlockStart = (l: string) => /^\s*(Host|Match)\s/i.test(l);
  const isGlobalBlock = (l: string) =>
    /^\s*Host\s+\*\s*$/i.test(l) || /^\s*Match\s+all\s*$/i.test(l);

  const re = matcher("space", key);
  let global = true; // top of file: before any block
  let last = -1; // start of the last block
  let hit = -1;
  lines.forEach((l, i) => {
    if (isBlockStart(l)) (global = isGlobalBlock(l), last = i);
    else if (hit < 0 && global && !COMMENT.test(l) && re.test(l)) hit = i;
  });

  if (hit >= 0) {
    lines[hit] = lines[hit]!.match(/^\s*/)![0] + `${key} ${value}`;
    return lines.join("\n");
  }
  if (last < 0 || !isGlobalBlock(lines[last]!)) {
    return `${trimEnd(text)}\n\n${SSH_BANNER}\nHost *\n${setting}\n`;
  }
  // Inside the trailing global block, after its last real line.
  let end = lines.length;
  while (end > last + 1 && (lines[end - 1] ?? "").trim() === "") end--;
  lines.splice(end, 0, setting);
  return lines.join("\n");
}

/** The FIRST value of `key` — sshd's rule, the opposite of `readKey`'s.
 *  `text` must already be flattened (includes spliced in, conditional blocks
 *  removed); this only answers "which line does the daemon see first". */
export function readFirstKey(
  text: string,
  fmt: ConfFormat,
  key: string,
): string | null {
  const re = matcher(fmt, key);
  for (const l of text.split("\n")) {
    if (COMMENT.test(l)) continue;
    const m = l.match(re);
    if (m) return (m[2] ?? "").trim();
  }
  return null;
}

// ----------------------------------------------------------------- sudo

/** The effective global value of one sudoers `Defaults` option: `true` for a
 *  set flag, `false` for a negated one (`!use_pty`), the value for
 *  `name=value`, or null when no plain `Defaults` line mentions it.
 *
 *  Parsed per entry, because substring matching lies three ways: a TAB after
 *  `Defaults` is valid, `timestamp_timeout=50` contains `=5`, and `!use_pty`
 *  contains `use_pty`. Later entries win, as in sudo. Scoped lines
 *  (`Defaults:alice`, `Defaults@host`, …) are not global and are skipped. */
export function sudoDefault(
  text: string,
  name: string,
): string | boolean | null {
  let out: string | boolean | null = null;
  const joined = text.replace(/\\\n/g, " "); // backslash continuations
  for (const l of joined.split("\n")) {
    const m = l.match(/^\s*Defaults\s+(.*)$/);
    if (!m) continue;
    for (const entry of splitEntries(m[1]!)) {
      const e = entry.match(/^(!*)\s*([A-Za-z_]+)\s*(?:[+-]?=\s*(.*))?$/);
      if (!e || e[2] !== name) continue;
      out = e[3] !== undefined
        ? e[3].trim().replace(/^"(.*)"$/, "$1")
        : e[1]!.length % 2 === 0;
    }
  }
  return out;
}

/** Split a Defaults list on commas outside double quotes, up to a comment. */
const splitEntries = (list: string): string[] => {
  const out: string[] = [];
  let cur = "", quoted = false;
  for (const ch of list) {
    if (ch === '"') quoted = !quoted;
    if (!quoted && ch === "#") break;
    if (!quoted && ch === ",") (out.push(cur.trim()), cur = "");
    else cur += ch;
  }
  out.push(cur.trim());
  return out.filter(Boolean);
};

// --------------------------------------------------------------- mozilla

const prefLine = (name: string, literal: string) =>
  `user_pref(${JSON.stringify(name)}, ${literal});`;

const prefMatcher = (name: string) =>
  new RegExp(
    `^\\s*user_pref\\(\\s*["']${esc(name)}["']\\s*,\\s*(.*?)\\s*\\)\\s*;\\s*$`,
  );

/** The literal a Mozilla prefs file assigns to `name`, or null when the file
 *  does not mention it — which means the application's own default is in
 *  force, not that the pref is off. */
export function readUserPref(text: string, name: string): string | null {
  const re = prefMatcher(name);
  const lines = text.split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    const m = lines[i]!.match(re);
    if (m) return m[1] ?? null;
  }
  return null;
}

/** Set a pref, replacing its line or appending one.
 *
 *  `literal` is written verbatim, so it must already be JS source: `true`,
 *  `2`, `"a string"`. That is how the file itself stores it, and rendering it
 *  any other way would produce a prefs file Firefox rewrites on next start. */
export function upsertUserPref(
  text: string,
  name: string,
  literal: string,
): string {
  const re = prefMatcher(name);
  const lines = text.split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    if (re.test(lines[i]!)) {
      lines[i] = prefLine(name, literal);
      return lines.join("\n");
    }
  }
  return `${trimEnd(text)}\n${prefLine(name, literal)}\n`;
}

/** Strip the quotes from a prefs literal, leaving numbers and booleans alone —
 *  so a policy row can talk about the value rather than its spelling. */
export const prefValue = (literal: string): string =>
  literal.length > 1 && /^["'].*["']$/.test(literal)
    ? literal.slice(1, -1)
    : literal;
