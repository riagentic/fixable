// System configuration under /etc.
//
// Read-only, always. Every row here needs root, and most of them restart a
// service that something is using right now — an SSH session, a print job, the
// resolver every open program is talking to. The app's job is to notice, to
// explain what the setting costs, and to hand over the exact edit.
//
// A file that does not exist means the service is not installed, which is the
// same answer as "not applicable" — the whole SSH-server family stays silent on
// a machine that does not accept SSH.
import type { Check, Finding } from "../type/check.ts";
import type { EtcPolicy } from "../type/policy.ts";
import { readFirstKey, readKey, sudoDefault } from "../lib/conf.ts";
import { readText } from "./sys.server.ts";
import { basename, dirname, isAbsolute, join } from "@std/path";
import { ETC_SSH_POLICIES } from "../lib/policy/etc-ssh.ts";
import { ETC_SYSTEM_POLICIES } from "../lib/policy/etc-system.ts";
import { ETC_HARDENING_POLICIES } from "../lib/policy/etc-hardening.ts";

export const ETC_POLICIES: EtcPolicy[] = [
  ...ETC_SSH_POLICIES,
  ...ETC_SYSTEM_POLICIES,
  ...ETC_HARDENING_POLICIES,
];

/** `Defaults` lines in sudoers, and a few others, repeat one keyword with
 *  different values — so for those the question is "what does sudo end up
 *  with for this option", not "what is the value of the keyword". */
const isFlagKey = (p: EtcPolicy) => p.key === "Defaults";

const SSHD = "/etc/ssh/sshd_config";

/** Does the effective sudo option satisfy `safe` (`flag` or `name=value`)?
 *  A numeric limit is met by anything from 0 up to it — a shorter sudo
 *  timeout is stricter, not a finding; a negative one never expires. */
const sudoSatisfied = (text: string, safe: string): boolean => {
  const [name, want] = safe.split("=", 2) as [string, string?];
  const got = sudoDefault(text, name);
  if (want === undefined) return got === true;
  if (typeof got !== "string") return false;
  if (/^\d+$/.test(want) && /^-?\d+$/.test(got)) {
    return Number(got) >= 0 && Number(got) <= Number(want);
  }
  return got === want;
};

/** Files matching one include argument, in the lexical order daemons use.
 *  Only the last path segment may hold wildcards (`sshd_config.d/*.conf`). */
async function glob(pattern: string): Promise<string[]> {
  const base = basename(pattern);
  if (!/[*?]/.test(base)) return [pattern];
  const re = new RegExp(
    `^${
      base.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")
        .replace(/\?/g, ".")
    }$`,
  );
  const dir = dirname(pattern);
  const names: string[] = [];
  try {
    for await (const e of Deno.readDir(dir)) {
      if (re.test(e.name) && !e.isDirectory) names.push(e.name);
    }
  } catch (e) {
    if (e instanceof Deno.errors.NotFound) return [];
    throw e;
  }
  return names.sort().map((n) => join(dir, n));
}

/** sshd_config as sshd reads it: each `Include` replaced by its files, in
 *  place, and every `Match` block dropped — those settings are conditional,
 *  and this row asks about the global value. A Match in an included file ends
 *  at that file's end. */
async function sshdText(path: string, depth = 0): Promise<string | null> {
  const text = await readText(path);
  if (text === null || depth > 8) return text;
  const out: string[] = [];
  let inMatch = false;
  for (const l of text.split("\n")) {
    if (/^\s*Match\s/i.test(l)) inMatch = true;
    if (inMatch) continue;
    const inc = l.match(/^\s*Include\s+(.+?)\s*$/i);
    if (!inc) {
      out.push(l);
      continue;
    }
    for (const arg of inc[1]!.split(/\s+/)) {
      const abs = isAbsolute(arg) ? arg : join("/etc/ssh", arg);
      for (const f of await glob(abs)) {
        out.push((await sshdText(f, depth + 1)) ?? "");
      }
    }
  }
  return out.join("\n");
}

/** sudoers with `@include`/`@includedir` (and their `#` spellings) spliced in.
 *  sudo skips includedir entries containing a `.` or ending in `~`. */
async function sudoersText(path: string, depth = 0): Promise<string | null> {
  const text = await readText(path);
  if (text === null || depth > 8) return text;
  const out: string[] = [];
  for (const l of text.split("\n")) {
    const inc = l.match(/^\s*[@#](include|includedir)\s+(.+?)\s*$/);
    if (!inc) {
      out.push(l);
      continue;
    }
    const arg = isAbsolute(inc[2]!) ? inc[2]! : join(dirname(path), inc[2]!);
    const files = inc[1] === "include"
      ? [arg]
      : (await glob(join(arg, "*"))).filter((f) =>
        !basename(f).includes(".") && !f.endsWith("~")
      );
    for (const f of files) out.push((await sudoersText(f, depth + 1)) ?? "");
  }
  return out.join("\n");
}

/** The file as its daemon sees it, or null when it is not installed. */
const load = (p: EtcPolicy): Promise<string | null> =>
  isFlagKey(p)
    ? sudoersText(p.file)
    : p.file === SSHD
    ? sshdText(p.file)
    : readText(p.file);

export function etcCheck(p: EtcPolicy): Check {
  return {
    id: p.id,
    title: p.title,
    category: p.category,
    severity: p.severity,
    weight: p.weight,
    mode: "scan",
    tier: "advisory",
    explanation:
      `No automatic fix: this file belongs to root, and changing it ` +
      `restarts or reconfigures a service that is running right now. ${p.how}`,
    probe: async (): Promise<Finding | null> => {
      try {
        (await Deno.open(p.file)).close();
      } catch (e) {
        // sudoers (0440) and audit rules (0640) are root-only by design, so
        // for a normal user these rows can never run. Reporting them as
        // "could not measure" on every scan would be permanent noise, not
        // information — they are silent unless the app runs as root. Only the
        // row's own file earns this: an unreadable INCLUDED file (a 0600
        // sshd_config.d drop-in) still fails the probe, since it may hold
        // the very setting asked about.
        if (e instanceof Deno.errors.PermissionDenied) return null;
        // Anything else (absent, …) is answered by the real read below.
      }
      const text = await load(p);
      if (text === null) return null; // not installed on this machine

      if (isFlagKey(p)) {
        return sudoSatisfied(text, p.safe)
          ? null
          : { detail: `${p.detail} (${p.safe} not set)` };
      }

      // sshd takes the FIRST value it meets; most other files, the last.
      const current = p.file === SSHD
        ? readFirstKey(text, p.format, p.key)
        : readKey(text, p.format, p.key, p.section);
      if (current === null) {
        return p.missingIsBad
          ? {
            detail:
              `${p.detail} (${p.key} not set — the built-in default applies)`,
          }
          : null;
      }
      if (current.toLowerCase() === p.safe.toLowerCase()) return null;
      return { detail: `${p.detail} (${p.key} = ${current})` };
    },
  };
}

export const ETC_CHECKS: Check[] = ETC_POLICIES.map(etcCheck);
