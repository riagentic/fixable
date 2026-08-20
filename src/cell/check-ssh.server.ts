// SSH client checks — read through `ssh -G`, written into a trailing
// `Host *` block.
//
// `ssh -G` is the only honest way to read this: ssh_config is first-match-wins
// across Host blocks, includes, and the system-wide file, so parsing
// ~/.ssh/config would answer a different question than ssh does. `-G` prints
// exactly what ssh would use, and re-running it after the fix proves the change
// actually took effect rather than being shadowed by an earlier block.
import type { Check, Finding } from "../type/check.ts";
import type { SshPolicy } from "../type/policy.ts";
import { SSH_POLICIES } from "../lib/policy/ssh.ts";
import { upsertSshOption } from "../lib/conf.ts";
import { isBad } from "../lib/verdict.ts";
import { has, home, readText, run } from "./sys.server.ts";
import { restoreConf, writeConf } from "./conf.server.ts";
import { join } from "@std/path";

/** A name that resolves to nothing and matches no sensible `Host` block, so
 *  what comes back is the baseline every connection starts from. */
const BASELINE_HOST = "fixable-baseline.invalid";

/** Every effective option, lowercased keys — the shape `ssh -G` prints. */
async function effective(): Promise<Map<string, string> | null> {
  if (!(await has("ssh"))) return null;
  const r = await run("ssh", ["-G", BASELINE_HOST], 8_000);
  if (!r.ok) return null;
  const out = new Map<string, string>();
  for (const l of r.out.split("\n")) {
    const at = l.indexOf(" ");
    if (at > 0) out.set(l.slice(0, at).toLowerCase(), l.slice(at + 1).trim());
    else if (l.length > 0) out.set(l.toLowerCase(), "");
  }
  return out;
}

export function sshCheck(p: SshPolicy): Check {
  const auto = p.advisory === undefined;
  return {
    id: p.id,
    title: p.title,
    category: p.category,
    severity: p.severity,
    weight: p.weight,
    mode: "scan",
    tier: auto ? "fix" : "advisory",
    explanation: p.advisory ??
      `Adds \`${p.key} ${p.safe}\` to a \`Host *\` block at the END of ` +
        `~/.ssh/config. ${p.because} A trailing \`Host *\` applies only where ` +
        `nothing more specific already answered, so your per-host settings ` +
        `keep winning. The file's previous contents are recorded in full and ` +
        `Undo restores them exactly.`,
    probe: async (): Promise<Finding | null> => {
      const conf = await effective();
      if (!conf) return null; // no ssh on this machine
      const raw = conf.get(p.key.toLowerCase());
      if (raw === undefined) return null; // option unknown to this ssh
      const verdict = isBad(p.bad, raw);
      if (verdict === null) {
        throw new Error(`ssh ${p.key}: cannot judge ${JSON.stringify(raw)}`);
      }
      if (!verdict) return null;

      const detail = `${p.detail} (${p.key} = ${raw})`;
      if (!auto) return { detail };

      return {
        detail,
        apply: async () => {
          const path = join(home(), ".ssh", "config");
          const before = await readText(path);
          const write = await writeConf(
            path,
            upsertSshOption(before ?? "", p.key, p.safe),
          );
          return {
            summary: `ssh_config Host *: ${p.key} ${raw} -> ${p.safe}`,
            // A later fix appends to the same `Host *` block, so undo by
            // putting this one keyword back rather than rewriting the file.
            revert: restoreConf(
              write,
              (later) => upsertSshOption(later, p.key, raw),
            ),
          };
        },
      };
    },
  };
}

export const SSH_CHECKS: Check[] = SSH_POLICIES.map(sshCheck);
