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
import { readKey } from "../lib/conf.ts";
import { readText } from "./sys.server.ts";
import { ETC_SSH_POLICIES } from "../lib/policy/etc-ssh.ts";
import { ETC_SYSTEM_POLICIES } from "../lib/policy/etc-system.ts";
import { ETC_HARDENING_POLICIES } from "../lib/policy/etc-hardening.ts";

export const ETC_POLICIES: EtcPolicy[] = [
  ...ETC_SSH_POLICIES,
  ...ETC_SYSTEM_POLICIES,
  ...ETC_HARDENING_POLICIES,
];

/** `Defaults` lines in sudoers, and a few others, repeat one keyword with
 *  different values — so for those the question is "does this value appear",
 *  not "what is the value". */
const isFlagKey = (p: EtcPolicy) => p.key === "Defaults";

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
      const text = await readText(p.file);
      if (text === null) return null; // not installed on this machine

      if (isFlagKey(p)) {
        const wanted = p.safe.toLowerCase();
        const present = text.split("\n").some((l) =>
          !l.trimStart().startsWith("#") &&
          l.toLowerCase().includes(`${p.key.toLowerCase()} `) &&
          l.toLowerCase().includes(wanted)
        );
        return present ? null : { detail: `${p.detail} (${p.safe} not set)` };
      }

      const current = readKey(text, p.format, p.key, p.section);
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
