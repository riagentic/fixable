// Kernel-parameter checks — one per catalogue row.
//
// Every one of these needs root, which used to mean every one of them was
// report-only. It no longer does: a kernel parameter Fixable is allowed to
// write is written as a block in its own drop-in under /etc/sysctl.d, which is
// additive (no file the distribution ships is edited), labelled (one block per
// check, so undo removes exactly one), and read at boot.
//
// Which parameters are allowed is not decided here. lib/policy/root-safe.ts
// holds the list and the reason for every refusal, and a test asserts the two
// cover the catalogue exactly — so a row added later cannot default into being
// writable, and a rename cannot quietly move one across the line.
//
// The drop-in is also applied immediately after it is written, but only for
// the allowed set: every member of it is either the value the distribution
// already ships or a ceiling going up, so applying it now cannot disturb a
// connection, a container or a program that is running. The refused ones are
// exactly the ones where that sentence would not be true.
import type { Check, Finding } from "../type/check.ts";
import type { SysctlPolicy } from "../type/policy.ts";
import { SYSCTL_POLICIES } from "../lib/policy/sysctl.ts";
import {
  SYSCTL_ROOT_DENIED,
  SYSCTL_ROOT_OPTIONAL,
  SYSCTL_ROOT_SAFE,
} from "../lib/policy/root-safe.ts";
import { isBad } from "../lib/verdict.ts";
import { readText } from "./sys.server.ts";

/** Read through `/proc/sys` rather than shelling out to `sysctl`: it is one
 *  file read instead of one subprocess, and a hundred checks run on every
 *  scan. */
const procPath = (key: string) => `/proc/sys/${key.replaceAll(".", "/")}`;

/** The one file this family writes. One drop-in for every kernel parameter
 *  rather than one per check: a hundred files in /etc/sysctl.d is a mess
 *  somebody has to clean up, and the blocks inside one file are already
 *  labelled well enough to undo individually. */
export const SYSCTL_DROPIN = "/etc/sysctl.d/99-fixable.conf";

export function sysctlCheck(p: SysctlPolicy): Check {
  const writable = SYSCTL_ROOT_SAFE.has(p.id);
  // Allowed, but a trade: it keeps its button and loses its place in the
  // batch, because a batch is where an unasked-for change would hide. The
  // string is what it costs, said before the button is pressed.
  const choice = SYSCTL_ROOT_OPTIONAL[p.id];
  const refused = SYSCTL_ROOT_DENIED[p.id];

  const read = async (): Promise<string | null> => {
    const raw = (await readText(procPath(p.key)))?.trim();
    return raw === undefined || raw === "" ? null : raw;
  };

  return {
    id: p.id,
    title: p.title,
    category: p.category,
    severity: p.severity,
    weight: p.weight,
    mode: "scan",
    tier: writable
      ? (choice !== undefined ? "optional-sudo" : "sudo")
      : "advisory",
    explanation: writable
      ? (choice !== undefined ? `${choice} ` : "") +
        `Writes \`${p.key} = ${p.safe}\` into ${SYSCTL_DROPIN} — a file that ` +
        `belongs to this app, so nothing the system ships is edited — and ` +
        `applies it. Needs the root password; Undo removes that one line ` +
        `again and puts the previous value back.`
      : `No automatic fix. ${refused ?? ""} Set it yourself if you want it, ` +
        `with \`sudo sysctl -w ${p.key}=${p.safe}\`, and make it survive a ` +
        `reboot by adding \`${p.key} = ${p.safe}\` to ` +
        `/etc/sysctl.d/99-local.conf.`,
    probe: async (): Promise<Finding | null> => {
      const raw = await read();
      if (raw === null) return null; // not on this kernel
      const verdict = isBad(p.bad, raw);
      if (verdict === null) {
        throw new Error(`${p.key}: cannot judge ${JSON.stringify(raw)}`);
      }
      if (!verdict) return null;
      const detail = `${p.detail} (${p.key} = ${raw})`;
      if (!writable) return { detail };
      return {
        detail,
        root: {
          changes: [
            // The drop-in makes it survive a reboot; the live write makes it
            // true now, so the re-probe that follows the fix reports what
            // actually happened rather than what will happen eventually.
            {
              op: "line",
              path: SYSCTL_DROPIN,
              mode: "0644",
              id: p.id,
              text: `${p.key} = ${p.safe}`,
            },
            { op: "sysctl", key: p.key, value: p.safe, was: raw },
          ],
          summary: `${p.key}: ${raw} → ${p.safe}`,
        },
      };
    },
  };
}

export const SYSCTL_CHECKS: Check[] = SYSCTL_POLICIES.map(sysctlCheck);
