// Configuration-file checks — one per catalogue row, all auto-fixable.
//
// The rewrite is one line; the undo is the whole file, captured verbatim. See
// conf.server.ts for why that combination is the safe one.
import type { Check, Finding } from "../type/check.ts";
import type { ConfPolicy } from "../type/policy.ts";
import { disableKey, readKey, upsertKey } from "../lib/conf.ts";
import { has, home, readText } from "./sys.server.ts";
import {
  isSymlink,
  parentExists,
  restoreConf,
  writeConf,
} from "./conf.server.ts";
import { GNUPG_POLICIES } from "../lib/policy/gnupg.ts";
import { TOOL_POLICIES } from "../lib/policy/tools.ts";
import { TOOL2_POLICIES } from "../lib/policy/tools2.ts";
import { TOOL3_POLICIES } from "../lib/policy/tools3.ts";
import { join } from "@std/path";

export const CONF_POLICIES: ConfPolicy[] = [
  ...GNUPG_POLICIES,
  ...TOOL_POLICIES,
  ...TOOL2_POLICIES,
  ...TOOL3_POLICIES,
];

const shows = (p: ConfPolicy, value: string) =>
  p.safe === "" ? `${p.key} (set)` : `${p.key} = ${value}`;

export function confCheck(p: ConfPolicy): Check {
  const auto = p.advisory === undefined;
  const action = p.presentIsBad
    ? `Comments out \`${p.key}\` in ~/${p.file}`
    : `Sets \`${p.key}\` to \`${p.safe || "(on)"}\` in ~/${p.file}`;
  return {
    id: p.id,
    title: p.title,
    category: p.category,
    severity: p.severity,
    weight: p.weight,
    mode: "scan",
    tier: auto ? "fix" : "advisory",
    explanation: p.advisory ??
      `${action}. ${p.because} One line changes; the file's previous ` +
        `contents are recorded in full and Undo restores them exactly — and ` +
        `refuses if you have edited the file since.`,
    probe: async (): Promise<Finding | null> => {
      if (p.needs && !(await has(p.needs))) return null;
      const path = join(home(), p.file);
      const text = await readText(path);
      // Never build a directory tree to place a config file in.
      if (text === null && !(await parentExists(path))) return null;

      const current = text === null
        ? null
        : readKey(text, p.format, p.key, p.section);

      if (p.presentIsBad) {
        if (current === null) return null;
      } else {
        if (current === null && !p.missingIsBad) return null;
        if (
          current !== null && current.toLowerCase() === p.safe.toLowerCase()
        ) {
          return null;
        }
      }

      const detail = `${p.detail} (${
        current === null ? `${p.key} unset` : shows(p, current)
      })`;
      if (!auto) return { detail };
      // A linked dotfile (stow, a dotfiles repo) is reported without a button:
      // writeConf would refuse it anyway, and a Fix that can only fail is noise.
      if (await isSymlink(path)) {
        return {
          detail: `${detail} — ~/${p.file} is a symlink; edit it by hand`,
        };
      }

      return {
        detail,
        apply: async () => {
          const base = text ?? "";
          const next = p.presentIsBad
            ? disableKey(base, p.format, p.key, p.section)
            : upsertKey(base, p.format, p.key, p.safe, p.section);
          const write = await writeConf(path, next);
          // If the file moves on before this is undone — the next fix in a
          // "Fix all" run usually does exactly that — put back this one key
          // and leave every other line where it is.
          const narrow = (later: string) =>
            current === null
              ? disableKey(later, p.format, p.key, p.section)
              : upsertKey(later, p.format, p.key, current, p.section);
          return {
            summary: `${p.file}: ${p.key} ${
              current === null ? "unset" : `= ${current}`
            } -> ${p.presentIsBad ? "commented out" : p.safe || "(on)"}`,
            revert: restoreConf(write, narrow),
          };
        },
      };
    },
  };
}

export const CONF_CHECKS: Check[] = CONF_POLICIES.map(confCheck);
