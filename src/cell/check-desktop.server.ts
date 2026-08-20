// Desktop-setting checks — one per catalogue row, all auto-fixable.
//
// This is the shape that makes a fix safe: one setting, one value, the old
// value recorded. Nothing is deleted, nothing is stopped, and Undo puts back
// exactly what was there.
import type { Check, Finding } from "../type/check.ts";
import type { SettingPolicy } from "../type/policy.ts";
import { isBad } from "../lib/verdict.ts";
import { gsGet, gsSet, pickSchema } from "./sys.server.ts";
import { LOCK_POLICIES } from "../lib/policy/lock.ts";
import { PRIVACY_POLICIES } from "../lib/policy/privacy.ts";
import { MEDIA_POLICIES } from "../lib/policy/media.ts";
import { SESSION_POLICIES } from "../lib/policy/session.ts";
import { FILEMGR_POLICIES } from "../lib/policy/filemgr.ts";
import { DESKTOP_EXTRA_POLICIES } from "../lib/policy/desktop-extra.ts";
import { DESKTOP3_POLICIES } from "../lib/policy/desktop3.ts";

export const SETTING_POLICIES: SettingPolicy[] = [
  ...LOCK_POLICIES,
  ...PRIVACY_POLICIES,
  ...MEDIA_POLICIES,
  ...SESSION_POLICIES,
  ...FILEMGR_POLICIES,
  ...DESKTOP_EXTRA_POLICIES,
  ...DESKTOP3_POLICIES,
];

/** One catalogue row becomes one check.
 *
 *  The schema is resolved on the machine the probe runs on, so the explanation
 *  can name the exact command the button will run — a Fix whose effect you
 *  cannot read beforehand is not a Fix anyone should press. */
export function settingCheck(p: SettingPolicy): Check {
  return {
    id: p.id,
    title: p.title,
    category: p.category,
    severity: p.severity,
    weight: p.weight,
    mode: "scan",
    tier: p.advisory === undefined ? "fix" : "advisory",
    explanation: p.advisory ??
      `Sets ${p.key} to ${p.safe}. ${p.because} One desktop setting changes; ` +
        `the previous value is recorded and Undo restores it.`,
    probe: async (): Promise<Finding | null> => {
      const schema = await pickSchema(p.schemas);
      if (!schema) return null; // not this desktop — not an issue
      const raw = await gsGet(schema, p.key);
      if (raw === null) return null; // key absent on this version
      const verdict = isBad(p.bad, raw);
      if (verdict === null) {
        // A value we cannot judge is not a value we call fine.
        throw new Error(
          `${schema} ${p.key}: cannot judge ${JSON.stringify(raw)}`,
        );
      }
      if (!verdict) return null;

      const detail = `${p.detail} (${p.key} = ${raw})`;
      if (p.advisory) return { detail };

      return {
        detail,
        explanation:
          `Runs \`gsettings set ${schema} ${p.key} ${p.safe}\`. ${p.because} ` +
          `The previous value (${raw}) is recorded and Undo restores it. ` +
          `Nothing is deleted and no program is stopped.`,
        apply: async () => {
          const { previous } = await gsSet(schema, p.key, p.safe);
          return {
            summary: `${schema} ${p.key}: ${previous ?? "unset"} -> ${p.safe}`,
            revert: previous === null ? undefined : async () => {
              await gsSet(schema, p.key, previous);
            },
          };
        },
      };
    },
  };
}

export const DESKTOP_CHECKS: Check[] = SETTING_POLICIES.map(settingCheck);
