// `git config --global` checks — one per catalogue row, all auto-fixable.
//
// Tool-mediated on purpose: the fix runs `git config`, so nothing here parses
// or rewrites ~/.gitconfig. There is no file format to get wrong, and
// `--unset` is an exact undo for a key that was not there before.
import type { Check, Finding } from "../type/check.ts";
import type { GitPolicy } from "../type/policy.ts";
import { GIT_POLICIES } from "../lib/policy/git.ts";
import { run } from "./sys.server.ts";

/** `git config --global --get <key>`, or null when git is absent or the key
 *  is unset. The two are distinguished by asking whether git exists at all —
 *  no git means the whole family does not apply to this machine. */
async function gitGet(key: string): Promise<string | null | undefined> {
  const present = await run("git", ["--version"], 5_000);
  if (!present.ok) return undefined; // no git here
  const r = await run("git", ["config", "--global", "--get", key], 5_000);
  return r.ok ? r.out : null;
}

export function gitCheck(p: GitPolicy): Check {
  return {
    id: p.id,
    title: p.title,
    category: p.category,
    severity: p.severity,
    weight: p.weight,
    mode: "scan",
    tier: p.advisory === undefined ? "fix" : "advisory",
    explanation: p.advisory ??
      `Runs \`git config --global ${p.key} ${p.safe}\`. ${p.because} No file ` +
        `is edited by hand, no repository is touched, and Undo restores the ` +
        `previous value (or removes the key if there was none).`,
    probe: async (): Promise<Finding | null> => {
      const current = await gitGet(p.key);
      if (current === undefined) return null; // git not installed
      if (current === null && !p.missingIsBad) return null;
      if (current !== null && current === p.safe) return null;

      const detail = `${p.detail} (${p.key} = ${current ?? "unset"})`;
      // An advisory row is only an issue when the key IS set — its whole point
      // is that someone put a dangerous value there. `onlyWhen` narrows it to
      // the value that is actually dangerous, so a safe helper is not reported.
      if (p.advisory) {
        if (current === null) return null;
        if (p.onlyWhen && !current.includes(p.onlyWhen)) return null;
        return { detail };
      }

      return {
        detail,
        apply: async () => {
          const r = await run(
            "git",
            ["config", "--global", p.key, p.safe],
            5_000,
          );
          if (!r.ok) throw new Error(`git config --global ${p.key} failed`);
          return {
            summary: `git config --global ${p.key}: ${
              current ?? "unset"
            } -> ${p.safe}`,
            revert: async () => {
              const args = current === null
                ? ["config", "--global", "--unset", p.key]
                : ["config", "--global", p.key, current];
              const r = await run("git", args, 5_000);
              // An Undo that silently did nothing would be recorded as undone.
              if (!r.ok) throw new Error(`git ${args.join(" ")} failed`);
            },
          };
        },
      };
    },
  };
}

export const GIT_CHECKS: Check[] = GIT_POLICIES.map(gitCheck);
