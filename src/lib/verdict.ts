// Evaluating a policy's `bad` clause against a measured value. Pure — no aio,
// no Deno — because this is the one piece of logic every catalogue row runs
// through, and a wrong answer here is a wrong verdict on someone's machine.
import type { Verdict } from "../type/policy.ts";

/** Every spelling of a boolean this catalogue meets.
 *
 *  `gsettings` says `true`/`false`, `ssh -G` says `yes`/`no` — and mixes the
 *  two in one output, since some options are tri-state internally. `.wgetrc`
 *  says `on`/`off`. One parser, because a policy row should describe the
 *  setting, not the dialect its tool happens to print. */
const TRUE = new Set(["true", "yes", "on", "1", "enabled"]);
const FALSE = new Set(["false", "no", "off", "0", "disabled"]);

export const asBool = (raw: string): boolean | null => {
  const v = raw.trim().toLowerCase();
  return TRUE.has(v) ? true : FALSE.has(v) ? false : null;
};

/** GVariant prints its type first: `uint32 900`, `int64 -5`, `uint16 0`. The
 *  prefix has to be dropped before the number is read — a naive "first digits"
 *  match reads `uint32 0` as **32**, and every integer policy on the machine
 *  then judges the wrong number. */
const TYPE_PREFIX = /^(?:u?int(?:16|32|64)|byte|double|handle)\s+/;

export const asInt = (raw: string): number | null => {
  const m = raw.replace(TYPE_PREFIX, "").match(/^-?\d+/);
  return m ? Number(m[0]) : null;
};

/** Does `raw` satisfy the `bad` clause?
 *
 *  `null` means "cannot tell" — a boolean clause against a non-boolean value,
 *  or a numeric clause against something with no number in it. That is never
 *  silently read as "fine": the caller turns it into an unmeasured check. */
export function isBad(bad: Verdict, raw: string): boolean | null {
  if (bad === "true" || bad === "false") {
    const b = asBool(raw);
    return b === null ? null : b === (bad === "true");
  }
  if (bad[0] === "~") {
    return raw.toLowerCase().includes(bad.slice(1).toLowerCase());
  }
  const n = asInt(raw);
  const limit = Number(bad.slice(1));
  if (n === null || !Number.isFinite(limit)) return null;
  return bad[0] === "=" ? n === limit : bad[0] === "<" ? n < limit : n > limit;
}

/** Would writing `safe` actually clear the `bad` clause?
 *
 *  A row whose safe value is itself bad would produce a Fix button that runs,
 *  changes the setting, and leaves the issue standing. The catalogue test calls
 *  this on every row so that row can never ship. */
export const clears = (bad: Verdict, safe: string): boolean =>
  isBad(bad, safe) === false;
