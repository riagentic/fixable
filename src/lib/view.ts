// The Auto / Sudo / Optional / Manual / All filter. Pure — no aio, no Deno.
import type { Issue, Tier, View } from "../type/issue.ts";
import { isOptionalTier, TIERS } from "../type/issue.ts";

export const VIEWS: readonly View[] = [
  "auto",
  "sudo",
  "optional",
  "manual",
  "all",
];

export const isView = (v: string): v is View =>
  (VIEWS as readonly string[]).includes(v);

/** The tiers each view shows. One mapping, used by the filter, the counter and
 *  the header's denominator, so a view cannot claim a number that disagrees
 *  with the rows under it.
 *
 *  Optional collects both of its tiers: whether a choice needs a password is
 *  something the row says, not something that should scatter the choices
 *  across two places. `all` has no entry — it is everything by definition. */
export const VIEW_TIERS: Record<Exclude<View, "all">, readonly Tier[]> = {
  auto: ["fix"],
  sudo: ["sudo"],
  optional: TIERS.filter(isOptionalTier),
  manual: ["advisory"],
};

/** The tier a remedy came from, reconstructed from what crossed the wire. */
export const tierOf = (i: Issue): Tier =>
  i.remedy.kind === "optional"
    ? (i.remedy.root ? "optional-sudo" : "optional")
    : i.remedy.kind;

/** What the segments are called, and what the label promises. */
export const VIEW_LABEL: Record<View, string> = {
  auto: "Auto",
  sudo: "Sudo",
  optional: "Optional",
  manual: "Manual",
  all: "All",
};

export const VIEW_MEANING: Record<View, string> = {
  auto: "Fixed on one click, with nothing taken away and nothing to type.",
  sudo: "Fixed on one click and one root password. Each one either narrows a " +
    "file's permissions or adds a line to a file that belongs to Fixable — " +
    "nothing running is stopped, restarted or reconfigured.",
  optional:
    "Beneficial, not broken. Each of these takes something away as well as " +
    "giving something, so it waits for you and is never part of a Fix all. " +
    "Some ask for the root password; the row says which.",
  manual:
    "No safe automatic fix exists. Each row says what one would have to touch.",
  all: "Everything found, whatever can be done about it.",
};

/** Does an issue belong in `view`? */
export const inView = (view: View, i: Issue): boolean =>
  view === "all" || VIEW_TIERS[view].includes(tierOf(i));

export const visible = (view: View, issues: readonly Issue[]): Issue[] =>
  issues.filter((i) => inView(view, i));

/** How many checks could possibly report into `view`. */
export const possibleIn = (
  view: View,
  totals: Record<Tier, number>,
): number =>
  (view === "all" ? TIERS : VIEW_TIERS[view])
    .reduce((n, t) => n + totals[t], 0);
