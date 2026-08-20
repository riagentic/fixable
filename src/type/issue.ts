// Wire types — what the UI reads and what persists. Zero dependencies.

/** The lenses Fixable diagnoses a computer through.
 *
 *  `safety` and `stability` were added once the catalogue grew past desktop
 *  settings: "you have no backup" is not a resource problem and "a service is
 *  failing" is not a security one, and filing them under either made both
 *  unreadable. Every check names exactly one of these, and the UI shows it. */
export type Category =
  /** Someone else could read, change or reach something of yours. */
  | "security"
  /** Something is reporting on you, or keeping a record you did not ask for. */
  | "privacy"
  /** Your data could be lost — no backup, no encryption, no confirmation. */
  | "safety"
  /** The machine could stop working correctly — failing services, hardware,
   *  filesystem errors, updates that never arrive. */
  | "stability"
  /** The machine is slower than it should be. */
  | "performance"
  /** Disk, memory or swap is running out. */
  | "resource"
  /** The machine is working harder than it needs to. */
  | "utilization"
  /** Something is configured in a way that does not do what it looks like. */
  | "settings";

/** Display order — most consequential first. Also the order of the header
 *  breakdown, so the eye lands on security and safety before tidiness. */
export const CATEGORIES: readonly Category[] = [
  "security",
  "safety",
  "privacy",
  "stability",
  "performance",
  "resource",
  "utilization",
  "settings",
];

/** Significance band. Also the primary sort key of the issue list. */
export type Severity = "critical" | "major" | "minor";

/** How an issue may be remedied — the safety rule, enforced at the type level.
 *
 *  `fix`      — non-destructive, reversible and non-disruptive by construction,
 *               and it changes nothing anybody would have chosen on purpose.
 *               Runs on one click, and on "Fix all".
 *  `sudo`     — the same bar, except it needs root. Every one of these either
 *               narrows a file mode or writes a drop-in file that belongs to
 *               Fixable; none edits a file it does not own, and none touches
 *               live state, so nothing running changes behaviour. `commands`
 *               is the exact script, shown before the password is asked for.
 *  `optional` — a real, reversible fix that takes away something you might
 *               want: a preference, a feature in daily use, a policy spanning
 *               many programs. It has a button, it is never in a "Fix all",
 *               and it is filed apart from the faults because it is not one.
 *               `root` says whether pressing it asks for a password: being a
 *               choice and needing privilege are separate facts.
 *               `root` says whether pressing it will ask for a password —
 *               being a choice and needing privilege are separate facts, and
 *               collapsing them is what leaves a fixable row with no button.
 *  `advisory` — no safe automatic fix exists. `explanation` says what one
 *               would have to touch, and therefore why there isn't one.
 *
 *  Nothing else exists. A change either meets the bar unattended (`fix`,
 *  `sudo`), meets it only with a deliberate press (`optional`), or cannot be
 *  made safely at all (`advisory`). */
export type Remedy =
  | { kind: "fix"; explanation: string }
  | { kind: "sudo"; explanation: string; commands: string[] }
  | { kind: "optional"; explanation: string; root: boolean; commands: string[] }
  | { kind: "advisory"; explanation: string };

/** What a check can offer, before anything has been probed. Declared by the
 *  factory that builds it, so the header can count each tier up front and the
 *  registry can assert that every finding agrees with its tier.
 *
 *  Two questions, not one: can this run unattended, and does it need root?
 *  `optional-sudo` is the corner that exists only because both answers matter
 *  — blacklisting a kernel module, or refusing password logins over SSH, needs
 *  a password AND takes something away. A model with one axis has to drop one
 *  of those facts, and dropping either is what turns a perfectly fixable row
 *  into a paragraph telling you to go and type it yourself. */
export type Tier =
  | "fix"
  | "sudo"
  | "optional"
  | "optional-sudo"
  | "advisory";

export const TIERS: readonly Tier[] = [
  "fix",
  "sudo",
  "optional",
  "optional-sudo",
  "advisory",
];

/** Does pressing this tier's button ask for the root password? */
export const isRootTier = (t: Tier): boolean =>
  t === "sudo" || t === "optional-sudo";

/** Is this tier a choice rather than a fault — shown apart from the faults,
 *  and never swept up by a "Fix all"? */
export const isOptionalTier = (t: Tier): boolean =>
  t === "optional" || t === "optional-sudo";

export type Issue = {
  /** Check id — stable across runs, so the UI keys rows on it. */
  id: string;
  /** Column 1 — what is wrong, in one line. */
  title: string;
  /** Column 2. */
  category: Category;
  /** Column 3. */
  severity: Severity;
  /** Tie-break inside a severity band — higher first. */
  weight: number;
  /** The measurement behind the verdict ("/home is 91% full"). */
  detail: string;
  /** Columns 4 + 5. */
  remedy: Remedy;
};

/** Which issues the list shows. One segment per remedy tier, plus everything.
 *
 *  `auto`     — fixes that run on a click. The default: the ones you can act
 *               on without leaving the app and without being asked anything.
 *  `sudo`     — fixes that need the root password, run as one reviewed batch.
 *  `optional` — beneficial changes that cost you something; yours to choose.
 *  `manual`   — the ones with no safe automatic fix, each with the reason.
 *  `all`      — everything found. */
export type View = "auto" | "sudo" | "optional" | "manual" | "all";

/** One applied fix. Kept so every change this app made stays visible and,
 *  where the fix wrote a previous value, undoable. */
export type FixRecord = {
  id: string;
  title: string;
  /** Epoch ms. */
  at: number;
  /** Exactly what changed, in the fix's own words. */
  summary: string;
  undoable: boolean;
};
