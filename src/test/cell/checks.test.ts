// The safety rule, as tests rather than as a promise.
import { assertEquals, assertRejects } from "@std/assert";
import { CHECKS, POSSIBLE, probe } from "../../cell/checks.server.ts";
import { permCheck } from "../../cell/check-perms.server.ts";
import { mode, octal, tighten } from "../../cell/sys.server.ts";

Deno.test("every check is addressable and explains itself", () => {
  const ids = CHECKS.map((c) => c.id);
  assertEquals(new Set(ids).size, ids.length, "check ids must be unique");
  assertEquals(POSSIBLE, CHECKS.length);
  for (const c of CHECKS) {
    // The last column is the whole basis for pressing (or not pressing) the
    // button — a check that cannot say what it would do must not ship.
    assertEquals(c.explanation.length > 40, true, `${c.id}: thin explanation`);
    assertEquals(c.title.length > 0, true, `${c.id}: no title`);
    assertEquals(["monitor", "scan"].includes(c.mode), true, `${c.id}: mode`);
  }
});

Deno.test("advisory checks say why there is no fix", () => {
  // Every check whose remedy can only ever be advisory carries the reason in
  // its static explanation; the fixable ones override it per finding.
  const advisory = CHECKS.filter((c) =>
    c.explanation.startsWith("No automatic")
  );
  for (const c of advisory) {
    assertEquals(
      c.explanation.length > 80,
      true,
      `${c.id}: "no fix" needs a reason, not a refusal`,
    );
  }
});

Deno.test("tighten refuses to widen permissions", async () => {
  const path = await Deno.makeTempFile();
  try {
    await Deno.chmod(path, 0o600);
    // The direction guard is what stops a "fix" from opening a file up.
    await assertRejects(() => tighten(path, 0o644), Error, "refusing to widen");
    assertEquals(octal((await mode(path))!), "0600");

    // Narrowing is allowed, and hands back what it replaced.
    await Deno.chmod(path, 0o644);
    const { previous } = await tighten(path, 0o600);
    assertEquals(octal(previous), "0644");
    assertEquals(octal((await mode(path))!), "0600");
  } finally {
    await Deno.remove(path);
  }
});

Deno.test("a monitor pass reports only checks it ran, fully formed", async () => {
  const res = await probe("monitor");
  const monitorIds = CHECKS.filter((c) => c.mode === "monitor").map((c) =>
    c.id
  );
  assertEquals(new Set(res.ran).size, res.ran.length);
  assertEquals(res.ran.every((id) => monitorIds.includes(id)), true);

  for (const i of res.issues) {
    assertEquals(res.ran.includes(i.id), true, `${i.id} was not in scope`);
    // The five columns the UI promises — none of them optional.
    assertEquals(i.title.length > 0, true, `${i.id}: column 1`);
    assertEquals(i.category.length > 0, true, `${i.id}: column 2`);
    assertEquals(i.severity.length > 0, true, `${i.id}: column 3`);
    assertEquals(
      i.remedy.kind === "fix" || i.remedy.kind === "advisory",
      true,
      `${i.id}: column 4`,
    );
    assertEquals(i.remedy.explanation.length > 0, true, `${i.id}: column 5`);
    assertEquals(i.detail.length > 0, true, `${i.id}: no measurement`);
  }
});

Deno.test("a fix narrows, verifies, and undoes back to what it found", async () => {
  const path = await Deno.makeTempFile();
  const check = permCheck({
    id: "temp-file-perms",
    title: "temp file is readable by other accounts",
    category: "privacy",
    severity: "minor",
    weight: 1,
    target: 0o600,
    mask: 0o077,
    what: "a temp file",
    paths: [],
  }, () => Promise.resolve([path]));
  try {
    await Deno.chmod(path, 0o644);

    const found = await check.probe();
    assertEquals(Boolean(found?.apply), true, "a fixable finding lost its fix");

    const undo = await found!.apply!();
    assertEquals(octal((await mode(path))!), "0600", "the fix did not apply");
    // The follow-up probe is what turns "the command ran" into "it worked".
    assertEquals(await check.probe(), null, "the issue survived its own fix");

    assertEquals(Boolean(undo.revert), true, "the fix recorded no way back");
    await undo.revert!();
    assertEquals(octal((await mode(path))!), "0644", "undo did not restore");
  } finally {
    await Deno.remove(path);
  }
});

Deno.test("an unknown id is a loud error, never a silent no-op", async () => {
  const { applyFix, undoFix } = await import("../../cell/checks.server.ts");
  await assertRejects(() => applyFix("nope"), Error, "unknown check");
  await assertRejects(() => undoFix("nope"), Error, "no recorded change");
});

Deno.test("a fix never makes a directory untraversable", async () => {
  // The bug this pins: a row written for a history FILE (target 0600) was
  // applied to `~/.config/GIMP`, `~/.cache/fontconfig` and
  // `~/.local/share/systemd`, which are directories. `0600 & 0755` is `0600`,
  // and a directory without its owner-execute bit cannot be entered — every
  // file inside it stopped opening, for its owner, silently.
  const dir = await Deno.makeTempDir();
  const inner = `${dir}/inner`;
  try {
    await Deno.writeTextFile(inner, "x");
    await Deno.chmod(dir, 0o755);

    const check = permCheck({
      id: "temp-dir-perms",
      title: "a temp directory is readable by other accounts",
      category: "privacy",
      severity: "minor",
      weight: 1,
      paths: [],
      target: 0o600, // a FILE target, deliberately
      mask: 0o077,
      what: "a temp directory",
    }, () => Promise.resolve([dir]));

    const found = await check.probe();
    assertEquals(Boolean(found?.apply), true, "0755 directory not flagged");
    await found!.apply!();

    // Owner traversal survives, and group/other are gone.
    assertEquals(octal((await mode(dir))!), "0700");
    assertEquals(await Deno.readTextFile(inner), "x", "directory unusable");
  } finally {
    await Deno.chmod(dir, 0o700);
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("tighten refuses to strip a directory's execute bit", async () => {
  const dir = await Deno.makeTempDir();
  try {
    await Deno.chmod(dir, 0o755);
    await assertRejects(
      () => tighten(dir, 0o600),
      Error,
      "untraversable",
    );
    assertEquals(octal((await mode(dir))!), "0755", "mode changed anyway");
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("a setting the user chooses is never changed unasked", async () => {
  // "Never suspend", "never blank", "ignore the lid" and the timeouts around
  // them are deliberate choices, not faults. A fix that overrules one is the
  // app deciding it knows better than the person using the machine — which is
  // exactly what happened to a `sleep-inactive-ac-timeout` of 0.
  const CHOSEN = [
    "sleep-inactive-ac",
    "sleep-display-ac",
    "sleep-display-long",
    "screen-idle",
    "screen-idle-long",
    "lock-delay",
    "idle-dim-ac",
    "d3-lid-inhibit",
  ];
  const { CHECKS: ALL } = await import("../../cell/checks.server.ts");
  for (const id of CHOSEN) {
    const c = ALL.find((x) => x.id === id);
    assertEquals(Boolean(c), true, `${id}: row is gone — rename or removal?`);
    // "optional", not "advisory": the button is allowed back, because a
    // button is an offer. What must never happen is the change being made
    // without being asked for, and no tier but "fix" is ever swept up by
    // "Fix all".
    assertEquals(
      c!.tier === "optional" || c!.tier === "advisory",
      true,
      `${id}: tier=${c!.tier} — a deliberate choice would be overwritten`,
    );
  }
});
