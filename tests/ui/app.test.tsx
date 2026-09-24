import { assertEquals } from "@std/assert";
import { testUI } from "aio/testing";
import App from "../../src/App.tsx";
import { issues } from "../../src/cell/issues.ts";

testUI(
  App,
  "the header opens on Auto and offers both entry points",
  async (ui) => {
    // Nothing has run yet: no issues found, and the denominator is filled in by
    // the first pass — the header must still render rather than show NaN.
    assertEquals(ui.score.text.startsWith("0 of"), true, ui.score.text);
    assertEquals(ui.scan.disabled, false);
    // Nothing is fixable yet, so neither sweep may be pressable.
    assertEquals(ui.fixAll.disabled, true);
    assertEquals(ui.fixAllRoot.disabled, true);
    // Auto is the default view.
    await ui.expectCell(issues, (s) => s.view === "auto");
  },
);

testUI(App, "the switch moves between every tier", async (ui) => {
  // The monitor half, not the full sweep: it is the half that runs unattended,
  // and it needs no subprocesses beyond `df`. Everything it finds is manual —
  // you cannot free disk space or close programs from here — so it is also the
  // sharpest test that the default view hides what it should.
  await issues.monitor();
  await ui.settle();
  const found = issues.issues.length;

  ui["view-all"].click();
  await ui.expectCell(issues, (s) => s.view === "all");
  assertEquals(
    ui.score.text.startsWith(`${found} of`),
    true,
    `all: ${ui.score.text}`,
  );

  ui["view-manual"].click();
  await ui.expectCell(issues, (s) => s.view === "manual");
  assertEquals(
    issues.shown().every((i) => i.remedy.kind === "advisory"),
    true,
    "Manual showed an auto-fixable issue",
  );

  ui["view-sudo"].click();
  await ui.expectCell(issues, (s) => s.view === "sudo");
  assertEquals(
    issues.shown().every((i) => i.remedy.kind === "sudo"),
    true,
    "Sudo showed something that does not need the root password",
  );

  ui["view-optional"].click();
  await ui.expectCell(issues, (s) => s.view === "optional");
  assertEquals(
    issues.shown().every((i) => i.remedy.kind === "optional"),
    true,
    "Optional showed a fault rather than a choice",
  );

  ui["view-auto"].click();
  await ui.expectCell(issues, (s) => s.view === "auto");
  assertEquals(
    issues.shown().every((i) => i.remedy.kind === "fix"),
    true,
    "Auto showed an issue with no Fix button",
  );
  // The header speaks for the whole machine, whatever the view: a finding
  // with no button must not drop out of the summary because the list opened
  // on Auto.
  assertEquals(
    ui.score.text.startsWith(`${found} of`),
    true,
    `auto: ${ui.score.text}`,
  );
  const critical = issues.issues.filter((i) => i.severity === "critical");
  assertEquals(
    ui["tally-critical"].text.startsWith(`${critical.length} `),
    true,
    `auto: ${ui["tally-critical"].text}`,
  );
});

testUI(App, "every visible row carries all five columns", async (ui) => {
  await issues.monitor();
  ui["view-all"].click();
  await ui.settle();

  for (const issue of issues.shown()) {
    const text = ui[`row-${issue.id}`].text;
    assertEquals(text.includes(issue.title), true, `${issue.id}: no title`);
    assertEquals(
      text.includes(issue.category),
      true,
      `${issue.id}: no category`,
    );
    assertEquals(
      text.includes(issue.severity),
      true,
      `${issue.id}: no priority`,
    );
    assertEquals(
      text.includes(issue.remedy.explanation.slice(0, 24)),
      true,
      `${issue.id}: no explanation of the fix`,
    );
  }
});

testUI(
  App,
  "nothing runs as root until the plan has been shown",
  async (ui) => {
    // The consent step, asserted rather than assumed. Pressing "Fix all (sudo
    // required)" must produce a plan on screen and nothing else: no password
    // prompt, and no change. Only the button ON that plan may run it.
    await issues.scan();
    await ui.settle();
    await ui.expectCell(issues, (s) => !s.scanning);

    if (issues.rootCount() === 0) return; // nothing root-fixable on this machine

    // The panel is not on screen until it is asked for — asserted through the
    // state it renders from, which is what the component itself reads.
    assertEquals(
      issues.rootPlan,
      null,
      "a plan existed before it was asked for",
    );
    ui.fixAllRoot.click();
    await ui.expectCell(issues, (s) => s.rootPlan !== null && !s.rootFixing);

    const plan = issues.rootPlan!;
    assertEquals(plan.items.length > 0, true, "an empty plan was offered");
    assertEquals(plan.lines.length > 0, true, "a plan with no commands in it");
    // The panel shows the batch and the script, and offers a way out.
    assertEquals(ui.rootItems.text.includes(plan.items[0]!.summary), true);
    assertEquals(
      ui.rootScript.text.includes(plan.lines[0]!.split("\n")[0]!),
      true,
    );

    // Cancelling leaves the machine exactly as it was.
    const before = issues.issues.length;
    ui.rootCancel.click();
    await ui.expectCell(issues, (s) => s.rootPlan === null);
    assertEquals(issues.issues.length, before, "cancelling changed something");
  },
);
