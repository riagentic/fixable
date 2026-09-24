import { assertEquals } from "@std/assert";
import { bootCells, testCell } from "aio/testing";
import { issues, MONITOR_MS } from "../../src/cell/issues.ts";
import { POSSIBLE_BY_TIER } from "../../src/cell/checks.server.ts";

testCell(issues, "a monitor pass fills in the denominator", async (t) => {
  t.init();
  await t.send.monitor();
  // Each pass re-arms the next one; testCell has no clock to fire it on.
  t.expect.effects(["__schedule"]);
  // The denominator in "N of M" comes from the registry, not a hand-kept copy.
  t.expect.state(
    (s) =>
      s.possible.fix === POSSIBLE_BY_TIER.fix &&
      s.possible.sudo === POSSIBLE_BY_TIER.sudo,
    "possible not filled in",
  );
  t.expect.state((s) => s.lastMeasure !== null, "no measurement recorded");
});

Deno.test("monitoring keeps ticking on its own", async () => {
  await using h = await bootCells([issues]);
  await issues.monitor();
  const first = issues.lastMeasure;
  assertEquals(typeof first, "number");

  // Re-arming is the whole of "it monitors": one pass that never schedules the
  // next looks identical to a healthy machine.
  await h.advance(MONITOR_MS);
  // The tick's work is real (a dynamic import and a `df`), so it lands on a
  // macrotask that the virtual clock does not own — wait for the effect, not
  // for a fixed delay.
  for (let i = 0; i < 100 && issues.lastMeasure === first; i++) {
    await new Promise((r) => setTimeout(r, 10));
    await h.settle();
  }
  assertEquals(
    (issues.lastMeasure ?? 0) > (first ?? 0),
    true,
    "the monitor did not fire again",
  );
});

testCell(issues, "stop cancels the scan in flight", async (t) => {
  t.init();
  const scanning = t.send.scan(); // starts now, un-awaited
  await t.send.stop(); // lands mid-flight and aborts it
  await scanning;
  t.expect.state((s) => s.scanning === false, "scan kept its spinner");
});

testCell(
  issues,
  "a fix for an unknown check fails loud, then dismisses",
  async (t) => {
    t.init();
    await t.send.fix("not-a-check");
    await t.settle();
    // Silence would leave the user believing something was fixed.
    t.expect.state(
      (s) => s.error !== null && s.fixing.length === 0,
      "an impossible fix went unreported",
    );
    await t.send.dismissError();
    t.expect.state((s) => s.error === null);
  },
);

testCell(
  issues,
  "a monitor tick landing mid-scan does not spoil it",
  async (t) => {
    t.init();
    // The 30-second monitor fires while a full sweep is still running — the case
    // that made the first live run throw, because the scan's reads were pinned
    // to entry and the tick had moved the list underneath it.
    const scanning = t.send.scan();
    await t.send.monitor();
    t.expect.effects(["__schedule"]);
    await scanning;
    await t.settle();
    t.expect.state((s) => s.error === null, "the two passes collided");
    t.expect.state((s) => s.lastScan !== null && s.scanning === false);
  },
);

testCell(issues, "fix all with nothing fixable changes nothing", async (t) => {
  t.init();
  await t.send.fixAll();
  await t.settle();
  t.expect.state((s) => s.error === null && s.log.length === 0);
});

testCell(issues, "a second Fix all while one runs is ignored", async (t) => {
  t.init({ fixingAll: true });
  await t.send.fixAll();
  // Still flagged: the call returned without starting a sweep of its own, and
  // without clearing the flag the running one owns.
  t.expect.state((s) => s.fixingAll === true && s.log.length === 0);
});
