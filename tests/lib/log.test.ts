import { assertEquals } from "@std/assert";
import type { FixRecord } from "../../src/type/issue.ts";
import {
  hasUndoable,
  markUndone,
  remember,
  retireUndos,
} from "../../src/lib/log.ts";

const rec = (id: string, at: number, undoable = true): FixRecord => ({
  id,
  title: id,
  at,
  summary: `${id}@${at}`,
  undoable,
});

Deno.test("remember prepends and bounds the log", () => {
  const log = [rec("a", 1), rec("b", 2)];
  const next = remember(log, rec("c", 3), 2);
  assertEquals(next.map((r) => r.id), ["c", "a"]);
  assertEquals(log.length, 2, "remember mutated its input");
});

Deno.test("markUndone retires exactly the newest entry for that check", () => {
  // Two fixes of the same check, newest first. One undo must retire one button.
  const log = [rec("ssh", 2), rec("ssh", 1), rec("disk", 3)];
  const next = markUndone(log, "ssh");
  assertEquals(next.map((r) => r.undoable), [false, true, true]);
  assertEquals(next[0]?.summary.startsWith("undone — "), true);
});

Deno.test("markUndone on an unknown or already-undone check is a no-op", () => {
  const log = [rec("ssh", 1, false)];
  assertEquals(markUndone(log, "ssh"), log);
  assertEquals(markUndone(log, "nope"), log);
});

Deno.test("retireUndos leaves the history and takes only the buttons", () => {
  const log = [rec("a", 1), rec("b", 2, false)];
  const next = retireUndos(log);
  assertEquals(next.length, 2);
  assertEquals(hasUndoable(next), false);
  // Summaries are the record of what happened — untouched.
  assertEquals(next.map((r) => r.summary), log.map((r) => r.summary));
});
