import { assertEquals } from "@std/assert";
import type { Issue } from "../../type/issue.ts";
import {
  bySignificance,
  countBySeverity,
  fixable,
  ordered,
} from "../../lib/severity.ts";

const issue = (p: Partial<Issue> & Pick<Issue, "id">): Issue => ({
  title: p.id,
  category: "security",
  severity: "minor",
  weight: 0,
  detail: "",
  remedy: { kind: "advisory", explanation: "" },
  ...p,
});

Deno.test("orders by band, then weight, then id", () => {
  const list = [
    issue({ id: "c", severity: "minor", weight: 99 }),
    issue({ id: "a", severity: "critical", weight: 1 }),
    issue({ id: "b", severity: "major", weight: 5 }),
    issue({ id: "d", severity: "major", weight: 9 }),
  ];
  assertEquals(ordered(list).map((i) => i.id), ["a", "d", "b", "c"]);
});

Deno.test("equal band and weight break on id, both directions", () => {
  const x = issue({ id: "x" }), y = issue({ id: "y" });
  assertEquals(bySignificance(x, y) < 0, true);
  assertEquals(bySignificance(y, x) > 0, true);
});

Deno.test("ordered does not mutate its input", () => {
  const list = [issue({ id: "z", severity: "minor" }), issue({ id: "a" })];
  ordered(list);
  assertEquals(list.map((i) => i.id), ["z", "a"]);
});

Deno.test("counts every band, including the empty ones", () => {
  const counts = countBySeverity([
    issue({ id: "a", severity: "critical" }),
    issue({ id: "b", severity: "minor" }),
    issue({ id: "c", severity: "minor" }),
  ]);
  assertEquals(counts, { critical: 1, major: 0, minor: 2 });
});

Deno.test("fixable selects exactly the issues carrying a fix", () => {
  const list = [
    issue({ id: "a", remedy: { kind: "fix", explanation: "sets x" } }),
    issue({ id: "b" }),
  ];
  assertEquals(fixable(list).map((i) => i.id), ["a"]);
});
