import { assertEquals } from "@std/assert";
import type { Issue } from "../../type/issue.ts";
import { merge, mergeIds, without } from "../../lib/merge.ts";

const issue = (id: string, severity: Issue["severity"] = "minor"): Issue => ({
  id,
  title: id,
  category: "resource",
  severity,
  weight: 0,
  detail: "",
  remedy: { kind: "advisory", explanation: "" },
});

Deno.test("a partial pass only speaks for the checks it ran", () => {
  const current = [issue("disk"), issue("ssh")];
  // The monitor tick re-ran `disk` and found it healthy. `ssh` was not in
  // scope, so it must survive rather than silently disappear.
  assertEquals(merge(current, ["disk"], []).map((i) => i.id), ["ssh"]);
});

Deno.test("a re-run check is replaced, not duplicated", () => {
  const current = [issue("disk", "minor")];
  const next = merge(current, ["disk"], [issue("disk", "critical")]);
  assertEquals(next.length, 1);
  assertEquals(next[0]?.severity, "critical");
});

Deno.test("merge returns the list already ordered", () => {
  const next = merge([issue("a", "minor")], ["b"], [issue("b", "critical")]);
  assertEquals(next.map((i) => i.id), ["b", "a"]);
});

Deno.test("mergeIds folds unmeasured checks with the same scope rule", () => {
  assertEquals(mergeIds(["disk", "apt"], ["disk"], []), ["apt"]);
  assertEquals(mergeIds(["apt"], ["disk"], ["disk"]), ["apt", "disk"]);
});

Deno.test("without drops exactly one id", () => {
  assertEquals(
    without([issue("a"), issue("b")], "a").map((i) => i.id),
    ["b"],
  );
});
