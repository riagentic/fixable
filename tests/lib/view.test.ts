import { assertEquals } from "@std/assert";
import type { Issue, Tier } from "../../src/type/issue.ts";
import {
  inView,
  isView,
  possibleIn,
  VIEWS,
  visible,
} from "../../src/lib/view.ts";

const remedy = (tier: Tier): Issue["remedy"] => {
  switch (tier) {
    case "sudo":
      return { kind: "sudo", explanation: "x", commands: [] };
    case "optional":
      return { kind: "optional", explanation: "x", root: false, commands: [] };
    case "optional-sudo":
      return { kind: "optional", explanation: "x", root: true, commands: [] };
    default:
      return { kind: tier, explanation: "x" };
  }
};

const issue = (id: string, tier: Tier): Issue => ({
  id,
  title: id,
  category: "security",
  severity: "minor",
  weight: 0,
  detail: "",
  remedy: remedy(tier),
});

const LIST = [
  issue("a", "fix"),
  issue("b", "advisory"),
  issue("c", "fix"),
  issue("d", "sudo"),
  issue("e", "optional"),
  issue("f", "optional-sudo"),
];

Deno.test("Auto shows exactly the issues that fix themselves", () => {
  assertEquals(visible("auto", LIST).map((i) => i.id), ["a", "c"]);
});

Deno.test("Sudo shows exactly the issues that need the root password", () => {
  assertEquals(visible("sudo", LIST).map((i) => i.id), ["d"]);
});

Deno.test("Optional collects both of its tiers and stays out of Auto", () => {
  // The whole point of the tier: a beneficial change that costs you something
  // is not filed with the faults and is not swept up by "Fix all" — whether or
  // not it happens to need a password.
  assertEquals(visible("optional", LIST).map((i) => i.id), ["e", "f"]);
  assertEquals(visible("auto", LIST).some((i) => i.id === "e"), false);
  // And the one that needs root is not in the Sudo view either, because
  // "Fix all (sudo required)" must not sweep up a choice.
  assertEquals(visible("sudo", LIST).map((i) => i.id), ["d"]);
});

Deno.test("Manual shows only what has no button at all", () => {
  assertEquals(visible("manual", LIST).map((i) => i.id), ["b"]);
});

Deno.test("the tiers partition everything found", () => {
  assertEquals(visible("all", LIST).length, LIST.length);
  const parts = VIEWS.filter((v) => v !== "all")
    .reduce((n, v) => n + visible(v, LIST).length, 0);
  assertEquals(parts, LIST.length, "an issue fell through every view");
});

Deno.test("inView agrees with visible, issue by issue", () => {
  for (const v of VIEWS) {
    assertEquals(LIST.filter((i) => inView(v, i)), visible(v, LIST));
  }
});

Deno.test("each view has its own denominator", () => {
  const totals = {
    fix: 90,
    sudo: 20,
    optional: 15,
    "optional-sudo": 5,
    advisory: 35,
  };
  assertEquals(possibleIn("all", totals), 165);
  assertEquals(possibleIn("auto", totals), 90);
  assertEquals(possibleIn("sudo", totals), 20);
  // Both optional tiers, because the view shows both.
  assertEquals(possibleIn("optional", totals), 20);
  assertEquals(possibleIn("manual", totals), 35);
});

Deno.test("isView refuses anything that is not a view", () => {
  assertEquals(isView("auto"), true);
  assertEquals(isView("sudo"), true);
  assertEquals(isView("Auto"), false);
  assertEquals(isView("everything"), false);
});
