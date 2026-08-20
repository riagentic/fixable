// How a category is shown. Pure — no aio, no Deno.
import type { Category } from "../type/issue.ts";

/** One line each, because a category name alone does not tell you what the
 *  row is claiming. These are the tooltips. */
export const CATEGORY_MEANING: Record<Category, string> = {
  security: "Someone else could read, change or reach something of yours",
  privacy:
    "Something is reporting on you, or keeping a record you did not ask for",
  safety: "Your data could be lost — no backup, no encryption, no confirmation",
  stability: "The machine could stop working correctly",
  performance: "The machine is slower than it should be",
  resource: "Disk, memory or swap is running out",
  utilization: "The machine is working harder than it needs to",
  settings:
    "Something is configured in a way that does not do what it looks like",
};

/** Counts per category, in display order, including the empty ones — a
 *  breakdown that hides its zeros makes the set look different every scan. */
export const countByCategory = <T extends { category: Category }>(
  items: readonly T[],
  order: readonly Category[],
): [Category, number][] =>
  order.map((c) => [c, items.filter((i) => i.category === c).length]);
