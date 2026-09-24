import { assertEquals } from "@std/assert";
import { runRootPlan } from "../../src/cell/root.server.ts";

/** A stand-in for polkit: a script that "authorises" by running its argv as
 *  the current user, or refuses with pkexec's own exit code. */
const fakePkexec = async (dir: string, body: string): Promise<string> => {
  const path = `${dir}/pkexec`;
  await Deno.writeTextFile(path, `#!/bin/sh\n${body}\n`, { mode: 0o700 });
  await Deno.chmod(path, 0o700);
  return path;
};

Deno.test("the plan reaches the root shell on a pipe, never as a file", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const target = `${dir}/secret`;
    await Deno.writeTextFile(target, "x", { mode: 0o644 });
    await Deno.chmod(target, 0o644);
    // `exec "$@"` runs `/bin/sh` with no operand: it can only have read the
    // script from stdin.
    const helper = await fakePkexec(dir, 'exec "$@"');
    const run = await runRootPlan(
      [{ op: "chmod", path: target, mode: "0600", was: "0644" }],
      "fix",
      helper,
    );
    assertEquals(run, { done: [0], failed: [], skipped: [], problem: null });
    assertEquals((await Deno.stat(target)).mode! & 0o777, 0o600);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("a dismissed prompt changes nothing and says so", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const target = `${dir}/secret`;
    await Deno.writeTextFile(target, "x", { mode: 0o644 });
    await Deno.chmod(target, 0o644);
    const helper = await fakePkexec(dir, "exit 126");
    const run = await runRootPlan(
      [{ op: "chmod", path: target, mode: "0600", was: "0644" }],
      "fix",
      helper,
    );
    assertEquals(run.done, []);
    assertEquals(run.skipped, [0]);
    assertEquals(run.problem?.startsWith("Cancelled"), true);
    assertEquals((await Deno.stat(target)).mode! & 0o777, 0o644);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});
