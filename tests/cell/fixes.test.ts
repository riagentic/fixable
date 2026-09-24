// Multi-target fixes, symlinks, and the probes that read the machine — all in
// temp directories; nothing here touches the real home or /etc.
import { assertEquals, assertRejects } from "@std/assert";
import { join } from "@std/path";
import { permCheck } from "../../src/cell/check-perms.server.ts";
import { mozCheck } from "../../src/cell/check-mozilla.server.ts";
import { CLUTTER_CHECKS } from "../../src/cell/check-clutter.server.ts";
import { applyAll, mode, octal, tighten } from "../../src/cell/sys.server.ts";
import type { MozPolicy } from "../../src/type/policy.ts";

/** Run `body` with $HOME pointed at a fresh temp dir. */
async function withHome(body: (home: string) => Promise<void>): Promise<void> {
  const home = await Deno.makeTempDir();
  const was = Deno.env.get("HOME");
  Deno.env.set("HOME", home);
  try {
    await body(home);
  } finally {
    if (was === undefined) Deno.env.delete("HOME");
    else Deno.env.set("HOME", was);
    await Deno.remove(home, { recursive: true });
  }
}

const perm = (paths: string[]) =>
  permCheck({
    id: "temp-perms",
    title: "temp",
    category: "privacy",
    severity: "minor",
    weight: 1,
    target: 0o600,
    mask: 0o077,
    what: "temp files",
    paths: [],
  }, () => Promise.resolve(paths));

Deno.test("applyAll undoes what landed when a later step fails", async () => {
  const log: string[] = [];
  await assertRejects(
    () =>
      applyAll([1, 2, 3], (n) => {
        if (n === 3) return Promise.reject(new Error("boom"));
        log.push(`do ${n}`);
        return Promise.resolve(() => {
          log.push(`undo ${n}`);
          return Promise.resolve();
        });
      }),
    Error,
    "boom",
  );
  assertEquals(log, ["do 1", "do 2", "undo 2", "undo 1"]);
});

Deno.test("a chmod fix that fails half-way leaves every mode as it was", async () => {
  const dir = await Deno.makeTempDir();
  const [a, b] = [join(dir, "a"), join(dir, "b")];
  try {
    for (const p of [a, b]) {
      await Deno.writeTextFile(p, "x");
      await Deno.chmod(p, 0o644);
    }
    const found = await perm([a, b]).probe();
    await Deno.remove(b); // the second target fails at apply time
    await assertRejects(() => found!.apply!());
    assertEquals(
      octal((await mode(a))!),
      "0644",
      "first target not rolled back",
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("a symlink is neither reported nor chmodded", async () => {
  const dir = await Deno.makeTempDir();
  const [target, link] = [join(dir, "t"), join(dir, "l")];
  try {
    await Deno.writeTextFile(target, "x");
    await Deno.chmod(target, 0o666);
    await Deno.symlink(target, link);
    assertEquals(await perm([link]).probe(), null);
    await assertRejects(() => tighten(link, 0o600), Error, "symlink");
    assertEquals(octal((await mode(target))!), "0666");
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

const MOZ: MozPolicy = {
  id: "moz-test",
  title: "test pref",
  category: "privacy",
  severity: "minor",
  weight: 1,
  product: "firefox",
  pref: "test.pref",
  fallback: "true",
  bad: "true",
  safe: "false",
  detail: "test pref is on",
  because: "Testing.",
};

const profile = async (home: string, name: string, text: string) => {
  const dir = join(home, ".mozilla/firefox", name);
  await Deno.mkdir(dir, { recursive: true });
  await Deno.writeTextFile(join(dir, "prefs.js"), text);
  return dir;
};

Deno.test("mozilla: a failed profile rolls back the ones already written", async () => {
  await withHome(async (home) => {
    const one = await profile(home, "a.default", "// a\n");
    const two = await profile(home, "b.default", "// b\n");
    const found = await mozCheck(MOZ).probe();
    // The second profile's prefs.js becomes a symlink: writeConf refuses it.
    const real = join(home, "elsewhere.js");
    await Deno.writeTextFile(real, "// b\n");
    await Deno.remove(join(two, "prefs.js"));
    await Deno.symlink(real, join(two, "prefs.js"));
    await assertRejects(() => found!.apply!(), Error, "symlink");
    assertEquals(await Deno.readTextFile(join(one, "prefs.js")), "// a\n");
  });
});

Deno.test("mozilla: undo refuses while the program is running", async () => {
  await withHome(async (home) => {
    const dir = await profile(home, "a.default", "// a\n");
    const found = await mozCheck(MOZ).probe();
    const done = await found!.apply!();
    const wrote = await Deno.readTextFile(join(dir, "prefs.js"));
    await Deno.symlink("127.0.0.1:+1234", join(dir, "lock"));
    await assertRejects(() => done.revert!(), Error, "running");
    assertEquals(await Deno.readTextFile(join(dir, "prefs.js")), wrote);
    await Deno.remove(join(dir, "lock"));
    await done.revert!();
    assertEquals(await Deno.readTextFile(join(dir, "prefs.js")), "// a\n");
  });
});

Deno.test("mozilla: a value that cannot be judged fails the probe", async () => {
  await withHome(async (home) => {
    await profile(home, "a.default", 'user_pref("test.pref", "maybe");\n');
    await assertRejects(() => mozCheck(MOZ).probe(), Error, "cannot judge");
  });
});

Deno.test("autostart: entries the desktop disabled are not counted", async () => {
  const check = CLUTTER_CHECKS.find((c) => c.id === "autostart-count")!;
  await withHome(async (home) => {
    const dir = join(home, ".config/autostart");
    await Deno.mkdir(dir, { recursive: true });
    for (let i = 0; i < 20; i++) {
      const off = i % 2 === 0
        ? "X-GNOME-Autostart-enabled=false"
        : "Hidden=true";
      await Deno.writeTextFile(
        join(dir, `app${i}.desktop`),
        `[Desktop Entry]\nName=app${i}\n${i < 10 ? off : ""}\n`,
      );
    }
    // 10 enabled of 20 — under the threshold once the disabled are excluded.
    assertEquals(await check.probe(), null);
    for (let i = 20; i < 23; i++) {
      await Deno.writeTextFile(
        join(dir, `app${i}.desktop`),
        "[Desktop Entry]\n",
      );
    }
    assertEquals(Boolean(await check.probe()), true);
  });
});
