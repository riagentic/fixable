// The config-file engine. This is the code that rewrites files a user owns,
// so it gets the most tests in the project.
import { assertEquals, assertRejects } from "@std/assert";
import {
  disableKey,
  readKey,
  upsertKey,
  upsertSshOption,
} from "../../lib/conf.ts";
import { restoreConf, writeConf } from "../../cell/conf.server.ts";

Deno.test("reads a space-separated keyword, case-insensitively", () => {
  const text = "# a comment\nkeyid-format 0xlong\nno-comments\n";
  assertEquals(readKey(text, "space", "keyid-format"), "0xlong");
  assertEquals(readKey(text, "space", "KEYID-FORMAT"), "0xlong");
  // A bare flag reads as present-with-no-value, not as absent.
  assertEquals(readKey(text, "space", "no-comments"), "");
  assertEquals(readKey(text, "space", "no-emit-version"), null);
});

Deno.test("a commented-out line is not a setting", () => {
  assertEquals(readKey("# audit=false\n", "equals", "audit"), null);
  assertEquals(readKey("; audit=false\n", "equals", "audit"), null);
});

Deno.test("the last occurrence wins, as the tools themselves do", () => {
  const text = "audit=false\naudit=true\n";
  assertEquals(readKey(text, "equals", "audit"), "true");
});

Deno.test("upsert replaces in place and keeps every other line", () => {
  const text = "# header\naudit=false\nfund=false\n";
  const next = upsertKey(text, "equals", "audit", "true");
  assertEquals(next, "# header\naudit=true\nfund=false\n");
});

Deno.test("upsert appends when the key is absent, without eating the file", () => {
  const next = upsertKey("# header\n", "equals", "audit", "true");
  assertEquals(next, "# header\naudit=true\n");
  // …and on an empty file.
  assertEquals(upsertKey("", "equals", "audit", "true"), "\naudit=true\n");
});

Deno.test("a bare flag is written without a value", () => {
  assertEquals(upsertKey("", "space", "no-comments", ""), "\nno-comments\n");
});

Deno.test("ini keys are written spaced, and land inside their section", () => {
  const text = "[global]\ntimeout = 15\n\n[install]\nuser = true\n";
  const next = upsertKey(text, "ini", "require-virtualenv", "true", "global");
  assertEquals(
    next,
    "[global]\ntimeout = 15\nrequire-virtualenv = true\n\n[install]\nuser = true\n",
  );
});

Deno.test("a key of the same name in another section is not mistaken for ours", () => {
  const text = "[global]\nuser = false\n\n[install]\nuser = true\n";
  assertEquals(readKey(text, "ini", "user", "install"), "true");
  assertEquals(readKey(text, "ini", "user", "global"), "false");
});

Deno.test("a missing section is created rather than guessed at", () => {
  const next = upsertKey("[install]\nuser = true\n", "ini", "x", "1", "global");
  assertEquals(next, "[install]\nuser = true\n\n[global]\nx = 1\n");
});

Deno.test("disableKey comments out every occurrence and deletes nothing", () => {
  const text = "insecure\nverbose\ninsecure\n";
  const next = disableKey(text, "space", "insecure");
  assertEquals(
    next.split("\n").filter((l) => l.includes("insecure")).length,
    2,
  );
  assertEquals(next.includes("# disabled by Fixable: insecure"), true);
  assertEquals(next.includes("verbose"), true);
  // Running it twice is a no-op — the comment is not itself a setting.
  assertEquals(disableKey(next, "space", "insecure"), next);
});

// ---------------------------------------------------------------- ssh_config

Deno.test("ssh options go into a trailing Host * block, never the top", () => {
  const text = "Host prod\n    User deploy\n    ForwardAgent yes\n";
  const next = upsertSshOption(text, "ForwardAgent", "no");
  // The per-host setting is untouched: ssh_config is first-match-wins, so
  // prepending would have silently overridden it.
  assertEquals(next.indexOf("Host prod") < next.indexOf("Host *"), true);
  assertEquals(next.includes("    ForwardAgent yes"), true);
  assertEquals(next.trimEnd().endsWith("ForwardAgent no"), true);
});

Deno.test("a second option joins the existing Host * block", () => {
  const one = upsertSshOption("", "ForwardAgent", "no");
  const two = upsertSshOption(one, "ForwardX11", "no");
  assertEquals(two.split("Host *").length - 1, 1, "made a second Host * block");
  assertEquals(two.includes("ForwardAgent no"), true);
  assertEquals(two.includes("ForwardX11 no"), true);
});

Deno.test("re-writing an option replaces it inside the block", () => {
  const one = upsertSshOption("", "ServerAliveInterval", "60");
  const two = upsertSshOption(one, "ServerAliveInterval", "30");
  assertEquals(two.includes("60"), false);
  assertEquals(two.split("ServerAliveInterval").length - 1, 1);
});

Deno.test("a Host * block followed by another block keeps its own lines", () => {
  const text = "Host *\n    User me\n\nHost prod\n    User deploy\n";
  const next = upsertSshOption(text, "ForwardAgent", "no");
  const lines = next.split("\n");
  const star = lines.indexOf("Host *");
  const prod = lines.indexOf("Host prod");
  const added = lines.findIndex((l) => l.includes("ForwardAgent no"));
  assertEquals(added > star && added < prod, true, "landed in the wrong block");
});

// ------------------------------------------------------- undo after a batch

Deno.test("undo puts back one key when the file has moved on", async () => {
  // A dozen gpg.conf rows run in one "Fix all". Undoing the first must not
  // refuse (leaving no way back) and must not rewrite the file over the other
  // eleven. It reverts its own key and leaves the rest alone.
  const path = await Deno.makeTempFile();
  try {
    await Deno.writeTextFile(path, "keyid-format short\n");
    const first = await writeConf(
      path,
      upsertKey("keyid-format short\n", "space", "keyid-format", "0xlong"),
    );
    const undoFirst = restoreConf(
      first,
      (later) => upsertKey(later, "space", "keyid-format", "short"),
    );

    // A second fix edits the same file, so the whole-file restore is now wrong.
    await writeConf(
      path,
      upsertKey(await Deno.readTextFile(path), "space", "no-comments", ""),
    );

    await undoFirst();
    const text = await Deno.readTextFile(path);
    assertEquals(readKey(text, "space", "keyid-format"), "short", "not undone");
    assertEquals(
      readKey(text, "space", "no-comments"),
      "",
      "undo clobbered the later fix",
    );
  } finally {
    await Deno.remove(path);
  }
});

Deno.test("undo restores the whole file when nothing else touched it", async () => {
  const path = await Deno.makeTempFile();
  try {
    await Deno.writeTextFile(path, "# mine\naudit=false\n");
    const w = await writeConf(
      path,
      upsertKey("# mine\naudit=false\n", "equals", "audit", "true"),
    );
    await restoreConf(w)();
    assertEquals(await Deno.readTextFile(path), "# mine\naudit=false\n");
  } finally {
    await Deno.remove(path);
  }
});

Deno.test("a file the fix created is removed again by undo", async () => {
  const dir = await Deno.makeTempDir();
  const path = `${dir}/new.conf`;
  try {
    const w = await writeConf(path, upsertKey("", "equals", "audit", "true"));
    assertEquals(w.before, null, "file already existed");
    await restoreConf(w)();
    await assertRejects(() => Deno.stat(path));
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});
