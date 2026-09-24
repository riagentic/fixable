// The config-file engine. This is the code that rewrites files a user owns,
// so it gets the most tests in the project.
import { assertEquals, assertRejects } from "@std/assert";
import {
  disableKey,
  readFirstKey,
  readKey,
  sudoDefault,
  upsertKey,
  upsertSshOption,
} from "../../src/lib/conf.ts";
import { restoreConf, writeConf } from "../../src/cell/conf.server.ts";
import { readText } from "../../src/cell/sys.server.ts";

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

Deno.test("an earlier Host * block is not reused — it would beat later hosts", () => {
  // First match wins: a line added to this `Host *` would override the
  // `Host prod` block below it. A new trailing block is the only safe place.
  const text = "Host *\n    User me\n\nHost prod\n    ForwardAgent yes\n";
  const next = upsertSshOption(text, "ForwardAgent", "no");
  const lines = next.split("\n");
  const prod = lines.indexOf("Host prod");
  const added = lines.findIndex((l) => l.includes("ForwardAgent no"));
  assertEquals(added > prod, true, "landed above a per-host block");
  assertEquals(lines.lastIndexOf("Host *") > prod, true, "no trailing block");
  assertEquals(next.startsWith("Host *\n    User me\n"), true);
});

Deno.test("a trailing Match all block is reused", () => {
  const text = "Host prod\n    User deploy\n\nMatch all\n    User me\n";
  const next = upsertSshOption(text, "ForwardAgent", "no");
  assertEquals(
    next,
    "Host prod\n    User deploy\n\nMatch all\n    User me\n    ForwardAgent no\n",
  );
});

Deno.test("a key already set globally is edited where ssh reads it", () => {
  // Top-of-file lines are global and come first; appending a later block
  // would change nothing.
  const top = "ForwardAgent yes\n\nHost prod\n    User deploy\n";
  assertEquals(
    upsertSshOption(top, "ForwardAgent", "no"),
    "ForwardAgent no\n\nHost prod\n    User deploy\n",
  );
  // Same for an earlier `Host *` that already holds the key: its line is the
  // effective one, and editing it in place keeps precedence as it was.
  const star = "Host *\n    ForwardAgent yes\n\nHost prod\n    User x\n";
  assertEquals(
    upsertSshOption(star, "ForwardAgent", "no"),
    "Host *\n    ForwardAgent no\n\nHost prod\n    User x\n",
  );
  // …but a per-host value is never the one edited.
  const host = "Host prod\n    ForwardAgent yes\n";
  const next = upsertSshOption(host, "ForwardAgent", "no");
  assertEquals(next.includes("    ForwardAgent yes"), true);
  assertEquals(next.trimEnd().endsWith("ForwardAgent no"), true);
});

// ------------------------------------------------------------ sshd / sudo

Deno.test("readFirstKey takes the first value, as sshd does", () => {
  const text =
    "# PermitRootLogin yes\nPermitRootLogin no\npermitrootlogin yes\n";
  assertEquals(readFirstKey(text, "space", "PermitRootLogin"), "no");
  assertEquals(readFirstKey(text, "space", "X11Forwarding"), null);
});

Deno.test("sudoDefault parses entries instead of matching substrings", () => {
  // A TAB separator is valid sudoers.
  assertEquals(sudoDefault("Defaults\tuse_pty\n", "use_pty"), true);
  // `!use_pty` negates; the later line wins.
  assertEquals(
    sudoDefault("Defaults use_pty\nDefaults !use_pty\n", "use_pty"),
    false,
  );
  assertEquals(sudoDefault("Defaults !use_pty\n", "use_pty"), false);
  // `=50` is not `=5`.
  assertEquals(
    sudoDefault(
      "Defaults env_reset, timestamp_timeout=50\n",
      "timestamp_timeout",
    ),
    "50",
  );
  assertEquals(
    sudoDefault("Defaults env_reset,mail_badpass\n", "env_reset"),
    true,
  );
  assertEquals(
    sudoDefault('Defaults logfile="/var/log/sudo.log"\n', "logfile"),
    "/var/log/sudo.log",
  );
  // Comments and scoped (non-global) Defaults do not count.
  assertEquals(sudoDefault("# Defaults use_pty\n", "use_pty"), null);
  assertEquals(sudoDefault("Defaults:alice use_pty\n", "use_pty"), null);
  // Backslash continuation joins the next line.
  assertEquals(
    sudoDefault("Defaults env_reset,\\\n  use_pty\n", "use_pty"),
    true,
  );
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

// ------------------------------------------------------------ writeConf safety

Deno.test("writeConf refuses a symlink and leaves it a symlink", async () => {
  const dir = await Deno.makeTempDir();
  try {
    await Deno.writeTextFile(`${dir}/real`, "audit=false\n");
    await Deno.symlink(`${dir}/real`, `${dir}/link`);
    await assertRejects(() => writeConf(`${dir}/link`, "audit=true\n"));
    assertEquals((await Deno.lstat(`${dir}/link`)).isSymlink, true);
    assertEquals(await Deno.readTextFile(`${dir}/real`), "audit=false\n");
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("writeConf refuses a file that is not UTF-8, writing nothing", async () => {
  const dir = await Deno.makeTempDir();
  const path = `${dir}/latin1.conf`;
  const bytes = new Uint8Array([0x23, 0x20, 0xe9, 0x0a]); // "# é" in Latin-1
  try {
    await Deno.writeFile(path, bytes);
    await assertRejects(() => writeConf(path, "x\n"));
    assertEquals(await Deno.readFile(path), bytes);
    assertEquals([...Deno.readDirSync(dir)].length, 1, "temp file left behind");
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("writeConf keeps the mode, and a new file is 0600", async () => {
  const dir = await Deno.makeTempDir();
  try {
    await Deno.writeTextFile(`${dir}/a`, "x\n");
    await Deno.chmod(`${dir}/a`, 0o640);
    await writeConf(`${dir}/a`, "y\n");
    assertEquals((await Deno.stat(`${dir}/a`)).mode! & 0o7777, 0o640);
    await writeConf(`${dir}/b`, "y\n");
    assertEquals((await Deno.stat(`${dir}/b`)).mode! & 0o7777, 0o600);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("an unreadable file is not treated as absent", async () => {
  if (Deno.uid() === 0) return; // root reads everything
  const dir = await Deno.makeTempDir();
  const path = `${dir}/locked.conf`;
  try {
    await Deno.writeTextFile(path, "secret=1\n");
    await Deno.chmod(path, 0o000);
    await assertRejects(() => readText(path), Deno.errors.PermissionDenied);
    await assertRejects(() => writeConf(path, "x\n"));
    await Deno.chmod(path, 0o600);
    assertEquals(await Deno.readTextFile(path), "secret=1\n");
    assertEquals(await readText(`${dir}/missing`), null);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});
