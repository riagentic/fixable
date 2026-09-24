// The privilege boundary. These are the tests that decide whether "no fix can
// harm this machine" is a claim or a property.
import { assertEquals, assertThrows } from "@std/assert";
import type { RootOp } from "../../src/type/check.ts";
import {
  buildScript,
  commandLines,
  invertChanges,
  isDropIn,
  narrows,
  parseResult,
  rootOpIsSafe,
  shq,
} from "../../src/lib/root.ts";
import { parseDropIn, renderDropIn, withBlock } from "../../src/lib/dropin.ts";

// ------------------------------------------------------------ chmod narrows

Deno.test("a chmod that widens is refused, in every direction", () => {
  // The single most important assertion in the app: the root tier's safety
  // argument is that a mode change can only ever remove access, so a fix
  // cannot hand anybody a file they could not already read.
  assertEquals(narrows("0640", "0644"), true, "0644 → 0640 removes o+r");
  assertEquals(narrows("0644", "0640"), false, "would add o+r");
  assertEquals(narrows("0600", "0644"), true);
  assertEquals(narrows("0755", "0700"), false, "would add g+rx and o+rx");
  assertEquals(narrows("0644", "0644"), false, "a no-op is not a fix");
  // A bit removed here and added there is still a widening.
  assertEquals(narrows("0464", "0644"), false, "swaps o+r for g+w");
});

Deno.test("only four-digit octal counts as a mode", () => {
  assertEquals(narrows("640", "0644"), false);
  assertEquals(narrows("0640", "rw-r--r--"), false);
  assertEquals(narrows("0999", "0644"), false);
});

Deno.test("a widening chmod cannot reach the script", () => {
  assertThrows(
    () =>
      buildScript([{
        op: "chmod",
        path: "/etc/shadow",
        mode: "0666",
        was: "0640",
      }]),
    Error,
    "refusing to build a root plan",
  );
});

Deno.test("undo may restore the exact previous mode, and only then", () => {
  const back: RootOp = {
    op: "chmod",
    path: "/etc/shadow",
    mode: "0644",
    was: "0640",
  };
  assertEquals(rootOpIsSafe(back, "fix"), false, "not allowed as a fix");
  assertEquals(rootOpIsSafe(back, "undo"), true, "must be allowed as an undo");
});

// ------------------------------------------------------------ drop-ins only

Deno.test("a write may only land on a file this app owns", () => {
  assertEquals(isDropIn("/etc/sysctl.d/99-fixable.conf"), true);
  assertEquals(isDropIn("/etc/modprobe.d/99-fixable-net.conf"), true);
  // Everything the distribution ships is out of reach, by name.
  assertEquals(isDropIn("/etc/sysctl.conf"), false);
  assertEquals(isDropIn("/etc/sysctl.d/99-sysctl.conf"), false);
  assertEquals(isDropIn("/etc/passwd"), false);
  assertEquals(isDropIn("/etc/pam.d/common-auth"), false);
  assertEquals(isDropIn("/etc/sudoers.d/99-fixable.conf"), false);
  // And so is anything that tries to climb out of a directory that is.
  assertEquals(isDropIn("/etc/sysctl.d/../../etc/99-fixable.conf"), false);
});

Deno.test("a write outside a drop-in cannot reach the script", () => {
  assertThrows(
    () =>
      buildScript([{
        op: "write",
        path: "/etc/passwd",
        mode: "0644",
        content: "root::0:0::/root:/bin/sh\n",
        before: null,
      }]),
    Error,
    "does not own",
  );
});

Deno.test("a removal cannot reach a file the system ships", () => {
  assertThrows(
    () => buildScript([{ op: "remove", path: "/etc/shadow" }]),
    Error,
    "not a Fixable drop-in",
  );
});

// -------------------------------------------------------------- sysctl only

Deno.test("a sysctl op can name nothing outside /proc/sys", () => {
  const ok: RootOp = {
    op: "sysctl",
    key: "net.ipv4.conf.all.accept_redirects",
    value: "0",
    was: "1",
  };
  assertEquals(rootOpIsSafe(ok), true);
  for (
    const key of [
      "kernel.dmesg_restrict; rm -rf /",
      "../../src/etc/passwd",
      "kernel.$(id)",
      "",
    ]
  ) {
    assertEquals(
      rootOpIsSafe({ ...ok, key }),
      false,
      `${JSON.stringify(key)} was accepted as a parameter name`,
    );
  }
  for (const value of ["0; reboot", "`id`", "$(id)", "a".repeat(65)]) {
    assertEquals(
      rootOpIsSafe({ ...ok, value }),
      false,
      `${JSON.stringify(value)} was accepted as a value`,
    );
  }
  // A pair like an ephemeral port range is a legitimate value.
  assertEquals(rootOpIsSafe({ ...ok, value: "1024 65535" }), true);
});

// ------------------------------------------------------------------ quoting

Deno.test("single-quoting survives a quote in the string", () => {
  assertEquals(shq("plain"), "'plain'");
  assertEquals(shq("it's"), `'it'\\''s'`);
  assertEquals(shq("; rm -rf /"), "'; rm -rf /'");
});

// ---------------------------------------------------------------- the shell

const SCRIPT_OPS: RootOp[] = [
  { op: "chmod", path: "/etc/shadow", mode: "0640", was: "0644" },
  {
    op: "write",
    path: "/etc/sysctl.d/99-fixable.conf",
    mode: "0644",
    content: "fs.protected_regular = 2\n",
    before: null,
  },
];

Deno.test("the generated script is valid shell", async () => {
  // `sh -n` parses without running. A heredoc inside an `if` condition is
  // exactly the kind of thing that is fine until it is not.
  const path = await Deno.makeTempFile({ suffix: ".sh" });
  try {
    await Deno.writeTextFile(path, buildScript(SCRIPT_OPS));
    const out = await new Deno.Command("sh", {
      args: ["-n", path],
      stderr: "piped",
    }).output();
    assertEquals(
      out.code,
      0,
      new TextDecoder().decode(out.stderr),
    );
  } finally {
    await Deno.remove(path);
  }
});

Deno.test("the script really writes what it says, and reports each step", async () => {
  // End to end, without root: the same builder, the same shell, against paths
  // inside a temporary directory. What is being proven is that a step which
  // cannot work is reported as a failure rather than passing silently — the
  // first op below targets /etc/shadow and will not succeed as this user.
  const dir = await Deno.makeTempDir();
  try {
    const target = `${dir}/99-fixable.conf`;
    const script = buildScript(SCRIPT_OPS)
      .replaceAll("/etc/sysctl.d/99-fixable.conf", target);
    // Fed on stdin, exactly as root.server.ts hands it to the root shell —
    // the heredoc has to survive being read from a pipe.
    const sh = new Deno.Command("sh", { stdin: "piped", stdout: "piped" })
      .spawn();
    const writer = sh.stdin.getWriter();
    await writer.write(new TextEncoder().encode(script));
    await writer.close();
    const out = await sh.output();
    const { steps, finished } = parseResult(
      new TextDecoder().decode(out.stdout),
    );
    assertEquals(finished, true, "the script did not run to the end");
    assertEquals(steps.length, 2, "not every step reported");
    assertEquals(steps[0]!.ok, false, "chmod on /etc/shadow was not refused");
    assertEquals(steps[1]!.ok, true, "the drop-in was not written");
    assertEquals(
      await Deno.readTextFile(target),
      "fs.protected_regular = 2\n",
    );
    assertEquals((await Deno.stat(target)).mode! & 0o777, 0o644);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("a step that fails does not stop the ones after it", () => {
  const out = [
    "__fixable__fail 0",
    "noise from a command",
    "__fixable__ok 1",
    "__fixable__ok 2",
    "__fixable__done",
  ].join("\n");
  const { steps, finished } = parseResult(out);
  assertEquals(finished, true);
  assertEquals(steps.map((s) => `${s.index}:${s.ok}`), [
    "0:false",
    "1:true",
    "2:true",
  ]);
});

// ----------------------------------------------------------------- drop-ins

Deno.test("blocks round-trip, one per check, sorted", () => {
  const blocks = withBlock(
    withBlock(new Map(), "sysctl-b", "b = 1"),
    "sysctl-a",
    "a = 1",
  );
  const text = renderDropIn(blocks);
  // Sorted, so the same set of applied checks always renders identically.
  assertEquals(
    text.indexOf("fixable:sysctl-a") < text.indexOf("fixable:sysctl-b"),
    true,
  );
  assertEquals(
    parseDropIn(text),
    new Map([["sysctl-a", "a = 1"], ["sysctl-b", "b = 1"]]),
  );
});

Deno.test("undoing one check leaves every other check's line alone", () => {
  const before = renderDropIn(
    withBlock(withBlock(new Map(), "one", "x = 1"), "two", "y = 2"),
  );
  const after = renderDropIn(withBlock(parseDropIn(before), "one", null));
  assertEquals(parseDropIn(after), new Map([["two", "y = 2"]]));
  assertEquals(after.includes("x = 1"), false);
});

Deno.test("the last block out empties the file, so the caller can delete it", () => {
  const one = renderDropIn(withBlock(new Map(), "only", "z = 1"));
  assertEquals(renderDropIn(withBlock(parseDropIn(one), "only", null)), "");
});

Deno.test("a marker with nothing under it is not a block", () => {
  assertEquals(
    parseDropIn("# fixable:empty\n\n# fixable:real\nk = 1\n").size,
    1,
  );
});

// --------------------------------------------------------------- the way back

Deno.test("every change a check can make has an inverse", () => {
  const back = invertChanges([
    { op: "chmod", path: "/etc/crontab", mode: "0600", was: "0644" },
    {
      op: "line",
      path: "/etc/sysctl.d/99-fixable.conf",
      mode: "0644",
      id: "sysctl-x",
      text: "a.b = 1",
    },
    { op: "sysctl", key: "a.b", value: "1", was: "0" },
  ]);
  // Reversed, because changes in one plan can touch the same thing.
  assertEquals(back[0], { op: "sysctl", key: "a.b", value: "0", was: "1" });
  assertEquals(back[1], {
    op: "line",
    path: "/etc/sysctl.d/99-fixable.conf",
    mode: "0644",
    id: "sysctl-x",
    text: null,
  });
  assertEquals(back[2], {
    op: "chmod",
    path: "/etc/crontab",
    mode: "0644",
    was: "0600",
  });
});

Deno.test("the preview shows the payload, not just that there is one", () => {
  // Nobody can consent to "writes a file". The line and its contents both
  // have to be on screen before a password is asked for.
  const lines = commandLines(SCRIPT_OPS);
  assertEquals(lines[0], "chmod 640 /etc/shadow    # was 644");
  assertEquals(lines[1]!.includes("fs.protected_regular = 2"), true);
});
