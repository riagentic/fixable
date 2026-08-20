// Catalogue integrity. These are the tests that make growing the catalogue a
// matter of adding rows: a row that would misbehave on someone's machine fails
// here instead, before it can ever be probed.
import { assertEquals } from "@std/assert";
import { clears, isBad } from "../../lib/verdict.ts";
import { SETTING_POLICIES } from "../../cell/check-desktop.server.ts";
import { PERM_POLICIES } from "../../lib/policy/perms.ts";
import { GIT_POLICIES } from "../../lib/policy/git.ts";
import { SYSCTL_POLICIES } from "../../lib/policy/sysctl.ts";
import { CONF_POLICIES } from "../../cell/check-conf.server.ts";
import { SSH_POLICIES } from "../../lib/policy/ssh.ts";
import { MOZILLA_POLICIES } from "../../cell/check-mozilla.server.ts";
import { ALL_CHROMIUM_POLICIES as CHROMIUM_POLICIES } from "../../cell/check-chromium.server.ts";
import { ETC_POLICIES } from "../../cell/check-etc.server.ts";
import { CHECKS } from "../../cell/checks.server.ts";
import { NO_BUTTON, OPTIONAL, RETIRED } from "../../lib/policy/preferences.ts";

Deno.test("isBad answers booleans, integers and 'cannot tell'", () => {
  assertEquals(isBad("true", "true"), true);
  // ssh -G says yes/no, .wgetrc says on/off — one parser answers for all of
  // them, because a policy row describes the setting, not the dialect.
  assertEquals(isBad("true", "yes"), true);
  assertEquals(isBad("false", "no"), true);
  assertEquals(isBad("false", "off"), true);
  assertEquals(isBad("true", "on"), true);
  // A tri-state value is "cannot tell", never "fine".
  assertEquals(isBad("true", "accept-new"), null);
  // Substring clauses, for algorithm lists.
  assertEquals(isBad("~cbc", "aes256-cbc,aes128-ctr"), true);
  assertEquals(isBad("~cbc", "aes128-ctr"), false);
  assertEquals(isBad("true", "false"), false);
  assertEquals(isBad("false", "false"), true);
  assertEquals(isBad("=0", "uint32 0"), true);
  assertEquals(isBad("=-1", "-1"), true);
  assertEquals(isBad("=-1", "30"), false);
  assertEquals(isBad(">30", "uint32 90"), true);
  assertEquals(isBad(">30", "30"), false);
  assertEquals(isBad("<2", "1"), true);
  assertEquals(isBad("<2", "2"), false);
  // A boolean clause against a string, and a numeric clause against no number.
  assertEquals(isBad("true", "'grid'"), null);
  assertEquals(isBad(">30", "none"), null);
});

Deno.test("every setting policy's safe value actually clears its own clause", () => {
  // Without this, a row ships a Fix button that runs, changes the setting, and
  // leaves the issue standing — which the registry then reports as a failure
  // to the user. The bug belongs here, not on their screen.
  for (const p of SETTING_POLICIES) {
    if (p.advisory) continue; // no button, so nothing to clear
    assertEquals(
      clears(p.bad, p.safe),
      true,
      `${p.id}: safe value "${p.safe}" still satisfies bad clause "${p.bad}"`,
    );
  }
});

Deno.test("every sysctl policy's safe value clears its own clause", () => {
  for (const p of SYSCTL_POLICIES) {
    assertEquals(
      clears(p.bad, p.safe),
      true,
      `${p.id}: safe value "${p.safe}" still satisfies "${p.bad}"`,
    );
  }
});

Deno.test("catalogue ids are unique across every family", () => {
  const ids = [
    ...SETTING_POLICIES.map((p) => p.id),
    ...PERM_POLICIES.map((p) => p.id),
    ...GIT_POLICIES.map((p) => p.id),
    ...SYSCTL_POLICIES.map((p) => p.id),
    ...CONF_POLICIES.map((p) => p.id),
    ...SSH_POLICIES.map((p) => p.id),
    ...MOZILLA_POLICIES.map((p) => p.id),
    ...CHROMIUM_POLICIES.map((p) => p.id),
    ...ETC_POLICIES.map((p) => p.id),
  ];
  const seen = new Set<string>();
  const dupes = ids.filter((id) => seen.size === seen.add(id).size);
  assertEquals(dupes, [], "duplicate catalogue ids");
});

Deno.test("permission targets are narrower than the bits they object to", () => {
  // The fix writes `target & current`. If `target` still carried a bit from
  // `mask`, the fix would leave the very access it flagged.
  for (const p of PERM_POLICIES) {
    assertEquals(
      p.target & p.mask,
      0,
      `${p.id}: target ${p.target.toString(8)} keeps masked bits`,
    );
    assertEquals(p.paths.length > 0, true, `${p.id}: no paths`);
  }
});

Deno.test("every row explains itself in the user's terms", () => {
  for (const p of SETTING_POLICIES) {
    assertEquals(p.title.length > 10, true, `${p.id}: thin title`);
    assertEquals(p.detail.length > 10, true, `${p.id}: thin detail`);
    assertEquals(
      (p.advisory ?? p.because).length > 20,
      true,
      `${p.id}: no reason given for the change`,
    );
  }
  for (const p of [...GIT_POLICIES, ...CONF_POLICIES, ...SSH_POLICIES]) {
    assertEquals(
      (p.advisory ?? p.because).length > 20,
      true,
      `${p.id}: no reason given for the change`,
    );
    assertEquals(p.detail.length > 10, true, `${p.id}: thin detail`);
    assertEquals(p.title.length > 10, true, `${p.id}: thin title`);
  }
});

Deno.test("every auto row names a value the check would accept", () => {
  // A conf row whose safe value differs from what the probe compares against
  // would fix, re-probe, and report itself as still broken.
  for (const p of CONF_POLICIES) {
    if (p.advisory || p.presentIsBad) continue;
    assertEquals(
      p.safe === p.safe.trim(),
      true,
      `${p.id}: safe value has stray whitespace`,
    );
  }
  for (const p of SSH_POLICIES) {
    if (p.advisory) continue;
    assertEquals(
      clears(p.bad, p.safe),
      true,
      `${p.id}: safe value "${p.safe}" still satisfies "${p.bad}"`,
    );
  }
});

Deno.test("a presentIsBad row never also claims a safe value", () => {
  // The two are contradictory: one says "this key must not be here", the other
  // says "write this into it".
  for (const p of CONF_POLICIES) {
    if (!p.presentIsBad) continue;
    assertEquals(p.safe, "", `${p.id}: presentIsBad row carries a safe value`);
    assertEquals(p.missingIsBad, false, `${p.id}: missing cannot also be bad`);
  }
});

Deno.test("no two rows ask the same question of the same setting", () => {
  // A catalogue grows by copy-and-edit, and the failure mode is two rows on one
  // key: the user sees the same problem twice, and "Fix all" writes it twice.
  // Checks for the sake of the count are exactly what this catalogue is not.
  const seen = (pairs: string[], what: string) => {
    const dupes = pairs.filter((k, i) => pairs.indexOf(k) !== i);
    assertEquals(dupes, [], `${what}: two rows on one target`);
  };
  seen(
    MOZILLA_POLICIES.map((p) => `${p.product}:${p.pref}:${p.bad}`),
    "mozilla",
  );
  seen(CHROMIUM_POLICIES.map((p) => `${p.path}:${p.bad}`), "chromium");
  seen(
    SETTING_POLICIES.map((p) => `${p.schemas[0]}:${p.key}:${p.bad}`),
    "gsettings",
  );
  seen(GIT_POLICIES.map((p) => p.key), "git");
  seen(CONF_POLICIES.map((p) => `${p.file}:${p.key}`), "config files");
  seen(SSH_POLICIES.map((p) => `${p.key}:${p.bad}`), "ssh");
  seen(SYSCTL_POLICIES.map((p) => p.key), "sysctl");
  seen(ETC_POLICIES.map((p) => `${p.file}:${p.key}:${p.safe}`), "/etc");
  seen(PERM_POLICIES.map((p) => `${p.paths.join()}:${p.mask}`), "permissions");
});

Deno.test("every browser row's safe value clears its own clause", () => {
  for (const p of [...MOZILLA_POLICIES, ...CHROMIUM_POLICIES]) {
    const safe = p.safe.startsWith('"') ? p.safe.slice(1, -1) : p.safe;
    assertEquals(
      clears(p.bad, safe),
      true,
      `${p.id}: safe value "${p.safe}" still satisfies "${p.bad}"`,
    );
  }
});

Deno.test("the assembled catalogue is coherent", () => {
  // The registry is what actually runs, so the invariants are asserted on it
  // rather than on the tables that feed it.
  const ids = CHECKS.map((c) => c.id);
  assertEquals(new Set(ids).size, ids.length, "duplicate check id in registry");
  assertEquals(CHECKS.length >= 1000, true, `only ${CHECKS.length} checks`);
  for (const c of CHECKS) {
    assertEquals(c.title.length > 10, true, `${c.id}: thin title`);
    assertEquals(c.explanation.length > 60, true, `${c.id}: thin explanation`);
    assertEquals(c.weight > 0, true, `${c.id}: no weight`);
    // A manual check must say what to do instead of just refusing.
    if (c.tier === "advisory") {
      assertEquals(
        /No automatic fix|reported only|belongs to root|needs root/i.test(
          c.explanation,
        ),
        true,
        `${c.id}: manual check does not say why`,
      );
    }
  }
});

// ---------------------------------------------------------------- the audit

Deno.test("the audit still names checks that exist", async () => {
  // A rename would silently un-audit a row: the id in preferences.ts would
  // match nothing, the check would go back to writing, and nobody would know
  // until it changed a setting on somebody's machine. So the audit is checked
  // against the catalogue, not trusted.
  const { CHECKS: RAW } = await import("../../cell/checks.server.ts");
  const live = new Set(RAW.map((c) => c.id));
  const retired = new Set(Object.keys(RETIRED));
  for (const id of [...Object.keys(OPTIONAL), ...Object.keys(NO_BUTTON)]) {
    assertEquals(
      live.has(id) || retired.has(id),
      true,
      `preferences.ts names "${id}", which is not a check any more`,
    );
  }
});

Deno.test("no audited check runs unattended", () => {
  // The audit's promise is not "no button". It is "nothing here happens
  // unless somebody presses it" — which is the same as saying no audited row
  // is ever in the `fix` tier, because `fix` is the only tier "Fix all"
  // sweeps up.
  for (const c of CHECKS) {
    if (c.id in OPTIONAL) {
      assertEquals(c.tier, "optional", `${c.id}: audited, but runs unattended`);
    }
    if (c.id in NO_BUTTON) {
      assertEquals(c.tier, "advisory", `${c.id}: must have no button at all`);
    }
  }
});

Deno.test("a retired check is gone from the catalogue", () => {
  for (const id of Object.keys(RETIRED)) {
    assertEquals(
      CHECKS.some((c) => c.id === id),
      false,
      `${id}: retired by the audit but still registered`,
    );
  }
});

Deno.test("an optional check keeps its fix, and a no-button one loses it", async () => {
  // Both halves have to reach the FINDING, not just the label. An optional row
  // whose probe stopped handing back `apply` would be a button that cannot
  // act; a no-button row that still hands one out would put a Fix button on
  // the accessibility rows, and the registry's drift guard would throw on it.
  const optional = CHECKS.filter((c) => c.id in OPTIONAL);
  assertEquals(optional.length > 50, true, "the audit lost its subjects");
  for (const c of optional.slice(0, 40)) {
    const f = await c.probe();
    if (f) {
      assertEquals(
        typeof f.apply === "function",
        true,
        `${c.id}: optional, but its finding carries no fix`,
      );
    }
  }
  for (const c of CHECKS.filter((x) => x.id in NO_BUTTON)) {
    const f = await c.probe();
    if (f) {
      assertEquals(
        f.apply === undefined && f.root === undefined,
        true,
        `${c.id}: must have no button, but its finding carries one`,
      );
    }
  }
});

Deno.test("nothing read from the running system may write", async () => {
  // Hardware, firewalls, mounts, services and containers are the places a
  // "fix" can take down something that is working, for a program this app
  // cannot see. The engine gives every one of these checks tier "advisory";
  // this asserts the whole family really did come out that way — including
  // that none of them acquired a root plan when the sudo tier arrived.
  const { SYS_POLICIES } = await import("../../cell/checks.server.ts");
  const ids = new Set(SYS_POLICIES.map((p) => p.id));
  assertEquals(ids.size > 500, true, `only ${ids.size} system readings`);
  // A row may opt out, but only by naming a drop-in — and the vocabulary for
  // that is one line in one file, which cannot express stopping a service or
  // unloading a module however it is written.
  const writes = new Set(SYS_POLICIES.filter((p) => p.fix).map((p) => p.id));
  for (const c of CHECKS) {
    if (ids.has(c.id) && !writes.has(c.id)) {
      assertEquals(c.tier, "advisory", `${c.id}: a system reading that writes`);
    }
  }
  // Opting out is meant to stay rare and deliberate. If this trips, the
  // question to ask is whether the newest batch really is all drop-ins.
  assertEquals(
    writes.size < ids.size / 10,
    true,
    `${writes.size} of ${ids.size} system readings now write — audit them`,
  );
});

Deno.test("a system reading that writes can only write a Fixable drop-in", async () => {
  // The privilege boundary, checked at the level of the catalogue rather than
  // the level of the shell. Every drop-in path a row names has to be one the
  // gate in lib/root.ts would accept, so a typo — or a path that is somebody
  // else's file — fails here rather than at a password prompt.
  const { SYS_POLICIES } = await import("../../cell/checks.server.ts");
  const { isDropIn } = await import("../../lib/root.ts");
  for (const p of SYS_POLICIES.filter((x) => x.fix)) {
    assertEquals(
      isDropIn(p.fix!.path),
      true,
      `${p.id}: ${p.fix!.path} is not a file this app may write`,
    );
  }
});

Deno.test("every manual check hands over something actionable", () => {
  // A row that says "no automatic fix" and stops there is worse than no row:
  // it reports a problem and leaves the reader with nowhere to go.
  //
  // The test is on substance, not on shape. An earlier version demanded a
  // backtick command and failed 23 rows whose right answer is prose — "clean
  // the vents", "back up before anything else", "log out and pick a Wayland
  // session". So what is checked is that something survives once the generic
  // refusal is stripped off.
  // Drop the opening refusal — one sentence, nothing cleverer. A pattern that
  // tried to strip the whole preamble kept eating the guidance with it, which
  // is its own lesson about testing prose with regular expressions.
  const withoutRefusal = (text: string) =>
    text.split(/(?<=\.)\s+/).slice(1).join(" ").trim();
  // Twenty characters, not forty: for many rows the ideal answer IS short —
  // "`sudo systemctl enable ufw`." is a complete remedy and a longer one would
  // be padding. What is being caught is a row that refuses and says nothing.
  const thin = CHECKS.filter((c) =>
    c.tier === "advisory" && withoutRefusal(c.explanation).length < 20
  );
  assertEquals(thin.map((c) => c.id), [], "manual checks that only refuse");
});

Deno.test("every check with a button names the way back", () => {
  // The reversibility claim is load-bearing for the whole safety argument, so
  // it is asserted rather than assumed — for all three acting tiers, since the
  // root tier makes exactly the same promise and pays a password for it.
  const silent = CHECKS.filter((c) =>
    c.tier !== "advisory" && !/Undo|undo|previous|restores/.test(c.explanation)
  );
  assertEquals(
    silent.map((c) => c.id),
    [],
    "checks with a button that never mention undo",
  );
});

Deno.test("permission targets can only ever narrow", () => {
  // Proven over the modes a real file or directory actually carries: the mode
  // a fix would write is always a subset of the one already there, and a
  // directory always keeps the owner-execute bit that makes it usable.
  const MODES = [0o400, 0o600, 0o640, 0o644, 0o700, 0o750, 0o755, 0o775, 0o777];
  for (const p of PERM_POLICIES) {
    assertEquals(
      (p.target & 0o400) !== 0,
      true,
      `${p.id}: target drops owner read`,
    );
    assertEquals(
      p.target & p.mask,
      0,
      `${p.id}: target keeps a bit it objects to`,
    );
    for (const current of MODES) {
      for (const dir of [false, true]) {
        const wanted = dir ? p.target | 0o100 : p.target;
        const next = wanted & current;
        assertEquals(
          next & ~current,
          0,
          `${p.id}: would widen ${current.toString(8)}`,
        );
        if (dir && (current & 0o100) !== 0) {
          assertEquals(next & 0o100, 0o100, `${p.id}: would break a directory`);
        }
      }
    }
  }
});

// ------------------------------------------------------------ the root audit

Deno.test("every kernel parameter is either allowed as root or refused by name", async () => {
  // The same rule the preferences audit follows, for the tier that has a
  // password behind it: a row cannot default into being writable, and a
  // rename cannot quietly move one across the line. Both directions are
  // checked, so an id that no longer exists is also caught.
  const { SYSCTL_POLICIES } = await import("../../lib/policy/sysctl.ts");
  const { SYSCTL_ROOT_DENIED, SYSCTL_ROOT_SAFE } = await import(
    "../../lib/policy/root-safe.ts"
  );
  const ids = new Set(SYSCTL_POLICIES.map((p) => p.id));
  for (const id of ids) {
    assertEquals(
      SYSCTL_ROOT_SAFE.has(id) !== (id in SYSCTL_ROOT_DENIED),
      true,
      `${id}: must be allowed or refused in root-safe.ts, and exactly one`,
    );
  }
  for (const id of [...SYSCTL_ROOT_SAFE, ...Object.keys(SYSCTL_ROOT_DENIED)]) {
    assertEquals(
      ids.has(id),
      true,
      `root-safe.ts names "${id}", which is gone`,
    );
  }
});

Deno.test("nothing that would break containers, the network or a debugger is writable", async () => {
  // Named rather than derived. These are the parameters a hardening guide will
  // happily tell you to set and that would, on this machine, stop Docker from
  // starting, leave a laptop with no IPv6, or turn `gdb -p` into a permission
  // error. If one of them ever shows up in the allowed set, this fails.
  const { SYSCTL_ROOT_SAFE } = await import("../../lib/policy/root-safe.ts");
  const FORBIDDEN = [
    "sysctl-userns", // Docker, podman, Flatpak, Chromium sandboxes
    "sysctl-max-user-namespaces",
    "sysctl-ip-forward", // container and VM networking
    "sysctl-ipv6-forward",
    "sysctl-forwarding-default",
    "sysctl-rp-filter", // VPN and asymmetric routing
    "sysctl-default-rp-filter",
    "sysctl-ipv6-ra", // IPv6 autoconfiguration
    "sysctl-ipv6-default-ra",
    "sysctl-ipv6-autoconf",
    "sysctl-ptrace", // debuggers and profilers
    "sysctl-perf-event",
    "sysctl-unprivileged-bpf",
    "sysctl-panic-on-oops", // turns a survivable fault into a reboot
    "sysctl-ip-local-port-range", // ephemeral ports colliding with services
  ];
  for (const id of FORBIDDEN) {
    assertEquals(
      SYSCTL_ROOT_SAFE.has(id),
      false,
      `${id}: became root-writable — this one breaks working software`,
    );
  }
});

Deno.test("a trade can only be marked on something already allowed", async () => {
  // The optional list narrows the allowed list; it cannot smuggle a row into
  // it. A refused parameter named here would otherwise become writable by
  // being called a choice.
  const { SYSCTL_ROOT_OPTIONAL, SYSCTL_ROOT_SAFE } = await import(
    "../../lib/policy/root-safe.ts"
  );
  for (const id of Object.keys(SYSCTL_ROOT_OPTIONAL)) {
    assertEquals(
      SYSCTL_ROOT_SAFE.has(id),
      true,
      `${id}: marked optional but never allowed as a root fix`,
    );
  }
});

Deno.test("a root fix is never swept up unless it is a repair", async () => {
  // "Fix all (sudo required)" takes the `sudo` tier and nothing else. A change
  // that trades a capability away needs a password AND a deliberate press, and
  // the tier is what carries the second half of that.
  const { CHECKS: ALL } = await import("../../cell/checks.server.ts");
  for (const c of ALL.filter((x) => x.tier === "sudo")) {
    assertEquals(
      c.id in OPTIONAL || c.id in NO_BUTTON,
      false,
      `${c.id}: audited as a choice, but would run in a root batch`,
    );
  }
});
