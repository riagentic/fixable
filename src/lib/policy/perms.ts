// The permission catalogue: rows from the three tables next to this file,
// turned into policies by three builders.
//
// Every row is auto-fixable, because narrowing a mode takes nothing away: the
// file keeps its contents, its owner keeps its access, and the writer refuses
// outright any change that would widen it.
import type { PermPolicy } from "../../type/policy.ts";
import { SECRET_FILES } from "./perms-secrets.ts";
import { HISTORY_FILES } from "./perms-history.ts";
import { PRIVATE_DIRS, WRITABLE_PATHS } from "./perms-dirs.ts";

const GO = 0o077; // any group/other access at all
const GO_W = 0o022; // group/other write

/** Weights descend within a family so that, inside one severity band, rows
 *  still come out in a deliberate order rather than an accidental one. */
const step = (top: number, i: number) => Math.max(1, top - i);

export const PERM_POLICIES: PermPolicy[] = [
  {
    id: "perm-home",
    title: "Your home directory is writable by other accounts",
    category: "security",
    severity: "critical",
    weight: 99,
    paths: ["."],
    target: 0o755,
    mask: GO_W,
    what: "your home directory",
  },
  {
    id: "perm-gnupg-keys",
    title: "A GnuPG private key is readable by other accounts",
    category: "security",
    severity: "critical",
    weight: 98,
    paths: [".gnupg/private-keys-v1.d/*"],
    target: 0o600,
    mask: GO,
    what: "your GnuPG private keys",
  },
  {
    id: "perm-rhosts",
    title: "A legacy rhosts trust file is readable by other accounts",
    category: "security",
    severity: "critical",
    weight: 97,
    paths: [".rhosts", ".shosts"],
    target: 0o600,
    mask: GO,
    what: "~/.rhosts and ~/.shosts",
  },

  // Code-execution paths: what matters here is the WRITE bit. A file another
  // account can write is a program that runs as you at your next login.
  // 0755 keeps a directory traversable and a script readable while stripping
  // group/other write, which is all `mask` flags.
  ...WRITABLE_PATHS.map(
    ([id, paths, what, title, severity, weight]): PermPolicy => ({
      id: `perm-w-${id}`,
      title,
      category: "security",
      severity,
      weight,
      paths,
      target: 0o755,
      mask: GO_W,
      what,
    }),
  ),

  ...SECRET_FILES.map(([id, path, what, severity], i): PermPolicy => ({
    id: `perm-${id}`,
    title: `${what} is readable by other accounts`,
    category: "security",
    severity,
    weight: step(70, i),
    paths: [path],
    target: 0o600,
    mask: GO,
    what,
  })),

  ...PRIVATE_DIRS.map(([id, path, what, severity], i): PermPolicy => ({
    id: `perm-${id}`,
    title: `${what} is reachable by other accounts`,
    category: "security",
    severity,
    weight: step(68, i),
    paths: [path],
    target: 0o700,
    mask: GO,
    what,
  })),

  ...HISTORY_FILES.map(([id, path, name], i): PermPolicy => ({
    id: `perm-${id}`,
    title: `${name} is readable by other accounts`,
    category: "privacy",
    severity: "minor",
    weight: step(40, i),
    paths: [path],
    target: 0o600,
    mask: GO,
    what: name,
  })),
];
