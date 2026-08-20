// Developer tool configuration: npm, pip, wget, curl, readline.
//
// These are the files that decide whether a download is verified, whether a
// package install can run arbitrary code, and whether a paste into your shell
// can execute itself.
import type { ConfPolicy } from "../../type/policy.ts";

const NPM: ConfPolicy[] = [
  {
    id: "npm-strict-ssl",
    title: "npm has TLS certificate verification switched off",
    category: "security",
    severity: "critical",
    weight: 99,
    file: ".npmrc",
    format: "equals",
    key: "strict-ssl",
    safe: "true",
    missingIsBad: false,
    needs: "npm",
    detail: "every package npm downloads is accepted from any certificate",
    because:
      "Restores certificate checking. If one internal registry needs an " +
      "exception, scope it to that registry instead of all of them.",
  },
  {
    id: "npm-audit",
    title: "npm vulnerability auditing is switched off",
    category: "security",
    severity: "major",
    weight: 66,
    file: ".npmrc",
    format: "equals",
    key: "audit",
    safe: "true",
    missingIsBad: false,
    needs: "npm",
    detail: "installs no longer report known vulnerabilities in what you pull",
    because: "Restores the report. It reports; it never changes a dependency.",
  },
  {
    id: "npm-package-lock",
    title: "npm does not write a lockfile",
    category: "settings",
    severity: "major",
    weight: 64,
    file: ".npmrc",
    format: "equals",
    key: "package-lock",
    safe: "true",
    missingIsBad: false,
    needs: "npm",
    detail: "installs are not reproducible — the same command gives two trees",
    because:
      "Restores lockfile writing. Existing projects are unaffected until you " +
      "install in them.",
  },
  {
    id: "npm-save-exact",
    title: "npm saves dependency ranges rather than exact versions",
    category: "settings",
    severity: "minor",
    weight: 34,
    file: ".npmrc",
    format: "equals",
    key: "save-exact",
    safe: "true",
    missingIsBad: true,
    needs: "npm",
    detail:
      "a caret range lets a future publish change your build without a commit",
    because: "New dependencies are pinned exactly. Nothing already in a " +
      "package.json is rewritten.",
  },
  {
    id: "npm-update-notifier",
    title: "npm checks for its own updates over the network",
    category: "privacy",
    severity: "minor",
    weight: 26,
    file: ".npmrc",
    format: "equals",
    key: "update-notifier",
    safe: "false",
    missingIsBad: true,
    needs: "npm",
    detail: "every npm run may make an extra request before doing its work",
    because: "npm still installs and updates exactly as before.",
  },
  {
    id: "npm-fund",
    title: "npm prints funding messages after every install",
    category: "performance",
    severity: "minor",
    weight: 6,
    file: ".npmrc",
    format: "equals",
    key: "fund",
    safe: "false",
    missingIsBad: true,
    needs: "npm",
    detail: "output noise that hides the lines that matter",
    because: "`npm fund` still lists them when you ask.",
  },
  {
    id: "npm-ignore-scripts",
    title: "npm runs install scripts from every package",
    category: "security",
    severity: "critical",
    weight: 93,
    file: ".npmrc",
    format: "equals",
    key: "ignore-scripts",
    safe: "true",
    missingIsBad: true,
    needs: "npm",
    detail:
      "any package in your tree — direct or transitive — executes code at install time",
    because: "",
    advisory:
      "No automatic fix. This is the single strongest defence against npm " +
      "supply-chain attacks, and it is also the one that breaks native " +
      "modules and any package that builds itself. That trade is yours to " +
      "make: set `ignore-scripts=true` in ~/.npmrc and re-enable it per " +
      "project with `npm install --foreground-scripts`.",
  },
];

const PIP: ConfPolicy[] = [
  {
    id: "pip-require-venv",
    title: "pip will install into the system Python",
    category: "settings",
    severity: "major",
    weight: 63,
    file: ".config/pip/pip.conf",
    format: "ini",
    section: "global",
    key: "require-virtualenv",
    safe: "true",
    missingIsBad: true,
    needs: "pip3",
    detail:
      "a stray `pip install` can overwrite packages your distribution owns",
    because:
      "pip refuses outside a virtualenv instead. Override for one command " +
      "with PIP_REQUIRE_VIRTUALENV=false.",
  },
  {
    id: "pip-version-check",
    title: "pip checks for its own updates on every run",
    category: "performance",
    severity: "minor",
    weight: 8,
    file: ".config/pip/pip.conf",
    format: "ini",
    section: "global",
    key: "disable-pip-version-check",
    safe: "true",
    missingIsBad: true,
    needs: "pip3",
    detail: "an extra network round-trip before every install",
    because: "pip still installs and upgrades exactly as before.",
  },
];

const DOWNLOAD: ConfPolicy[] = [
  {
    id: "wget-check-cert",
    title: "wget has certificate checking switched off",
    category: "security",
    severity: "critical",
    weight: 94,
    file: ".wgetrc",
    format: "ini",
    key: "check_certificate",
    safe: "on",
    missingIsBad: false,
    needs: "wget",
    detail: "every HTTPS download is accepted from any certificate",
    because: "Restores certificate checking for all downloads.",
  },
  {
    id: "wget-hsts",
    title: "wget does not remember HTTPS-only sites",
    category: "security",
    severity: "minor",
    weight: 32,
    file: ".wgetrc",
    format: "ini",
    key: "hsts",
    safe: "on",
    missingIsBad: false,
    needs: "wget",
    detail: "a site that asked to be HTTPS-only can be downgraded next time",
    because: "wget honours HSTS. It never downgrades a site by itself.",
  },
  {
    id: "curl-insecure",
    title: "curl is configured to skip certificate checks",
    category: "security",
    severity: "critical",
    weight: 100,
    file: ".curlrc",
    format: "space",
    key: "insecure",
    safe: "",
    missingIsBad: false,
    presentIsBad: true,
    needs: "curl",
    detail:
      "every curl on this account — including ones inside scripts and installers — accepts any certificate",
    because:
      "The line is commented out, not deleted, so you can see what was there. " +
      "Individual commands can still pass -k when you mean it.",
  },
  {
    id: "curl-proxy-insecure",
    title: "curl skips certificate checks for its proxy",
    category: "security",
    severity: "major",
    weight: 87,
    file: ".curlrc",
    format: "space",
    key: "proxy-insecure",
    safe: "",
    missingIsBad: false,
    presentIsBad: true,
    needs: "curl",
    detail: "the connection to your proxy is unauthenticated",
    because: "The line is commented out, not deleted.",
  },
];

const SHELL: ConfPolicy[] = [
  {
    id: "readline-bracketed-paste",
    title: "Bracketed paste is switched off in readline",
    category: "security",
    severity: "major",
    weight: 72,
    file: ".inputrc",
    format: "space",
    key: "set enable-bracketed-paste",
    safe: "on",
    missingIsBad: false,
    detail:
      "text you paste into a shell can contain a newline and run itself before you can read it",
    because:
      "Pasted text is inserted as literal text and waits for you to press " +
      "Enter. This is readline's own default; the file has turned it off.",
  },
];

export const TOOL_POLICIES: ConfPolicy[] = [
  ...NPM,
  ...PIP,
  ...DOWNLOAD,
  ...SHELL,
];
