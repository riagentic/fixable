// Telemetry and traces: the services that report on this machine, and the
// records it keeps of what you did on it.
import type { SysPolicy } from "../../../type/policy.ts";

const sh = (script: string) => ({
  kind: "cmd" as const,
  cmd: "sh",
  args: ["-c", script] as const,
});

/** [unit, what it sends, band, weight, how] */
const REPORTERS: [string, string, SysPolicy["severity"], number, string][] = [
  [
    "whoopsie",
    "crash reports, including memory from the crashed program, to the distribution",
    "major",
    66,
    "`sudo systemctl disable --now whoopsie` and set `report_crashes=false` in /etc/default/whoopsie.",
  ],
  [
    "apport",
    "crash data collected locally and offered for upload",
    "minor",
    48,
    "`sudo systemctl disable --now apport` and set `enabled=0` in /etc/default/apport.",
  ],
  [
    "kerneloops",
    "kernel oops traces to a public collector",
    "minor",
    46,
    "`sudo systemctl disable --now kerneloops`.",
  ],
  [
    "popularity-contest",
    "a weekly list of every package you have installed",
    "minor",
    50,
    "`sudo dpkg-reconfigure popularity-contest` and answer no, or `sudo systemctl disable --now popularity-contest.timer`.",
  ],
  [
    "motd-news",
    "a request to the vendor every time you open a terminal, carrying your release and architecture",
    "minor",
    52,
    "Set `ENABLED=0` in /etc/default/motd-news.",
  ],
  [
    "ubuntu-advantage",
    "machine attach state to the vendor",
    "minor",
    30,
    "`sudo systemctl disable --now ua-timer` if you have no support contract.",
  ],
  [
    "packagekit",
    "a background updater that also reports availability",
    "minor",
    28,
    "`sudo systemctl disable --now packagekit` if your desktop does not need it.",
  ],
  [
    "geoclue",
    "your approximate location to any application that asks",
    "major",
    68,
    "`sudo systemctl disable --now geoclue` if nothing you use needs location.",
  ],
  [
    "cups-browsed",
    "printer discovery traffic that announces this machine continuously",
    "minor",
    44,
    "`sudo systemctl disable --now cups-browsed` unless you rely on network printer discovery.",
  ],
  [
    "avahi-daemon",
    "this machine's name and services to the whole local network",
    "minor",
    47,
    "`sudo systemctl disable --now avahi-daemon`. Local printer and cast discovery stop with it.",
  ],
  [
    "ModemManager",
    "modem state on a machine that has no modem",
    "minor",
    20,
    "`sudo systemctl disable --now ModemManager` if there is no cellular hardware.",
  ],
  [
    "speech-dispatcher",
    "an always-running speech service",
    "minor",
    14,
    "`sudo systemctl disable --now speech-dispatcher` if you do not use speech output.",
  ],
];

const reporterRow = (
  [unit, what, severity, weight, how]: (typeof REPORTERS)[number],
): SysPolicy => ({
  id: `tel-${unit}`,
  title: `The ${unit} service is running`,
  category: "privacy",
  severity,
  weight,
  source: { kind: "cmd", cmd: "systemctl", args: ["is-active", unit] },
  bad: "~active",
  detail: `it sends ${what}`,
  how,
});

export const PRIVACY_SYS_POLICIES: SysPolicy[] = [
  ...REPORTERS.map(reporterRow),
  {
    id: "tel-machine-id-exposed",
    title: "The machine id is world-readable",
    category: "privacy",
    severity: "minor",
    weight: 32,
    source: sh("stat -c %a /etc/machine-id 2>/dev/null"),
    bad: ">444",
    detail:
      "a stable identifier for this machine that any program can read and send",
    how:
      "It is world-readable by design and several services need it. Worth knowing rather than changing.",
  },
  {
    id: "tel-journal-retention",
    title: "The journal keeps records indefinitely",
    category: "privacy",
    severity: "minor",
    weight: 36,
    source: sh(
      "grep -hE '^\\s*MaxRetentionSec' /etc/systemd/journald.conf 2>/dev/null || echo unset",
    ),
    bad: "~unset",
    detail:
      "every login, every service start and every error is retained for as long as the disk allows",
    how:
      "Set `MaxRetentionSec=1month` under [Journal] in /etc/systemd/journald.conf.",
  },
  {
    id: "tel-bash-history-size",
    title: "Shell history is kept without limit",
    category: "privacy",
    severity: "minor",
    weight: 34,
    source: sh(
      "grep -hE '^\\s*HISTSIZE=' ~/.bashrc 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '\"'",
    ),
    bad: ">10000",
    detail:
      "a transcript of everything you have typed, unbounded, in a file on disk",
    how:
      "Set `HISTSIZE=2000` and `HISTFILESIZE=2000` in ~/.bashrc if you want it bounded.",
  },
  {
    id: "tel-lastlog-world",
    title: "The login record is world-readable",
    category: "privacy",
    severity: "minor",
    weight: 26,
    source: sh("stat -c %a /var/log/lastlog 2>/dev/null"),
    bad: ">640",
    detail:
      "any account can see when every other account last logged in and from where",
    how: "`sudo chmod 640 /var/log/lastlog`.",
  },
  {
    id: "tel-wtmp-world",
    title: "The login history is world-readable",
    category: "privacy",
    severity: "minor",
    weight: 25,
    source: sh("stat -c %a /var/log/wtmp 2>/dev/null"),
    bad: ">640",
    detail:
      "the full login history is readable by every account on the machine",
    how: "`sudo chmod 640 /var/log/wtmp /var/log/btmp`.",
  },
  {
    id: "tel-thumbnailer-remote",
    title: "Thumbnails are generated for remote files",
    category: "privacy",
    severity: "minor",
    weight: 22,
    source: sh(
      "gsettings get org.gnome.desktop.thumbnail-cache maximum-size 2>/dev/null",
    ),
    bad: "=-1",
    detail:
      "small copies of files from network shares are written to this machine's disk without limit",
    how:
      "Set a cache ceiling in the file manager's preferences, or `gsettings set org.gnome.desktop.thumbnail-cache maximum-size 256`.",
  },
  {
    id: "tel-zeitgeist",
    title: "An activity log is recording what you open",
    category: "privacy",
    severity: "minor",
    weight: 42,
    source: sh(
      "ls ~/.local/share/zeitgeist/activity.sqlite 2>/dev/null | wc -l",
    ),
    bad: ">0",
    detail:
      "a database of documents opened, applications used and when — kept locally and readable by anything you run",
    how:
      "Clear it from Privacy settings, or remove the `zeitgeist-core` package if nothing on your desktop uses it.",
  },
  {
    id: "tel-tracker-index",
    title: "A full-text index of your documents exists",
    category: "privacy",
    severity: "minor",
    weight: 40,
    source: sh(
      "du -sm ~/.cache/tracker3 ~/.cache/tracker 2>/dev/null | awk '{s+=$1} END{print s+0}'",
    ),
    bad: ">200",
    detail:
      "the contents of your documents are duplicated into a search database, which is as sensitive as the documents",
    how:
      "`tracker3 reset --filesystem` clears it; the indexer's own settings control which folders it covers.",
  },
];
