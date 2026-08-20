// The remaining surfaces: printing, input, locale, logs, scheduled work, and
// the desktop services that answer the network.
import type { SysPolicy } from "../../../type/policy.ts";

const sh = (script: string) => ({
  kind: "cmd" as const,
  cmd: "sh",
  args: ["-c", script] as const,
});

export const MISC_POLICIES: SysPolicy[] = [
  // ------------------------------------------------------------- printing
  {
    id: "misc-cups-remote-admin",
    title: "The print server allows remote administration",
    category: "security",
    severity: "critical",
    weight: 90,
    source: sh(
      "grep -h 'Listen\\|Port' /etc/cups/cupsd.conf 2>/dev/null | grep -v localhost | grep -c '^\\s*\\(Listen\\|Port\\)'",
    ),
    bad: ">0",
    detail:
      "the printing service accepts configuration changes from the network",
    how:
      "Restrict `Listen` to `localhost:631` in /etc/cups/cupsd.conf and restart cups.",
  },
  {
    id: "misc-cups-jobs-kept",
    title: "Completed print jobs are retained",
    category: "privacy",
    severity: "minor",
    weight: 34,
    source: sh("ls /var/spool/cups/ 2>/dev/null | grep -c '^d0'"),
    bad: ">10",
    detail: "the contents of documents you have printed are still on disk",
    how:
      "Set `PreserveJobFiles No` in /etc/cups/cupsd.conf, and clear /var/spool/cups.",
  },
  {
    id: "misc-scanner-network",
    title: "A network scanner service is running",
    category: "security",
    severity: "minor",
    weight: 40,
    source: sh("systemctl is-active saned.socket 2>/dev/null || echo absent"),
    bad: "~active",
    detail: "the scanning daemon accepts connections from the network",
    how:
      "`sudo systemctl disable --now saned.socket` unless you scan over the network.",
  },
  // ----------------------------------------------------------------- input
  {
    id: "misc-sticky-keys",
    title: "Accessibility key shortcuts are enabled at the login screen",
    category: "settings",
    severity: "minor",
    weight: 14,
    source: sh(
      "gsettings get org.gnome.desktop.a11y.keyboard stickykeys-enable 2>/dev/null || gsettings get org.cinnamon.desktop.a11y.keyboard stickykeys-enable 2>/dev/null",
    ),
    bad: "true",
    detail:
      "reported so the setting is visible; on some systems this shortcut is also a known pre-login surface",
    how: "Turn it off in Accessibility settings if nobody uses it.",
  },
  {
    id: "misc-caps-remap",
    title: "Keyboard options are set to a non-default layout behaviour",
    category: "settings",
    severity: "minor",
    weight: 6,
    source: sh(
      "gsettings get org.gnome.desktop.input-sources xkb-options 2>/dev/null | grep -c 'ctrl:\\|caps:'",
    ),
    bad: ">0",
    detail:
      "reported so a remapped modifier is visible when a keyboard 'stops working correctly'",
    how:
      "`gsettings get org.gnome.desktop.input-sources xkb-options` shows the list.",
  },
  // ---------------------------------------------------------------- locale
  {
    id: "misc-locale-unset",
    title: "The system locale is not configured",
    category: "stability",
    severity: "minor",
    weight: 30,
    source: sh("localectl status 2>/dev/null | grep -c 'LANG=' || echo 0"),
    bad: "=0",
    detail:
      "programs fall back to the C locale, which changes sorting, number formatting and character handling — and produces bugs that only appear on this machine",
    how: "`sudo localectl set-locale LANG=en_US.UTF-8` (or your preference).",
  },
  {
    id: "misc-timezone-utc",
    title: "The machine's clock is set to local time rather than UTC",
    category: "stability",
    severity: "minor",
    weight: 28,
    source: sh("timedatectl show -p LocalRTC --value 2>/dev/null"),
    bad: "~yes",
    detail:
      "the hardware clock in local time causes an hour of drift twice a year and confuses every dual-boot arrangement",
    how:
      "`sudo timedatectl set-local-rtc 0`. If you dual-boot Windows, set Windows to use UTC instead.",
  },
  // ------------------------------------------------------------------ logs
  {
    id: "misc-journal-errors",
    title: "There are many errors in this boot's log",
    category: "stability",
    severity: "minor",
    weight: 50,
    source: sh("journalctl -b -p err --no-pager 2>/dev/null | wc -l"),
    bad: ">200",
    detail:
      "a high error rate is usually one thing failing repeatedly rather than many things failing once",
    how:
      "`journalctl -b -p err | sort | uniq -c | sort -rn | head` groups them so the repeated one stands out.",
  },
  {
    id: "misc-dmesg-errors",
    title: "The kernel is reporting hardware errors",
    category: "stability",
    severity: "critical",
    weight: 92,
    source: sh(
      "journalctl -k -b --no-pager 2>/dev/null | grep -ciE 'Hardware Error|MCE|EDAC.*error|PCIe Bus Error'",
    ),
    bad: ">0",
    detail:
      "machine-check or bus errors point at memory, the processor, or a failing card — not at software",
    how:
      "`journalctl -k -b | grep -iE 'hardware error|mce|edac'` for the detail. Test memory with memtest86+ before replacing anything.",
  },
  // -------------------------------------------------------- scheduled work
  {
    id: "misc-cron-allow-missing",
    title: "Scheduling access is not restricted",
    category: "security",
    severity: "minor",
    weight: 24,
    source: sh("[ -f /etc/cron.allow ] && echo present || echo absent"),
    bad: "~absent",
    detail: "any account can schedule a job that runs unattended",
    how:
      "Create /etc/cron.allow listing the accounts that may schedule, and remove /etc/cron.deny.",
  },
  {
    id: "misc-timers-failed",
    title: "A scheduled timer has not run when it should have",
    category: "stability",
    severity: "minor",
    weight: 44,
    source: sh(
      'systemctl list-timers --all --no-legend 2>/dev/null | awk \'$1=="n/a" || $2=="n/a"\' | wc -l',
    ),
    bad: ">2",
    detail:
      "timers that never fire are usually backups, trims or update checks that you believe are running",
    how: "`systemctl list-timers --all` shows the last and next run for each.",
  },
  {
    id: "misc-anacron-missing",
    title: "Nothing catches up on scheduled work after downtime",
    category: "stability",
    severity: "minor",
    weight: 20,
    source: sh("command -v anacron >/dev/null && echo present || echo absent"),
    bad: "~absent",
    detail:
      "a machine that is off at the scheduled time simply skips the job — on a laptop that can mean it never runs",
    how:
      "`sudo apt install anacron`, or use systemd timers with `Persistent=true`.",
  },
  // -------------------------------------------------------------- desktop
  {
    id: "misc-gnome-remote-login",
    title: "Remote login to the desktop is enabled",
    category: "security",
    severity: "critical",
    weight: 94,
    source: sh(
      "gsettings get org.gnome.desktop.remote-desktop.rdp enable 2>/dev/null || echo false",
    ),
    bad: "true",
    detail:
      "the desktop accepts remote sessions, which is a full interactive login over the network",
    how:
      "Turn it off in Sharing settings, or `gsettings set org.gnome.desktop.remote-desktop.rdp enable false`.",
  },
  {
    id: "misc-file-sharing",
    title: "File sharing is enabled on the desktop",
    category: "security",
    severity: "major",
    weight: 76,
    source: sh(
      "gsettings get org.gnome.desktop.file-sharing enabled 2>/dev/null || echo false",
    ),
    bad: "true",
    detail: "a folder on this machine is being served to the local network",
    how: "Turn it off in Sharing settings.",
  },
  {
    id: "misc-media-sharing",
    title: "Media sharing is enabled",
    category: "privacy",
    severity: "minor",
    weight: 42,
    source: sh("systemctl --user is-active rygel 2>/dev/null || echo absent"),
    bad: "~active",
    detail:
      "your media library is being advertised and served to the local network",
    how: "`systemctl --user disable --now rygel`.",
  },
  {
    id: "misc-gvfs-network",
    title: "Network shares are mounted in your session",
    category: "security",
    severity: "minor",
    weight: 26,
    source: sh("ls ~/.gvfs /run/user/$(id -u)/gvfs 2>/dev/null | grep -c ':'"),
    bad: ">0",
    detail:
      "reported so a mounted share is visible — anything that can read your session can read through it",
    how: "Unmount shares you are not using from the file manager sidebar.",
  },
  {
    id: "misc-xdg-portal-missing",
    title: "No desktop portal is available for sandboxed applications",
    category: "settings",
    severity: "minor",
    weight: 22,
    source: sh(
      "systemctl --user is-active xdg-desktop-portal 2>/dev/null || echo absent",
    ),
    bad: "~absent",
    detail:
      "sandboxed applications fall back to broader permissions because the mediated path is not there — file dialogs and screen sharing then need direct access",
    how:
      "`sudo apt install xdg-desktop-portal xdg-desktop-portal-gtk` (or the one matching your desktop).",
  },
  {
    id: "misc-swap-on-hdd",
    title: "Swap is on a rotational disk",
    category: "performance",
    severity: "minor",
    weight: 32,
    source: sh(
      "awk 'NR>1{print $1}' /proc/swaps 2>/dev/null | head -1 | xargs -r lsblk -no ROTA 2>/dev/null | head -1",
    ),
    bad: "=1",
    detail:
      "swapping to a spinning disk is thousands of times slower than to an SSD, which is why the machine appears to freeze rather than slow down",
    how: "Move swap to the SSD, or use zram so it never reaches a disk at all.",
  },
  {
    id: "misc-boot-slow",
    title: "The machine takes a long time to start",
    category: "performance",
    severity: "minor",
    weight: 36,
    source: sh(
      "systemd-analyze 2>/dev/null | grep -oE '= [0-9.]+s' | grep -oE '[0-9]+' | head -1",
    ),
    bad: ">60",
    detail:
      "over a minute from firmware to desktop, which is almost always one unit waiting on a timeout",
    how:
      "`systemd-analyze blame` and `systemd-analyze critical-chain` name the unit that is holding it up.",
  },
];
