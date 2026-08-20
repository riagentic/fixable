// The graphical session: what one program on your screen can learn about the
// others, and what is reachable from outside it.
import type { SysPolicy } from "../../../type/policy.ts";

const sh = (script: string) => ({
  kind: "cmd" as const,
  cmd: "sh",
  args: ["-c", script] as const,
});

export const SESSION_POLICIES: SysPolicy[] = [
  {
    id: "sess-x11",
    title: "The session runs on X11 rather than Wayland",
    category: "security",
    severity: "major",
    weight: 70,
    source: sh('echo "${XDG_SESSION_TYPE:-unknown}"'),
    bad: "~x11",
    detail:
      "X11 has no isolation between clients: any program you run can read every keystroke you type into any window, and take a screenshot of any of them, with no permission prompt",
    how:
      "Log out and pick a Wayland session at the login screen, if your desktop offers one. NVIDIA drivers and a few applications still work better on X11 — this is a real trade-off, not a clear win.",
  },
  {
    id: "sess-xhost-open",
    title: "The X server accepts connections from anyone",
    category: "security",
    severity: "critical",
    weight: 96,
    source: sh("xhost 2>/dev/null | head -1"),
    bad: "~disabled",
    detail:
      "access control has been relaxed — typically by an `xhost +` someone ran to make a container or a remote program display, and then never undid",
    how:
      "`xhost` lists who is allowed; `xhost -` removes them all. If a container needs the display, pass a magic cookie instead of opening the server.",
  },
  {
    id: "sess-remote-desktop",
    title: "A remote desktop service is running",
    category: "security",
    severity: "critical",
    weight: 95,
    source: sh(
      "for u in gnome-remote-desktop vino-server xrdp x11vnc rustdesk anydesk teamviewerd; do systemctl is-active --quiet $u 2>/dev/null && echo $u; done | wc -l",
    ),
    bad: ">0",
    detail:
      "something on this machine is prepared to hand your screen and input to a remote party",
    how:
      "Identify it (`systemctl list-units --state=running | grep -iE 'vnc|rdp|remote|anydesk|rustdesk'`) and disable what you did not set up deliberately.",
  },
  {
    id: "sess-ssh-agent-forwarded",
    title: "An SSH agent socket is being forwarded into this session",
    category: "security",
    severity: "major",
    weight: 74,
    source: sh(
      '[ -n "$SSH_AUTH_SOCK" ] && echo "$SSH_AUTH_SOCK" | grep -c \'^/tmp/ssh-\' || echo 0',
    ),
    bad: ">0",
    detail:
      "the socket lets anything running as you sign with your private keys, and a forwarded agent extends that to whatever machine you are connected to",
    how:
      "Use `ForwardAgent no` by default and turn it on per-host. `ssh-add -c` makes the agent ask before each use.",
  },
  {
    id: "sess-clipboard-manager",
    title: "A clipboard manager is keeping a history",
    category: "privacy",
    severity: "major",
    weight: 68,
    source: sh(
      "ls ~/.cache/clipit ~/.config/clipit ~/.local/share/clipman* ~/.config/copyq ~/.cache/diodon 2>/dev/null | wc -l",
    ),
    bad: ">0",
    detail:
      "everything you copy is written to disk, including every password you copy out of a password manager",
    how:
      "Most clipboard managers can exclude password managers or disable history for secret content — turn that on, and clear the existing history.",
  },
  {
    id: "sess-screen-recording",
    title: "A screen capture portal is permanently allowed",
    category: "privacy",
    severity: "major",
    weight: 65,
    source: sh(
      "grep -rl 'screencast\\|screenshot' ~/.local/share/flatpak/db/ /var/lib/flatpak/db/ 2>/dev/null | wc -l",
    ),
    bad: ">0",
    detail: "an application holds a standing permission to record your screen",
    how:
      "Review with `flatpak permission-show`, and reset with `flatpak permission-reset <app>`.",
  },
  {
    id: "sess-a11y-bus",
    title: "The accessibility bus is enabled",
    category: "privacy",
    severity: "minor",
    weight: 30,
    source: sh(
      "gsettings get org.gnome.desktop.interface toolkit-accessibility 2>/dev/null",
    ),
    bad: "true",
    detail:
      "the accessibility bus lets one program read the contents of another's windows — which is exactly what a screen reader needs, and exactly what a keylogger would want",
    how:
      "Leave this alone if you use assistive technology. If you do not, `gsettings set org.gnome.desktop.interface toolkit-accessibility false`.",
  },
  {
    id: "sess-autostart-count",
    title: "Many programs start with your session",
    category: "performance",
    severity: "minor",
    weight: 34,
    source: sh("ls ~/.config/autostart/*.desktop 2>/dev/null | wc -l"),
    bad: ">12",
    detail:
      "each one costs memory and startup time, every login, whether or not you use it that day",
    how:
      "Review them in Startup Applications. Disabling is reversible; deleting the .desktop file is not.",
  },
  {
    id: "sess-user-timers",
    title: "Your account has scheduled jobs you may not know about",
    category: "security",
    severity: "minor",
    weight: 48,
    source: sh(
      "{ crontab -l 2>/dev/null | grep -cvE '^\\s*(#|$)'; systemctl --user list-timers --no-legend 2>/dev/null | wc -l; } | awk '{s+=$1} END{print s}'",
    ),
    bad: ">6",
    detail:
      "cron entries and user timers run as you, on a schedule, whether or not you are at the machine",
    how:
      "`crontab -l` and `systemctl --user list-timers` list them. Anything you do not recognise is worth reading before removing.",
  },
  {
    id: "sess-ld-preload",
    title: "A library is being force-loaded into every program you run",
    category: "security",
    severity: "critical",
    weight: 97,
    source: sh(
      'echo "${LD_PRELOAD:-}${LD_LIBRARY_PATH:+ }${LD_LIBRARY_PATH:-}" | grep -c .',
    ),
    bad: ">0",
    detail:
      "LD_PRELOAD or LD_LIBRARY_PATH is set in your environment, which means a library of someone's choosing is loaded into everything you start — a standard persistence technique",
    how:
      "`echo $LD_PRELOAD $LD_LIBRARY_PATH` and find where it is set: your shell files, ~/.pam_environment, or /etc/environment. Remove it unless you put it there for a specific tool.",
  },
  {
    id: "sess-path-dot",
    title: "The current directory is on your PATH",
    category: "security",
    severity: "critical",
    weight: 94,
    source: sh("echo \"$PATH\" | tr ':' '\\n' | grep -cE '^$|^\\.$'"),
    bad: ">0",
    detail:
      "a file called `ls` in a directory you `cd` into runs instead of the real one — an empty PATH element means the same thing",
    how:
      "Find the `.` or the empty entry (a leading, trailing or doubled colon) in your shell startup files and remove it.",
  },
  {
    id: "sess-path-writable",
    title: "A directory on your PATH is writable by other accounts",
    category: "security",
    severity: "critical",
    weight: 93,
    source: sh(
      'echo "$PATH" | tr \':\' \'\\n\' | while read -r d; do [ -n "$d" ] && [ -d "$d" ] && [ -w "$d" ] && find "$d" -maxdepth 0 -perm -o+w -o -maxdepth 0 -perm -g+w; done 2>/dev/null | wc -l',
    ),
    bad: ">0",
    detail:
      "another account can put a program there and have you run it, as you, without noticing",
    how:
      "`ls -ld $(echo $PATH | tr ':' ' ')` shows the modes. `chmod go-w` on any that are group- or world-writable.",
  },
];
