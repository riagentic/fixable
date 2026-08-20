// Application-level settings that only make sense read from the running
// system: office macro policy, media autoplay, and the tools that hold
// credentials or execute what they are given.
import type { SysPolicy } from "../../../type/policy.ts";

const sh = (script: string) => ({
  kind: "cmd" as const,
  cmd: "sh",
  args: ["-c", script] as const,
});

export const APP_POLICIES: SysPolicy[] = [
  {
    id: "app-lo-macro-security",
    title: "Office macro security is below the recommended level",
    category: "security",
    severity: "critical",
    weight: 93,
    source: sh(
      "grep -o 'MacroSecurityLevel[^/]*oor:value=\"[0-9]\"' ~/.config/libreoffice/4/user/registrymodifications.xcu 2>/dev/null | grep -oE '[0-9]\"$' | tr -d '\"' | head -1",
    ),
    bad: "<2",
    detail:
      "a document that arrives by mail can run its embedded macros — still one of the most reliable ways a machine gets compromised",
    how:
      "In LibreOffice: Tools → Options → Security → Macro Security, set High or Very High. It is the single most valuable office setting there is.",
  },
  {
    id: "app-lo-remote-content",
    title: "Office documents may load remote content",
    category: "privacy",
    severity: "major",
    weight: 70,
    source: sh(
      "grep -c 'LinkUpdateMode.*oor:value=\"2\"' ~/.config/libreoffice/4/user/registrymodifications.xcu 2>/dev/null",
    ),
    bad: ">0",
    detail:
      "opening a document confirms to its sender that you opened it, and can pull in content they control",
    how:
      "Tools → Options → Security → Options, set link updating to 'On request'.",
  },
  {
    id: "app-lo-recovery-off",
    title: "Office autorecovery is disabled",
    category: "safety",
    severity: "major",
    weight: 74,
    source: sh(
      "grep -c 'AutoSave.*oor:value=\"false\"' ~/.config/libreoffice/4/user/registrymodifications.xcu 2>/dev/null",
    ),
    bad: ">0",
    detail:
      "a crash or a power cut loses everything since your last manual save",
    how:
      "Tools → Options → Load/Save → General, enable autorecovery and set it to every 5 minutes.",
  },
  {
    id: "app-vscode-telemetry",
    title: "The editor sends telemetry",
    category: "privacy",
    severity: "minor",
    weight: 44,
    source: sh(
      'for f in ~/.config/Code/User/settings.json ~/.config/VSCodium/User/settings.json ~/.config/Cursor/User/settings.json; do [ -f "$f" ] && grep -c \'telemetry.telemetryLevel\\\\?\\\\s*\\\\?:\\\\s*\\\\?"off"\' "$f"; done | awk \'{s+=$1} END{print (NR==0)?"":(s>0?"off":"on")}\'',
    ),
    bad: "~on",
    detail:
      "what you edit, which extensions you use and how long you spend is reported",
    how:
      'Set `"telemetry.telemetryLevel": "off"` in the editor\'s settings.json.',
  },
  {
    id: "app-vscode-workspace-trust",
    title: "Workspace trust is disabled in the editor",
    category: "security",
    severity: "critical",
    weight: 91,
    source: sh(
      "for f in ~/.config/Code/User/settings.json ~/.config/VSCodium/User/settings.json ~/.config/Cursor/User/settings.json; do [ -f \"$f\" ] && grep -c 'security.workspace.trust.enabled\\\\?\\\\s*\\\\?:\\\\s*\\\\?false' \"$f\"; done | awk '{s+=$1} END{print s+0}'",
    ),
    bad: ">0",
    detail:
      "opening a folder runs that folder's tasks, formatters and extension settings — which is code from whoever wrote the repository",
    how:
      'Remove `"security.workspace.trust.enabled": false` from settings.json. Trust is the feature that stops a cloned repository executing on open.',
  },
  {
    id: "app-vscode-autofetch",
    title: "The editor fetches from remotes automatically",
    category: "privacy",
    severity: "minor",
    weight: 20,
    source: sh(
      "for f in ~/.config/Code/User/settings.json; do [ -f \"$f\" ] && grep -c 'git.autofetch\\\\?\\\\s*\\\\?:\\\\s*\\\\?true' \"$f\"; done | awk '{s+=$1} END{print s+0}'",
    ),
    bad: ">0",
    detail:
      "every open repository contacts its remote on a timer, which is traffic and credential use you did not initiate",
    how: 'Set `"git.autofetch": false` if you would rather fetch deliberately.',
  },
  {
    id: "app-jetbrains-telemetry",
    title: "The IDE participates in usage statistics",
    category: "privacy",
    severity: "minor",
    weight: 40,
    source: sh(
      "grep -rl 'allowed=\"true\"' ~/.config/JetBrains/*/options/statistics.xml 2>/dev/null | wc -l",
    ),
    bad: ">0",
    detail: "usage data about what you build and how is reported",
    how:
      "Turn it off in Settings → Appearance & Behavior → System Settings → Data Sharing.",
  },
  {
    id: "app-media-autoplay",
    title: "Media plays automatically with sound",
    category: "settings",
    severity: "minor",
    weight: 16,
    source: sh(
      "gsettings get org.gnome.desktop.media-handling autorun-x-content-start-app 2>/dev/null | grep -c 'audio\\|video'",
    ),
    bad: ">0",
    detail: "inserting a disc or a stick starts a player without asking",
    how: "Change the Removable Media preferences to 'Ask what to do'.",
  },
  {
    id: "app-gimp-scripts",
    title: "Image editor script directories are writable by other accounts",
    category: "security",
    severity: "major",
    weight: 72,
    source: sh(
      "find ~/.config/GIMP -maxdepth 3 -type d -name 'scripts' -perm -o+w 2>/dev/null | wc -l",
    ),
    bad: ">0",
    detail: "scripts placed there run when the editor starts",
    how: "`chmod go-w` on the script directories.",
  },
  {
    id: "app-thunderbird-addons",
    title: "Mail client extensions are installed",
    category: "security",
    severity: "minor",
    weight: 38,
    source: sh("ls -d ~/.thunderbird/*/extensions/* 2>/dev/null | wc -l"),
    bad: ">4",
    detail: "each extension can read every message you open",
    how: "Review them in Add-ons Manager and remove what you do not use.",
  },
  {
    id: "app-browser-extensions",
    title: "Many browser extensions are installed",
    category: "security",
    severity: "minor",
    weight: 50,
    source: sh(
      "{ ls -d ~/.mozilla/firefox/*/extensions/* 2>/dev/null; ls -d ~/.config/*/Default/Extensions/* 2>/dev/null; } | wc -l",
    ),
    bad: ">10",
    detail:
      "an extension typically reads and can rewrite every page you visit, and extensions change hands more often than people expect",
    how:
      "Review the list in each browser and remove anything you do not actively use. An extension you forgot you installed is the usual problem.",
  },
  {
    id: "app-appimage-integration",
    title: "AppImages run without desktop integration or sandboxing",
    category: "security",
    severity: "minor",
    weight: 42,
    source: sh(
      "ls ~/Applications/*.AppImage ~/.local/bin/*.AppImage 2>/dev/null | wc -l",
    ),
    bad: ">0",
    detail:
      "an AppImage is an unsandboxed program with your full permissions, updated only when you remember to download a new one — and it bundles its own libraries, so system security updates do not reach it",
    how:
      "Prefer the distribution package or a Flatpak where one exists. Where you keep an AppImage, check for updates yourself and know where it came from.",
  },
  {
    id: "app-snap-classic",
    title: "A snap is installed in classic confinement",
    category: "security",
    severity: "major",
    weight: 68,
    source: sh("snap list 2>/dev/null | grep -c classic"),
    bad: ">0",
    detail:
      "classic confinement means no confinement — the application has your full access",
    how:
      "`snap list` shows which. Prefer strictly confined versions where they exist.",
  },
  {
    id: "app-pip-system",
    title: "Packages have been installed into the system Python",
    category: "stability",
    severity: "major",
    weight: 66,
    source: sh("ls /usr/local/lib/python3*/dist-packages 2>/dev/null | wc -l"),
    bad: ">3",
    detail:
      "packages installed outside the package manager can shadow distribution ones and break system tools that are written in Python — including the package manager",
    how:
      "Move them into a virtual environment or use `pipx` for applications. `pip list --user` and /usr/local/lib/python3*/dist-packages show what is there.",
  },
  {
    id: "app-npm-global-root",
    title: "Global npm packages are installed as root",
    category: "security",
    severity: "major",
    weight: 64,
    source: sh(
      "[ -d /usr/local/lib/node_modules ] && find /usr/local/lib/node_modules -maxdepth 1 -mindepth 1 2>/dev/null | wc -l || echo 0",
    ),
    bad: ">0",
    detail:
      "`sudo npm install -g` runs the package's install scripts as root, which is a lot of trust to place in a dependency tree",
    how:
      "Use a user-level prefix (`npm config set prefix ~/.npm-global`) or a version manager, so global installs never need root.",
  },
];
