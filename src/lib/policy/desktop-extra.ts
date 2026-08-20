// Login screen, LAN file sharing, and the update reminder — three places where
// a desktop quietly exposes something or quietly stops protecting you.
import type { SettingPolicy } from "../../type/policy.ts";
import { MINT_UPDATES } from "./schemas.ts";

const GREETER = ["x.dm.slick-greeter"] as const;
const WARP = ["org.x.warpinator.preferences"] as const;
const MUFFIN = ["org.cinnamon.muffin", "org.gnome.mutter"] as const;

export const DESKTOP_EXTRA_POLICIES: SettingPolicy[] = [
  {
    id: "greeter-hostname",
    title: "The login screen displays this machine's hostname",
    category: "privacy",
    severity: "minor",
    weight: 29,
    schemas: GREETER,
    key: "show-hostname",
    bad: "true",
    safe: "false",
    detail: "anyone who walks past the locked machine learns its name",
    because: "The greeter still works; it stops naming the machine.",
  },
  {
    id: "greeter-quit",
    title: "Anyone at the login screen can shut the machine down",
    category: "security",
    severity: "minor",
    weight: 51,
    schemas: GREETER,
    key: "show-power",
    bad: "true",
    safe: "false",
    detail:
      "a passer-by can power off the machine mid-work, losing anything unsaved",
    because:
      "You can still shut down from inside your session. Holding the power " +
      "button always works.",
  },
  {
    id: "warpinator-autostart",
    title: "A LAN file-receiving service starts with your session",
    category: "security",
    severity: "major",
    weight: 83,
    schemas: WARP,
    key: "autostart",
    bad: "true",
    safe: "false",
    detail:
      "a service that accepts files from the local network runs every time you log in",
    because:
      "Warpinator still runs when you open it. It stops listening the rest " +
      "of the time.",
  },
  {
    id: "warpinator-permission",
    title: "LAN file transfers are accepted without asking",
    category: "security",
    severity: "critical",
    weight: 95,
    schemas: WARP,
    key: "ask-for-send-permission",
    bad: "false",
    safe: "true",
    detail:
      "anything on the local network can push files onto this machine unprompted",
    because: "You are asked before each transfer. Sending is unaffected.",
  },
  {
    id: "warpinator-overwrite",
    title: "Incoming LAN transfers may overwrite your files",
    category: "security",
    severity: "critical",
    weight: 94,
    schemas: WARP,
    key: "no-overwrite",
    bad: "false",
    safe: "true",
    detail:
      "a file arriving from the network can replace one you already have, silently",
    because: "Incoming files are renamed instead of replacing yours. Nothing " +
      "already received is affected.",
  },
  {
    id: "updates-refresh-schedule",
    title: "The machine never checks for updates on its own",
    category: "settings",
    severity: "major",
    weight: 80,
    schemas: MINT_UPDATES,
    key: "refresh-schedule-enabled",
    bad: "false",
    safe: "true",
    detail:
      "security updates are only noticed if you go and look for them yourself",
    because:
      "The updater checks on a schedule and tells you. It still installs " +
      "nothing without you.",
  },
  {
    id: "updates-hide-tray",
    title: "The update indicator is hidden",
    category: "settings",
    severity: "minor",
    weight: 42,
    schemas: MINT_UPDATES,
    key: "hide-systray",
    bad: "true",
    safe: "false",
    detail: "pending updates have nowhere to show themselves",
    because: "The tray icon returns. It appears only when there is something.",
  },
  {
    id: "updates-hide-kernel-warning",
    title: "The kernel update warning has been suppressed",
    category: "security",
    severity: "major",
    weight: 79,
    schemas: MINT_UPDATES,
    key: "hide-kernel-update-warning",
    bad: "true",
    safe: "false",
    detail:
      "the one warning that tells you the running kernel has known holes was dismissed permanently",
    because: "The warning comes back. It warns; it installs nothing.",
  },
  {
    id: "updates-flatpak-visible",
    title: "Flatpak updates are not listed",
    category: "settings",
    severity: "minor",
    weight: 41,
    schemas: MINT_UPDATES,
    key: "show-flatpak-updates",
    bad: "false",
    safe: "true",
    detail:
      "applications installed as Flatpaks age out of sight of the updater",
    because: "They appear in the list. Nothing is installed automatically.",
  },
  {
    id: "unredirect-fullscreen",
    title: "Full-screen windows are composited unnecessarily",
    category: "performance",
    severity: "minor",
    weight: 16,
    schemas: MUFFIN,
    key: "unredirect-fullscreen-windows",
    bad: "false",
    safe: "true",
    detail:
      "video and games pay for a compositing pass that changes nothing on screen",
    because: "The compositor steps aside for genuinely full-screen windows. " +
      "Everything else is unaffected.",
  },
];
