// Schema families, best-first. A policy names a family, not a schema, because
// the same setting lives under a different prefix on every desktop — Mint ships
// both `org.cinnamon.*` and `org.gnome.*`, and writing the one the running
// session does not read is a fix that changes nothing.
export const SCREENSAVER = [
  "org.cinnamon.desktop.screensaver",
  "org.gnome.desktop.screensaver",
  "org.mate.screensaver",
] as const;

export const SESSION = [
  "org.cinnamon.desktop.session",
  "org.gnome.desktop.session",
  "org.mate.session",
] as const;

export const PRIVACY = [
  "org.cinnamon.desktop.privacy",
  "org.gnome.desktop.privacy",
] as const;

export const LOCKDOWN = [
  "org.cinnamon.desktop.lockdown",
  "org.gnome.desktop.lockdown",
  "org.mate.lockdown",
] as const;

export const MEDIA = [
  "org.cinnamon.desktop.media-handling",
  "org.gnome.desktop.media-handling",
  "org.mate.desktop.media-handling",
] as const;

export const NOTIFY = [
  "org.cinnamon.desktop.notifications",
  "org.gnome.desktop.notifications",
] as const;

export const POWER = [
  "org.cinnamon.settings-daemon.plugins.power",
  "org.gnome.settings-daemon.plugins.power",
] as const;

export const THUMB_CACHE = [
  "org.cinnamon.desktop.thumbnail-cache",
  "org.gnome.desktop.thumbnail-cache",
] as const;

export const THUMBNAILERS = [
  "org.cinnamon.desktop.thumbnailers",
  "org.gnome.desktop.thumbnailers",
] as const;

export const INTERFACE = [
  "org.cinnamon.desktop.interface",
  "org.gnome.desktop.interface",
  "org.mate.interface",
] as const;

export const SOUND = [
  "org.cinnamon.desktop.sound",
  "org.gnome.desktop.sound",
] as const;

export const FILE_MANAGER = ["org.nemo.preferences"] as const;

export const LOCATION = ["org.gnome.system.location"] as const;

export const SEARCH_PROVIDERS = ["org.gnome.desktop.search-providers"] as const;

export const HOUSEKEEPING = [
  "org.cinnamon.settings-daemon.plugins.housekeeping",
  "org.gnome.settings-daemon.plugins.housekeeping",
] as const;

export const MINT_UPDATES = ["com.linuxmint.updates"] as const;
export const MINT_REPORT = ["com.linuxmint.report"] as const;
export const MINT_MENU_APPS = [
  "com.linuxmint.mintmenu.plugins.applications",
] as const;
export const MINT_MENU_RECENT = [
  "com.linuxmint.mintmenu.plugins.recent",
] as const;
