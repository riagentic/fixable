// The audit: which checks are optional rather than automatic, and why.
//
// A row belongs here when its current value could reasonably be something the
// person chose. The test applied to every auto-fixable check was:
//
//     If this value was set deliberately, what does the fix take away?
//
// A row with an answer to that question is not a fault, and the app does not
// treat it as one: it never runs on "Fix all", it is filed under Optional
// rather than among the things that are wrong, and its explanation opens with
// what the change would cost you. What it DOES keep is its button. Taking the
// button away as well was the wrong lesson to draw from the one row that
// caused real harm here — a machine set to never suspend, suspending at an
// hour, because the app "corrected" a preference unasked. The fault there was
// acting without being asked, not offering. So: nothing in this file is ever
// applied unattended, and everything in it is one click away with the cost
// stated and Undo behind it.
//
// Four answers put a row in this file (and two more, below, that came out of
// later passes — a lockdown somebody set, and a value nothing reaches by
// accident):
//
//   1. It is a plain preference — a toggle or a number in the system's own
//      settings panels. Power, Screensaver, Notifications and Sound exist
//      precisely because these are choices. A "correction" here is the app
//      deciding it knows better than the person using the machine. This is the
//      class that set `sleep-inactive-ac-timeout` from "never" to one hour.
//   2. It removes a capability that gets used — autofill, translation, sync,
//      auto-mounting a USB stick, the recent-files list. A security gain that
//      costs a daily-use feature is not obviously a gain.
//   3. Its blast radius is wider than one setting — the Flatpak rows apply a
//      policy to EVERY sandboxed application at once, and the failure mode is
//      an app that silently cannot open your files.
//   4. It is accessibility-relevant. An on-screen keyboard on a lock screen or
//      the accessibility bus in a sandbox is not decoration; taking either away
//      can lock somebody out of their own machine.
//
// Nothing here is dropped, and nothing here is hidden. Every one of these
// still runs, still reports, and still offers the change — under a label that
// says it is yours to choose.

const group = (reason: string, ids: string[]): [string, string][] =>
  ids.map((id) => [id, reason]);

/** 1 — plain preferences, exposed in the system's own settings panels. */
const PANEL = group(
  "Optional — this is a preference, not a fault. It is a setting in your " +
    "desktop's own panels, which means it is one somebody chooses, so it is " +
    "never changed unless you press this button and never touched by " +
    '"Fix all".',
  [
    // Power and idle. The class that caused a machine to suspend at one hour
    // when its owner had set "never".
    "d3-idle-brightness",
    "critical-battery-late",
    "low-battery-late",
    "housekeeping-threshold",
    // Screensaver and lock — whether you are asked for a password is yours.
    "screen-lock",
    "lock-activation",
    "lock-on-suspend",
    "lock-ubuntu-suspend",
    // Notifications and sound.
    "notification-timeout",
    "notifications-fullscreen",
    // Notifications on the lock screen are a toggle in the Notifications
    // panel; hiding them is a choice about convenience, not a repair.
    "lock-notifications",
    "lock-notifications-gnome",
    "event-sounds",
    "d3-sounds-notification",
    "d3-power-notify-mouse",
    "d3-power-notify-keyboard",
    "d3-power-notify-other",
    "d3-session-idle-notify",
    // Appearance and interaction.
    "clock-seconds",
    "d3-fm-desktop-trash",
    "d3-fm-home-desktop",
    "d3-fm-parent-dblclick",
    "d3-fm-context-all",
    "d3-touchpad-typing",
    "fm-preload-limit",
    // Delete confirmations — how many prompts stand between you and the trash
    // is a file-manager preference, and a pro who turned them off meant it.
    "fm-confirm-trash",
    "fm-permanent-delete",
    // Retention and cache sizes — how much history you keep is a choice.
    "recent-files-forever",
    "recent-files-long",
    "old-files-age",
    "menu-recent-docs",
    "thumbnail-cache-age",
    "thumbnail-cache-size",
    "d3-thumbnail-remote",
    "update-grace-period",
  ],
);

/** 2 — removes something that gets used. */
const CAPABILITY = group(
  "Optional — this takes away something you may well use. The security or " +
    "privacy gain is real, but so is the loss, and which one wins depends on " +
    "how you work, so nothing happens here until you say so. Undo puts the " +
    "capability back.",
  [
    // Desktop capabilities.
    "automount",
    "automount-open",
    "fm-detect-content",
    "fm-thumbnail-inherit",
    "lock-user-switch",
    "lock-media-control",
    "lock-keyboard-shortcuts",
    "lockdown-show-password",
    "location-services",
    "remember-recent-files",
    "warpinator-autostart",
    "d3-cinnamon-devtools",
    "unredirect-fullscreen",
    "remember-app-usage",
    "menu-internet-search",
    "external-search",
    "tool-wget-content-disposition",
    "ff2-captive-portal",
    "ff2-connectivity-service",
    // Browser features people use every day.
    "ff-search-suggest",
    "ff-formfill",
    "ff-autofill-addresses",
    "ff-autofill-cards",
    "ff-signon-autofill",
    "ff-tracking-protection",
    "ff-https-only",
    "ff-https-only-pbm",
    "ff-pdf-scripting",
    "ff2-session-privacy",
    "ff2-downloads-tmp",
    "ff2-dom-push",
    "ff2-cookie-behavior",
    "ff2-tls-min",
    "cr-sync-disabled",
    "cr-signin-allowed",
    "cr-translate",
    "cr-url-suggest",
    "cr-autofill-cards",
    "cr-autofill-profile",
    "cr-payments-query",
    "cr-download-prompt",
    "cr-https-only",
    "cr-webrtc-ip",
    "cr-webrtc-routes",
    "cr-webrtc-udp",
    // Chromium capability defaults. The shipped value is "ask", which leaves
    // the decision with you; "block" takes away your ability to say yes.
    "cr-geolocation",
    "cr-notifications",
    "cr-auto-downloads",
    "cr-midi",
    "cr-serial",
    "cr-hid",
    "cr-usb",
    "cr-bluetooth",
    "cr-sensors",
    "cr-idle-detection",
    "cr-clipboard",
    "cr-file-write",
    "cr-popups",
    "cr-sandbox-network",
    "cr-window-management",
    "cr-storage-access",
    "cr-protocol-handlers",
    "cr-fileedit-guard",
    "cr-insecure-downloads",
    // Mail rendering and composition.
    "tb-html-as-plain",
    "tb-sanitize-html",
    "tb-compose-html",
    "tb-rss-scripts",
    // Tooling that changes how a command behaves.
    "npm-save-exact",
    "pip-require-venv",
    "tool-wget-secure-protocol",
    "tool-curl-doh",
    "tool-go-noproxy-insecure",
    "tool-vim-viminfo",
    "tool-histfile-perms-cmd",
    "tool-umask-bashrc",
    "t3-tmux-lock",
    "t3-screen-lock",
    "t3-gpg-agent-ttl",
    "t3-gpg-agent-max-ttl",
    "ssh-identities-only",
    "ssh-exit-on-forward-failure",
    // Debian and Ubuntu ship both `yes` in /etc/ssh/ssh_config: untrusted X11
    // breaks clipboard and GL in forwarded apps, and no GSSAPI breaks
    // Kerberos single sign-on.
    "ssh-x11-trusted",
    "ssh-gssapi-auth",
    // Strict pinning refuses any certificate from a root you installed — the
    // whole of corporate TLS inspection, AV web shields and mitmproxy.
    "ff-cert-pinning",
    // Git rows that change what a command does rather than how safe it is.
    "git-default-branch",
    "git-diff-algorithm",
    "git-conflict-style",
    "git-rebase-autostash",
    "git-rerere",
    "git-rerere-autoupdate",
    "git-am-threeway",
    "git-push-autosetup",
    "git-fetch-prune",
    "git-http-version",
    "git-core-fsmonitor",
    "git-pack-window-memory",
    "git-gpg-min-trust",
    // Strict fsck refuses real repositories that carry old malformed objects,
    // and the failure is a clone that will not finish.
    "git-fsck-transfer",
    "git-fsck-fetch",
    "git-fsck-receive",

    // ---- second audit, over the rows added in the 2,009-check tranche ----
    // Browser capabilities a page may legitimately need, or that a person
    // uses directly. The shipped default for the Chromium content settings is
    // "ask", which leaves the decision with you; "block" takes it away.
    "ff3-gamepad",
    "ff3-vr",
    "ff3-midi",
    "ff3-speech",
    "ff3-form-autofill-heuristics",
    "ff3-search-update",
    "ff3-geo-provider",
    "ff3-cert-error-override",
    "ff3-disk-cache-ssl",
    "ff3-sanitize-onshutdown-cache",
    "ff3-process-count",
    // Falling back to software rendering is a SYMPTOM. Turning the pref off
    // does not restore acceleration — it removes the fallback that is keeping
    // the browser usable, which is the opposite of a fix.
    "ff3-gfx-webrender-software",
    "cr2-nfc",
    "cr2-vr",
    "cr2-ar",
    "cr2-camera-pan",
    "cr2-font-access",
    "cr2-auto-picture",
    "cr2-captured-surface",
    "cr2-smart-card",
    "cr2-web-printing",
    "cr2-keyboard-lock",
    "cr2-pointer-lock",
    "cr2-background-sync",
    "cr2-media-engagement",
    "cr2-side-panel-companion",
    "cr2-default-browser-nag",
    "cr2-extensions-sideload",
    "cr2-dns-over-https-off",
    "cr2-https-first-balanced",
    // Mail: rendering, composition, and the two rows that could stop mail
    // reaching a server that does not offer TLS.
    "tb2-remote-in-feeds",
    "tb2-auto-download-images",
    "tb2-link-preview",
    "tb2-send-format",
    "tb2-ssl-required",
    "tb2-imap-ssl",
    "tb2-chat-enabled",
  ],
);

/** 2b — the row is a real trade in both directions, so neither answer is a
 *  "fix". Reported with both halves stated. */
const TRADE_OFF = group(
  "Optional — a genuine trade, not a fault. Turning it off buys privacy and " +
    "costs a protection; turning it on does the reverse. Which side you want " +
    "is yours to pick, so this one waits for you to pick it.",
  [
    "ff2-safebrowsing-downloads",
    "ff3-safebrowsing-provider",
    // Opt-in protections that send something to do their job: the page URL
    // in real time, a hashed credential prefix. Both are a user's choice.
    "cr-safebrowsing-enhanced",
    "cr2-password-leak-detect",
  ],
);

/** 2c — a lockdown. Nobody reaches one by accident: an administrator, a
 *  kiosk or school image, or a parental control put it there, and lifting it
 *  unasked undoes somebody's policy on a machine that may be theirs. */
const ADMIN_POLICY = group(
  "Optional — this is a lockdown, and lockdowns are set on purpose: by an " +
    "administrator, a kiosk or classroom image, or a parental control. " +
    "Lifting one undoes that policy, so it happens only when you press this " +
    'button and never on "Fix all". Undo puts the restriction back.',
  [
    "lockdown-save-to-disk",
    "lockdown-printing",
    "lockdown-print-setup",
    "lockdown-command-line",
    "lockdown-user-switching",
    "lockdown-log-out",
    "d3-lockdown-user-admin",
    "d3-lockdown-app-handlers",
  ],
);

/** 2d — off its default only because somebody changed it. The reason is not
 *  visible from here, and "put the default back" is the app guessing it. */
const DELIBERATE = group(
  "Optional — nothing sets this by accident. It is off its default because " +
    "somebody changed it, usually for a reason this app cannot see, so it is " +
    'put back only when you press this button, never on "Fix all". Undo ' +
    "restores your value.",
  [
    "git-symlinks-core",
    "ssh-accept-new-host-key",
    "ff3-accessibility-force",
  ],
);

/** 3 — one write, many programs affected. */
const BLAST_RADIUS = group(
  "Optional, and wide — this is a global override. One line applies to EVERY " +
    "sandboxed application at once, and an app that can suddenly not reach " +
    "your files, your screen or the network gives no useful sign of why. " +
    "Undo puts it back, but the narrower form of this change is per " +
    "application: `flatpak override --user <app>` for the one you mean.",
  [
    "t3-fp-host-fs",
    "t3-fp-devices",
    "t3-fp-x11-fallback",
    "t3-fp-talk-flatpak",
  ],
);

/** 4 — accessibility. The one class with no button at all.
 *
 *  Everything else in this file is offered and left to you. These are not,
 *  and the difference is who finds out it went wrong: a preference you did not
 *  want back is an annoyance you can see and undo, while an on-screen keyboard
 *  missing from a lock screen is discovered by somebody standing in front of a
 *  machine they can no longer get into. A button whose worst case is "cannot
 *  reach the undo button" should not exist. */
const ACCESSIBILITY = group(
  "No automatic fix, and no button: this is accessibility machinery. Taking " +
    "it away can leave somebody unable to use — or unable to unlock — their " +
    "own machine, and that is not a thing to discover after the fact. Change " +
    "it in your desktop's accessibility settings if you are sure.",
  [
    "lock-embedded-keyboard",
    "t3-fp-talk-a11y",
  ],
);

/** Check id → why the change waits for a deliberate press.
 *
 *  These keep their fix. They are shown under Optional, never counted among
 *  the faults, and never run by "Fix all". */
export const OPTIONAL: Record<string, string> = Object.fromEntries([
  ...PANEL,
  ...CAPABILITY,
  ...TRADE_OFF,
  ...ADMIN_POLICY,
  ...DELIBERATE,
  ...BLAST_RADIUS,
]);

/** Check id → why there is no button at all. The genuine exceptions. */
export const NO_BUTTON: Record<string, string> = Object.fromEntries([
  ...ACCESSIBILITY,
]);

/** Checks withdrawn entirely by the same audit.
 *
 *  None is a judgement call: a row that writes the value the tool already uses
 *  (so it "fixes" nothing and reports on every machine), a row whose key can
 *  never match, a row that asks a question another row already asks, and a
 *  row whose reading cannot mean what its title says. All are checks for the
 *  sake of being checks. */
export const RETIRED: Record<string, string> = {
  "git-tag-forcesign": "writes git's existing default — fixes nothing",
  "git-log-showsig": "writes git's existing default — fixes nothing",
  "git-merge-verify": "writes git's existing default — fixes nothing",
  "git-receive-deny-current": "writes git's existing default — fixes nothing",
  "git-gc-prune-expire": "writes git's existing default — fixes nothing",
  "t3-kubectl-noproxy": "~/.kube/config is YAML; the key could never match",
  "t3-docker-content-trust": "~/.docker/config.json is JSON; ditto",
  "t3-aws-metadata": "an EC2-only setting, meaningless on a workstation",
  "t3-ssh-agent-ttl": "could never fire, and asserted nothing if it did",
  "t3-fp-session-bus":
    "asked for a global network denial it then argued against",
  "cr-printing-preview": "clears a remembered print destination — not an issue",
  "ff3-dom-storage-quota": "writes Firefox's existing default — fixes nothing",
  "ff3-indexeddb-shutdown": "writes Firefox's existing default — fixes nothing",
  "cr2-signin-promo": "resets a counter; the prompt setting is a different key",
  "cr-search-autocomplete":
    "names a policy key that does not exist in a profile's Preferences",
  "etcmode-etc-machine-id":
    "asked to take root's write bit off a world-readable file — the value is " +
    "what identifies the machine, and the mode hides none of it",
  "git-index-threads":
    "writes git's existing default, and reported a tuned thread count as a fault",
  "tb-js-in-mail":
    "Thunderbird's real default is on and message JavaScript is already " +
    "blocked by other means; turning it off breaks OAuth sign-in",
  "cr2-network-time":
    "names a dictionary of cached time data as if it were a boolean switch",
  "cr2-safe-browsing-extended":
    "the pre-Scout spelling of cr-safebrowsing-reporting — same question twice",
  "d3-session-idle-zero": "same key as screen-idle-long, with a laxer limit",
  "limit-watches": "same parameter as sysctl-inotify-watches",
  "limit-pid-max": "same parameter as sysctl-pid-max",
  "net-ipv6-privacy": "same parameter as sysctl-tempaddr",
  "swappiness-high-ssd": "same parameter as sysctl-swappiness",
  "etch-grub-lockdown":
    "compared the whole quoted GRUB line for equality, so fired everywhere; " +
    "hard-kernel-lockdown reads the lockdown actually in force",
  "etch-apparmor-enabled":
    "same whole-line comparison; hard-apparmor-cmdline asks for the one " +
    "token that matters, on the command line actually booted",
  "etc-grub-audit":
    "same whole-line comparison, so it reported every machine; the tokens " +
    "worth noticing each have a /proc/cmdline row now",
  "etch-sysctl-conf-local":
    "asked for a hand-kept file the app's own drop-in has replaced",
};
