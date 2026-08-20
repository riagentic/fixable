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
// Four answers put a row in this file:
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
    "d3-session-idle-zero",
    "d3-numlock-remember",
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
    "greeter-quit",
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
  ["ff2-safebrowsing-downloads"],
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
  ...BLAST_RADIUS,
]);

/** Check id → why there is no button at all. The genuine exceptions. */
export const NO_BUTTON: Record<string, string> = Object.fromEntries([
  ...ACCESSIBILITY,
]);

/** Checks withdrawn entirely by the same audit.
 *
 *  Two kinds, and neither is a judgement call: a row that writes the value the
 *  tool already uses (so it "fixes" nothing and reports on every machine), and
 *  a row whose file format means its key can never match, so it could never
 *  have worked. Both are checks for the sake of being checks. */
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
};
