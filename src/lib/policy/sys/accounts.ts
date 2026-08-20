// Accounts and privilege — who can become root on this machine, and how.
import type { SysPolicy } from "../../../type/policy.ts";

const sh = (script: string) => ({
  kind: "cmd" as const,
  cmd: "sh",
  args: ["-c", script] as const,
});

export const ACCOUNT_POLICIES: SysPolicy[] = [
  {
    id: "acct-empty-password",
    title: "An account has no password",
    category: "security",
    severity: "critical",
    weight: 99,
    source: sh(
      "sudo -n awk -F: '($2==\"\"){print $1}' /etc/shadow 2>/dev/null | wc -l || awk -F: '($2==\"\"){print $1}' /etc/passwd 2>/dev/null | wc -l",
    ),
    bad: ">0",
    detail:
      "an account that can be logged into with an empty password is an open door, including over SSH if password authentication is on",
    how:
      "Find it with `sudo awk -F: '($2==\"\")' /etc/shadow`, then set a password (`sudo passwd <user>`) or lock the account (`sudo passwd -l <user>`).",
  },
  {
    id: "acct-duplicate-uid0",
    title: "More than one account has root's user id",
    category: "security",
    severity: "critical",
    weight: 98,
    source: sh("awk -F: '($3==0){c++} END{print c+0}' /etc/passwd 2>/dev/null"),
    bad: ">1",
    detail:
      "a second account with uid 0 is root under another name, and it will not appear in any list of administrators",
    how:
      "`awk -F: '($3==0)' /etc/passwd` names them. Anything other than `root` should be investigated before it is removed.",
  },
  {
    id: "acct-root-login-shell",
    title: "The root account has an interactive shell",
    category: "security",
    severity: "minor",
    weight: 40,
    source: sh("awk -F: '($1==\"root\"){print $7}' /etc/passwd 2>/dev/null"),
    bad: "~/bin/bash",
    detail:
      "on a machine administered through sudo, a login shell for root is one more way in that nobody uses deliberately",
    how:
      "Many distributions leave this as-is on purpose, and locking it can make single-user recovery harder. Consider it only if you are confident in your recovery path.",
  },
  {
    id: "acct-sudo-nopasswd",
    title: "Someone can use sudo without a password",
    category: "security",
    severity: "critical",
    weight: 97,
    source: sh(
      "grep -rhE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | wc -l",
    ),
    bad: ">0",
    detail:
      "any program running as that user becomes root without a prompt — which removes the one barrier between a compromised application and the whole machine",
    how:
      "`sudo grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/` shows the rules. Narrow them to specific commands, or remove them, with `sudo visudo`.",
  },
  {
    id: "acct-sudo-group-large",
    title: "Several accounts can become root",
    category: "security",
    severity: "minor",
    weight: 42,
    source: sh(
      "getent group sudo admin 2>/dev/null | awk -F: '{n=split($4,a,\",\"); t+=n} END{print t+0}'",
    ),
    bad: ">2",
    detail: "every member of the sudo group has full control of this machine",
    how:
      "`getent group sudo` lists them. Remove anyone who does not need it with `sudo deluser <user> sudo`.",
  },
  {
    id: "acct-docker-group",
    title: "An account is in the docker group",
    category: "security",
    severity: "critical",
    weight: 92,
    source: sh(
      "getent group docker 2>/dev/null | awk -F: '{print length($4)}'",
    ),
    bad: ">0",
    detail:
      "membership of the docker group is equivalent to root, without a password and without appearing in any sudo log — a container can mount the host filesystem",
    how:
      "This is a documented Docker property, not a misconfiguration you can patch. If you need containers without it, use Podman rootless. Otherwise treat docker-group membership exactly as you would a passwordless sudo rule.",
  },
  {
    id: "acct-home-readable",
    title: "Another user's home directory is readable",
    category: "privacy",
    severity: "major",
    weight: 66,
    source: sh(
      "find /home -maxdepth 1 -mindepth 1 -type d ! -user $(id -un) -perm -o+r 2>/dev/null | wc -l",
    ),
    bad: ">0",
    detail:
      "you can read another account's files, which means they can read yours if theirs is set the same way",
    how:
      "`sudo chmod 750 /home/<user>` for each. On a single-user machine there is nothing to do.",
  },
  {
    id: "acct-passwd-writable",
    title: "The account database is writable by non-root",
    category: "security",
    severity: "critical",
    weight: 99,
    source: sh(
      "find /etc/passwd /etc/group /etc/shadow /etc/gshadow -perm -o+w -o -perm -g+w 2>/dev/null | wc -l",
    ),
    bad: ">0",
    detail: "anyone who can write these files can add themselves as root",
    how:
      "`sudo chmod 644 /etc/passwd /etc/group` and `sudo chmod 640 /etc/shadow /etc/gshadow`.",
  },
  {
    id: "acct-shells-nologin",
    title: "System accounts have interactive shells",
    category: "security",
    severity: "minor",
    weight: 36,
    source: sh(
      "awk -F: '($3<1000 && $3!=0 && $7 !~ /(nologin|false|sync)/){c++} END{print c+0}' /etc/passwd 2>/dev/null",
    ),
    bad: ">2",
    detail:
      "service accounts that are never meant to log in have a working shell, which turns any credential leak into a session",
    how:
      "`sudo usermod -s /usr/sbin/nologin <account>` for the ones that do not need a shell. Check each — a few, like `sync`, are meant to have one.",
  },
  {
    id: "acct-lastlog-unknown",
    title: "There are recent failed login attempts",
    category: "security",
    severity: "major",
    weight: 64,
    source: sh(
      "journalctl -b --no-pager 2>/dev/null | grep -ciE 'authentication failure|Failed password'",
    ),
    bad: ">20",
    detail:
      "repeated authentication failures since boot — either something is misconfigured and retrying, or something is guessing",
    how:
      "`journalctl -b | grep -i 'authentication failure'` shows the source. If it is coming from the network, that is what the firewall and fail2ban are for.",
  },
  {
    id: "acct-autologin",
    title: "This machine logs in automatically",
    category: "security",
    severity: "critical",
    weight: 96,
    source: sh(
      "grep -rhiE '^\\s*(autologin-user|AutomaticLogin)\\s*=' /etc/lightdm /etc/gdm3 /etc/sddm.conf* 2>/dev/null | grep -vc '=\\s*$'",
    ),
    bad: ">0",
    detail:
      "anyone who powers the machine on is inside your session — no password, no lock screen, and every saved credential in it",
    how:
      "Turn off automatic login in Users settings, or remove the autologin line from your display manager's configuration. It also disables the login keyring's automatic unlock, which is the point.",
  },
  {
    id: "acct-guest-session",
    title: "A guest session is available",
    category: "security",
    severity: "major",
    weight: 82,
    source: sh(
      "grep -rhiE '^\\s*allow-guest\\s*=\\s*true' /etc/lightdm 2>/dev/null | wc -l",
    ),
    bad: ">0",
    detail:
      "anyone at the machine can start a session on it without an account, which puts them on the local network from inside your network",
    how: "Set `allow-guest=false` in /etc/lightdm/lightdm.conf.",
  },
  {
    id: "acct-root-unlocked",
    title: "The root account has a usable password",
    category: "security",
    severity: "major",
    weight: 80,
    source: sh(
      "sudo -n passwd -S root 2>/dev/null | awk '{print $2}' || echo unknown",
    ),
    bad: "~P",
    detail:
      "root can be logged into directly, which bypasses sudo's logging and its per-command limits",
    how:
      "`sudo passwd -l root` locks it. Make sure you can still reach a recovery shell before you do — on most desktops sudo is the only route back.",
  },
  {
    id: "acct-uptime-long",
    title: "The machine has been running for a long time without a restart",
    category: "stability",
    severity: "major",
    weight: 70,
    source: sh("awk '{print int($1/86400)}' /proc/uptime 2>/dev/null"),
    bad: ">45",
    detail:
      "every kernel and library update installed in that time is on disk and not in use — the running system is as old as the last boot",
    how:
      "Reboot. `journalctl -k | head -1` shows when the running kernel started; `uname -r` against /boot shows how far behind it is.",
  },
  {
    id: "acct-hibernate-plain",
    title: "Hibernation writes memory to unencrypted swap",
    category: "security",
    severity: "critical",
    weight: 91,
    source: sh(
      "if grep -q disk /sys/power/state 2>/dev/null && grep -qE '^/dev' /proc/swaps 2>/dev/null; then lsblk -no TYPE 2>/dev/null | grep -c crypt; else echo 1; fi",
    ),
    bad: "=0",
    detail:
      "hibernating writes the entire contents of memory — keys, passwords, open documents — to a swap device that anyone can read afterwards",
    how:
      "Either encrypt the swap device (a /etc/crypttab entry) or disable hibernation (`sudo systemctl mask hibernate.target hybrid-sleep.target`). Suspend-to-RAM is unaffected.",
  },
];
