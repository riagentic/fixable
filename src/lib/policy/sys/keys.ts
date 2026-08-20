// Key hygiene: the SSH and GnuPG material this account actually holds, and
// whether any of it is too old or too weak to still be trusted.
import type { SysPolicy } from "../../../type/policy.ts";

const sh = (script: string) => ({
  kind: "cmd" as const,
  cmd: "sh",
  args: ["-c", script] as const,
});

export const KEY_POLICIES: SysPolicy[] = [
  {
    id: "key-ssh-dsa",
    title: "A DSA SSH key is present",
    category: "security",
    severity: "critical",
    weight: 92,
    source: sh(
      'for f in ~/.ssh/*.pub; do [ -e "$f" ] && ssh-keygen -l -f "$f" 2>/dev/null; done | grep -ci \'(DSA)\'',
    ),
    bad: ">0",
    detail:
      "DSA keys are capped at 1024 bits and OpenSSH removed support years ago — a key that is still there is a key still being offered",
    how:
      "Generate a replacement (`ssh-keygen -t ed25519`), install the new public key everywhere the old one was, then delete the old pair.",
  },
  {
    id: "key-ssh-rsa-weak",
    title: "An SSH key is shorter than 3072 bits",
    category: "security",
    severity: "major",
    weight: 84,
    source: sh(
      'for f in ~/.ssh/*.pub; do [ -e "$f" ] && ssh-keygen -l -f "$f" 2>/dev/null; done | awk \'/RSA/{print $1}\' | sort -n | head -1',
    ),
    bad: "<3072",
    detail:
      "a short RSA key is the weakest link in every connection it authenticates",
    how:
      "`ssh-keygen -t ed25519 -a 100` produces a better key that is also shorter and faster. Roll it out before removing the old one.",
  },
  {
    id: "key-ssh-no-passphrase",
    title: "A private SSH key has no passphrase",
    category: "security",
    severity: "major",
    weight: 86,
    source: sh(
      'c=0; for f in ~/.ssh/*; do case "$f" in *.pub) continue;; esac; [ -f "$f" ] && grep -qE \'PRIVATE KEY\' "$f" 2>/dev/null && ! grep -q \'ENCRYPTED\' "$f" 2>/dev/null && head -c 100 "$f" | grep -q \'OPENSSH PRIVATE KEY\' && ssh-keygen -y -P \'\' -f "$f" >/dev/null 2>&1 && c=$((c+1)); done; echo $c',
    ),
    bad: ">0",
    detail:
      "a key file without a passphrase is usable by anyone who copies it — a backup, a stolen laptop, or any program running as you",
    how:
      "`ssh-keygen -p -f ~/.ssh/<key>` adds one without changing the key itself. Use `ssh-agent` so you type it once per session.",
  },
  {
    id: "key-ssh-old",
    title: "An SSH key is very old",
    category: "security",
    severity: "minor",
    weight: 40,
    source: sh(
      'for f in ~/.ssh/*.pub; do [ -e "$f" ] && echo $(( ( $(date +%s) - $(stat -c %Y "$f") ) / 86400 )); done | sort -rn | head -1',
    ),
    bad: ">1825",
    detail:
      "a key that has been in use for five years has been copied to more places than you remember",
    how:
      "Rotate it: generate a new pair, add it everywhere, then remove the old public key from each `authorized_keys` before deleting the private one.",
  },
  {
    id: "key-known-hosts-plain",
    title: "known_hosts records host names in clear text",
    category: "privacy",
    severity: "major",
    weight: 66,
    source: sh(
      "[ -f ~/.ssh/known_hosts ] && grep -cv '^|1|' ~/.ssh/known_hosts 2>/dev/null || echo 0",
    ),
    bad: ">0",
    detail:
      "anything that can read the file gets a list of every server you connect to",
    how:
      "`ssh-keygen -H` hashes the existing file (it keeps a `.old` backup). Set `HashKnownHosts yes` so new entries are hashed too.",
  },
  {
    id: "key-authorized-keys",
    title: "This account accepts SSH logins by key",
    category: "security",
    severity: "major",
    weight: 74,
    source: sh(
      "[ -f ~/.ssh/authorized_keys ] && grep -cvE '^\\s*(#|$)' ~/.ssh/authorized_keys 2>/dev/null || echo 0",
    ),
    bad: ">0",
    detail:
      "each entry is a key that can log in as you — worth knowing about, and worth checking you still recognise every one",
    how:
      "`ssh-keygen -l -f ~/.ssh/authorized_keys` prints a fingerprint per line. Remove anything you do not recognise.",
  },
  {
    id: "key-agent-no-confirm",
    title: "The SSH agent signs without asking",
    category: "security",
    severity: "minor",
    weight: 48,
    source: sh("ssh-add -l 2>/dev/null | grep -c . || echo 0"),
    bad: ">0",
    detail:
      "any program running as you can have the agent sign with your keys, silently, for as long as they are loaded",
    how:
      "Load keys with `ssh-add -c` so each use prompts, and `ssh-add -t 1h` so they expire.",
  },
  {
    id: "key-gpg-expired",
    title: "A GnuPG key has expired",
    category: "stability",
    severity: "minor",
    weight: 44,
    source: sh(
      'gpg --list-keys --with-colons 2>/dev/null | awk -F: \'$1=="pub" && $2=="e"\' | wc -l',
    ),
    bad: ">0",
    detail:
      "signatures made with it no longer verify, and people who try to encrypt to it will be refused",
    how:
      "`gpg --edit-key <id>` then `expire` to extend it — the key itself stays valid, only the expiry moves. Re-publish afterwards.",
  },
  {
    id: "key-gpg-expiring",
    title: "A GnuPG key expires soon",
    category: "stability",
    severity: "minor",
    weight: 36,
    source: sh(
      'n=$(date -d \'+60 days\' +%s 2>/dev/null); gpg --list-keys --with-colons 2>/dev/null | awk -F: -v n="$n" \'$1=="pub" && $7!="" && $7+0<n\' | wc -l',
    ),
    bad: ">0",
    detail:
      "it stops working within two months, and the people who need the new one will not find out until it does",
    how:
      "Extend it with `gpg --edit-key <id>` / `expire`, and publish the update before the date.",
  },
  {
    id: "key-gpg-weak",
    title: "A GnuPG key is shorter than 3072 bits",
    category: "security",
    severity: "major",
    weight: 80,
    source: sh(
      "gpg --list-keys --with-colons 2>/dev/null | awk -F: '$1==\"pub\" && $4==1 {print $3}' | sort -n | head -1",
    ),
    bad: "<3072",
    detail:
      "a short RSA key is the weak point in every signature it makes and every message encrypted to it",
    how:
      "Generate a new key (`gpg --full-generate-key`, ed25519 or 4096-bit RSA), sign it with the old one, publish, and set the old one to expire.",
  },
  {
    id: "key-gpg-no-revocation",
    title: "There is no revocation certificate for your GnuPG key",
    category: "safety",
    severity: "major",
    weight: 76,
    source: sh(
      'k=$(gpg --list-secret-keys --with-colons 2>/dev/null | grep -c \'^sec\'); r=$(ls ~/.gnupg/openpgp-revocs.d/*.rev 2>/dev/null | wc -l); [ "$k" -gt 0 ] && [ "$r" -eq 0 ] && echo 1 || echo 0',
    ),
    bad: ">0",
    detail:
      "if the key is lost or compromised there is no way to tell anyone — the key stays valid to everyone who has it, forever",
    how:
      "`gpg --gen-revoke <id> > revoke.asc`, then store it somewhere other than this machine. Modern GnuPG generates one automatically in ~/.gnupg/openpgp-revocs.d — check it is really there.",
  },
  {
    id: "key-gpg-backup",
    title: "Your GnuPG secret keys exist only on this machine",
    category: "safety",
    severity: "major",
    weight: 78,
    source: sh(
      "gpg --list-secret-keys --with-colons 2>/dev/null | grep -c '^sec'",
    ),
    bad: ">0",
    detail:
      "a disk failure takes every encrypted file and every identity that key represents with it, and no backup of the machine helps if the backup is encrypted to the same key",
    how:
      "`gpg --export-secret-keys --armor <id>` and store the result offline — printed, or on a drive you keep elsewhere. Test the restore.",
  },
];
