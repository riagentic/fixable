// The two areas Fixable had no answer for at all, and they are the two that
// decide whether a bad day is an inconvenience or a catastrophe: whether the
// data is backed up, and whether the disk is encrypted.
//
// No amount of hardening substitutes for either.
import type { SysPolicy } from "../../../type/policy.ts";

const BACKUP: SysPolicy[] = [
  {
    id: "backup-none-configured",
    title: "No backup tool is configured on this machine",
    category: "safety",
    severity: "critical",
    weight: 99,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: [
        "-c",
        "ls -d ~/.config/deja-dup ~/.config/borgmatic ~/.config/restic ~/.config/duplicity ~/.config/timeshift /etc/timeshift* ~/.config/vorta ~/.config/pika-backup ~/.config/rsnapshot 2>/dev/null | wc -l",
      ],
    },
    bad: "=0",
    detail:
      "nothing on this machine is copying your files anywhere — a failed disk, a mistaken delete or ransomware costs you everything on it",
    how:
      "Pick one and set it up today: Déjà Dup (in the software manager, simplest), Pika Backup or Vorta for Borg, or `restic` for a scriptable one. Back up to something that is not this machine, and check that a restore actually works.",
  },
  {
    id: "backup-stale-dejadup",
    title: "The last backup was a long time ago",
    category: "safety",
    severity: "critical",
    weight: 98,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: [
        "-c",
        'd=$(gsettings get org.gnome.DejaDup last-backup 2>/dev/null | tr -d "\'"); [ -n "$d" ] && python3 -c "import sys,datetime;print(int((datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(sys.argv[1].replace(\'Z\',\'+00:00\'))).days))" "$d" 2>/dev/null || echo \'\'',
      ],
    },
    bad: ">14",
    detail:
      "a backup that is weeks old is a backup of work you have since redone",
    how:
      "Open your backup tool and run one now, then set a schedule. Weekly is the least that is useful; daily is better if the machine is on daily.",
  },
  {
    id: "backup-timeshift-none",
    title: "No system snapshots are configured",
    category: "safety",
    severity: "major",
    weight: 74,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: ["-c", "ls /etc/timeshift/timeshift.json 2>/dev/null | wc -l"],
    },
    bad: "=0",
    detail:
      "an update or a configuration change that breaks the machine has no route back except a reinstall",
    how:
      "Install Timeshift and take a snapshot before big changes. Note that Timeshift protects the SYSTEM, not your files — it is not a substitute for a real backup.",
  },
  {
    id: "backup-same-disk",
    title: "Backups appear to live on the same physical disk",
    category: "safety",
    severity: "critical",
    weight: 97,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: [
        "-c",
        'n=$(lsblk -dno NAME,TYPE 2>/dev/null | grep -c disk); [ "$n" = 1 ] && ls -d ~/Backups ~/backup /backup 2>/dev/null | wc -l || echo 0',
      ],
    },
    bad: ">0",
    detail:
      "a backup on the disk it is protecting survives a mistaken delete and nothing else — not a disk failure, not a theft, not ransomware",
    how:
      "Move it to an external drive or a remote target. A copy on the same disk is a convenience, not a backup.",
  },
  {
    id: "backup-trash-as-safety",
    title: "The trash is holding a large amount of data",
    category: "safety",
    severity: "minor",
    weight: 30,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: ["-c", "du -sm ~/.local/share/Trash 2>/dev/null | cut -f1"],
    },
    bad: ">2048",
    detail:
      "gigabytes of deleted files are still occupying the disk, and the trash is not a backup either",
    how:
      "Empty it when you are sure — but check first that nothing in it is the only copy of something.",
  },
];

const CRYPTO: SysPolicy[] = [
  {
    id: "disk-no-luks",
    title: "No encrypted volume is in use on this machine",
    category: "security",
    severity: "critical",
    weight: 96,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: ["-c", "lsblk -no TYPE 2>/dev/null | grep -c crypt"],
    },
    bad: "=0",
    detail:
      "anyone who takes the machine, or the disk out of it, reads every file on it — no password on the login screen changes that",
    how:
      "Full-disk encryption has to be set up at install time on most distributions. If this machine holds anything you would not hand to a stranger, that is the honest answer: reinstall with encryption, or at minimum move the sensitive parts into an encrypted container (`cryptsetup`, or a VeraCrypt volume).",
  },
  {
    id: "disk-swap-unencrypted",
    title: "Swap is not encrypted",
    category: "security",
    severity: "major",
    weight: 86,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: [
        "-c",
        "if grep -qE '^/dev' /proc/swaps 2>/dev/null; then lsblk -no NAME,TYPE 2>/dev/null | grep -c crypt; else echo 1; fi",
      ],
    },
    bad: "=0",
    detail:
      "anything that has been in memory — keys, passwords, documents — can be written to swap in clear text and stays on the disk after shutdown",
    how:
      "Use an encrypted swap device (a `/etc/crypttab` entry with a random key), or switch to zram, which never touches the disk. A swap FILE inside an encrypted filesystem is fine as it is.",
  },
  {
    id: "disk-home-unencrypted",
    title: "The home directory is on an unencrypted filesystem",
    category: "security",
    severity: "major",
    weight: 85,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: [
        "-c",
        'src=$(findmnt -no SOURCE --target "$HOME" 2>/dev/null); case "$src" in *mapper*|*crypt*) echo encrypted;; *) echo plain;; esac',
      ],
    },
    bad: "~plain",
    detail:
      "your documents, keys and browser profiles are readable by anyone who can boot from a USB stick",
    how:
      "Encrypting an existing /home in place is not a small operation — back up, then either reinstall with encryption or move /home to a new LUKS volume. Treat this as a project, not a quick fix.",
  },
  {
    id: "crypt-tpm-absent",
    title: "No TPM is available for measured boot",
    category: "security",
    severity: "minor",
    weight: 34,
    source: { kind: "file", path: "/sys/class/tpm/tpm0/tpm_version_major" },
    missingIsBad: true,
    detail:
      "there is no hardware root of trust, so disk encryption cannot be bound to this machine's boot state",
    how:
      "This is firmware: enable the TPM (often called PTT or fTPM) in your BIOS setup. It matters only if you want unattended unlock bound to a known-good boot.",
  },
  {
    id: "crypt-secureboot-off",
    title: "Secure Boot is off",
    category: "security",
    severity: "minor",
    weight: 48,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: [
        "-c",
        "mokutil --sb-state 2>/dev/null || bootctl status 2>/dev/null | grep -i 'secure boot' || echo unknown",
      ],
    },
    bad: "~disabled",
    detail:
      "the firmware will start any bootloader, so a tampered one starts as readily as yours",
    how:
      "Enable Secure Boot in BIOS setup. Check first that your kernel modules are signed — an NVIDIA driver built by DKMS needs enrolling with `mokutil`, or the machine boots without graphics.",
  },
  {
    id: "crypt-user-ca",
    title: "Extra certificate authorities are installed on this machine",
    category: "security",
    severity: "major",
    weight: 87,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: [
        "-c",
        "ls /usr/local/share/ca-certificates/*.crt 2>/dev/null | wc -l",
      ],
    },
    bad: ">0",
    detail:
      "a locally installed certificate authority can issue a valid certificate for any site, which is exactly how traffic interception works — sometimes it is your employer, sometimes it is not",
    how:
      "List them with `ls /usr/local/share/ca-certificates/` and `trust list`. Remove anything you do not recognise and run `sudo update-ca-certificates --fresh`.",
  },
  {
    id: "crypt-ca-store-stale",
    title:
      "The certificate authority bundle has not been updated in a long time",
    category: "security",
    severity: "minor",
    weight: 43,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: [
        "-c",
        "f=/etc/ssl/certs/ca-certificates.crt; [ -e $f ] && echo $(( ( $(date +%s) - $(stat -c %Y $f) ) / 86400 )) || echo ''",
      ],
    },
    bad: ">365",
    detail:
      "revoked and expired roots are still trusted, and newly issued ones are not",
    how:
      "It updates with the `ca-certificates` package: `sudo apt update && sudo apt install --only-upgrade ca-certificates`.",
  },
];

export const DATA_POLICIES: SysPolicy[] = [...BACKUP, ...CRYPTO];
