// Disks and filesystems: health, capacity, and the settings that decide
// whether an SSD stays fast and a filesystem stays consistent.
import type { SysPolicy } from "../../../type/policy.ts";

const sh = (script: string) => ({
  kind: "cmd" as const,
  cmd: "sh",
  args: ["-c", script] as const,
});

export const DISK_POLICIES: SysPolicy[] = [
  // ---------------------------------------------------------------- health
  {
    id: "disk-smart-failing",
    title: "A disk reports that it is failing",
    category: "stability",
    severity: "critical",
    weight: 99,
    source: sh(
      "for d in /dev/sd? /dev/nvme?n?; do [ -e $d ] && smartctl -H $d 2>/dev/null; done | grep -iE 'result|health' | head -2",
    ),
    bad: "~FAILED",
    detail:
      "the drive's own self-assessment says it is failing — this is the one warning you get, and it usually comes days before the data goes",
    how:
      "Back up now, before anything else. Then `sudo smartctl -a /dev/…` for the detail and replace the drive. Do not run a long self-test on a drive you have not copied off yet.",
  },
  {
    id: "disk-reallocated",
    title: "A disk has reallocated sectors",
    category: "stability",
    severity: "major",
    weight: 88,
    source: sh(
      "for d in /dev/sd? /dev/nvme?n?; do [ -e $d ] && smartctl -A $d 2>/dev/null; done | awk '/Reallocated_Sector_Ct/{print $10}' | sort -rn | head -1",
    ),
    bad: ">0",
    detail:
      "the drive has moved data off sectors that stopped holding it — a count that grows is a drive on its way out",
    how:
      "Note the number and check it again in a week. If it is rising, replace the drive. `sudo smartctl -a /dev/…` shows the trend.",
  },
  {
    id: "disk-pending-sectors",
    title: "A disk has sectors it cannot read",
    category: "stability",
    severity: "critical",
    weight: 95,
    source: sh(
      "for d in /dev/sd? /dev/nvme?n?; do [ -e $d ] && smartctl -A $d 2>/dev/null; done | awk '/Current_Pending_Sector/{print $10}' | sort -rn | head -1",
    ),
    bad: ">0",
    detail: "there is data on this drive the drive itself cannot read back",
    how:
      "Back up immediately. A pending sector means a file is already unreadable or about to be.",
  },
  {
    id: "disk-crc-errors",
    title: "A disk interface is reporting transfer errors",
    category: "stability",
    severity: "major",
    weight: 76,
    source: sh(
      "for d in /dev/sd?; do [ -e $d ] && smartctl -A $d 2>/dev/null; done | awk '/UDMA_CRC_Error_Count/{print $10}' | sort -rn | head -1",
    ),
    bad: ">10",
    detail:
      "the cable or connector between the drive and the board is losing data in transit",
    how:
      "This is almost always the SATA cable. Reseat it, or replace it — it is the cheapest part in the machine.",
  },
  {
    id: "disk-nvme-wear",
    title: "An SSD is well through its rated write endurance",
    category: "stability",
    severity: "major",
    weight: 70,
    source: sh(
      'nvme smart-log /dev/nvme0n1 2>/dev/null | awk \'/percentage_used/{gsub("%","",$3); print $3}\'',
    ),
    bad: ">80",
    detail:
      "the drive reports most of its write life used, and endurance falls off sharply at the end",
    how:
      "Plan a replacement. Meanwhile reduce needless writes: `noatime` on busy filesystems, and swap on zram rather than the SSD.",
  },
  {
    id: "disk-fs-errors",
    title: "The kernel is logging filesystem errors",
    category: "stability",
    severity: "critical",
    weight: 94,
    source: sh(
      "journalctl -k -b -p err --no-pager 2>/dev/null | grep -icE 'ext4-fs error|btrfs.*(error|corrupt)|xfs.*corrupt|i/o error'",
    ),
    bad: ">0",
    detail:
      "the filesystem or the device under it is returning errors right now",
    how:
      "`journalctl -k -b -p err` for the detail. Back up first, then unmount and check the filesystem — never fsck a mounted one.",
  },
  {
    id: "disk-remounted-ro",
    title: "A filesystem has been remounted read-only after an error",
    category: "stability",
    severity: "critical",
    weight: 97,
    source: sh(
      "journalctl -k -b --no-pager 2>/dev/null | grep -ic 'Remounting filesystem read-only'",
    ),
    bad: ">0",
    detail:
      "the kernel hit an error it could not recover from and stopped writing to protect what is left",
    how:
      "Do not reboot into it repeatedly. Back up what you can read, then check the filesystem from a live USB.",
  },
  {
    id: "disk-btrfs-errors",
    title: "Btrfs is reporting device errors",
    category: "stability",
    severity: "critical",
    weight: 96,
    source: sh(
      "btrfs device stats / 2>/dev/null | awk -F'  *' '{s+=$2} END{print s+0}'",
    ),
    bad: ">0",
    detail:
      "the filesystem has recorded read, write or checksum failures on a device",
    how:
      "`sudo btrfs device stats /` names the counter. A non-zero checksum count means data has already been corrupted — restore those files from backup and check the drive.",
  },
  {
    id: "disk-btrfs-scrub-stale",
    title: "Btrfs has not been scrubbed in a long time",
    category: "stability",
    severity: "minor",
    weight: 48,
    source: sh(
      "btrfs scrub status / 2>/dev/null | awk -F': ' '/Scrub started|last scrub/{print $2}' | head -1 | xargs -I{} date -d {} +%s 2>/dev/null | awk '{print int(('$(date +%s)'-$1)/86400)}'",
    ),
    bad: ">90",
    detail:
      "nothing has verified the checksums, so silent corruption would go unnoticed until you open the file",
    how:
      "`sudo btrfs scrub start /`. It runs in the background and can be paused; schedule it monthly with a systemd timer.",
  },
  {
    id: "disk-raid-degraded",
    title: "A RAID array is degraded",
    category: "stability",
    severity: "critical",
    weight: 98,
    source: { kind: "file", path: "/proc/mdstat" },
    bad: "~_",
    detail:
      "the array is running with a failed member, so there is no redundancy left — the next failure loses the data",
    how:
      "`cat /proc/mdstat` and `sudo mdadm --detail /dev/mdX` to identify the failed device, then replace it and let it rebuild.",
  },
  // -------------------------------------------------------------- capacity
  {
    id: "disk-inodes",
    title: "A filesystem is running out of inodes",
    category: "resource",
    severity: "major",
    weight: 82,
    source: sh(
      'df -i -P 2>/dev/null | awk \'NR>1 && $1 ~ /^\\/dev/ {gsub("%","",$5); if($5+0>90) print $5}\' | sort -rn | head -1',
    ),
    bad: ">90",
    detail:
      "the disk has space but no free inodes, so writes fail with 'no space left' while df shows room — one of the most confusing failures there is",
    how:
      "Find the directory with the file count: `sudo du --inodes -x -d3 / | sort -rn | head`. It is usually a cache or a mail spool.",
  },
  {
    id: "disk-boot-full",
    title: "The boot partition is nearly full",
    category: "stability",
    severity: "critical",
    weight: 93,
    source: sh(
      'df -P /boot 2>/dev/null | awk \'NR==2{gsub("%","",$5); print $5}\'',
    ),
    bad: ">80",
    detail:
      "a full /boot makes the next kernel update fail part-way, which can leave the machine unbootable",
    how:
      "`sudo apt autoremove --purge` removes old kernels. Check what is there with `dpkg -l 'linux-image-*'` and keep the running one plus one spare.",
  },
  {
    id: "disk-old-kernels",
    title: "Several old kernels are installed",
    category: "resource",
    severity: "minor",
    weight: 40,
    source: sh("dpkg -l 'linux-image-[0-9]*' 2>/dev/null | grep -c '^ii'"),
    bad: ">3",
    detail:
      "each kernel takes hundreds of megabytes of /boot, and /boot is the partition that is never big enough",
    how:
      "`sudo apt autoremove --purge`. Keep the running kernel and one previous — that is your way back if an update misbehaves.",
  },
  {
    id: "disk-apt-cache",
    title: "The package cache is large",
    category: "resource",
    severity: "minor",
    weight: 32,
    source: sh("du -sm /var/cache/apt/archives 2>/dev/null | cut -f1"),
    bad: ">2048",
    detail: "downloaded package files nothing needs any more",
    how:
      "`sudo apt clean`. Nothing installed is affected — these are the downloaded archives.",
  },
  {
    id: "disk-journal-size",
    title: "The system journal is large",
    category: "resource",
    severity: "minor",
    weight: 34,
    source: sh(
      'journalctl --disk-usage 2>/dev/null | grep -oE \'[0-9.]+[MG]\' | head -1 | awk \'/G/{gsub("G","");print $1*1024} /M/{gsub("M","");print $1}\'',
    ),
    bad: ">2048",
    detail:
      "logs have grown without a cap, and they grow fastest exactly when something is going wrong",
    how:
      "`sudo journalctl --vacuum-size=500M` now, and set `SystemMaxUse=500M` in /etc/systemd/journald.conf so it stays bounded.",
  },
  {
    id: "disk-coredumps",
    title: "Core dumps are taking up space",
    category: "privacy",
    severity: "minor",
    weight: 36,
    source: sh("du -sm /var/lib/systemd/coredump 2>/dev/null | cut -f1"),
    bad: ">200",
    detail:
      "each dump is a copy of a program's memory, which routinely includes keys and passwords, sitting on disk",
    how:
      "`sudo rm -rf /var/lib/systemd/coredump/*` and set `Storage=none` in /etc/systemd/coredump.conf.",
  },
  {
    id: "disk-docker-usage",
    title: "Docker is using a lot of disk",
    category: "resource",
    severity: "minor",
    weight: 38,
    source: sh(
      'docker system df --format \'{{.Size}}\' 2>/dev/null | head -1 | awk \'/GB/{gsub("GB","");print $1*1024} /MB/{gsub("MB","");print $1}\'',
    ),
    bad: ">20480",
    detail: "images, volumes and build cache that nothing is running any more",
    how:
      "`docker system df` to see the breakdown, then `docker system prune` (add `-a` for unused images). Check your volumes first — prune can remove data.",
  },
  {
    id: "disk-flatpak-unused",
    title: "Unused Flatpak runtimes are installed",
    category: "resource",
    severity: "minor",
    weight: 30,
    source: sh(
      "flatpak uninstall --unused --assumeyes --no-deploy 2>/dev/null | grep -c . ; flatpak list --runtime 2>/dev/null | wc -l",
    ),
    bad: ">12",
    detail:
      "old runtime versions stay behind after apps move on, and each is hundreds of megabytes",
    how:
      "`flatpak uninstall --unused`. It lists what it will remove before doing it.",
  },
  // -------------------------------------------------------------- settings
  {
    id: "disk-trim-timer",
    title: "Scheduled TRIM is not running",
    category: "performance",
    severity: "minor",
    weight: 50,
    source: {
      kind: "cmd",
      cmd: "systemctl",
      args: ["is-enabled", "fstrim.timer"],
    },
    bad: "~disabled",
    detail:
      "an SSD that is never trimmed gets slower at writing as it fills, and stays slow",
    how:
      "`sudo systemctl enable --now fstrim.timer`. It runs weekly and takes seconds.",
  },
  {
    id: "disk-scheduler-ssd",
    title: "An NVMe drive is using a rotational I/O scheduler",
    category: "performance",
    severity: "minor",
    weight: 42,
    source: sh("cat /sys/block/nvme0n1/queue/scheduler 2>/dev/null"),
    bad: "~[bfq]",
    detail:
      "a scheduler designed to minimise head movement adds latency to a device that has no head",
    how:
      "`echo none | sudo tee /sys/block/nvme0n1/queue/scheduler`, and make it permanent with a udev rule.",
  },
  {
    id: "disk-atime",
    title: "A filesystem records an access time for every read",
    category: "performance",
    severity: "minor",
    weight: 33,
    source: sh(
      "findmnt -no OPTIONS / 2>/dev/null | grep -o 'relatime\\|noatime\\|strictatime' | head -1",
    ),
    bad: "~strictatime",
    detail:
      "every file you read causes a write, which costs SSD life and IO for information almost nothing uses",
    how:
      "Change the option to `relatime` (the usual default) or `noatime` in /etc/fstab.",
  },
  {
    id: "disk-discard-mount",
    title: "A filesystem is mounted with continuous discard",
    category: "performance",
    severity: "minor",
    weight: 29,
    source: sh("findmnt -no OPTIONS / 2>/dev/null"),
    bad: "~discard",
    detail:
      "issuing a TRIM on every delete stalls writes on many drives; the weekly timer does the same job without the pauses",
    how:
      "Remove `discard` from the mount options in /etc/fstab and rely on `fstrim.timer` instead.",
  },
  {
    id: "disk-reserved-blocks",
    title: "A large data filesystem reserves space for root",
    category: "resource",
    severity: "minor",
    weight: 25,
    source: sh(
      "for d in $(lsblk -pnro NAME,FSTYPE | awk '$2 ~ /^ext[34]$/{print $1}'); do tune2fs -l $d 2>/dev/null | awk -F': *' '/Reserved block count/{r=$2} /Block count/{b=$2} END{if(b>0) print int(r*100/b)}'; done | sort -rn | head -1",
    ),
    bad: ">4",
    detail:
      "5% of a large data partition is reserved for a root user that never writes there — on a multi-terabyte disk that is tens of gigabytes",
    how:
      "`sudo tune2fs -m 1 /dev/…` on data partitions only. Leave the system partition at 5%: that reserve is what stops a full disk from wedging the machine.",
  },
];
