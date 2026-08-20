// Hardware and firmware: the buses that grant direct memory access, the disks
// that are about to fail, and the radios that are on when nothing is using them.
import type { SysPolicy } from "../../../type/policy.ts";

export const HARDWARE_POLICIES: SysPolicy[] = [
  // ------------------------------------------------------------------- DMA
  {
    id: "hw-thunderbolt-security",
    title: "Thunderbolt accepts devices without authorisation",
    category: "security",
    severity: "critical",
    weight: 93,
    source: {
      kind: "file",
      path: "/sys/bus/thunderbolt/devices/domain0/security",
    },
    bad: "~none",
    detail:
      "a Thunderbolt device plugged into this machine gets direct access to memory — the whole of it — with no prompt",
    how:
      "Set the Thunderbolt security level to `user` or `secure` in BIOS setup. `secure` asks you to approve each device once.",
  },
  {
    id: "hw-iommu-off",
    title: "The IOMMU is not enabled",
    category: "security",
    severity: "major",
    weight: 84,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: ["-c", "ls /sys/class/iommu/ 2>/dev/null | wc -l"],
    },
    bad: "=0",
    detail:
      "nothing constrains what an attached device can read or write in memory, which is what makes a malicious Thunderbolt or PCIe device dangerous",
    how:
      "Enable VT-d (Intel) or AMD-Vi in BIOS setup, and add `intel_iommu=on` or `amd_iommu=on` to the kernel command line if it is not picked up automatically.",
  },
  {
    id: "hw-usb-authorized-default",
    title: "Every USB device is authorised the moment it is plugged in",
    category: "security",
    severity: "minor",
    weight: 46,
    source: {
      kind: "file",
      path: "/sys/module/usbcore/parameters/authorized_default",
    },
    bad: "=1",
    detail:
      "a USB device that presents itself as a keyboard starts typing immediately — the whole basis of a 'rubber ducky' attack",
    how:
      "USBGuard is the proper answer: `sudo apt install usbguard`, generate a policy from what is currently attached, then enable it. Do not set `authorized_default=0` without USBGuard, or your keyboard stops working at the next boot.",
  },
  {
    id: "hw-usbguard-absent",
    title: "No USB device policy is in place",
    category: "security",
    severity: "minor",
    weight: 45,
    source: { kind: "cmd", cmd: "systemctl", args: ["is-active", "usbguard"] },
    bad: "~inactive",
    detail:
      "any USB device is accepted, including one that claims to be a keyboard or a network adapter",
    how:
      "`sudo apt install usbguard`, then `sudo usbguard generate-policy > /etc/usbguard/rules.conf` while your normal devices are attached, then enable the service. Read the policy before enabling it.",
  },
  // -------------------------------------------------------------- firmware
  {
    id: "hw-firmware-updates",
    title: "Firmware updates are available",
    category: "stability",
    severity: "major",
    weight: 75,
    source: {
      kind: "cmd",
      cmd: "fwupdmgr",
      args: ["get-updates"],
      needs: "fwupdmgr",
    },
    bad: "~Upgrade",
    detail:
      "firmware fixes are how processor and storage vulnerabilities actually reach the hardware, and they arrive separately from system updates",
    how:
      "`fwupdmgr get-updates` to read them, `fwupdmgr update` to apply. Do it on mains power and do not interrupt it.",
  },
  {
    id: "hw-firmware-unsupported",
    title: "This hardware receives no firmware updates through the system",
    category: "stability",
    severity: "minor",
    weight: 24,
    source: {
      kind: "cmd",
      cmd: "fwupdmgr",
      args: ["get-devices"],
      needs: "fwupdmgr",
    },
    bad: "~not supported",
    detail:
      "some devices here are outside the update service, so their firmware only changes if you go to the vendor",
    how:
      "Check the vendor's support page for the affected devices. Nothing to do on the machine itself.",
  },
  // --------------------------------------------------------------- radios
  {
    id: "hw-bluetooth-discoverable",
    title: "Bluetooth is discoverable",
    category: "privacy",
    severity: "major",
    weight: 72,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: [
        "-c",
        "bluetoothctl show 2>/dev/null | grep -i '^\\s*Discoverable:'",
      ],
    },
    bad: "~yes",
    detail:
      "the machine announces itself, by name, to every Bluetooth radio in range",
    how:
      "`bluetoothctl discoverable off`. Pairing still works — you just have to start it from this side.",
  },
  {
    id: "hw-bluetooth-pairable",
    title: "Bluetooth accepts new pairings",
    category: "security",
    severity: "minor",
    weight: 44,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: ["-c", "bluetoothctl show 2>/dev/null | grep -i '^\\s*Pairable:'"],
    },
    bad: "~yes",
    detail: "a device in range can begin a pairing request at any time",
    how:
      "`bluetoothctl pairable off`, and turn it on for the minute you need it.",
  },
  {
    id: "hw-bluetooth-unused",
    title: "Bluetooth is running with nothing paired",
    category: "security",
    severity: "minor",
    weight: 26,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: [
        "-c",
        "if systemctl is-active --quiet bluetooth 2>/dev/null; then bluetoothctl devices 2>/dev/null | wc -l; else echo 1; fi",
      ],
    },
    bad: "=0",
    detail:
      "a radio stack is listening on a machine that has never paired anything to it",
    how:
      "`sudo systemctl disable --now bluetooth` if you do not use it. It comes back with one command when you do.",
  },
  {
    id: "hw-wifi-powersave",
    title: "Wi-Fi power saving is causing latency",
    category: "performance",
    severity: "minor",
    weight: 28,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: [
        "-c",
        'iw dev 2>/dev/null | awk \'/Interface/{i=$2} END{if(i) system("iw dev " i " get power_save 2>/dev/null")}\'',
      ],
    },
    bad: "~on",
    detail:
      "the radio sleeps between packets, which shows up as inconsistent ping and stuttering calls",
    how:
      "Set `wifi.powersave = 2` under [connection] in /etc/NetworkManager/conf.d/wifi-powersave.conf. It costs battery on a laptop.",
  },
  // ---------------------------------------------------------------- power
  {
    id: "hw-battery-health",
    title: "The battery has lost a large share of its capacity",
    category: "stability",
    severity: "minor",
    weight: 38,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: [
        "-c",
        'for b in /sys/class/power_supply/BAT*; do [ -e "$b/charge_full" ] && awk -v f="$(cat $b/charge_full)" -v d="$(cat $b/charge_full_design)" \'BEGIN{if(d>0) print int(f*100/d)}\'; done | head -1',
      ],
    },
    bad: "<70",
    detail:
      "the battery holds well under its original charge, so runtime estimates and shutdown thresholds are no longer what they were",
    how:
      "Nothing on the machine fixes a worn cell. If runtime matters, replace it; meanwhile raise the low-battery warning so you are not caught out.",
  },
  {
    id: "hw-ac-only-profile",
    title: "The machine is on battery with a performance power profile",
    category: "resource",
    severity: "minor",
    weight: 20,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: [
        "-c",
        's=$(cat /sys/class/power_supply/A*/online 2>/dev/null | head -1); g=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null); [ "$s" = 0 ] && echo "$g" || echo ok',
      ],
    },
    bad: "~performance",
    detail:
      "running unplugged at full clocks drains the battery several times faster for work that rarely needs it",
    how:
      "Let a profile daemon switch it: `power-profiles-daemon` or `tlp` handle this automatically on AC and battery.",
  },
  {
    id: "hw-sensors-hot",
    title: "A temperature sensor is reading high",
    category: "stability",
    severity: "major",
    weight: 68,
    source: {
      kind: "cmd",
      cmd: "sh",
      args: [
        "-c",
        "sensors 2>/dev/null | grep -oE '\\+[0-9]+\\.[0-9]°C' | tr -d '+°C' | sort -rn | head -1",
      ],
    },
    bad: ">90",
    detail:
      "sustained temperatures at this level shorten hardware life and force the processor to slow down",
    how:
      "Clean the vents and check the fans first — dust is the cause far more often than a failing part. `sensors` and `watch -n1 sensors` show it live.",
  },
];
