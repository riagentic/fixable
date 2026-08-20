// Name resolution, wireless, and the network settings that decide who can see
// what this machine is doing.
import type { SysPolicy } from "../../../type/policy.ts";

const sh = (script: string) => ({
  kind: "cmd" as const,
  cmd: "sh",
  args: ["-c", script] as const,
});

export const NETWORK_POLICIES: SysPolicy[] = [
  {
    id: "net-dns-plaintext",
    title: "DNS queries are sent in clear text",
    category: "privacy",
    severity: "major",
    weight: 77,
    source: sh(
      "resolvectl status 2>/dev/null | grep -m1 -i 'DNS over TLS' || echo 'DNSOverTLS: no'",
    ),
    bad: "~no",
    detail:
      "every name you look up is visible to your network and your provider, whatever the traffic itself is encrypted with",
    how:
      "Set `DNSOverTLS=opportunistic` under [Resolve] in /etc/systemd/resolved.conf and restart systemd-resolved. `strict` is stronger but fails closed on networks that block it.",
  },
  {
    id: "net-dnssec-off",
    title: "DNS answers are not validated",
    category: "security",
    severity: "major",
    weight: 76,
    source: sh(
      "resolvectl status 2>/dev/null | grep -m1 -i 'DNSSEC setting' || echo 'DNSSEC: no'",
    ),
    bad: "~no",
    detail:
      "a forged answer sends you to the wrong server, and nothing on screen distinguishes it from the right one",
    how:
      "`DNSSEC=allow-downgrade` under [Resolve] in /etc/systemd/resolved.conf.",
  },
  {
    id: "net-dns-isp",
    title: "Name resolution uses the network's own resolver",
    category: "privacy",
    severity: "minor",
    weight: 42,
    source: sh(
      "resolvectl status 2>/dev/null | grep -m1 'Current DNS Server' || echo none",
    ),
    bad: "~192.168.",
    detail:
      "your router, and through it your provider, has a complete list of every site you visit",
    how:
      "Set a resolver you choose in NetworkManager (per-connection) or globally in /etc/systemd/resolved.conf. Combine it with DNS over TLS or the change is only cosmetic.",
  },
  {
    id: "net-resolv-symlink",
    title: "/etc/resolv.conf is not managed by the resolver",
    category: "stability",
    severity: "minor",
    weight: 34,
    source: sh("[ -L /etc/resolv.conf ] && echo managed || echo static"),
    bad: "~static",
    detail:
      "a hand-written resolv.conf is silently replaced by some tools and silently kept by others, which is why DNS 'sometimes' changes by itself",
    how:
      "Let systemd-resolved own it: `sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf`.",
  },
  {
    id: "net-wifi-mac-static",
    title: "Wi-Fi uses your real hardware address",
    category: "privacy",
    severity: "major",
    weight: 74,
    source: sh(
      "nmcli -t -f 802-11-wireless.cloned-mac-address con show 2>/dev/null | head -1; echo unset",
    ),
    bad: "~unset",
    detail:
      "every access point you pass records the same identifier for this machine, which is enough to track it between locations",
    how:
      "Set `wifi.scan-rand-mac-address=yes` under [device] and `wifi.cloned-mac-address=stable` under [connection] in /etc/NetworkManager/NetworkManager.conf.",
  },
  {
    id: "net-wifi-open-saved",
    title: "An open Wi-Fi network is saved",
    category: "security",
    severity: "major",
    weight: 78,
    source: sh(
      "grep -rl 'key-mgmt=none' /etc/NetworkManager/system-connections/ 2>/dev/null | wc -l",
    ),
    bad: ">0",
    detail:
      "the machine will rejoin an unencrypted network automatically, and anyone can impersonate one by broadcasting the same name",
    how:
      "Remove saved open networks you do not need, and turn off auto-connect on the ones you keep.",
  },
  {
    id: "net-wifi-wep",
    title: "A saved Wi-Fi network uses broken encryption",
    category: "security",
    severity: "critical",
    weight: 90,
    source: sh(
      "grep -rlE 'key-mgmt=(none|ieee8021x)|wep-key' /etc/NetworkManager/system-connections/ 2>/dev/null | wc -l",
    ),
    bad: ">0",
    detail: "WEP is decrypted in minutes with commodity tools",
    how:
      "Change the access point to WPA2 or WPA3 and remove the saved profile.",
  },
  {
    id: "net-autoconnect-any",
    title: "The machine joins known networks automatically anywhere",
    category: "security",
    severity: "minor",
    weight: 44,
    source: sh(
      "grep -rc 'autoconnect=true' /etc/NetworkManager/system-connections/ 2>/dev/null | awk -F: '{s+=$2} END{print s+0}'",
    ),
    bad: ">6",
    detail:
      "an attacker who broadcasts the name of a network you have saved gets the machine to join them",
    how: "Turn off auto-connect for networks outside your home and office.",
  },
  {
    id: "net-ipv6-privacy",
    title: "IPv6 privacy addresses are not preferred",
    category: "privacy",
    severity: "major",
    weight: 73,
    source: { kind: "file", path: "/proc/sys/net/ipv6/conf/all/use_tempaddr" },
    bad: "<2",
    detail:
      "the outbound IPv6 address is derived from the hardware address, so every site you visit can follow this exact machine across networks",
    how:
      "`net.ipv6.conf.all.use_tempaddr=2` and the same for `default` in /etc/sysctl.d/99-local.conf.",
  },
  {
    id: "net-hostname-broadcast",
    title: "The machine sends its hostname to every network it joins",
    category: "privacy",
    severity: "minor",
    weight: 40,
    source: sh(
      "grep -rhc 'dhcp-send-hostname=false' /etc/NetworkManager/ 2>/dev/null | awk '{s+=$1} END{print (s>0)?\"set\":\"unset\"}'",
    ),
    bad: "~unset",
    detail:
      "your DHCP request carries the machine's name, which is often a person's name, to every café and airport network",
    how:
      "Set `dhcp-send-hostname=false` in a NetworkManager connection profile, or globally under [connection].",
  },
  {
    id: "net-bbr",
    title: "The connection is using an older congestion control algorithm",
    category: "performance",
    severity: "minor",
    weight: 28,
    source: { kind: "file", path: "/proc/sys/net/ipv4/tcp_congestion_control" },
    bad: "~cubic",
    detail:
      "on links with any loss, BBR sustains noticeably higher throughput than the default",
    how:
      "`net.ipv4.tcp_congestion_control=bbr` plus `net.core.default_qdisc=fq` in /etc/sysctl.d/99-local.conf.",
  },
  {
    id: "net-proxy-env",
    title: "A proxy is configured in your environment",
    category: "privacy",
    severity: "major",
    weight: 66,
    source: sh(
      'echo "${http_proxy:-}${https_proxy:-}${all_proxy:-}" | grep -c .',
    ),
    bad: ">0",
    detail:
      "every command-line tool routes through it, which means whoever runs that proxy sees the traffic",
    how:
      "`env | grep -i proxy` and find where it is set. Remove it if it is not yours.",
  },
  {
    id: "net-hosts-hijack",
    title: "/etc/hosts redirects well-known domains",
    category: "security",
    severity: "major",
    weight: 80,
    source: sh(
      "grep -vE '^\\s*#|^\\s*$|localhost|127\\.0\\.0\\.1|::1|ip6-' /etc/hosts 2>/dev/null | wc -l",
    ),
    bad: ">3",
    detail:
      "entries here override DNS entirely, and they are a common way to redirect update or licence checks — sometimes deliberately, sometimes not by you",
    how: "`cat /etc/hosts` and remove anything you did not add.",
  },
  {
    id: "net-listening-count",
    title: "A lot of services are listening on this machine",
    category: "security",
    severity: "minor",
    weight: 38,
    source: sh(
      "ss -ltun 2>/dev/null | tail -n +2 | grep -vcE '127\\.0\\.0\\.1|\\[::1\\]'",
    ),
    bad: ">12",
    detail:
      "each open socket is something that accepts input from the network; a workstation rarely needs many",
    how:
      "`sudo ss -ltunp` names the owner of each. Work down the list and turn off what you do not use.",
  },
];
