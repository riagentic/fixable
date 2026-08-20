// Firewall, and the ways a desktop ends up with none.
import type { SysPolicy } from "../../../type/policy.ts";

export const FIREWALL_POLICIES: SysPolicy[] = [
  {
    id: "fw-ufw-inactive",
    title: "The firewall is installed but not running",
    category: "security",
    severity: "critical",
    weight: 92,
    source: {
      kind: "cmd",
      cmd: "systemctl",
      args: ["is-active", "ufw"],
      needs: "ufw",
    },
    bad: "~inactive",
    detail:
      "nothing filters what reaches this machine from the network it is on",
    how:
      "`sudo ufw enable` — check `sudo ufw status verbose` first so you know what it will allow. On a laptop that joins untrusted networks this is the single highest-value change on this list.",
  },
  {
    id: "fw-ufw-not-enabled-boot",
    title: "The firewall does not start at boot",
    category: "security",
    severity: "major",
    weight: 84,
    source: {
      kind: "cmd",
      cmd: "systemctl",
      args: ["is-enabled", "ufw"],
      needs: "ufw",
    },
    bad: "~disabled",
    detail: "the firewall protects this machine only until it is restarted",
    how: "`sudo systemctl enable ufw`.",
  },
  {
    id: "fw-nft-empty",
    title: "The kernel packet filter has no rules at all",
    category: "security",
    severity: "major",
    weight: 83,
    source: {
      kind: "cmd",
      cmd: "nft",
      args: ["list", "ruleset"],
      needs: "nft",
    },
    bad: "=0",
    extract: "^(\\s*)$",
    detail:
      "nftables is present and its ruleset is empty, so every packet is accepted",
    how:
      "Use ufw (`sudo ufw enable`) unless you are managing nftables directly. Check with `sudo nft list ruleset`.",
  },
  {
    id: "fw-iptables-accept",
    title: "The default INPUT policy accepts everything",
    category: "security",
    severity: "major",
    weight: 82,
    source: { kind: "cmd", cmd: "iptables", args: ["-S"], needs: "iptables" },
    bad: "~-P INPUT ACCEPT",
    detail: "anything not explicitly dropped is allowed in",
    how:
      "Let ufw manage this (`sudo ufw enable`, which sets a deny-incoming default), or set the policy yourself once you have rules that keep you connected.",
  },
  {
    id: "fw-docker-bypass",
    title: "Docker publishes ports around the firewall",
    category: "security",
    severity: "critical",
    weight: 91,
    source: {
      kind: "cmd",
      cmd: "iptables",
      args: ["-S", "DOCKER"],
      needs: "iptables",
    },
    bad: "~-j ACCEPT",
    detail:
      "a container published with -p is reachable from the network even when ufw says deny — Docker writes its own rules ahead of ufw's, and this surprises almost everyone",
    how:
      'Publish to localhost explicitly (`-p 127.0.0.1:8080:80`), or set `"iptables": false` in /etc/docker/daemon.json and manage the rules yourself. Do not rely on ufw alone while Docker is running.',
  },
  {
    id: "fw-ip6-disabled-only",
    title: "IPv6 is up but the firewall covers IPv4 only",
    category: "security",
    severity: "major",
    weight: 81,
    source: { kind: "file", path: "/etc/default/ufw" },
    bad: "~IPV6=no",
    detail:
      "every rule you added protects one address family, and the machine is reachable over the other",
    how: "Set `IPV6=yes` in /etc/default/ufw and `sudo ufw reload`.",
  },
  {
    id: "fw-ufw-logging-off",
    title: "The firewall keeps no log",
    category: "security",
    severity: "minor",
    weight: 42,
    source: { kind: "file", path: "/etc/ufw/ufw.conf" },
    bad: "~LOGLEVEL=off",
    detail:
      "blocked traffic leaves no trace, so there is nothing to look at after the fact",
    how: "`sudo ufw logging low`. Higher levels are noisy on a desktop.",
  },
  {
    id: "fw-forwarding-on",
    title: "Packet forwarding is enabled with no firewall in front of it",
    category: "security",
    severity: "major",
    weight: 80,
    source: { kind: "file", path: "/proc/sys/net/ipv4/ip_forward" },
    bad: "=1",
    detail:
      "the machine routes traffic between the networks it is attached to, which can bridge an untrusted one into a trusted one",
    how:
      "If this is not deliberate (a VM host, a container bridge or a shared connection turns it on), set `net.ipv4.ip_forward=0` in /etc/sysctl.d/99-local.conf.",
  },
];
