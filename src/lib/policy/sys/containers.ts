// Containers and virtualisation — the parts that reach back out to the host.
import type { SysPolicy } from "../../../type/policy.ts";

const sh = (script: string) => ({
  kind: "cmd" as const,
  cmd: "sh",
  args: ["-c", script] as const,
});

export const CONTAINER_POLICIES: SysPolicy[] = [
  {
    id: "ctr-privileged",
    title: "A container is running with full host privileges",
    category: "security",
    severity: "critical",
    weight: 97,
    source: sh(
      "docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.HostConfig.Privileged}}' 2>/dev/null | grep -c true",
    ),
    bad: ">0",
    detail:
      "a privileged container has effectively the same access as root on the host — the isolation is nominal",
    how:
      "`docker ps --format '{{.Names}}'` then `docker inspect <name> | grep Privileged`. Replace `--privileged` with the specific capabilities the workload needs.",
  },
  {
    id: "ctr-host-network",
    title: "A container shares the host network",
    category: "security",
    severity: "major",
    weight: 80,
    source: sh(
      "docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.HostConfig.NetworkMode}}' 2>/dev/null | grep -c '^host$'",
    ),
    bad: ">0",
    detail:
      "the container binds ports directly on the host, so its services are exposed exactly as a host service would be — and the firewall rules you wrote for containers do not apply",
    how:
      "Use the default bridge network and publish only the ports you mean, to 127.0.0.1 where possible.",
  },
  {
    id: "ctr-docker-sock-mounted",
    title: "A container has the Docker socket mounted into it",
    category: "security",
    severity: "critical",
    weight: 98,
    source: sh(
      "docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null | grep -c 'docker.sock'",
    ),
    bad: ">0",
    detail:
      "a container that can talk to the Docker socket can start another container that mounts the host filesystem — it is root on the host, one step removed",
    how:
      "Remove the mount, or put a socket proxy in front of it that only exposes the endpoints that container actually needs.",
  },
  {
    id: "ctr-restart-always-stopped",
    title: "A container is set to always restart and keeps stopping",
    category: "stability",
    severity: "minor",
    weight: 46,
    source: sh(
      "docker ps -a --filter 'status=restarting' -q 2>/dev/null | wc -l",
    ),
    bad: ">0",
    detail:
      "a container is looping through restarts, burning CPU and filling the log",
    how:
      "`docker ps -a --filter status=restarting` names it, `docker logs <name>` says why.",
  },
  {
    id: "ctr-images-stale",
    title: "Container images have not been rebuilt in a long time",
    category: "security",
    severity: "minor",
    weight: 52,
    source: sh(
      "docker images --format '{{.CreatedSince}}' 2>/dev/null | grep -cE '(1[0-9]|[2-9][0-9]) months|years'",
    ),
    bad: ">2",
    detail:
      "an image carries the libraries it was built with, so an old image carries old vulnerabilities however current the host is",
    how:
      "`docker images` to see the ages, then `docker pull` and rebuild the ones you still run.",
  },
  {
    id: "ctr-userns-off",
    title: "Docker is not using user namespace remapping",
    category: "security",
    severity: "minor",
    weight: 50,
    // "not contains" has no verdict spelling, so the shell answers the
    // question and the row compares the answer.
    source: sh(
      "docker info --format '{{.SecurityOptions}}' 2>/dev/null | grep -q userns && echo on || echo off",
    ),
    bad: "~off",
    detail:
      "root inside a container is root on the host if it escapes; user-namespace remapping makes it an unprivileged id instead",
    how:
      'Set `"userns-remap": "default"` in /etc/docker/daemon.json and restart Docker. It changes volume ownership, so read the documentation before turning it on.',
  },
  {
    id: "ctr-flatpak-host-fs",
    title: "A sandboxed application has access to your whole filesystem",
    category: "security",
    severity: "critical",
    weight: 91,
    source: sh(
      'flatpak list --app --columns=application 2>/dev/null | while read -r a; do flatpak info --show-permissions "$a" 2>/dev/null | grep -qE \'filesystems=.*(host|home)\' && echo "$a"; done | wc -l',
    ),
    bad: ">0",
    detail:
      "an application inside a sandbox that can read your entire home directory is not meaningfully sandboxed",
    how:
      "`flatpak list --app` then `flatpak info --show-permissions <app>`. Narrow it with `flatpak override --user --nofilesystem=home <app> --filesystem=~/Documents`, one application at a time so you can tell what breaks.",
  },
  {
    id: "ctr-flatpak-devices",
    title: "A sandboxed application can reach every device",
    category: "security",
    severity: "major",
    weight: 78,
    source: sh(
      'flatpak list --app --columns=application 2>/dev/null | while read -r a; do flatpak info --show-permissions "$a" 2>/dev/null | grep -q \'devices=all\' && echo "$a"; done | wc -l',
    ),
    bad: ">0",
    detail:
      "`devices=all` includes raw input devices, which is enough to read your keyboard from inside the sandbox",
    how:
      "`flatpak override --user --nodevice=all --device=dri <app>` keeps graphics working while removing the rest.",
  },
  {
    id: "ctr-flatpak-talk-flatpak",
    title: "A sandboxed application can escape its own sandbox",
    category: "security",
    severity: "critical",
    weight: 96,
    source: sh(
      'flatpak list --app --columns=application 2>/dev/null | while read -r a; do flatpak info --show-permissions "$a" 2>/dev/null | grep -q \'org.freedesktop.Flatpak\' && echo "$a"; done | wc -l',
    ),
    bad: ">0",
    detail:
      "an application allowed to call the Flatpak service can start a process outside its sandbox, which makes the sandbox decorative",
    how:
      "`flatpak override --user --no-talk-name=org.freedesktop.Flatpak <app>`. Some development tools genuinely need it — those are the ones to be deliberate about.",
  },
  {
    id: "ctr-flatpak-stale",
    title: "Sandboxed applications have not been updated in a long time",
    category: "security",
    severity: "minor",
    weight: 47,
    source: sh(
      'f=$(ls -d /var/lib/flatpak 2>/dev/null); [ -n "$f" ] && echo $(( ( $(date +%s) - $(stat -c %Y "$f") ) / 86400 )) || echo \'\'',
    ),
    bad: ">60",
    detail:
      "each Flatpak bundles its own libraries, so its vulnerabilities are its own and system updates do not touch them",
    how: "`flatpak update`. Consider a weekly timer for it.",
  },
];
