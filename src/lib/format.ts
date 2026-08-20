// Display formatting. Pure — no aio, no Deno.

const KIB = 1024;
const UNITS = ["B", "KB", "MB", "GB", "TB", "PB"] as const;

export function bytes(n: number): string {
  let v = Math.max(0, n), i = 0;
  while (v >= KIB && i < UNITS.length - 1) (v /= KIB, i++);
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${UNITS[i]}`;
}

export const pct = (part: number, whole: number): number =>
  whole > 0 ? Math.round((part / whole) * 100) : 0;

export function duration(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min`;
  const h = Math.round(m / 60);
  return h < 48 ? `${h} h` : `${Math.round(h / 24)} days`;
}

/** "just now" / "3 min ago". `now` is a parameter so this stays pure — and so
 *  a test does not have to freeze the clock. */
export const ago = (at: number, now: number): string =>
  now - at < 5_000 ? "just now" : `${duration(now - at)} ago`;

export const clock = (at: number): string =>
  new Date(at).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
