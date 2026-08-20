// Writing a user configuration file, safely.
//
// Three properties, and the whole family of config checks rests on them:
//
//   1. Atomic — the new contents land by rename, so a crash mid-write leaves
//      the old file intact rather than half a file.
//   2. Exactly undoable — the previous contents are captured verbatim,
//      including "there was no file", and Undo restores that state.
//   3. Never clobbers — Undo refuses if the file no longer holds what the fix
//      wrote. Silently overwriting someone's later edit would be precisely the
//      harm this app exists to avoid.
import { dirname } from "@std/path";
import { readText } from "./sys.server.ts";

export type ConfWrite = {
  path: string;
  /** The file's contents before the fix, or null when it did not exist. */
  before: string | null;
  /** What the fix wrote — the fingerprint Undo checks against. */
  wrote: string;
};

/** Does the parent directory exist?
 *
 *  A config policy may create its file, but never its directory tree: making
 *  `~/.gnupg` (and getting its mode right) is the tool's job, not ours. No
 *  parent means the check does not apply to this machine. */
export async function parentExists(path: string): Promise<boolean> {
  try {
    return (await Deno.stat(dirname(path))).isDirectory;
  } catch {
    return false;
  }
}

/** Replace a file's contents atomically, preserving its mode. */
export async function writeConf(
  path: string,
  next: string,
): Promise<ConfWrite> {
  const before = await readText(path);
  const tmp = `${path}.fixable-${Deno.pid}.tmp`;
  await Deno.writeTextFile(tmp, next);
  try {
    // A new config file is private by default: these hold tokens often enough
    // that 0644 would be its own finding two rows down this very list.
    const mode = before === null
      ? 0o600
      : (await Deno.stat(path)).mode ?? 0o600;
    await Deno.chmod(tmp, mode & 0o7777);
    await Deno.rename(tmp, path);
  } catch (e) {
    await Deno.remove(tmp).catch(() => {});
    throw e;
  }
  return { path, before, wrote: next };
}

/** Put back exactly what was there — or, if the file has moved on, put back
 *  only the part this fix changed.
 *
 *  The whole-file restore is the exact one and is used whenever it is still
 *  correct. It stops being correct as soon as anything else edits the file —
 *  including the NEXT fix, since a dozen rows can share one `gpg.conf`. Undoing
 *  the first of them would then either refuse (leaving you no way back) or
 *  overwrite the other eleven. Neither is acceptable, so a `narrow` fallback
 *  reverts one key and leaves every other line alone. */
export const restoreConf = (
  w: ConfWrite,
  narrow?: (text: string) => string,
) =>
async (): Promise<void> => {
  const current = await readText(w.path);
  if (current === w.wrote) {
    if (w.before === null) await Deno.remove(w.path);
    else await writeConf(w.path, w.before);
    return;
  }
  if (current !== null && narrow) {
    await writeConf(w.path, narrow(current));
    return;
  }
  throw new Error(
    `${w.path} has changed since the fix, and this change cannot be undone ` +
      `on its own — edit the file by hand`,
  );
};
